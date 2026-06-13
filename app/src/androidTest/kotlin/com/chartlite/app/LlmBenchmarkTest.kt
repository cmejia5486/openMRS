package com.chartlite.app

import android.app.ActivityManager
import android.content.Context
import android.os.Build
import android.util.Log
import androidx.test.ext.junit.runners.AndroidJUnit4
import androidx.test.platform.app.InstrumentationRegistry
import com.chartlite.app.config.AppConfig
import com.chartlite.app.config.CountryConfigLoader
import com.chartlite.app.extraction.*
import com.chartlite.app.extraction.LlmModelManager.GenerationConfig
import com.chartlite.app.extraction.LlmModelManager.ModelTier
import com.chartlite.app.model.Formulary
import com.chartlite.app.model.ICD10Index
import com.chartlite.app.model.StructuredEncounter
import kotlinx.coroutines.runBlocking
import org.json.JSONArray
import org.json.JSONObject
import org.junit.After
import org.junit.Before
import org.junit.Test
import org.junit.runner.RunWith
import java.io.File

/**
 * LLM engine benchmark — run on real devices to compare inference across tiers.
 *
 * Measures per engine:
 * - Model load time (cold start)
 * - Inference latency (time to complete)
 * - Output length (chars, rough token proxy)
 * - Extraction quality (did it find expected diagnoses/meds/vitals?)
 * - Peak memory usage
 *
 * Run on a specific device:
 *   ./gradlew connectedDebugAndroidTest \
 *     -Pandroid.testInstrumentationRunnerArguments.class=com.chartlite.app.LlmBenchmarkTest
 *
 * Results logged to logcat (tag: LlmBenchmark) and saved to:
 *   /sdcard/Download/chartlite_benchmark_{device}.json
 */
@RunWith(AndroidJUnit4::class)
class LlmBenchmarkTest {

    companion object {
        private const val TAG = "LlmBenchmark"

        // Standard clinical transcripts for benchmarking — varying complexity
        val TRANSCRIPT_SIMPLE = """
            45 year old male presenting with cough for 3 days.
            Temperature 38.2 degrees. BP 130 over 85. Pulse 88.
            Diagnosis pneumonia. Prescribe amoxicillin 500mg TDS for 7 days.
            Follow up in 1 week.
        """.trimIndent()

        val TRANSCRIPT_COMPLEX = """
            32 year old female, known diabetic on metformin 500mg BD.
            Presenting today with productive cough, fever for 5 days, and chest pain on deep breathing.
            She also reports increased urination and thirst over the past 2 weeks.
            Allergies to penicillin and sulfa drugs.
            On examination temperature 39.1 degrees celsius. BP is 145 over 92.
            Pulse 110 beats per minute. Respiratory rate 24. SpO2 93% on room air.
            Weight 78 kg.
            Assessment: community acquired pneumonia, possible diabetic ketoacidosis.
            Plan: admit for observation. Start IV ceftriaxone 1g BD.
            Check random blood glucose and HbA1c.
            Continue metformin. Add insulin sliding scale if glucose above 15.
            Refer to internal medicine urgently.
            Follow up bloods in 48 hours.
        """.trimIndent()

        val TRANSCRIPT_MULTILINGUAL = """
            Umuntu oneminyaka engu-28, owesifazane.
            Patient is 28 year old female presenting with headache and dizziness for 2 days.
            BP 160 over 100. Temperature normal. Pulse 76.
            She is 6 months pregnant. No allergies.
            Diagnosis pregnancy induced hypertension.
            Start methyldopa 250mg TDS.
            Refer to antenatal clinic. Follow up in 3 days.
        """.trimIndent()
    }

    private lateinit var context: Context
    private lateinit var modelManager: LlmModelManager
    private lateinit var formulary: Formulary
    private lateinit var icd10: ICD10Index
    private val results = JSONArray()

    @Before
    fun setup() {
        context = InstrumentationRegistry.getInstrumentation().targetContext
        modelManager = LlmModelManager(context)

        // Load clinical reference data for extraction quality scoring
        val configLoader = CountryConfigLoader(context)
        formulary = try {
            configLoader.loadFormulary("formulary/za_formulary.json")
        } catch (_: Exception) {
            Formulary("1.0", "za", emptyList())
        }
        icd10 = try {
            configLoader.loadICD10("icd10/phc_top300.json")
        } catch (_: Exception) {
            ICD10Index("1.0", emptyList())
        }
    }

    @After
    fun teardown() {
        // Save results to device storage
        try {
            val deviceName = "${Build.MANUFACTURER}_${Build.MODEL}".replace(" ", "_")
            val outFile = File("/sdcard/Download/chartlite_benchmark_$deviceName.json")
            val report = JSONObject().apply {
                put("device", deviceInfo())
                put("timestamp", System.currentTimeMillis())
                put("results", results)
            }
            outFile.writeText(report.toString(2))
            Log.i(TAG, "Benchmark results saved to: ${outFile.absolutePath}")
        } catch (e: Exception) {
            Log.w(TAG, "Could not save results file (storage permission?), results in logcat only", e)
        }

        // Clean up
        try { modelManager.unloadModel() } catch (_: Exception) {}
    }

    // ═══════════════════════════════════════════════════════════════════════
    // On-Device: Qwen via MNN
    // ═══════════════════════════════════════════════════════════════════════

    @Test
    fun benchmark_onDevice_recommended_tier() = runBlocking {
        val tier = modelManager.recommendedTier()
        Log.i(TAG, "═══ Device: ${deviceLabel()} | Recommended tier: ${tier.label} ═══")

        if (!modelManager.isReady()) {
            logSkip("on_device_${tier.name}", "Model not downloaded (${tier.label})")
            return@runBlocking
        }

        benchmarkOnDeviceTier(tier)
    }

    @Test
    fun benchmark_onDevice_small_tier() = runBlocking {
        Log.i(TAG, "═══ Device: ${deviceLabel()} | Forced tier: SMALL ═══")
        modelManager.overrideTier = ModelTier.SMALL

        if (!modelManager.isReady()) {
            logSkip("on_device_SMALL", "Small model not downloaded")
            return@runBlocking
        }

        benchmarkOnDeviceTier(ModelTier.SMALL)
        modelManager.overrideTier = null
    }

    @Test
    fun benchmark_onDevice_large_tier() = runBlocking {
        Log.i(TAG, "═══ Device: ${deviceLabel()} | Forced tier: LARGE ═══")
        modelManager.overrideTier = ModelTier.LARGE

        if (!modelManager.isReady()) {
            logSkip("on_device_LARGE", "Large model not downloaded")
            return@runBlocking
        }

        if (!modelManager.hasRuntimeHeadroom()) {
            logSkip("on_device_LARGE", "Insufficient RAM for large model on this device")
            return@runBlocking
        }

        benchmarkOnDeviceTier(ModelTier.LARGE)
        modelManager.overrideTier = null
    }

    // ═══════════════════════════════════════════════════════════════════════
    // Regex baseline (always available, measures extraction-only speed)
    // ═══════════════════════════════════════════════════════════════════════

    @Test
    fun benchmark_regex_extraction() = runBlocking {
        Log.i(TAG, "═══ Regex extraction baseline ═══")

        val extractor = ClinicalExtractor(formulary, icd10)
        val transcripts = mapOf(
            "simple" to TRANSCRIPT_SIMPLE,
            "complex" to TRANSCRIPT_COMPLEX,
            "multilingual" to TRANSCRIPT_MULTILINGUAL
        )

        for ((label, transcript) in transcripts) {
            val ramBefore = availableRamMb()
            val start = System.nanoTime()
            val result = extractor.extract(transcript, "pat-001", "prov-001", "fac-001")
            val elapsed = (System.nanoTime() - start) / 1_000_000.0
            val ramAfter = availableRamMb()

            val entry = JSONObject().apply {
                put("engine", "regex")
                put("transcript", label)
                put("load_ms", 0)
                put("inference_ms", elapsed)
                put("output_chars", 0) // regex doesn't produce raw text
                put("ram_before_mb", ramBefore)
                put("ram_after_mb", ramAfter)
                put("quality", qualityScore(result, label))
            }
            results.put(entry)

            Log.i(TAG, "  Regex [$label]: ${elapsed.toLong()}ms | quality=${qualityScore(result, label)}")
        }
    }

    // ═══════════════════════════════════════════════════════════════════════
    // Cloud engines (skipped if no API key configured)
    // ═══════════════════════════════════════════════════════════════════════

    @Test
    fun benchmark_cloud_engines() = runBlocking {
        Log.i(TAG, "═══ Cloud engine benchmarks ═══")

        val appConfig = try { AppConfig(context) } catch (e: Exception) {
            Log.w(TAG, "Could not init AppConfig (encryption key?), skipping cloud tests", e)
            logSkip("cloud", "AppConfig init failed: ${e.message}")
            return@runBlocking
        }
        val promptBuilder = ExtractionPromptBuilder(icd10, formulary)
        val responseParser = LlmResponseParser(icd10, formulary)

        // Claude
        val claudeKey = appConfig.claudeApiKey
        if (claudeKey.isNotBlank()) {
            benchmarkCloudEngine("claude", ClaudeExtractionStrategy(
                context, promptBuilder, responseParser,
                ClaudeExtractionStrategy.AuthConfig.Direct { claudeKey }
            ))
        } else {
            logSkip("claude", "No API key configured")
        }

        // Gemini
        val geminiKey = appConfig.geminiApiKey
        if (geminiKey.isNotBlank()) {
            benchmarkCloudEngine("gemini", GeminiExtractionStrategy(
                context, promptBuilder, responseParser,
                GeminiExtractionStrategy.AuthConfig.Direct { geminiKey }
            ))
        } else {
            logSkip("gemini", "No API key configured")
        }

        // OpenAI
        val openaiKey = appConfig.openaiApiKey
        if (openaiKey.isNotBlank()) {
            benchmarkCloudEngine("openai", OpenAIExtractionStrategy(
                context, promptBuilder, responseParser,
                OpenAIExtractionStrategy.AuthConfig.Direct { openaiKey }
            ))
        } else {
            logSkip("openai", "No API key configured")
        }
    }

    // ═══════════════════════════════════════════════════════════════════════
    // Helpers
    // ═══════════════════════════════════════════════════════════════════════

    private suspend fun benchmarkOnDeviceTier(tier: ModelTier) {
        val transcripts = mapOf(
            "simple" to TRANSCRIPT_SIMPLE,
            "complex" to TRANSCRIPT_COMPLEX,
            "multilingual" to TRANSCRIPT_MULTILINGUAL
        )

        // Cold start: unload first, measure load time
        try { modelManager.unloadModel() } catch (_: Exception) {}
        Thread.sleep(500) // let GC settle

        val ramBeforeLoad = availableRamMb()
        val loadStart = System.nanoTime()
        modelManager.loadModel()
        val loadMs = (System.nanoTime() - loadStart) / 1_000_000.0
        val ramAfterLoad = availableRamMb()

        Log.i(TAG, "  Model load: ${loadMs.toLong()}ms | RAM: ${ramBeforeLoad}MB → ${ramAfterLoad}MB (Δ${ramBeforeLoad - ramAfterLoad}MB)")

        // Warm-up inference (first inference is always slower due to KV cache init)
        modelManager.runInference("Hello", maxTokens = 16)

        // Benchmark each transcript
        for ((label, transcript) in transcripts) {
            val ramBefore = availableRamMb()
            val start = System.nanoTime()
            val output = modelManager.runChatInference(
                systemPrompt = "Extract clinical data from this transcript as JSON.",
                userMessage = transcript,
                maxTokens = 512,
                config = GenerationConfig(temperature = 0.1f)
            )
            val inferenceMs = (System.nanoTime() - start) / 1_000_000.0
            val ramAfter = availableRamMb()

            // Also run through the full extraction strategy for quality scoring
            val promptBuilder = ExtractionPromptBuilder(icd10, formulary)
            val responseParser = LlmResponseParser(icd10, formulary)
            val strategy = QwenExtractionStrategy(
                modelManagerProvider = { modelManager },
                promptBuilder = promptBuilder,
                responseParser = responseParser
            )
            val encounter = try {
                strategy.extract(transcript, "pat-001", "prov-001", "fac-001")
            } catch (_: Exception) { null }

            val entry = JSONObject().apply {
                put("engine", "qwen_${tier.name.lowercase()}")
                put("tier", tier.label)
                put("transcript", label)
                put("load_ms", loadMs)
                put("inference_ms", inferenceMs)
                put("output_chars", output?.length ?: 0)
                put("ram_before_mb", ramBefore)
                put("ram_after_mb", ramAfter)
                put("ram_load_delta_mb", ramBeforeLoad - ramAfterLoad)
                put("quality", qualityScore(encounter, label))
                put("output_preview", output?.take(200) ?: "null")
            }
            results.put(entry)

            Log.i(TAG, buildString {
                append("  Qwen ${tier.label} [$label]: ")
                append("${inferenceMs.toLong()}ms | ")
                append("${output?.length ?: 0} chars | ")
                append("RAM Δ${ramBefore - ramAfter}MB | ")
                append("quality=${qualityScore(encounter, label)}")
            })
        }

        // Measure unload time
        val unloadStart = System.nanoTime()
        modelManager.unloadModel()
        val unloadMs = (System.nanoTime() - unloadStart) / 1_000_000.0
        Log.i(TAG, "  Model unload: ${unloadMs.toLong()}ms | RAM recovered to ${availableRamMb()}MB")
    }

    private suspend fun benchmarkCloudEngine(name: String, strategy: ExtractionStrategy) {
        if (!strategy.isAvailable()) {
            logSkip(name, "Strategy reports unavailable")
            return
        }

        val transcripts = mapOf(
            "simple" to TRANSCRIPT_SIMPLE,
            "complex" to TRANSCRIPT_COMPLEX,
            "multilingual" to TRANSCRIPT_MULTILINGUAL
        )

        for ((label, transcript) in transcripts) {
            val start = System.nanoTime()
            val encounter = try {
                strategy.extract(transcript, "pat-001", "prov-001", "fac-001")
            } catch (e: Exception) {
                Log.w(TAG, "  $name [$label]: FAILED — ${e.message}")
                null
            }
            val elapsedMs = (System.nanoTime() - start) / 1_000_000.0

            val entry = JSONObject().apply {
                put("engine", name)
                put("transcript", label)
                put("load_ms", 0)
                put("inference_ms", elapsedMs)
                put("output_chars", 0) // cloud doesn't expose raw output here
                put("quality", qualityScore(encounter, label))
            }
            results.put(entry)

            Log.i(TAG, "  $name [$label]: ${elapsedMs.toLong()}ms | quality=${qualityScore(encounter, label)}")
        }
    }

    /**
     * Score extraction quality 0-100 based on expected clinical findings.
     * Each transcript has known ground-truth items we expect to find.
     */
    private fun qualityScore(encounter: StructuredEncounter?, label: String): JSONObject {
        if (encounter == null) return JSONObject().apply {
            put("score", 0)
            put("details", "null result")
        }

        val checks = mutableListOf<Pair<String, Boolean>>()

        when (label) {
            "simple" -> {
                checks += "has_diagnosis" to encounter.diagnoses.isNotEmpty()
                checks += "has_pneumonia" to encounter.diagnoses.any {
                    it.icd10Code.startsWith("J") || it.name.contains("pneumonia", true)
                }
                checks += "has_medication" to encounter.medications.isNotEmpty()
                checks += "has_amoxicillin" to encounter.medications.any {
                    it.name.contains("amoxicillin", true)
                }
                checks += "has_vitals" to (encounter.vitals != null)
                checks += "has_bp" to (encounter.vitals?.systolicBP != null)
                checks += "has_temp" to (encounter.vitals?.temperature != null)
                checks += "has_followup" to (encounter.followUp != null)
            }
            "complex" -> {
                checks += "has_diagnosis" to encounter.diagnoses.isNotEmpty()
                checks += "has_pneumonia" to encounter.diagnoses.any {
                    it.icd10Code.startsWith("J") || it.name.contains("pneumonia", true)
                }
                checks += "has_2plus_diagnoses" to (encounter.diagnoses.size >= 2)
                checks += "has_medication" to encounter.medications.isNotEmpty()
                checks += "has_ceftriaxone" to encounter.medications.any {
                    it.name.contains("ceftriaxone", true)
                }
                checks += "has_metformin" to encounter.medications.any {
                    it.name.contains("metformin", true)
                }
                checks += "has_vitals" to (encounter.vitals != null)
                checks += "has_spo2" to (encounter.vitals?.oxygenSaturation != null)
                checks += "has_allergies" to encounter.allergies.isNotEmpty()
                checks += "has_penicillin_allergy" to encounter.allergies.any {
                    it.contains("penicillin", true)
                }
                checks += "has_referral" to (encounter.referral != null)
                checks += "has_followup" to (encounter.followUp != null)
            }
            "multilingual" -> {
                checks += "has_diagnosis" to encounter.diagnoses.isNotEmpty()
                checks += "has_hypertension" to encounter.diagnoses.any {
                    it.icd10Code.startsWith("O13") || it.icd10Code.startsWith("O14") ||
                        it.name.contains("hypertension", true)
                }
                checks += "has_medication" to encounter.medications.isNotEmpty()
                checks += "has_methyldopa" to encounter.medications.any {
                    it.name.contains("methyldopa", true)
                }
                checks += "has_vitals" to (encounter.vitals != null)
                checks += "has_high_bp" to ((encounter.vitals?.systolicBP ?: 0) >= 140)
                checks += "has_referral" to (encounter.referral != null)
            }
        }

        val passed = checks.count { it.second }
        val total = checks.size
        val score = if (total > 0) (passed * 100) / total else 0

        return JSONObject().apply {
            put("score", score)
            put("passed", passed)
            put("total", total)
            put("checks", JSONObject().apply {
                checks.forEach { (name, ok) -> put(name, ok) }
            })
        }
    }

    private fun logSkip(engine: String, reason: String) {
        Log.i(TAG, "  SKIP [$engine]: $reason")
        results.put(JSONObject().apply {
            put("engine", engine)
            put("skipped", true)
            put("reason", reason)
        })
    }

    private fun deviceInfo(): JSONObject = JSONObject().apply {
        val am = context.getSystemService(Context.ACTIVITY_SERVICE) as ActivityManager
        val memInfo = ActivityManager.MemoryInfo()
        am.getMemoryInfo(memInfo)

        put("manufacturer", Build.MANUFACTURER)
        put("model", Build.MODEL)
        put("device", Build.DEVICE)
        put("sdk", Build.VERSION.SDK_INT)
        put("abi", Build.SUPPORTED_ABIS.toList().toString())
        put("total_ram_mb", memInfo.totalMem / 1024 / 1024)
        put("available_ram_mb", memInfo.availMem / 1024 / 1024)
        put("low_memory", memInfo.lowMemory)
        put("cores", Runtime.getRuntime().availableProcessors())
        put("recommended_tier", modelManager.recommendedTier().name)
        put("model_downloaded", modelManager.isModelDownloaded())
        put("native_available", modelManager.isNativeAvailable())
    }

    private fun deviceLabel(): String = "${Build.MANUFACTURER} ${Build.MODEL} (${totalRamGb()}GB RAM)"

    private fun totalRamGb(): String {
        val am = context.getSystemService(Context.ACTIVITY_SERVICE) as ActivityManager
        val memInfo = ActivityManager.MemoryInfo()
        am.getMemoryInfo(memInfo)
        return "%.1f".format(memInfo.totalMem / (1024.0 * 1024.0 * 1024.0))
    }

    private fun availableRamMb(): Long {
        val am = context.getSystemService(Context.ACTIVITY_SERVICE) as ActivityManager
        val memInfo = ActivityManager.MemoryInfo()
        am.getMemoryInfo(memInfo)
        return memInfo.availMem / 1024 / 1024
    }
}
