package com.chartlite.benchmark

import android.app.ActivityManager
import android.content.Context
import android.os.Build
import android.os.Bundle
import android.util.Log
import androidx.activity.ComponentActivity
import androidx.activity.compose.setContent
import androidx.compose.foundation.horizontalScroll
import androidx.compose.foundation.layout.*
import androidx.compose.foundation.lazy.LazyColumn
import androidx.compose.foundation.lazy.items
import androidx.compose.foundation.rememberScrollState
import androidx.compose.material3.*
import androidx.compose.runtime.*
import androidx.compose.ui.Alignment
import androidx.compose.ui.Modifier
import androidx.compose.ui.graphics.Color
import androidx.compose.ui.text.font.FontFamily
import androidx.compose.ui.text.font.FontWeight
import androidx.compose.ui.text.style.TextOverflow
import androidx.compose.ui.unit.dp
import androidx.compose.ui.unit.sp
import com.chartlite.benchmark.engine.*
import kotlinx.coroutines.launch
import org.json.JSONArray
import org.json.JSONObject
import java.io.File

class MainActivity : ComponentActivity() {
    override fun onCreate(savedInstanceState: Bundle?) {
        super.onCreate(savedInstanceState)
        setContent {
            MaterialTheme(colorScheme = darkColorScheme()) {
                BenchmarkScreen(this@MainActivity)
            }
        }
    }
}

private const val TAG = "LlmBenchmark"

/** Clinical EMR prompt — same across all engines for fair comparison. */
private const val BENCHMARK_PROMPT = """45 year old male presenting with cough for 3 days, productive with yellow sputum. Temperature 38.5 degrees celsius. BP 135 over 88. Pulse 96 bpm. SpO2 94% on room air. Weight 82 kg. Known hypertensive on amlodipine 5mg daily. Allergic to penicillin. Assessment: community acquired pneumonia. Plan: prescribe levofloxacin 750mg OD for 7 days. Paracetamol 1g QDS PRN for fever. Continue amlodipine. Follow up in 5 days. Refer to chest clinic if no improvement."""

/** All engines that have downloadable Qwen 3.5 0.8B models. */
private fun createEngines(context: Context): List<BenchmarkEngine> = listOf(
    MnnEngine(context),
    LlamaCppEngine(context),
)

@Composable
fun BenchmarkScreen(context: Context) {
    val scope = rememberCoroutineScope()
    val engines = remember { createEngines(context) }

    var status by remember { mutableStateOf("Ready") }
    var busyEngine by remember { mutableStateOf<String?>(null) } // which engine is busy (download/run)
    var runningAll by remember { mutableStateOf(false) }
    var results by remember { mutableStateOf<List<BenchmarkResult>>(emptyList()) }
    var downloadProgress by remember { mutableStateOf<Map<String, Float>>(emptyMap()) }
    // Track ready state separately so it recomposes after download
    var readyState by remember { mutableStateOf(engines.associate { it.name to it.isModelReady() }) }

    val isBusy = busyEngine != null || runningAll

    Surface(modifier = Modifier.fillMaxSize(), color = MaterialTheme.colorScheme.background) {
        LazyColumn(
            modifier = Modifier
                .fillMaxSize()
                .padding(16.dp),
            verticalArrangement = Arrangement.spacedBy(12.dp)
        ) {
            // Header
            item {
                Text(
                    "Qwen 3.5 0.8B Benchmark",
                    style = MaterialTheme.typography.headlineMedium,
                    fontWeight = FontWeight.Bold
                )
                Spacer(Modifier.height(4.dp))
                Text(
                    deviceLabel(context),
                    style = MaterialTheme.typography.bodySmall,
                    color = MaterialTheme.colorScheme.onSurfaceVariant
                )
                Spacer(Modifier.height(2.dp))
                Text(
                    "Same model, same prompt — comparing inference runtimes",
                    style = MaterialTheme.typography.bodySmall,
                    color = MaterialTheme.colorScheme.onSurfaceVariant
                )
                if (isBusy) {
                    Spacer(Modifier.height(4.dp))
                    Text(
                        status,
                        style = MaterialTheme.typography.bodySmall,
                        color = MaterialTheme.colorScheme.primary
                    )
                }
            }

            // Engine cards with per-engine download & run
            items(engines) { engine ->
                val ready = readyState[engine.name] == true
                val result = results.find { it.engine == engine.name }
                EngineCard(
                    engine = engine,
                    ready = ready,
                    progress = downloadProgress[engine.name],
                    result = result,
                    isBusy = isBusy,
                    onDownload = {
                        scope.launch {
                            busyEngine = engine.name
                            status = "Downloading ${engine.name}..."
                            val ok = downloadModel(engine, context) { pct ->
                                downloadProgress = downloadProgress + (engine.name to pct)
                            }
                            downloadProgress = downloadProgress - engine.name
                            readyState = readyState + (engine.name to engine.isModelReady())
                            status = if (ok) "${engine.name} downloaded" else "${engine.name} download failed"
                            busyEngine = null
                        }
                    },
                    onRun = {
                        scope.launch {
                            busyEngine = engine.name
                            results = results.filter { it.engine != engine.name }
                            val r = runSingleBenchmark(engine) { s -> status = "${engine.name}: $s" }
                            results = results + r
                            status = if (r.error == null) "${engine.name}: ${"%.1f".format(r.metrics.decodeTokPerSec)} tok/s" else "${engine.name}: failed"
                            busyEngine = null
                            saveResults(context, results)
                        }
                    }
                )
            }

            // Bulk action buttons
            item {
                Spacer(Modifier.height(4.dp))
                val allReady = engines.all { readyState[it.name] == true }
                val anyReady = engines.any { readyState[it.name] == true }
                val anyNotReady = engines.any { readyState[it.name] != true }

                Row(
                    modifier = Modifier.fillMaxWidth(),
                    horizontalArrangement = Arrangement.spacedBy(8.dp)
                ) {
                    if (anyNotReady) {
                        OutlinedButton(
                            onClick = {
                                scope.launch {
                                    runningAll = true
                                    for (engine in engines) {
                                        if (engine.isModelReady()) continue
                                        status = "Downloading ${engine.name}..."
                                        downloadModel(engine, context) { pct ->
                                            downloadProgress = downloadProgress + (engine.name to pct)
                                        }
                                        downloadProgress = downloadProgress - engine.name
                                        readyState = readyState + (engine.name to engine.isModelReady())
                                    }
                                    status = "Downloads complete"
                                    runningAll = false
                                }
                            },
                            enabled = !isBusy,
                            modifier = Modifier.weight(1f)
                        ) {
                            Text("Download All", maxLines = 1)
                        }
                    }

                    Button(
                        onClick = {
                            scope.launch {
                                runningAll = true
                                results = emptyList()
                                val readyEngines = engines.filter { it.isModelReady() }
                                for (engine in readyEngines) {
                                    val r = runSingleBenchmark(engine) { s -> status = "${engine.name}: $s" }
                                    results = results + r
                                }
                                status = "Done — ${results.count { it.error == null }}/${results.size} engines"
                                runningAll = false
                                saveResults(context, results)
                            }
                        },
                        enabled = !isBusy && anyReady,
                        modifier = Modifier.weight(1f)
                    ) {
                        Text("Run All", maxLines = 1)
                    }
                }
            }

            // Results table
            if (results.any { it.error == null }) {
                item {
                    Spacer(Modifier.height(8.dp))
                    Text("Results", style = MaterialTheme.typography.titleMedium, fontWeight = FontWeight.Bold)
                }
                item { ResultsTable(results) }
                items(results) { result -> ResultDetailCard(result) }
            }
        }
    }
}

@Composable
fun EngineCard(
    engine: BenchmarkEngine,
    ready: Boolean,
    progress: Float?,
    result: BenchmarkResult?,
    isBusy: Boolean,
    onDownload: () -> Unit,
    onRun: () -> Unit,
) {
    val sizeMb = when (engine) {
        is MnnEngine -> MnnEngine.MODEL_SIZE_MB
        is LlamaCppEngine -> LlamaCppEngine.MODEL_SIZE_MB
        else -> 0
    }

    Card(
        modifier = Modifier.fillMaxWidth(),
        colors = CardDefaults.cardColors(
            containerColor = when {
                result?.error == null && result != null -> MaterialTheme.colorScheme.primaryContainer.copy(alpha = 0.3f)
                ready -> MaterialTheme.colorScheme.surfaceVariant.copy(alpha = 0.7f)
                else -> MaterialTheme.colorScheme.surfaceVariant.copy(alpha = 0.4f)
            }
        )
    ) {
        Column(modifier = Modifier.padding(12.dp)) {
            Row(
                modifier = Modifier.fillMaxWidth(),
                horizontalArrangement = Arrangement.SpaceBetween,
                verticalAlignment = Alignment.CenterVertically
            ) {
                Column(modifier = Modifier.weight(1f)) {
                    Text(engine.name, fontWeight = FontWeight.Bold)
                    Text(
                        "${engine.modelFormat} · ${sizeMb}MB",
                        style = MaterialTheme.typography.bodySmall,
                        color = MaterialTheme.colorScheme.onSurfaceVariant
                    )
                }
                Row(horizontalArrangement = Arrangement.spacedBy(6.dp)) {
                    if (!ready && progress == null) {
                        OutlinedButton(
                            onClick = onDownload,
                            enabled = !isBusy,
                            contentPadding = PaddingValues(horizontal = 12.dp, vertical = 4.dp)
                        ) {
                            Text("Download", style = MaterialTheme.typography.labelSmall)
                        }
                    }
                    if (ready) {
                        Button(
                            onClick = onRun,
                            enabled = !isBusy,
                            contentPadding = PaddingValues(horizontal = 12.dp, vertical = 4.dp)
                        ) {
                            Text("Run", style = MaterialTheme.typography.labelSmall)
                        }
                    }
                }
            }

            // Download progress
            if (progress != null) {
                Spacer(Modifier.height(6.dp))
                LinearProgressIndicator(
                    progress = { progress },
                    modifier = Modifier.fillMaxWidth()
                )
                Text(
                    "Downloading… ${(progress * 100).toInt()}%",
                    style = MaterialTheme.typography.labelSmall,
                    color = MaterialTheme.colorScheme.onSurfaceVariant,
                    modifier = Modifier.padding(top = 2.dp)
                )
            }

            // Inline result summary
            if (result != null) {
                Spacer(Modifier.height(6.dp))
                if (result.error != null) {
                    Text(
                        "✗ ${result.error}",
                        style = MaterialTheme.typography.bodySmall,
                        color = MaterialTheme.colorScheme.error
                    )
                } else {
                    Text(
                        "✓ ${"%.1f".format(result.metrics.decodeTokPerSec)} tok/s · Load ${result.metrics.loadMs.toLong()}ms · Decode ${result.metrics.decodedTokens} tok in ${result.metrics.decodeMs.toLong()}ms",
                        style = MaterialTheme.typography.bodySmall,
                        color = Color(0xFF66BB6A)
                    )
                }
            }
        }
    }
}

@Composable
fun ResultsTable(results: List<BenchmarkResult>) {
    val successResults = results.filter { it.error == null }
    if (successResults.isEmpty()) return

    Card(modifier = Modifier.fillMaxWidth()) {
        Column(
            modifier = Modifier
                .horizontalScroll(rememberScrollState())
                .padding(12.dp)
        ) {
            Row {
                TableCell("Engine", 100.dp, fontWeight = FontWeight.Bold)
                TableCell("Load", 70.dp, fontWeight = FontWeight.Bold)
                TableCell("Prefill", 80.dp, fontWeight = FontWeight.Bold)
                TableCell("Decode", 80.dp, fontWeight = FontWeight.Bold)
                TableCell("tok/s", 70.dp, fontWeight = FontWeight.Bold)
                TableCell("Tokens", 60.dp, fontWeight = FontWeight.Bold)
            }
            HorizontalDivider(modifier = Modifier.padding(vertical = 4.dp))
            for (r in results) {
                if (r.error != null) {
                    Row {
                        TableCell(r.engine, 100.dp)
                        TableCell("—", 70.dp)
                        TableCell("error", 80.dp)
                        TableCell("", 80.dp)
                        TableCell("", 70.dp)
                        TableCell("", 60.dp)
                    }
                } else {
                    Row {
                        TableCell(r.engine, 100.dp)
                        TableCell("${r.metrics.loadMs.toLong()}ms", 70.dp)
                        TableCell("${r.metrics.prefillMs.toLong()}ms", 80.dp)
                        TableCell("${r.metrics.decodeMs.toLong()}ms", 80.dp)
                        TableCell("%.1f".format(r.metrics.decodeTokPerSec), 70.dp)
                        TableCell("${r.metrics.decodedTokens}", 60.dp)
                    }
                }
            }
        }
    }
}

@Composable
fun TableCell(text: String, width: androidx.compose.ui.unit.Dp, fontWeight: FontWeight? = null) {
    Text(
        text,
        modifier = Modifier.width(width),
        style = MaterialTheme.typography.bodySmall.copy(
            fontFamily = FontFamily.Monospace,
            fontWeight = fontWeight
        ),
        maxLines = 1,
        overflow = TextOverflow.Ellipsis
    )
}

@Composable
fun ResultDetailCard(result: BenchmarkResult) {
    Card(modifier = Modifier.fillMaxWidth()) {
        Column(modifier = Modifier.padding(12.dp)) {
            Text(
                "${result.engine} (${result.format})",
                fontWeight = FontWeight.Bold,
                style = MaterialTheme.typography.titleSmall
            )
            Spacer(Modifier.height(4.dp))
            if (result.error != null) {
                Text(
                    "Error: ${result.error}",
                    color = MaterialTheme.colorScheme.error,
                    style = MaterialTheme.typography.bodySmall
                )
            } else {
                val m = result.metrics
                Text(
                    buildString {
                        appendLine("Load: ${m.loadMs.toLong()}ms")
                        appendLine("Prefill: ${m.promptTokens} tok in ${m.prefillMs.toLong()}ms (${"%.1f".format(m.prefillTokPerSec)} tok/s)")
                        appendLine("Decode: ${m.decodedTokens} tok in ${m.decodeMs.toLong()}ms (${"%.1f".format(m.decodeTokPerSec)} tok/s)")
                        appendLine("Total: ${m.totalMs.toLong()}ms")
                    },
                    style = MaterialTheme.typography.bodySmall.copy(fontFamily = FontFamily.Monospace),
                    lineHeight = 18.sp
                )
                if (result.outputPreview.isNotBlank()) {
                    Spacer(Modifier.height(4.dp))
                    Text(
                        "Output: ${result.outputPreview}",
                        style = MaterialTheme.typography.bodySmall,
                        maxLines = 3,
                        overflow = TextOverflow.Ellipsis,
                        color = MaterialTheme.colorScheme.onSurfaceVariant
                    )
                }
            }
        }
    }
}

data class BenchmarkResult(
    val engine: String,
    val format: String,
    val metrics: EngineMetrics,
    val outputPreview: String = "",
    val error: String? = null
)

private suspend fun downloadModel(
    engine: BenchmarkEngine,
    context: Context,
    onProgress: (Float) -> Unit
): Boolean {
    return when (engine) {
        is MnnEngine -> {
            val zipFile = File(context.noBackupFilesDir, "benchmark_models/mnn/model.zip")
            val success = ModelDownloader.download(MnnEngine.MODEL_URL, zipFile) {
                onProgress(it.percent / 100f)
            }
            if (success) {
                // Zip contains files at root — extract directly into the modelDir subdirectory
                val destDir = File(context.noBackupFilesDir, "benchmark_models/mnn/qwen35-0.8b-mnn")
                ModelDownloader.extractZip(zipFile, destDir)
            } else false
        }
        is LlamaCppEngine -> {
            engine.modelFile.parentFile?.mkdirs()
            ModelDownloader.download(LlamaCppEngine.MODEL_URL, engine.modelFile) {
                onProgress(it.percent / 100f)
            }
        }
        else -> false
    }
}

private suspend fun runSingleBenchmark(
    engine: BenchmarkEngine,
    onStatus: (String) -> Unit
): BenchmarkResult {
    if (!engine.isModelReady()) {
        return BenchmarkResult(engine.name, engine.modelFormat, EngineMetrics(), error = "Model not downloaded")
    }

    onStatus("loading…")
    return try {
        engine.unload()
        Thread.sleep(300)
        val loadMs = engine.loadModel()
        Log.i(TAG, "${engine.name} loaded in ${loadMs.toLong()}ms")

        onStatus("warm-up…")
        engine.generate("Hello", maxTokens = 16)

        onStatus("generating…")
        val output = engine.generate(BENCHMARK_PROMPT, maxTokens = 256)
        val metrics = engine.lastMetrics()

        Log.i(TAG, "${engine.name}: prefill=${metrics.prefillTokPerSec.toLong()} tok/s, decode=${metrics.decodeTokPerSec.toLong()} tok/s")
        engine.unload()

        BenchmarkResult(
            engine = engine.name,
            format = engine.modelFormat,
            metrics = metrics,
            outputPreview = output?.take(200) ?: "(empty)"
        )
    } catch (e: Exception) {
        Log.e(TAG, "${engine.name} failed", e)
        try { engine.unload() } catch (_: Exception) {}
        BenchmarkResult(engine.name, engine.modelFormat, EngineMetrics(), error = e.message)
    }
}

private fun saveResults(context: Context, results: List<BenchmarkResult>) {
    try {
        val deviceName = "${Build.MANUFACTURER}_${Build.MODEL}".replace(" ", "_")
        val report = JSONObject().apply {
            put("device", JSONObject().apply {
                put("manufacturer", Build.MANUFACTURER)
                put("model", Build.MODEL)
                put("sdk", Build.VERSION.SDK_INT)
                put("abi", Build.SUPPORTED_ABIS.toList().toString())
                put("total_ram_mb", totalRamMb(context))
                put("cores", Runtime.getRuntime().availableProcessors())
            })
            put("model", "Qwen3.5-0.8B")
            put("timestamp", System.currentTimeMillis())
            put("prompt_length", BENCHMARK_PROMPT.length)
            put("results", JSONArray().apply {
                results.forEach { r ->
                    put(JSONObject().apply {
                        put("engine", r.engine)
                        put("format", r.format)
                        put("load_ms", r.metrics.loadMs)
                        put("prefill_ms", r.metrics.prefillMs)
                        put("decode_ms", r.metrics.decodeMs)
                        put("prefill_tok_s", r.metrics.prefillTokPerSec)
                        put("decode_tok_s", r.metrics.decodeTokPerSec)
                        put("prompt_tokens", r.metrics.promptTokens)
                        put("decoded_tokens", r.metrics.decodedTokens)
                        put("error", r.error)
                    })
                }
            })
        }

        val outFile = File(context.getExternalFilesDir(null), "benchmark_$deviceName.json")
        outFile.writeText(report.toString(2))
        Log.i(TAG, "Results saved to: ${outFile.absolutePath}")
    } catch (e: Exception) {
        Log.w(TAG, "Could not save results", e)
    }
}

private fun deviceLabel(context: Context): String {
    val ram = totalRamMb(context)
    val cores = Runtime.getRuntime().availableProcessors()
    return "${Build.MANUFACTURER} ${Build.MODEL} | ${ram / 1024}GB RAM | $cores cores | API ${Build.VERSION.SDK_INT}"
}

private fun totalRamMb(context: Context): Long {
    val am = context.getSystemService(Context.ACTIVITY_SERVICE) as ActivityManager
    val memInfo = ActivityManager.MemoryInfo()
    am.getMemoryInfo(memInfo)
    return memInfo.totalMem / 1024 / 1024
}
