package com.chartlite.app

import android.app.Application
import android.util.Log
import com.chartlite.app.asr.ASREngine
import com.chartlite.app.auth.AuditLogger
import com.chartlite.app.auth.JoinCodeManager
import com.chartlite.app.auth.SessionManager
import com.chartlite.app.cdss.StaticCDSS
import com.chartlite.app.config.AppConfig
import com.chartlite.app.config.CountryConfigLoader
import com.chartlite.app.database.AppDatabase
import com.chartlite.app.database.EncounterRepository
import com.chartlite.app.database.PatientRepository
import com.chartlite.app.database.VisitRepository
import com.chartlite.app.agent.ClinicalDataService
import com.chartlite.app.database.repository.AppointmentRepository
import com.chartlite.app.database.repository.FPRepository
import com.chartlite.app.database.repository.GrowthRepository
import com.chartlite.app.database.repository.ImmunizationRepository
import com.chartlite.app.database.repository.LabOrderRepository
import com.chartlite.app.database.repository.ReferralRepository
import com.chartlite.app.database.repository.SmsLogRepository
import com.chartlite.app.database.repository.StockRepository
import com.chartlite.app.export.DataExporter
import com.chartlite.app.extraction.*
import com.chartlite.app.facilities.FacilityDirectory
import com.chartlite.app.model.Formulary
import com.chartlite.app.model.ICD10Index
import com.chartlite.app.protocols.ClinicalProtocolEngine
import com.chartlite.app.sms.AppointmentReminder
import com.chartlite.app.sms.DecodedEncounterV4
import com.chartlite.app.sms.SMSSender
import com.chartlite.app.sync.SyncEngine
import kotlinx.coroutines.CoroutineScope
import kotlinx.coroutines.Dispatchers
import kotlinx.coroutines.Job
import kotlinx.coroutines.SupervisorJob
import kotlinx.coroutines.delay
import kotlinx.coroutines.flow.MutableStateFlow
import kotlinx.coroutines.flow.StateFlow
import kotlinx.coroutines.flow.first
import kotlinx.coroutines.launch
import kotlinx.coroutines.withContext
import kotlinx.coroutines.withTimeoutOrNull
import java.io.File

class App : Application() {

    /** Application-scoped coroutine scope — use for fire-and-forget work that must survive navigation. */
    val appScope = CoroutineScope(SupervisorJob() + Dispatchers.Main)

    /**
     * Transient holder for decoded SMS data during "Register from SMS" flow.
     * Set in SMSDecryptScreen → consumed in PatientRegistrationScreen after patient is saved.
     * Allows the full decoded health record (encounter, immunizations, growth, chronic conditions)
     * to be imported into the new patient's local DB as a synthetic baseline encounter.
     */
    @Volatile
    var pendingSmsImport: DecodedEncounterV4? = null

    lateinit var appConfig: AppConfig private set
    lateinit var database: AppDatabase private set
    lateinit var patientRepository: PatientRepository private set
    lateinit var encounterRepository: EncounterRepository private set
    lateinit var visitRepository: VisitRepository private set
    lateinit var asr: ASREngine private set
    lateinit var cdss: StaticCDSS private set
    lateinit var smsSender: SMSSender private set
    lateinit var dataExporter: DataExporter private set
    lateinit var syncEngine: SyncEngine private set
    lateinit var sessionManager: SessionManager private set
    lateinit var auditLogger: AuditLogger private set
    lateinit var joinCodeManager: JoinCodeManager private set
    lateinit var labOrderRepository: LabOrderRepository private set
    lateinit var appointmentRepository: AppointmentRepository private set
    lateinit var referralRepository: ReferralRepository private set
    lateinit var clinicalDataService: ClinicalDataService private set
    lateinit var stockRepository: StockRepository private set
    lateinit var immunizationRepository: ImmunizationRepository private set
    lateinit var fpRepository: FPRepository private set
    lateinit var growthRepository: GrowthRepository private set
    lateinit var protocolEngine: ClinicalProtocolEngine private set
    lateinit var facilityDirectory: FacilityDirectory private set
    lateinit var smsLogRepository: SmsLogRepository private set
    lateinit var appointmentReminder: AppointmentReminder private set
    lateinit var playIntegrityManager: com.chartlite.app.auth.PlayIntegrityManager private set
    lateinit var extractionQueueRepository: ExtractionQueueRepository private set

    private lateinit var configLoader: CountryConfigLoader
    private val llmInitLock = Any()
    @Volatile private var llmModelManagerBacking: LlmModelManager? = null
    private val extractionInitLock = Any()
    @Volatile private var extractionServicesBacking: ExtractionServices? = null
    private val extractionKnowledgeLock = Any()
    @Volatile private var extractionKnowledgeBacking: ExtractionKnowledge? = null
    @Volatile private var extractionKnowledgeCountryCode: String? = null
    private val noteGenerationInitLock = Any()
    @Volatile private var noteGenerationCache: NoteGenerationCache? = null
    private val _extractionServicesReady = MutableStateFlow(false)
    val extractionServicesReady: StateFlow<Boolean> = _extractionServicesReady
    private var deferredExtractionWarmupJob: Job? = null
    private var deferredKnowledgeWarmupJob: Job? = null

    val llmModelManager: LlmModelManager
        get() = llmModelManagerBacking ?: synchronized(llmInitLock) {
            llmModelManagerBacking ?: createLlmModelManager().also { llmModelManagerBacking = it }
        }

    val vectorStore: ClinicalVectorStore
        get() = getOrCreateExtractionServices().vectorStore

    val clinicalExtractor: ClinicalExtractor
        get() = getOrCreateExtractionServices().clinicalExtractor

    val extractionOrchestrator: ExtractionOrchestrator
        get() = getOrCreateExtractionServices().extractionOrchestrator

    val extractionQueue: ExtractionQueue
        get() = getOrCreateExtractionServices().extractionQueue

    fun peekExtractionQueue(): ExtractionQueue? = extractionServicesBacking?.extractionQueue

    /**
     * Immediate draft-note path used by recording screens.
     * This avoids building the full extraction pipeline just to get a draft note.
     */
    suspend fun generateDraftNoteDirect(
        transcript: String,
        patientId: String,
        providerId: String,
        facilityId: String
    ): ExtractionOrchestrator.NoteGenerationResult? =
        withContext(Dispatchers.Default) {
            if (shouldPreferStructuredDraftNoteOnLowRam()) {
                generateStructuredDraftNoteFromExtraction(
                    transcript = transcript,
                    patientId = patientId,
                    providerId = providerId,
                    facilityId = facilityId
                )?.let { return@withContext it }
            }
            getOrCreateNoteGenerationOrchestrator().generateNote(transcript)
        }

    /**
     * Build the extraction services in the background while the clinician reviews
     * the generated draft note. This keeps the two-step UX but hides most of the
     * second-step setup cost behind review time.
     */
    fun prewarmExtractionPipelineForImmediateReview() {
        if (extractionServicesBacking != null) return
        appScope.launch(Dispatchers.Default) {
            runCatching { getOrCreateExtractionServices() }
                .onFailure { Log.w(TAG, "Background extraction prewarm failed", it) }
        }
    }

    /**
     * Resolve the active LLM tier without initializing the model manager.
     */
    private fun fastActiveLlmTier(): LlmModelManager.ModelTier {
        val override = appConfig.llmTierOverride.takeIf { it.isNotBlank() }
            ?.let { runCatching { LlmModelManager.ModelTier.valueOf(it) }.getOrNull() }
            ?.let(LlmModelManager::normalizeSupportedTier)
        return override ?: LlmModelManager.recommendedTierForRam(totalRamGb())
    }

    // Cache total RAM — it never changes at runtime. Avoids repeated
    // ActivityManager.getMemoryInfo() calls with MemoryInfo allocation.
    private val cachedTotalRamGb: Double by lazy { computeTotalRamGb() }
    private val cachedIsLowRamDevice: Boolean by lazy {
        (getSystemService(android.content.Context.ACTIVITY_SERVICE) as android.app.ActivityManager).isLowRamDevice
    }

    private fun computeTotalRamGb(): Double {
        val am = getSystemService(android.content.Context.ACTIVITY_SERVICE) as android.app.ActivityManager
        val memInfo = android.app.ActivityManager.MemoryInfo()
        am.getMemoryInfo(memInfo)
        return memInfo.totalMem / (1024.0 * 1024.0 * 1024.0)
    }

    private fun totalRamGb(): Double = cachedTotalRamGb

    private fun shouldAggressivelySerializeAsrAndLlm(): Boolean =
        cachedIsLowRamDevice || cachedTotalRamGb <= 4.0

    fun shouldForceBatchNoteProcessing(): Boolean =
        cachedIsLowRamDevice || cachedTotalRamGb <= 3.5

    /**
     * Modes that can execute the local Qwen fallback should inherit low-RAM
     * protections even when cloud is tried first.
     */
    fun aiModeCanUseOnDeviceFallback(mode: String = appConfig.aiMode): Boolean =
        mode == "on_device" || mode == "auto"

    /**
     * 3 GB / low-RAM phones need strict mutual exclusion between offline ASR and
     * the local MNN runtime. This is the mode that allows immediate on-device notes
     * without keeping both heavy runtimes resident at once.
     */
    fun shouldUseStrictLowRamSerialization(mode: String = appConfig.aiMode): Boolean {
        val am = getSystemService(android.content.Context.ACTIVITY_SERVICE) as android.app.ActivityManager
        return (am.isLowRamDevice || totalRamGb() <= 3.5) && aiModeCanUseOnDeviceFallback(mode)
    }

    private fun shouldPreferStructuredDraftNoteOnLowRam(): Boolean =
        shouldUseStrictLowRamSerialization() &&
            fastActiveLlmTier() == LlmModelManager.ModelTier.SMALL

    private fun isOnDeviceNoteWorkActive(): Boolean {
        if (!shouldUseStrictLowRamSerialization()) return false
        val llmBusy = llmModelManagerBacking?.isBusyForLowRamHandoff() == true
        return llmBusy
    }

    /**
     * Force any warm LLM instance out of memory on constrained devices so ASR
     * and LLM never overlap during low-memory handoffs.
     */
    suspend fun releaseLlmForLowMemoryHandoff() {
        if (!shouldAggressivelySerializeAsrAndLlm()) return
        val unloaded = llmModelManagerBacking?.unloadModelIfIdleAndWait() ?: false
        if (unloaded) {
            System.gc()
        }
    }

    /**
     * Prepare offline ASR for the next voice capture while ensuring a warm LLM
     * has already been released on low-RAM devices.
     */
    suspend fun prepareOfflineAsrForCapture(language: String = appConfig.language): Boolean {
        if (isOnDeviceNoteWorkActive()) {
            Log.w(TAG, "Skipping ASR preload while on-device note work is active")
            return false
        }
        releaseLlmForLowMemoryHandoff()
        if (asr.mode != ASREngine.Mode.ONNX_OFFLINE) return true
        if (!asr.isOnnxModelDownloadedFast()) return false
        if (asr.isModelLoaded()) return true
        if (asr.isPreparing.value) {
            val prepared = waitForAsrPreparationToFinish()
            return prepared && asr.isModelLoaded()
        }
        return asr.loadModel(language)
    }

    /**
     * Shared ASR start path for voice capture screens. Keeps ASR/LLM handoff
     * policy centralized so future screens don't bypass low-memory protections.
     */
    suspend fun startAsrCaptureWithLowMemoryHandoff(
        language: String = appConfig.language,
        onError: ((String) -> Unit)? = null,
        maxRecordingMinutes: Int? = null,
        disableSilenceAutoStop: Boolean = false
    ) {
        if (isOnDeviceNoteWorkActive()) {
            onError?.invoke("Wait for the current on-device note to finish before starting a new recording.")
            return
        }
        if (asr.mode == ASREngine.Mode.ONNX_OFFLINE && asr.isOnnxModelDownloadedFast()) {
            val prepared = prepareOfflineAsrForCapture(language)
            if (!prepared && asr.isPreparing.value) {
                onError?.invoke("Offline voice model is still loading. Try again in a moment.")
                return
            }
        } else {
            releaseLlmForLowMemoryHandoff()
        }
        asr.startListening(
            language = language,
            onError = onError,
            maxRecordingMinutes = maxRecordingMinutes,
            disableSilenceAutoStop = disableSilenceAutoStop
        )
    }

    private suspend fun waitForAsrPreparationToFinish(): Boolean {
        if (!asr.isPreparing.value) return true
        val completed = withTimeoutOrNull(ASR_PREPARATION_TIMEOUT_MS) {
            asr.isPreparing.first { !it }
        } != null
        if (!completed) {
            Log.w(TAG, "Timed out waiting for offline ASR preparation to finish")
        }
        return completed
    }

    /**
     * Shared LLM start path for low-RAM immediate mode. Ensures ASR is not
     * recording or still preloading before local note processing begins.
     */
    suspend fun prepareOnDeviceNoteProcessingForLowRam(
        onError: ((String) -> Unit)? = null
    ): Boolean {
        if (!shouldUseStrictLowRamSerialization()) {
            asr.unloadOfflineModelIfIdleAndWait()
            return true
        }
        if (asr.isListening.value) {
            onError?.invoke("Finish or cancel the recording before starting on-device note processing.")
            return false
        }
        if (asr.isPreparing.value) {
            val prepared = waitForAsrPreparationToFinish()
            if (!prepared) {
                onError?.invoke("Voice model is still preparing. Try again in a moment.")
                return false
            }
        }
        asr.unloadOfflineModelIfIdleAndWait()
        return true
    }

    /**
     * Cheap file-existence check for whether the recommended/overridden on-device LLM
     * is installed. This avoids initializing the native LLM bridge for simple UI gating.
     */
    fun isLlmModelDownloadedFast(): Boolean {
        val tier = fastActiveLlmTier()
        val dir = File(noBackupFilesDir, "llm_models/${tier.dirName}")
        return LlmModelManager.hasRequiredModelFiles(dir, tier)
    }

    /**
     * Cheap check for whether the active tier supports on-device vision and is installed.
     * Used to hide camera actions when low-memory devices default to the text-only tier.
     */
    fun isLlmVisionModelDownloadedFast(): Boolean {
        if (!LlmModelManager.ON_DEVICE_VISION_ENABLED) return false
        val tier = fastActiveLlmTier()
        if (!tier.supportsVision) return false
        val dir = File(noBackupFilesDir, "llm_models/${tier.dirName}")
        return LlmModelManager.hasRequiredModelFiles(dir, tier)
    }

    val promptBuilder: ExtractionPromptBuilder
        get() = getOrCreateExtractionServices().promptBuilder

    override fun onCreate() {
        super.onCreate()
        Log.d(TAG, "App.onCreate() starting")

        // Load SQLCipher native library before any database operations
        try {
            System.loadLibrary("sqlcipher")
            Log.d(TAG, "SQLCipher native library loaded")
        } catch (e: UnsatisfiedLinkError) {
            Log.e(TAG, "Failed to load sqlcipher native lib", e)
        }

        appConfig = AppConfig(this)
        configLoader = CountryConfigLoader(this)
        Log.d(TAG, "Config loaded, initializing database...")

        // Initialize database with a device-derived passphrase
        val passphrase = getOrCreatePassphrase()
        Log.d(TAG, "Passphrase ready, building Room database...")
        database = AppDatabase.getInstance(this, passphrase)
        Log.d(TAG, "Database initialized")

        patientRepository = PatientRepository(database.patientDao())
        encounterRepository = EncounterRepository(database.encounterDao())
        visitRepository = VisitRepository(database.visitDao())
        extractionQueueRepository = ExtractionQueueRepository(database.extractionQueueDao())

        // Initialize auth system (SessionManager gets auditLogDao for auth event logging)
        sessionManager = SessionManager(appConfig, database.userDao(), database.auditLogDao())
        auditLogger = AuditLogger(database.auditLogDao(), sessionManager)
        joinCodeManager = JoinCodeManager(appConfig)

        // Wire audit logger into repositories that need it
        encounterRepository.auditLogger = auditLogger

        // Initialize Phase 2 repositories
        labOrderRepository = LabOrderRepository(database.labOrderDao())
        appointmentRepository = AppointmentRepository(database.appointmentDao(), database.patientDao())
        referralRepository = ReferralRepository(database.referralDao())

        // Initialize Phase 3+4 repositories
        smsLogRepository = SmsLogRepository(database.smsLogDao())
        stockRepository = StockRepository(database.stockDao())
        immunizationRepository = ImmunizationRepository(database.immunizationDao())
        fpRepository = FPRepository(database.fpVisitDao())
        growthRepository = GrowthRepository(database.growthDao())

        // Initialize AI agent data service (permission-gated, audit-logged)
        clinicalDataService = ClinicalDataService(
            patientRepository = patientRepository,
            encounterRepository = encounterRepository,
            labOrderRepository = labOrderRepository,
            appointmentRepository = appointmentRepository,
            referralRepository = referralRepository,
            auditLogger = auditLogger
        )

        // Initialize proxy auth manager (Play Integrity + non-GMS device enrollment)
        playIntegrityManager = com.chartlite.app.auth.PlayIntegrityManager(
            context = this,
            deviceId = appConfig.deviceId,
            deviceEnrollmentCodeProvider = { appConfig.chartliteEnrollmentCode },
            onDeviceEnrollmentSuccess = {
                // Keep enrollment code in AppConfig — needed if the device Keystore key is ever
                // regenerated (app reinstall, OS wipe) so the device can re-enroll automatically.
                // One-time enforcement is handled server-side per device_id.
            }
        )

        asr = ASREngine(this)
        // Restore ASR mode from saved preference
        asr.mode = when (appConfig.asrMode) {
            "onnx" -> ASREngine.Mode.ONNX_OFFLINE
            "cloud" -> ASREngine.Mode.CLOUD_ASR
            else -> ASREngine.Mode.GOOGLE_ONLINE
        }
        // Wire cloud ASR manager (lightweight — no resources allocated until recording starts)
        asr.cloudASRManager = com.chartlite.app.asr.cloud.CloudASRManager(this, appConfig, playIntegrityManager)
        smsSender = SMSSender(this, appConfig)
        dataExporter = DataExporter(this, encounterRepository)
        syncEngine = SyncEngine(this, patientRepository, encounterRepository, visitRepository, appConfig, auditLogger)

        // Initialize large asset-backed services lazily so cold start stays cheap on 3 GB phones.
        cdss = StaticCDSS(this)
        protocolEngine = ClinicalProtocolEngine(this)
        facilityDirectory = FacilityDirectory(this) { appConfig.countryCode }

        // Initialize Appointment Reminder system
        appointmentReminder = AppointmentReminder(
            smsSender = smsSender,
            appointmentRepository = appointmentRepository,
            patientRepository = patientRepository,
            appConfig = appConfig,
            auditLogger = auditLogger,
            smsLogRepository = smsLogRepository
        )

        // Apply lightweight country presentation settings eagerly; the extraction
        // pipeline is deferred so first draw is not blocked by vector indexing.
        applyCountryPresentationConfig()
        if (appConfig.isSetupComplete) {
            scheduleDeferredExtractionWarmup()
            scheduleDeferredKnowledgeWarmup()
        }

        // ASR model loading is deferred to first use (ASREngine.startListening)
        // to avoid consuming ~200MB of memory at startup on low-RAM devices.
        // Only refresh download state so Settings shows correct status.
        asr.modelDownloader.refreshState()

        // Start continuous sync service if multi-station mode is active
        if (com.chartlite.app.sync.ContinuousSyncService.shouldRun(this)) {
            com.chartlite.app.sync.ContinuousSyncService.start(this)
            Log.d(TAG, "Started continuous sync service")
        }
    }

    fun loadCountryData(deferExtraction: Boolean = false) {
        applyCountryPresentationConfig()
        facilityDirectory.invalidate()
        clearKnowledgeCaches()
        if (deferExtraction) {
            // Defer heavy extraction pipeline build to avoid OOM on low-RAM devices
            // during setup completion when memory is already constrained.
            scheduleDeferredExtractionWarmup()
        } else {
            getOrCreateExtractionServices(forceReload = true)
        }
        scheduleDeferredKnowledgeWarmup()
    }

    /** Rebuild the extraction pipeline (e.g., after changing AI mode or cloud key mode). */
    fun rebuildExtractionPipeline() {
        noteGenerationCache = null
        getOrCreateExtractionServices(forceReload = true)
    }

    private fun applyCountryPresentationConfig() {
        try {
            val configJson = assets.open("config/country_${appConfig.countryCode}.json")
                .bufferedReader().use { it.readText() }
            val countryConfig = com.google.gson.JsonParser.parseString(configJson).asJsonObject
            appConfig.countryDateFormat = countryConfig.get("dateFormat")?.asString ?: "dd/MM/yyyy"
            appConfig.countryNationalIdLabel = countryConfig.get("nationalIdLabel")?.asString ?: "National ID"
        } catch (_: Exception) {
            // Keep defaults
        }
    }

    private fun createLlmModelManager(): LlmModelManager {
        val manager = LlmModelManager(this)
        val savedTier = appConfig.llmTierOverride
        if (savedTier.isNotBlank()) {
            try {
                val override = LlmModelManager.normalizeSupportedTier(LlmModelManager.ModelTier.valueOf(savedTier))
                manager.overrideTier = override
                if (override == null) {
                    appConfig.llmTierOverride = ""
                }
            } catch (_: IllegalArgumentException) {
                appConfig.llmTierOverride = ""
            }
        }
        manager.refreshState()
        return manager
    }

    private fun getOrCreateExtractionServices(forceReload: Boolean = false): ExtractionServices {
        if (!forceReload) {
            extractionServicesBacking?.let { return it }
        }

        return synchronized(extractionInitLock) {
            if (!forceReload) {
                extractionServicesBacking?.let { return@synchronized it }
            }
            _extractionServicesReady.value = false
            val previous = extractionServicesBacking
            buildExtractionServices().also { fresh ->
                extractionServicesBacking = fresh
                _extractionServicesReady.value = true
                previous?.close()
            }
        }
    }

    private data class ExtractionKnowledge(
        val formulary: Formulary,
        val icd10: ICD10Index
    )

    private fun getOrCreateExtractionKnowledge(forceReload: Boolean = false): ExtractionKnowledge {
        val countryCode = appConfig.countryCode
        if (!forceReload) {
            extractionKnowledgeBacking?.takeIf { extractionKnowledgeCountryCode == countryCode }?.let { return it }
        }

        return synchronized(extractionKnowledgeLock) {
            if (!forceReload) {
                extractionKnowledgeBacking?.takeIf { extractionKnowledgeCountryCode == countryCode }?.let { return@synchronized it }
            }

            val formulary = try {
                configLoader.loadFormulary("formulary/${countryCode}_formulary.json")
            } catch (_: Exception) {
                Formulary("1.0", countryCode, emptyList())
            }

            val icd10 = try {
                configLoader.loadICD10("icd10/phc_top300.json")
            } catch (_: Exception) {
                ICD10Index("1.0", emptyList())
            }

            ExtractionKnowledge(formulary = formulary, icd10 = icd10).also {
                extractionKnowledgeBacking = it
                extractionKnowledgeCountryCode = countryCode
            }
        }
    }

    private fun currentNoteGenerationCacheKey(): String = buildString {
        append(appConfig.countryCode)
        append('|')
        append(appConfig.aiMode)
        append('|')
        append(appConfig.cloudNotesModel)
        append('|')
        append(appConfig.cloudKeyMode)
    }

    private fun getOrCreateNoteGenerationOrchestrator(forceReload: Boolean = false): ExtractionOrchestrator {
        val cacheKey = currentNoteGenerationCacheKey()
        if (!forceReload) {
            noteGenerationCache?.takeIf { it.key == cacheKey }?.orchestrator?.let { return it }
        }

        return synchronized(noteGenerationInitLock) {
            if (!forceReload) {
                noteGenerationCache?.takeIf { it.key == cacheKey }?.orchestrator?.let { return@synchronized it }
            }
            buildNoteGenerationOrchestrator().also {
                noteGenerationCache = NoteGenerationCache(cacheKey, it)
            }
        }
    }

    private fun clearKnowledgeCaches() {
        synchronized(extractionKnowledgeLock) {
            extractionKnowledgeBacking = null
            extractionKnowledgeCountryCode = null
        }
        synchronized(noteGenerationInitLock) {
            noteGenerationCache = null
        }
    }

    private fun buildStructuredDraftExtractionOrchestrator(): ExtractionOrchestrator {
        val knowledge = getOrCreateExtractionKnowledge()
        val promptBuilder = ExtractionPromptBuilder(knowledge.icd10, knowledge.formulary)
        val responseParser = LlmResponseParser(knowledge.icd10, knowledge.formulary)
        val strategies = mutableListOf<ExtractionStrategy>()
        val lowRamInferencePreflight: (suspend () -> Boolean)? =
            if (shouldUseStrictLowRamSerialization()) {
                { prepareOnDeviceNoteProcessingForLowRam() }
            } else {
                null
            }

        if (aiModeCanUseOnDeviceFallback() && fastActiveLlmTier() == LlmModelManager.ModelTier.SMALL) {
            strategies.add(
                QwenExtractionStrategy(
                    modelManagerProvider = { llmModelManager },
                    promptBuilder = promptBuilder,
                    responseParser = responseParser,
                    prepareForLowRamInference = lowRamInferencePreflight
                )
            )
        }

        return ExtractionOrchestrator(
            strategies,
            transcriptValidator = TranscriptValidator()
        )
    }

    private suspend fun generateStructuredDraftNoteFromExtraction(
        transcript: String,
        patientId: String,
        providerId: String,
        facilityId: String
    ): ExtractionOrchestrator.NoteGenerationResult? {
        val extractionResult = buildStructuredDraftExtractionOrchestrator().extract(
            transcript = transcript,
            patientId = patientId,
            providerId = providerId,
            facilityId = facilityId
        )
        if (!extractionResult.strategyUsed.contains("(on-device)")) return null
        val renderedNote = StructuredDraftNoteRenderer.render(extractionResult.encounter)
            ?: return null
        return ExtractionOrchestrator.NoteGenerationResult(
            note = renderedNote,
            strategyUsed = "${extractionResult.strategyUsed} (structured draft)",
            fallbacksAttempted = extractionResult.fallbacksAttempted
        )
    }

    private fun buildNoteGenerationOrchestrator(): ExtractionOrchestrator {
        val knowledge = getOrCreateExtractionKnowledge()
        val promptBuilder = ExtractionPromptBuilder(knowledge.icd10, knowledge.formulary)
        val responseParser = LlmResponseParser(knowledge.icd10, knowledge.formulary)
        val strategies = mutableListOf<ExtractionStrategy>()
        val lowRamInferencePreflight: (suspend () -> Boolean)? =
            if (shouldUseStrictLowRamSerialization()) {
                { prepareOnDeviceNoteProcessingForLowRam() }
            } else {
                null
            }

        fun addCloudStrategy() {
            val model = appConfig.cloudNotesModel
            when {
                model.startsWith("claude") -> {
                    val authConfig = if (appConfig.cloudKeyMode == "chartlite") {
                        ClaudeExtractionStrategy.AuthConfig.Proxied { playIntegrityManager.getAuthHeaders() }
                    } else {
                        ClaudeExtractionStrategy.AuthConfig.Direct { appConfig.claudeApiKey }
                    }
                    strategies.add(ClaudeExtractionStrategy(this, promptBuilder, responseParser, authConfig))
                }
                model.startsWith("gemini") -> {
                    val authConfig = if (appConfig.cloudKeyMode == "chartlite") {
                        GeminiExtractionStrategy.AuthConfig.Proxied { playIntegrityManager.getAuthHeaders() }
                    } else {
                        GeminiExtractionStrategy.AuthConfig.Direct { appConfig.geminiApiKey }
                    }
                    strategies.add(GeminiExtractionStrategy(this, promptBuilder, responseParser, authConfig))
                }
                model.startsWith("gpt") -> {
                    val authConfig = if (appConfig.cloudKeyMode == "chartlite") {
                        OpenAIExtractionStrategy.AuthConfig.Proxied { playIntegrityManager.getAuthHeaders() }
                    } else {
                        OpenAIExtractionStrategy.AuthConfig.Direct { appConfig.openaiApiKey }
                    }
                    strategies.add(OpenAIExtractionStrategy(this, promptBuilder, responseParser, authConfig, model))
                }
                else -> {
                    val authConfig = if (appConfig.cloudKeyMode == "chartlite") {
                        ClaudeExtractionStrategy.AuthConfig.Proxied { playIntegrityManager.getAuthHeaders() }
                    } else {
                        ClaudeExtractionStrategy.AuthConfig.Direct { appConfig.claudeApiKey }
                    }
                    strategies.add(ClaudeExtractionStrategy(this, promptBuilder, responseParser, authConfig))
                }
            }
        }

        when (appConfig.aiMode) {
            "cloud" -> addCloudStrategy()
            "on_device" -> {
                strategies.add(
                    QwenExtractionStrategy(
                        modelManagerProvider = { llmModelManager },
                        promptBuilder = promptBuilder,
                        responseParser = responseParser,
                        prepareForLowRamInference = lowRamInferencePreflight
                    )
                )
            }
            else -> {
                addCloudStrategy()
                strategies.add(
                    QwenExtractionStrategy(
                        modelManagerProvider = { llmModelManager },
                        promptBuilder = promptBuilder,
                        responseParser = responseParser,
                        prepareForLowRamInference = lowRamInferencePreflight
                    )
                )
            }
        }

        return ExtractionOrchestrator(
            strategies,
            transcriptValidator = TranscriptValidator()
        )
    }

    private fun buildExtractionServices(): ExtractionServices {
        val knowledge = getOrCreateExtractionKnowledge()
        val formulary = knowledge.formulary
        val icd10 = knowledge.icd10

        val vectorStore = ClinicalVectorStore(icd10, formulary)

        val clinicalExtractor = ClinicalExtractor(formulary, icd10, vectorStore)
        val promptBuilder = ExtractionPromptBuilder(icd10, formulary, vectorStore)
        val responseParser = LlmResponseParser(icd10, formulary)
        val strategies = mutableListOf<ExtractionStrategy>()
        val lowRamInferencePreflight: (suspend () -> Boolean)? =
            if (shouldUseStrictLowRamSerialization()) {
                { prepareOnDeviceNoteProcessingForLowRam() }
            } else {
                null
            }

        // Build cloud extraction strategy based on selected model
        fun addCloudStrategy() {
            val model = appConfig.cloudNotesModel
            when {
                model.startsWith("claude") -> {
                    val authConfig = if (appConfig.cloudKeyMode == "chartlite") {
                        ClaudeExtractionStrategy.AuthConfig.Proxied { playIntegrityManager.getAuthHeaders() }
                    } else {
                        ClaudeExtractionStrategy.AuthConfig.Direct { appConfig.claudeApiKey }
                    }
                    strategies.add(ClaudeExtractionStrategy(this, promptBuilder, responseParser, authConfig))
                }
                model.startsWith("gemini") -> {
                    val authConfig = if (appConfig.cloudKeyMode == "chartlite") {
                        GeminiExtractionStrategy.AuthConfig.Proxied { playIntegrityManager.getAuthHeaders() }
                    } else {
                        GeminiExtractionStrategy.AuthConfig.Direct { appConfig.geminiApiKey }
                    }
                    strategies.add(GeminiExtractionStrategy(this, promptBuilder, responseParser, authConfig))
                }
                model.startsWith("gpt") -> {
                    val authConfig = if (appConfig.cloudKeyMode == "chartlite") {
                        OpenAIExtractionStrategy.AuthConfig.Proxied { playIntegrityManager.getAuthHeaders() }
                    } else {
                        OpenAIExtractionStrategy.AuthConfig.Direct { appConfig.openaiApiKey }
                    }
                    strategies.add(OpenAIExtractionStrategy(this, promptBuilder, responseParser, authConfig, model))
                }
                else -> {
                    val authConfig = if (appConfig.cloudKeyMode == "chartlite") {
                        ClaudeExtractionStrategy.AuthConfig.Proxied { playIntegrityManager.getAuthHeaders() }
                    } else {
                        ClaudeExtractionStrategy.AuthConfig.Direct { appConfig.claudeApiKey }
                    }
                    strategies.add(ClaudeExtractionStrategy(this, promptBuilder, responseParser, authConfig))
                }
            }
        }

        when (appConfig.aiMode) {
            "cloud" -> addCloudStrategy()
            "on_device" -> {
                strategies.add(
                    QwenExtractionStrategy(
                        modelManagerProvider = { llmModelManager },
                        promptBuilder = promptBuilder,
                        responseParser = responseParser,
                        prepareForLowRamInference = lowRamInferencePreflight
                    )
                )
            }
            else -> {
                addCloudStrategy()
                strategies.add(
                    QwenExtractionStrategy(
                        modelManagerProvider = { llmModelManager },
                        promptBuilder = promptBuilder,
                        responseParser = responseParser,
                        prepareForLowRamInference = lowRamInferencePreflight
                    )
                )
            }
        }

        strategies.add(RegexExtractionStrategy(clinicalExtractor))
        val transcriptValidator = TranscriptValidator()
        val vitalsExtractor = VitalsExtractor()

        val extractionOrchestrator = ExtractionOrchestrator(
            strategies,
            transcriptValidator = transcriptValidator,
            vitalsExtractor = vitalsExtractor
        )
        Log.d(
            "App",
            "Extraction pipeline rebuilt for aiMode=${appConfig.aiMode}: " +
                strategies.joinToString(" -> ") { strategy ->
                    when (strategy) {
                        is QwenExtractionStrategy -> "Qwen 3.5 (on-device)"
                        is RegexExtractionStrategy -> "Regex (offline)"
                        else -> strategy.name
                    }
                }
        )

        val extractionQueue = ExtractionQueue(
            extractionOrchestrator,
            extractionQueueRepository,
            appScope,
            cancelCurrentProcessing = { llmModelManagerBacking?.cancelInference() },
            unloadLlm = { releaseLlmForLowMemoryHandoff() }
        )

        if (LlmModelManager.ON_DEVICE_VISION_ENABLED) {
            // Wire up photo processing for batch mode: analyze pending photos during batch
            val visionExtractor = VisionExtractor(llmModelManager, promptBuilder)
            val photoDao = database.clinicalPhotoDao()
            extractionQueue.photoProcessor = { patientId, encounter ->
                val pendingPhotos = photoDao.getByPatientAndType(patientId, "pending").first()
                var merged = encounter
                for (photo in pendingPhotos) {
                    try {
                        val result = visionExtractor.extract(photo.filePath)
                        if (result != null) {
                            merged = EncounterMerger.mergeVisionResult(merged, result)
                            photoDao.insert(photo.copy(contentType = result.contentType, extractedJson = result.rawJson))
                        }
                    } catch (e: Exception) {
                        android.util.Log.w(TAG, "Vision failed for photo ${photo.id}: ${e.message}")
                    }
                }
                merged
            }
        } else {
            extractionQueue.photoProcessor = null
        }

        return ExtractionServices(
            vectorStore = vectorStore,
            clinicalExtractor = clinicalExtractor,
            extractionOrchestrator = extractionOrchestrator,
            extractionQueue = extractionQueue,
            extractionQueueRepository = extractionQueueRepository,
            promptBuilder = promptBuilder
        )
    }

    private fun scheduleDeferredExtractionWarmup() {
        deferredExtractionWarmupJob?.cancel()
        deferredExtractionWarmupJob = appScope.launch(Dispatchers.Default) {
            // Wait longer on low-RAM devices to avoid competing with ASR model loading.
            // The extraction pipeline loads the MNN native library (~50MB) + vector store;
            // if ASR is also loading its ONNX model, both OOM on 3GB devices.
            val am = getSystemService(android.content.Context.ACTIVITY_SERVICE) as android.app.ActivityManager
            val memInfo = android.app.ActivityManager.MemoryInfo()
            am.getMemoryInfo(memInfo)
            val isLowRam = am.isLowRamDevice || (memInfo.totalMem / (1024 * 1024)) <= 4096
            if (isLowRam) {
                Log.d(TAG, "Skipping deferred extraction warm-up on low-RAM device; services stay lazy-loaded")
                return@launch
            }

            delay(DEFERRED_EXTRACTION_WARMUP_MS)

            // Use forceReload so the pipeline is built with current config
            // (country, AI mode, API keys) even if stale services exist.
            runCatching { getOrCreateExtractionServices(forceReload = true) }
                .onFailure { Log.w(TAG, "Deferred extraction warm-up failed", it) }
        }
    }

    private fun scheduleDeferredKnowledgeWarmup() {
        deferredKnowledgeWarmupJob?.cancel()
        if (!appConfig.isSetupComplete) return
        deferredKnowledgeWarmupJob = appScope.launch(Dispatchers.IO) {
            delay(DEFERRED_KNOWLEDGE_WARMUP_MS)
            runCatching {
                getOrCreateExtractionKnowledge()
                cdss.preload()
                protocolEngine.preload()
                facilityDirectory.preloadCurrentCountry()
            }.onFailure {
                Log.w(TAG, "Deferred knowledge warm-up failed", it)
            }
        }
    }

    private fun getOrCreatePassphrase(): ByteArray {
        // Use EncryptedSharedPreferences to store the random DB passphrase securely
        val masterKey = androidx.security.crypto.MasterKey.Builder(this)
            .setKeyScheme(androidx.security.crypto.MasterKey.KeyScheme.AES256_GCM)
            .build()
        val prefs = androidx.security.crypto.EncryptedSharedPreferences.create(
            this,
            "db_key_secure",
            masterKey,
            androidx.security.crypto.EncryptedSharedPreferences.PrefKeyEncryptionScheme.AES256_SIV,
            androidx.security.crypto.EncryptedSharedPreferences.PrefValueEncryptionScheme.AES256_GCM
        )

        // Migrate from plain SharedPreferences if needed (one-time upgrade)
        val plainPrefs = getSharedPreferences("db_key", MODE_PRIVATE)
        val plainPassphrase = plainPrefs.getString("passphrase", null)
        if (plainPassphrase != null) {
            prefs.edit().putString("passphrase", plainPassphrase).apply()
            plainPrefs.edit().clear().apply()
        }

        val existing = prefs.getString("passphrase", null)
        if (existing != null) {
            return existing.toByteArray(Charsets.UTF_8)
        }
        val newPassphrase = java.util.UUID.randomUUID().toString()
        prefs.edit().putString("passphrase", newPassphrase).apply()
        return newPassphrase.toByteArray(Charsets.UTF_8)
    }

    private data class ExtractionServices(
        val vectorStore: ClinicalVectorStore,
        val clinicalExtractor: ClinicalExtractor,
        val extractionOrchestrator: ExtractionOrchestrator,
        val extractionQueue: ExtractionQueue,
        val extractionQueueRepository: ExtractionQueueRepository,
        val promptBuilder: ExtractionPromptBuilder
    ) {
        fun close() {
            extractionQueue.close()
        }
    }

    private data class NoteGenerationCache(
        val key: String,
        val orchestrator: ExtractionOrchestrator
    )

    companion object {
        private const val TAG = "App"
        private const val DEFERRED_EXTRACTION_WARMUP_MS = 1_500L
        private const val DEFERRED_KNOWLEDGE_WARMUP_MS = 3_000L
        private const val ASR_PREPARATION_TIMEOUT_MS = 30_000L
    }
}
