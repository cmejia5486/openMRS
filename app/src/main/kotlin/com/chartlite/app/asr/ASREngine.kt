package com.chartlite.app.asr

import android.content.Context
import android.content.Intent
import android.os.Bundle
import android.speech.RecognitionListener
import android.speech.RecognizerIntent
import android.speech.SpeechRecognizer
import android.util.Log
import com.chartlite.app.model.TranscriptionResult
import kotlinx.coroutines.CoroutineScope
import kotlinx.coroutines.Dispatchers
import kotlinx.coroutines.Job
import kotlinx.coroutines.SupervisorJob
import kotlinx.coroutines.flow.MutableStateFlow
import kotlinx.coroutines.flow.StateFlow
import kotlinx.coroutines.launch
import kotlinx.coroutines.withContext

/**
 * ASREngine — Dual-mode speech recognition (offline-first).
 *
 * Mode 1: ONNX_OFFLINE (default)
 *   Uses Meta Omnilingual ASR (CTC) exported to ONNX format. Runs entirely
 *   on-device with ONNX Runtime. Supports 1600+ languages including Zulu,
 *   Xhosa, Amharic, Chichewa — all ChartLite target languages.
 *   Download the model from Settings (~365MB for 300M, ~1GB for 1B).
 *   Falls back to Google if model is not yet downloaded.
 *
 * Mode 2: GOOGLE_ONLINE
 *   Uses Android's built-in SpeechRecognizer. Works immediately on any device
 *   with the Google app installed. Requires internet for recognition.
 *   Supports continuous dictation via auto-restart for clinical encounters.
 */
class ASREngine(private val context: Context) {

    enum class Mode {
        ONNX_OFFLINE,    // Default — Meta Omnilingual ASR via ONNX Runtime (fully offline)
        GOOGLE_ONLINE,   // Fallback — Android SpeechRecognizer (needs internet)
        CLOUD_ASR        // Premium cloud providers (Google STT V2, OpenAI, Deepgram)
    }

    var mode: Mode = Mode.ONNX_OFFLINE

    // ── Observable state for UI binding ──

    private val _isListening = MutableStateFlow(false)
    val isListening: StateFlow<Boolean> = _isListening

    private val _isPreparing = MutableStateFlow(false)
    val isPreparing: StateFlow<Boolean> = _isPreparing

    private val _transcript = MutableStateFlow("")
    val transcript: StateFlow<String> = _transcript

    private val _amplitude = MutableStateFlow(0f)
    val amplitude: StateFlow<Float> = _amplitude

    // ── Google SpeechRecognizer state ──

    private var speechRecognizer: SpeechRecognizer? = null
    private var isContinuous = false
    private val segments = mutableListOf<String>()
    private var currentPartial = ""
    private var currentLanguage = "en"
    private var errorCallback: ((String) -> Unit)? = null

    // ── Error recovery state ──
    private var consecutiveErrors = 0
    private var lastRestartTime = 0L
    private val handler = android.os.Handler(android.os.Looper.getMainLooper())
    companion object {
        private const val MAX_CONSECUTIVE_ERRORS = 5
        private const val MIN_RESTART_INTERVAL_MS = 500L
        private const val DEFAULT_ONNX_FINALIZE_TIMEOUT_MS = 20_000L
    }

    // ── Cloud ASR manager (injected from App.kt when cloud mode is configured) ──

    var cloudASRManager: com.chartlite.app.asr.cloud.CloudASRManager? = null

    // ── Sherpa-ONNX offline pipeline (replaces raw ONNX Runtime) ──

    val sherpaPipeline = SherpaASRPipeline()
    @Deprecated("Use sherpaPipeline", replaceWith = ReplaceWith("sherpaPipeline"))
    val onnxPipeline: SherpaASRPipeline get() = sherpaPipeline
    val modelDownloader = ModelDownloader(context)
    private val audioRecorder = AudioRecorder(context)
    private val asrScope = CoroutineScope(SupervisorJob() + Dispatchers.IO)
    private var loadJob: Job? = null
    private var transcriptCollectorJob: Job? = null
    private var amplitudeCollectorJob: Job? = null
    private var recorderStateCollectorJob: Job? = null

    private fun availableRamMb(): Long {
        val am = context.getSystemService(Context.ACTIVITY_SERVICE) as android.app.ActivityManager
        val memInfo = android.app.ActivityManager.MemoryInfo()
        am.getMemoryInfo(memInfo)
        return memInfo.availMem / 1024 / 1024
    }

    // ── Public API ──

    fun isAvailable(): Boolean = when (mode) {
        Mode.GOOGLE_ONLINE -> SpeechRecognizer.isRecognitionAvailable(context)
        Mode.ONNX_OFFLINE -> sherpaPipeline.isLoaded.value
        Mode.CLOUD_ASR -> cloudASRManager?.isAvailable() ?: false
    }

    /**
     * Check if offline model is downloaded and ready.
     * Note: First call after app start may be slow (SHA-256 verification).
     * Use [isOnnxModelDownloadedFast] for main-thread checks.
     */
    fun isOnnxModelDownloaded(): Boolean = modelDownloader.isReady()

    /**
     * Fast check suitable for main thread — skips SHA-256 verification.
     * Returns true if all model files and vocab exist (size > 0) and the tier is configured.
     */
    fun isOnnxModelDownloadedFast(): Boolean = modelDownloader.isReadyFast()

    /**
     * Start continuous speech recognition.
     * Must be called from the main thread (SpeechRecognizer requirement for Google mode).
     */
    fun startListening(
        language: String = "en",
        onError: ((String) -> Unit)? = null,
        maxRecordingMinutes: Int? = null,
        disableSilenceAutoStop: Boolean = false
    ) {
        if (_isListening.value || _isPreparing.value) return

        currentLanguage = language
        errorCallback = onError
        segments.clear()
        currentPartial = ""
        _transcript.value = ""
        consecutiveErrors = 0
        lastRestartTime = 0L
        maxRecordingMinutes?.let { audioRecorder.setMaxRecordingMinutes(it) }
        audioRecorder.configureSilenceAutoStop(enabled = !disableSilenceAutoStop)

        when (mode) {
            Mode.GOOGLE_ONLINE -> startGoogleRecognition()
            Mode.ONNX_OFFLINE -> {
                // Use fast check (file existence only) on main thread.
                // Full SHA-256 verification runs on background thread inside the loadJob.
                if (!sherpaPipeline.isLoaded.value && modelDownloader.isReadyFast()) {
                    // Lazy-load model OFF main thread to avoid UI freeze on 3GB devices.
                    // Model load can take 500ms-3s depending on hardware.
                    _isPreparing.value = true
                    loadJob = asrScope.launch {
                        // Full SHA-256 verification (safe on background thread)
                        if (!modelDownloader.isReady()) {
                            withContext(Dispatchers.Main) {
                                _isPreparing.value = false
                                errorCallback?.invoke(
                                    "Offline ASR model integrity check failed. Re-download the model in Settings."
                                )
                            }
                            return@launch
                        }
                        val tier = modelDownloader.configuredTier()
                        val loaded = if (tier != null) {
                            sherpaPipeline.loadModel(
                                modelDownloader.modelsDir,
                                SherpaASRPipeline.Architecture.valueOf(tier.architecture.name),
                                modelDownloader.vocabFile,
                                context
                            )
                        } else {
                            sherpaPipeline.loadModel(modelDownloader.modelFile, modelDownloader.vocabFile, context)
                        }
                        withContext(Dispatchers.Main) {
                            if (!_isPreparing.value) return@withContext
                            _isPreparing.value = false
                            if (loaded) {
                                startOnnxRecognition()
                            } else {
                                errorCallback?.invoke(
                                    "Failed to load offline ASR model. " +
                                        "Check ASR model/tokens in Settings. Falling back to online mode."
                                )
                                startGoogleRecognition()
                            }
                        }
                    }
                } else if (sherpaPipeline.isLoaded.value) {
                    startOnnxRecognition()
                } else {
                    // Model not downloaded — try Google fallback if available
                    if (SpeechRecognizer.isRecognitionAvailable(context)) {
                        startGoogleRecognition()
                    } else {
                        _isPreparing.value = false
                        _isListening.value = false
                        errorCallback?.invoke(
                            "No offline model and no internet connection. " +
                            "Download the ASR model in Settings for offline use, or connect to the internet."
                        )
                    }
                }
            }
            Mode.CLOUD_ASR -> {
                val manager = cloudASRManager
                if (manager == null) {
                    _isListening.value = false
                    errorCallback?.invoke("Cloud ASR not configured. Select a provider in Settings.")
                    return
                }
                startCloudRecognition(manager)
            }
        }
    }

    /**
     * Stop recognition and return the final transcript.
     * Must be called from the main thread (for Google mode).
     */
    fun stopListening(): TranscriptionResult {
        // P1 fix: cancel any in-flight model load to prevent ghost recording
        loadJob?.cancel()
        loadJob = null
        transcriptCollectorJob?.cancel()
        transcriptCollectorJob = null
        amplitudeCollectorJob?.cancel()
        amplitudeCollectorJob = null
        recorderStateCollectorJob?.cancel()
        recorderStateCollectorJob = null
        _isPreparing.value = false

        return when {
            // P0 fix: check mode + pipeline loaded, NOT audioRecorder.isRecording.
            // AudioRecorder can auto-stop on silence while ONNX pipeline still has buffered transcript.
            mode == Mode.ONNX_OFFLINE && sherpaPipeline.isLoaded.value -> {
                val durationMs = audioRecorder.recordingDurationMs.value
                if (audioRecorder.isRecording.value) {
                    audioRecorder.stop()
                }
                val finalText = sherpaPipeline.stop()
                val error = if (finalText.isBlank()) sherpaPipeline.consumeLastFailureReason() else null
                _isListening.value = false
                _amplitude.value = 0f
                _transcript.value = finalText

                // Do not release synchronously here: stop() finalization runs in background
                // and immediate release can race native ONNX cleanup on some devices.
                // stopListeningAndAwait() handles deterministic release paths.

                TranscriptionResult(
                    text = finalText,
                    words = emptyList(),
                    durationMs = durationMs,
                    error = error
                )
            }
            // Cloud ASR — synchronous stop returns whatever we have so far
            mode == Mode.CLOUD_ASR -> {
                val durationMs = audioRecorder.recordingDurationMs.value
                if (audioRecorder.isRecording.value) {
                    audioRecorder.stop()
                }
                _isListening.value = false
                _amplitude.value = 0f

                // Synchronous stop: cloud manager will finalize in stopListeningAndAwait()
                TranscriptionResult(
                    text = _transcript.value,
                    words = emptyList(),
                    durationMs = durationMs,
                    error = null
                )
            }
            // Google mode or fallback
            else -> {
                isContinuous = false
                speechRecognizer?.stopListening()
                speechRecognizer?.destroy()
                speechRecognizer = null
                _isListening.value = false
                _amplitude.value = 0f

                val finalText = buildFullTranscript()
                _transcript.value = finalText

                TranscriptionResult(
                    text = finalText,
                    words = emptyList(),
                    durationMs = 0L,
                    error = null
                )
            }
        }
    }

    /**
     * Stop recognition and await finalized transcript (for ONNX mode).
     * Ensures all buffered audio is processed before returning.
     * Falls back to regular stopListening() for Google mode.
     */
    suspend fun stopListeningAndAwait(
        releaseOnnxAfterStop: Boolean = true,
        finalizeTimeoutMs: Long = DEFAULT_ONNX_FINALIZE_TIMEOUT_MS
    ): TranscriptionResult {
        loadJob?.cancel()
        loadJob = null
        transcriptCollectorJob?.cancel()
        transcriptCollectorJob = null
        amplitudeCollectorJob?.cancel()
        amplitudeCollectorJob = null
        recorderStateCollectorJob?.cancel()
        recorderStateCollectorJob = null
        _isPreparing.value = false

        return when {
            mode == Mode.ONNX_OFFLINE && sherpaPipeline.isLoaded.value -> {
                val durationMs = audioRecorder.recordingDurationMs.value
                if (audioRecorder.isRecording.value) {
                    audioRecorder.stop()
                }
                val finalizeStartedAt = System.currentTimeMillis()
                // Finalizing ONNX inference can be CPU-heavy; keep it off the main thread
                // to avoid UI hangs when users tap "Done" on voice capture screens.
                val finalText = withContext(Dispatchers.Default) {
                    sherpaPipeline.stopAndAwait(timeoutMs = finalizeTimeoutMs)
                }
                val finalizeElapsedMs = System.currentTimeMillis() - finalizeStartedAt
                val error = if (finalText.isBlank()) sherpaPipeline.consumeLastFailureReason() else null
                _isListening.value = false
                _amplitude.value = 0f
                _transcript.value = finalText
                Log.d(
                    "ASREngine",
                    "ASR finalize finished in ${finalizeElapsedMs}ms " +
                        "(chars=${finalText.length}, avail=${availableRamMb()}MB)"
                )

                // Release ONNX session to free RAM before SLM inference.
                // The pipeline auto-loads on next startListening() call.
                if (releaseOnnxAfterStop) {
                    val unloadStartedAt = System.currentTimeMillis()
                    withContext(Dispatchers.Default) {
                        sherpaPipeline.release()
                    }
                    Log.d(
                        "ASREngine",
                        "ASR unload after finalize finished in ${System.currentTimeMillis() - unloadStartedAt}ms " +
                            "(avail=${availableRamMb()}MB)"
                    )
                }

                TranscriptionResult(
                    text = finalText,
                    words = emptyList(),
                    durationMs = durationMs,
                    error = error
                )
            }
            mode == Mode.CLOUD_ASR -> {
                val durationMs = audioRecorder.recordingDurationMs.value
                if (audioRecorder.isRecording.value) {
                    audioRecorder.stop()
                }
                _isListening.value = false
                _amplitude.value = 0f

                val manager = cloudASRManager
                if (manager != null) {
                    withContext(Dispatchers.IO) {
                        manager.stopAndFinalize(durationMs)
                    }
                } else {
                    TranscriptionResult(
                        text = "",
                        words = emptyList(),
                        durationMs = durationMs,
                        error = "Cloud ASR not configured"
                    )
                }
            }
            else -> stopListening()
        }
    }

    /**
     * Load the ONNX model from disk if available.
     */
    suspend fun loadModel(language: String = "en"): Boolean {
        currentLanguage = language
        if (sherpaPipeline.isLoaded.value) return true
        if (_isPreparing.value) return false

        _isPreparing.value = true
        return try {
            withContext(Dispatchers.Default) {
                modelDownloader.refreshState()
                if (!modelDownloader.isReady()) return@withContext false
                if (sherpaPipeline.isLoaded.value) return@withContext true
                val tier = modelDownloader.configuredTier()
                if (tier != null) {
                    sherpaPipeline.loadModel(
                        modelDownloader.modelsDir,
                        SherpaASRPipeline.Architecture.valueOf(tier.architecture.name),
                        modelDownloader.vocabFile,
                        context
                    )
                } else {
                    sherpaPipeline.loadModel(modelDownloader.modelFile, modelDownloader.vocabFile, context)
                }
            }
        } finally {
            _isPreparing.value = false
        }
    }

    fun isModelLoaded(): Boolean = when (mode) {
        Mode.GOOGLE_ONLINE -> true
        Mode.ONNX_OFFLINE -> sherpaPipeline.isLoaded.value
        Mode.CLOUD_ASR -> true  // No model to load for cloud providers
    }

    fun unloadOfflineModelIfIdle() {
        if (_isListening.value || _isPreparing.value || !sherpaPipeline.isLoaded.value) return
        asrScope.launch {
            sherpaPipeline.release()
            System.gc() // Help OS see freed ~400 MB native ONNX memory sooner
        }
    }

    /**
     * Synchronously release the offline ASR model, but only when the engine is idle.
     * Use this before starting LLM work from non-recording screens to avoid overlapping
     * ASR teardown with native LLM model load on low-RAM devices.
     */
    suspend fun unloadOfflineModelIfIdleAndWait() {
        if (_isListening.value || _isPreparing.value || !sherpaPipeline.isLoaded.value) return
        unloadOfflineModelAndWait()
    }

    /**
     * Synchronously release the ONNX model and wait for memory to be freed.
     * Must be called from a coroutine context. Use this before loading the LLM
     * to avoid OOM on low-RAM (3GB) devices where both models can't coexist.
     */
    suspend fun unloadOfflineModelAndWait() {
        if (!sherpaPipeline.isLoaded.value) return
        val unloadStartedAt = System.currentTimeMillis()
        // Use IO dispatcher — release() uses Thread.sleep polling which blocks.
        // Default dispatcher has only 2 threads on 3GB; blocking one starves LLM.
        kotlinx.coroutines.withContext(kotlinx.coroutines.Dispatchers.IO) {
            sherpaPipeline.release()
        }
        // Give the GC a nudge to reclaim native memory before LLM loads
        System.gc()
        Log.d(
            "ASREngine",
            "Blocking ASR unload finished in ${System.currentTimeMillis() - unloadStartedAt}ms " +
                "(avail=${availableRamMb()}MB)"
        )
    }

    fun getCurrentLanguage(): String = currentLanguage

    fun cancelListening(releaseOnnxAfterCancel: Boolean = false) {
        handler.removeCallbacksAndMessages(null)
        loadJob?.cancel()
        loadJob = null
        transcriptCollectorJob?.cancel()
        transcriptCollectorJob = null
        amplitudeCollectorJob?.cancel()
        amplitudeCollectorJob = null
        recorderStateCollectorJob?.cancel()
        recorderStateCollectorJob = null

        if (audioRecorder.isRecording.value) {
            audioRecorder.stop()
        }

        when (mode) {
            Mode.ONNX_OFFLINE -> {
                sherpaPipeline.abort()
                if (releaseOnnxAfterCancel && sherpaPipeline.isLoaded.value) {
                    asrScope.launch {
                        sherpaPipeline.release()
                    }
                }
            }
            Mode.GOOGLE_ONLINE -> {
                isContinuous = false
                speechRecognizer?.cancel()
                speechRecognizer?.destroy()
                speechRecognizer = null
                segments.clear()
                currentPartial = ""
            }
            Mode.CLOUD_ASR -> {
                cloudASRManager?.cancelRecording()
            }
        }

        _isListening.value = false
        _isPreparing.value = false
        _amplitude.value = 0f
        _transcript.value = ""
        consecutiveErrors = 0
    }

    fun release() {
        isContinuous = false
        handler.removeCallbacksAndMessages(null)
        cancelListening(releaseOnnxAfterCancel = false)
        audioRecorder.release()
        // Use async release to avoid blocking the main thread for up to 5s
        // while waiting for in-flight native inference to drain.
        sherpaPipeline.releaseAsync(asrScope)
        _isListening.value = false
        _isPreparing.value = false
        _amplitude.value = 0f
        consecutiveErrors = 0
    }

    // ── ONNX recognition ──

    private fun startOnnxRecognition() {
        _isPreparing.value = false
        sherpaPipeline.start()

        // Wire AudioRecorder chunks to ONNX pipeline
        audioRecorder.setOnChunkReady { chunk ->
            sherpaPipeline.onAudioChunk(chunk)
        }

        // Collect pipeline transcript via StateFlow — updates appear as soon as
        // inference completes, not delayed until the next audio chunk arrives
        transcriptCollectorJob?.cancel()
        transcriptCollectorJob = asrScope.launch {
            sherpaPipeline.transcript.collect { text ->
                _transcript.value = text
            }
        }

        // Forward amplitude for UI mic animation (tracked for cleanup)
        amplitudeCollectorJob?.cancel()
        amplitudeCollectorJob = asrScope.launch {
            audioRecorder.amplitude.collect { amp ->
                _amplitude.value = amp
            }
        }

        recorderStateCollectorJob?.cancel()
        recorderStateCollectorJob = asrScope.launch {
            var sawActiveRecording = false
            audioRecorder.isRecording.collect { recording ->
                if (recording) {
                    sawActiveRecording = true
                    return@collect
                }
                if (!sawActiveRecording || !_isListening.value || mode != Mode.ONNX_OFFLINE) {
                    return@collect
                }
                sawActiveRecording = false
                val finalText = withContext(Dispatchers.Default) {
                    sherpaPipeline.stopAndAwait(timeoutMs = DEFAULT_ONNX_FINALIZE_TIMEOUT_MS)
                }
                val error = if (finalText.isBlank()) sherpaPipeline.consumeLastFailureReason() else null
                _transcript.value = finalText
                _amplitude.value = 0f
                _isListening.value = false
                if (error != null) {
                    errorCallback?.invoke(error)
                }
            }
        }

        val started = audioRecorder.start()
        if (started) {
            _isListening.value = true
        } else {
            _isPreparing.value = false
            _isListening.value = false
            transcriptCollectorJob?.cancel()
            transcriptCollectorJob = null
            amplitudeCollectorJob?.cancel()
            amplitudeCollectorJob = null
            recorderStateCollectorJob?.cancel()
            recorderStateCollectorJob = null
            sherpaPipeline.abort()
            errorCallback?.invoke("Failed to start audio recording. Check microphone permission.")
        }
    }

    // ── Cloud ASR recognition ──

    private fun startCloudRecognition(manager: com.chartlite.app.asr.cloud.CloudASRManager) {
        _isPreparing.value = false
        manager.startRecording(currentLanguage)

        // Wire AudioRecorder chunks to cloud ASR manager
        audioRecorder.setOnChunkReady { chunk ->
            manager.onAudioChunk(chunk)
        }

        // Forward amplitude for UI mic animation
        amplitudeCollectorJob?.cancel()
        amplitudeCollectorJob = asrScope.launch {
            audioRecorder.amplitude.collect { amp ->
                _amplitude.value = amp
            }
        }

        // Auto-stop on silence (same pattern as ONNX mode)
        recorderStateCollectorJob?.cancel()
        recorderStateCollectorJob = asrScope.launch {
            var sawActiveRecording = false
            audioRecorder.isRecording.collect { recording ->
                if (recording) {
                    sawActiveRecording = true
                    return@collect
                }
                if (!sawActiveRecording || !_isListening.value || mode != Mode.CLOUD_ASR) {
                    return@collect
                }
                sawActiveRecording = false
                _amplitude.value = 0f
                _isListening.value = false
            }
        }

        val started = audioRecorder.start()
        if (started) {
            _isListening.value = true
        } else {
            _isListening.value = false
            amplitudeCollectorJob?.cancel()
            amplitudeCollectorJob = null
            recorderStateCollectorJob?.cancel()
            recorderStateCollectorJob = null
            manager.cancelRecording()
            errorCallback?.invoke("Failed to start audio recording. Check microphone permission.")
        }
    }

    // ── Google SpeechRecognizer implementation ──

    private fun startGoogleRecognition() {
        _isPreparing.value = false
        if (!SpeechRecognizer.isRecognitionAvailable(context)) {
            _isListening.value = false
            errorCallback?.invoke("Speech recognition not available. Please install the Google app or use manual text input.")
            return
        }

        isContinuous = true
        startRecognitionSession()
    }

    private fun startRecognitionSession() {
        speechRecognizer?.destroy()
        speechRecognizer = SpeechRecognizer.createSpeechRecognizer(context)

        speechRecognizer?.setRecognitionListener(object : RecognitionListener {
            override fun onReadyForSpeech(params: Bundle?) {
                _isListening.value = true
            }

            override fun onBeginningOfSpeech() {}

            override fun onRmsChanged(rmsdB: Float) {
                // rmsdB typically ranges from -2 to 10
                val normalized = ((rmsdB + 2f) / 12f).coerceIn(0f, 1f)
                _amplitude.value = normalized
            }

            override fun onBufferReceived(buffer: ByteArray?) {}

            override fun onEndOfSpeech() {
                _amplitude.value = 0f
            }

            override fun onError(error: Int) {
                _amplitude.value = 0f
                when (error) {
                    SpeechRecognizer.ERROR_NO_MATCH,
                    SpeechRecognizer.ERROR_SPEECH_TIMEOUT -> {
                        // Normal — silence detected. Restart for continuous dictation.
                        // Reset error counter since these are expected between utterances.
                        consecutiveErrors = 0
                        if (isContinuous) restartWithBackoff()
                    }
                    SpeechRecognizer.ERROR_CLIENT -> {
                        // Quick restart collision — retry with limits
                        consecutiveErrors++
                        if (isContinuous && consecutiveErrors < MAX_CONSECUTIVE_ERRORS) {
                            restartWithBackoff()
                        } else if (consecutiveErrors >= MAX_CONSECUTIVE_ERRORS) {
                            _isListening.value = false
                            errorCallback?.invoke("Speech recognition stopped after repeated errors. Tap to try again.")
                            consecutiveErrors = 0
                        }
                    }
                    SpeechRecognizer.ERROR_NETWORK,
                    SpeechRecognizer.ERROR_NETWORK_TIMEOUT,
                    SpeechRecognizer.ERROR_SERVER -> {
                        // Transient network errors — retry a few times before giving up
                        consecutiveErrors++
                        if (isContinuous && consecutiveErrors <= 3) {
                            restartWithBackoff()
                        } else {
                            val offlineHint = if (!modelDownloader.isReadyFast())
                                ". Download the offline ASR model in Settings for use without internet." else ""
                            val msg = when (error) {
                                SpeechRecognizer.ERROR_NETWORK -> "Network error — check your internet connection$offlineHint"
                                SpeechRecognizer.ERROR_NETWORK_TIMEOUT -> "Network timeout — check your connection$offlineHint"
                                else -> "Server error — please try again$offlineHint"
                            }
                            _isListening.value = false
                            errorCallback?.invoke(msg)
                            consecutiveErrors = 0
                        }
                    }
                    else -> {
                        val msg = when (error) {
                            SpeechRecognizer.ERROR_AUDIO -> "Audio recording error"
                            SpeechRecognizer.ERROR_INSUFFICIENT_PERMISSIONS -> "Microphone permission required"
                            SpeechRecognizer.ERROR_RECOGNIZER_BUSY -> "Recognizer busy, please try again"
                            else -> "Speech recognition error ($error)"
                        }
                        _isListening.value = false
                        errorCallback?.invoke(msg)
                        consecutiveErrors = 0
                    }
                }
            }

            override fun onResults(results: Bundle?) {
                val matches = results?.getStringArrayList(SpeechRecognizer.RESULTS_RECOGNITION)
                val bestResult = matches?.firstOrNull() ?: ""

                if (bestResult.isNotBlank()) {
                    segments.add(bestResult)
                    currentPartial = ""
                    _transcript.value = buildFullTranscript()
                }

                // Successful result — reset error counter
                consecutiveErrors = 0

                // Continue listening for next utterance
                if (isContinuous) restartWithBackoff()
            }

            override fun onPartialResults(partialResults: Bundle?) {
                val matches = partialResults?.getStringArrayList(SpeechRecognizer.RESULTS_RECOGNITION)
                currentPartial = matches?.firstOrNull() ?: ""
                _transcript.value = buildFullTranscript()
            }

            override fun onEvent(eventType: Int, params: Bundle?) {}
        })

        val intent = Intent(RecognizerIntent.ACTION_RECOGNIZE_SPEECH).apply {
            putExtra(RecognizerIntent.EXTRA_LANGUAGE_MODEL, RecognizerIntent.LANGUAGE_MODEL_FREE_FORM)
            putExtra(RecognizerIntent.EXTRA_LANGUAGE, mapLanguageCode(currentLanguage))
            putExtra(RecognizerIntent.EXTRA_PARTIAL_RESULTS, true)
            putExtra(RecognizerIntent.EXTRA_MAX_RESULTS, 1)
            // Longer silence thresholds for clinical dictation
            putExtra(RecognizerIntent.EXTRA_SPEECH_INPUT_COMPLETE_SILENCE_LENGTH_MILLIS, 3000L)
            putExtra(RecognizerIntent.EXTRA_SPEECH_INPUT_POSSIBLY_COMPLETE_SILENCE_LENGTH_MILLIS, 3000L)
        }

        speechRecognizer?.startListening(intent)
    }

    /**
     * Restart recognition with a minimum interval to prevent rapid destroy/create cycles
     * that cause ERROR_CLIENT cascading failures on Android's SpeechRecognizer.
     */
    private fun restartWithBackoff() {
        val now = System.currentTimeMillis()
        val elapsed = now - lastRestartTime
        if (elapsed >= MIN_RESTART_INTERVAL_MS) {
            lastRestartTime = now
            startRecognitionSession()
        } else {
            // Delay the restart to avoid cycling too fast
            val delay = MIN_RESTART_INTERVAL_MS - elapsed
            handler.postDelayed({
                if (isContinuous) {
                    lastRestartTime = System.currentTimeMillis()
                    startRecognitionSession()
                }
            }, delay)
        }
    }

    private fun buildFullTranscript(): String {
        val committed = segments.joinToString(". ")
        return when {
            committed.isBlank() && currentPartial.isBlank() -> ""
            committed.isBlank() -> currentPartial
            currentPartial.isBlank() -> committed
            else -> "$committed. $currentPartial"
        }
    }

    /** Map short language codes to BCP-47 locale tags for SpeechRecognizer (Google mode). */
    private fun mapLanguageCode(code: String): String = when (code) {
        "en" -> "en-US"
        "zu" -> "zu-ZA"
        "xh" -> "xh-ZA"
        "am" -> "am-ET"
        "ny" -> "ny-MW"
        "af" -> "af-ZA"
        "st" -> "st-ZA"
        "tn" -> "tn-ZA"
        "sw" -> "sw-KE"
        "fr" -> "fr-FR"
        else -> code
    }
}
