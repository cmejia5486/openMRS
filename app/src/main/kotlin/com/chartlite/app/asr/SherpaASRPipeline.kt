package com.chartlite.app.asr

import android.content.Context
import android.util.Log
import com.k2fsa.sherpa.onnx.*
import kotlinx.coroutines.*
import kotlinx.coroutines.flow.MutableStateFlow
import kotlinx.coroutines.flow.StateFlow
import java.io.File
import java.util.concurrent.atomic.AtomicBoolean
import java.util.concurrent.atomic.AtomicInteger
import java.util.concurrent.atomic.AtomicLong
import java.util.concurrent.atomic.AtomicReference
import java.util.concurrent.locks.ReentrantLock

@OptIn(kotlinx.coroutines.ExperimentalCoroutinesApi::class)

/**
 * SherpaASRPipeline — On-device speech recognition powered by sherpa-onnx.
 *
 * Supports multiple model architectures:
 *   - CTC: Omnilingual (1600+ languages), medASR (English medical)
 *   - Moonshine: Ultra-light encoder-decoder (English, 125MB)
 *   - Transducer: Parakeet TDT (best English accuracy, 1.69% WER)
 *
 * Architecture:
 *   AudioRecorder (16kHz PCM chunks) → VAD → Recognizer → text
 *
 * Thread safety:
 *   - All VAD operations are serialized via [vadLock] since the native Silero VAD is not thread-safe.
 *   - Inference is serialized to preserve segment ordering (VAD segments commit in capture order).
 *   - [recognizerDestroyed] prevents use-after-free when release() times out waiting for in-flight decodes.
 */
class SherpaASRPipeline {

    /** Model architecture types supported by this pipeline. */
    enum class Architecture {
        CTC,           // Omnilingual CTC (1600+ languages)
        CTC_MEDASR,    // medASR English CTC (medical-specific)
        MOONSHINE,     // Moonshine v1 encoder-decoder (4 files)
        MOONSHINE_V2,  // Moonshine v2 merged decoder (2 files: encoder_model.ort + decoder_model_merged.ort)
        TRANSDUCER,    // Transducer (e.g., Parakeet TDT)
        SENSE_VOICE    // SenseVoice (ZH/EN/JA/KO/YUE)
    }

    private val _isLoaded = MutableStateFlow(false)
    val isLoaded: StateFlow<Boolean> = _isLoaded

    private val _transcript = MutableStateFlow("")
    val transcript: StateFlow<String> = _transcript

    // ── Sherpa-onnx recognizer ──
    private var recognizer: OfflineRecognizer? = null
    private var vad: Vad? = null

    // ── State ──
    private val committedSegments = mutableListOf<String>()
    private val transcriptBuilder = StringBuilder() // Incremental — avoids joinToString() O(n) on every segment
    private val sessionGeneration = AtomicLong(0L)
    @Volatile private var isRunning = false
    private val lastFailureReasonRef = AtomicReference<String?>(null)

    // Prevents JNI calls on a freed recognizer after release() times out.
    private val recognizerDestroyed = AtomicBoolean(false)

    // Audio buffer — VAD processes small windows, accumulates speech segments
    private val audioBuffer = ArrayDeque<FloatArray>()
    private val bufferLock = ReentrantLock()
    private var bufferedSamples = 0

    // VAD lock — Silero VAD native object is NOT thread-safe.
    // All calls to vad.acceptWaveform / vad.empty / vad.front / vad.pop / vad.flush / vad.reset
    // must hold this lock.
    private val vadLock = ReentrantLock()

    // Stop-path mutex — ensures only one of stop() / stopAndAwait() / auto-stop can
    // drain the pipeline at a time. Prevents double-flush of VAD.
    private val stopLock = ReentrantLock()

    // Inference runs on a dedicated scope to avoid blocking audio recording.
    // The scope's SupervisorJob is tracked so we can cancel and recreate it.
    private var inferenceSupervisor = SupervisorJob()
    private var inferenceScope = CoroutineScope(Dispatchers.Default + inferenceSupervisor)
    // Track in-flight inference coroutines (fixes race where two segments overlap)
    private val inFlightInference = AtomicInteger(0)
    // VAD parameters
    private val vadWindowSize = 512 // Silero VAD window (32ms at 16kHz)
    private val sampleRate = 16000

    // Minimum speech to process (0.3 seconds) — avoids wasting inference on tiny fragments
    private val minSpeechSamples = sampleRate * 3 / 10

    // Track loaded architecture for config awareness
    private var loadedArchitecture: Architecture = Architecture.CTC

    // Inference channel: segments are queued here and processed serially to preserve ordering.
    // Using a channel instead of launching concurrent coroutines ensures VAD segments
    // commit to committedSegments in capture order, not finish order.
    // Bounded to 8 segments to prevent unbounded memory growth on slow 3GB devices
    // where VAD may produce segments faster than inference can consume them.
    private val inferenceChannel = kotlinx.coroutines.channels.Channel<FloatArray>(
        capacity = 8
    )
    private var inferenceConsumerJob: Job? = null

    /**
     * Load models from disk.
     *
     * @param modelsDir directory containing model ONNX files
     * @param architecture which model architecture to configure
     * @param vocabFile tokens.txt file
     * @param context Android context for extracting bundled VAD model from assets
     */
    fun loadModel(
        modelsDir: File,
        architecture: Architecture,
        vocabFile: File,
        context: Context? = null
    ): Boolean {
        return try {
            Log.d(TAG, "Loading ASR model via sherpa-onnx: arch=$architecture dir=${modelsDir.name}")
            loadedArchitecture = architecture

            // Build OfflineRecognizer config based on architecture
            val config = buildRecognizerConfig(modelsDir, architecture, vocabFile)
            recognizer = OfflineRecognizer(assetManager = null, config = config)
            recognizerDestroyed.set(false)

            // Load Silero VAD — try extracted file first, then extract from bundled assets
            val vadFile = resolveVadModel(modelsDir, context)
            vad = if (vadFile != null) loadVad(vadFile) else null

            _isLoaded.value = true
            Log.i(TAG, "sherpa-onnx ASR loaded successfully (arch=$architecture, VAD: ${vad != null})")
            true
        } catch (e: Exception) {
            Log.e(TAG, "Failed loading sherpa-onnx ASR model", e)
            lastFailureReasonRef.set("Model load failed: ${e.message}")
            _isLoaded.value = false
            release()
            false
        }
    }

    /**
     * Legacy single-file load for backward compatibility (CTC models).
     */
    fun loadModel(modelFile: File, vocabFile: File, context: Context? = null): Boolean {
        val modelsDir = modelFile.parentFile ?: modelFile
        // Detect architecture from filename
        val files = modelsDir.listFiles()
        val arch = when {
            files?.any { it.name == "decoder_model_merged.ort" } == true -> Architecture.MOONSHINE_V2
            files?.any { it.name.startsWith("preprocess") } == true -> Architecture.MOONSHINE
            files?.any { it.name == "joiner.int8.onnx" || it.name == "joiner.onnx" } == true -> Architecture.TRANSDUCER
            files?.any { it.name == "model.int8.onnx" } == true && files.any { it.name == "tokens.txt" } && files.none { it.name.contains("encoder") } -> {
                // Could be SenseVoice, CTC, or medASR — check further
                // SenseVoice tokens.txt is ~316KB vs CTC ~437KB+, but safest to use a marker
                Architecture.CTC
            }
            else -> Architecture.CTC
        }
        return loadModel(modelsDir, arch, vocabFile, context)
    }

    /**
     * Find the Silero VAD model file. Priority:
     * 1. Already extracted in model directory
     * 2. Extract from bundled APK assets (models/silero_vad.onnx)
     */
    private fun resolveVadModel(modelDir: File?, context: Context?): File? {
        // Check if already in model directory
        val localVad = modelDir?.let { File(it, "silero_vad.onnx") }
        if (localVad?.exists() == true && localVad.length() > 100) return localVad

        // Extract from APK assets
        if (context == null) return null
        return try {
            val targetDir = modelDir ?: File(context.noBackupFilesDir, "models").apply { mkdirs() }
            val targetFile = File(targetDir, "silero_vad.onnx")
            if (targetFile.exists() && targetFile.length() > 100) return targetFile

            context.assets.open("models/silero_vad.onnx").use { input ->
                targetFile.outputStream().use { output ->
                    input.copyTo(output)
                }
            }
            Log.i(TAG, "Extracted bundled Silero VAD (${targetFile.length() / 1024}KB)")
            targetFile
        } catch (e: Exception) {
            Log.w(TAG, "Could not extract bundled VAD model: ${e.message}")
            null
        }
    }

    private fun buildRecognizerConfig(
        modelsDir: File,
        architecture: Architecture,
        vocabFile: File
    ): OfflineRecognizerConfig {
        val tokensPath = vocabFile.absolutePath
        // Dynamic thread count: use more cores on flagship devices for faster ASR.
        // Galaxy A03 (3GB, 8 cores): 2 threads (conservative for memory).
        // Flagship (8+ cores, 4GB+): 4 threads to utilize big cores.
        val cpuCount = Runtime.getRuntime().availableProcessors()
        val numThreads = when {
            cpuCount >= 8 -> 4  // Flagship: use big cores
            cpuCount >= 6 -> 3  // Mid-range
            else -> 2           // Low-end
        }

        val modelConfig = OfflineModelConfig().apply {
            tokens = tokensPath
            this.numThreads = numThreads
            debug = false
            provider = "cpu"

            when (architecture) {
                Architecture.CTC -> {
                    val modelFile = File(modelsDir, "model.int8.onnx")
                    omnilingual = OfflineOmnilingualAsrCtcModelConfig(model = modelFile.absolutePath)
                }

                Architecture.CTC_MEDASR -> {
                    val modelFile = File(modelsDir, "model.int8.onnx")
                    medasr = OfflineMedAsrCtcModelConfig(model = modelFile.absolutePath)
                }

                Architecture.MOONSHINE -> {
                    moonshine = OfflineMoonshineModelConfig(
                        preprocessor = File(modelsDir, "preprocess.onnx").absolutePath,
                        encoder = File(modelsDir, "encode.int8.onnx").absolutePath,
                        uncachedDecoder = File(modelsDir, "uncached_decode.int8.onnx").absolutePath,
                        cachedDecoder = File(modelsDir, "cached_decode.int8.onnx").absolutePath,
                    )
                }

                Architecture.MOONSHINE_V2 -> {
                    moonshine = OfflineMoonshineModelConfig(
                        encoder = File(modelsDir, "encoder_model.ort").absolutePath,
                        mergedDecoder = File(modelsDir, "decoder_model_merged.ort").absolutePath,
                    )
                }

                Architecture.SENSE_VOICE -> {
                    senseVoice = OfflineSenseVoiceModelConfig(
                        model = File(modelsDir, "model.int8.onnx").absolutePath,
                    )
                }

                Architecture.TRANSDUCER -> {
                    transducer = OfflineTransducerModelConfig(
                        encoder = File(modelsDir, "encoder.int8.onnx").absolutePath,
                        decoder = File(modelsDir, "decoder.int8.onnx").absolutePath,
                        joiner = File(modelsDir, "joiner.int8.onnx").absolutePath,
                    )
                }
            }
        }

        return OfflineRecognizerConfig().apply {
            featConfig = getFeatureConfig()
            this.modelConfig = modelConfig
            decodingMethod = "greedy_search"
        }
    }

    private fun getFeatureConfig(): FeatureConfig {
        return FeatureConfig(
            sampleRate = sampleRate,
            featureDim = 80,
        )
    }

    private fun loadVad(vadFile: File): Vad? {
        if (!vadFile.exists()) {
            Log.d(TAG, "VAD model not found at ${vadFile.absolutePath}, running without VAD")
            return null
        }
        return try {
            val config = VadModelConfig(
                sileroVadModelConfig = SileroVadModelConfig(
                    model = vadFile.absolutePath,
                    threshold = 0.4f,
                    minSilenceDuration = 0.3f,
                    minSpeechDuration = 0.1f,
                    windowSize = vadWindowSize,
                    maxSpeechDuration = 30.0f,
                ),
                sampleRate = sampleRate,
                numThreads = 1,
                provider = "cpu",
                debug = false,
            )
            Vad(assetManager = null, config = config).also {
                Log.i(TAG, "Silero VAD loaded successfully")
            }
        } catch (e: Exception) {
            Log.w(TAG, "Failed to load VAD, continuing without it: ${e.message}")
            null
        }
    }

    /**
     * Called by ASREngine when a new audio chunk arrives from AudioRecorder.
     * Converts Short→Float and feeds through VAD → recognizer pipeline.
     */
    fun onAudioChunk(chunk: ShortArray) {
        if (!_isLoaded.value || !isRunning) return

        // Convert PCM16 to float32 [-1.0, 1.0]
        val floatChunk = FloatArray(chunk.size) { chunk[it] / 32768.0f }

        if (vad != null) {
            processWithVad(floatChunk)
        } else {
            processWithoutVad(floatChunk)
        }
    }

    /**
     * VAD-assisted processing: only run inference on speech segments.
     *
     * FIX: Prepend any leftover samples from the previous chunk that were too small
     * for a full VAD window. Without this, sub-window fragments were orphaned in the
     * audio buffer and never fed to the VAD.
     *
     * Thread safety: All VAD operations are guarded by [vadLock] since the native
     * Silero VAD is not thread-safe and stop() may call feedBufferToVad() concurrently.
     */
    private fun processWithVad(samples: FloatArray) {
        val vadInstance = vad ?: return

        // Prepend any leftover samples from the previous chunk
        val leftover = drainFloatBuffer()
        val allSamples = if (leftover.isNotEmpty()) leftover + samples else samples

        // Feed samples to VAD in window-sized chunks (under lock)
        vadLock.lock()
        try {
            var offset = 0
            while (offset + vadWindowSize <= allSamples.size) {
                val window = allSamples.copyOfRange(offset, offset + vadWindowSize)
                vadInstance.acceptWaveform(window)
                offset += vadWindowSize

                // Check if VAD detected complete speech segments
                while (!vadInstance.empty()) {
                    val segment = vadInstance.front()
                    vadInstance.pop()

                    if (segment.samples.size >= minSpeechSamples) {
                        enqueueInference(segment.samples)
                    }
                }
            }

            // Buffer remaining samples (less than window size) for next chunk
            if (offset < allSamples.size) {
                val remaining = allSamples.copyOfRange(offset, allSamples.size)
                enqueueFloat(remaining)
            }
        } finally {
            vadLock.unlock()
        }
    }

    /**
     * Without VAD: buffer audio and run inference periodically.
     */
    private fun processWithoutVad(samples: FloatArray) {
        enqueueFloat(samples)

        val totalSamples = getBufferedSampleCount()
        // Run inference every 2 seconds of audio
        if (totalSamples >= sampleRate * 2 && inFlightInference.get() == 0) {
            val merged = drainFloatBuffer()
            if (merged.isNotEmpty()) {
                enqueueInference(merged)
            }
        }
    }

    /**
     * Enqueue a speech segment for serial inference processing.
     * Segments are processed in FIFO order to preserve transcript ordering.
     *
     * [inFlightInference] is incremented here (at enqueue time) rather than in the
     * consumer, eliminating the race window between channel.receive() removing the
     * item and the consumer incrementing the counter.
     */
    private fun enqueueInference(samples: FloatArray) {
        val result = inferenceChannel.trySend(samples)
        if (result.isSuccess) {
            inFlightInference.incrementAndGet()
        } else {
            // Channel full (capacity=8) — drop this segment rather than leaking the counter.
            // This only happens on extremely slow devices where VAD outpaces inference.
            Log.w(TAG, "Inference channel full, dropping ${samples.size} samples to prevent hang")
        }
    }

    /**
     * Single-threaded inference consumer. Processes segments from [inferenceChannel]
     * in order, ensuring transcript segments commit in capture order (not finish order).
     */
    private fun launchInferenceConsumer(readySignal: kotlinx.coroutines.CompletableDeferred<Unit>? = null) {
        inferenceConsumerJob?.cancel()
        inferenceConsumerJob = inferenceScope.launch {
            // Signal that the consumer loop is executing — audio chunks can now be processed.
            readySignal?.complete(Unit)
            for (samples in inferenceChannel) {
                if (recognizerDestroyed.get()) {
                    inFlightInference.decrementAndGet()
                    continue
                }
                val rec = recognizer ?: run {
                    inFlightInference.decrementAndGet()
                    continue
                }
                val generationId = sessionGeneration.get()

                try {
                    val stream = rec.createStream()
                    try {
                        stream.acceptWaveform(samples, sampleRate)
                        rec.decode(stream)
                        val result = rec.getResult(stream)

                        val text = result.text.trim()
                        if (generationId == sessionGeneration.get() && text.isNotBlank()) {
                            synchronized(committedSegments) {
                                committedSegments.add(text)
                                if (transcriptBuilder.isNotEmpty()) transcriptBuilder.append(". ")
                                transcriptBuilder.append(text)
                            }
                            _transcript.value = transcriptBuilder.toString()
                        }
                    } finally {
                        stream.release()
                    }
                } catch (e: Exception) {
                    Log.e(TAG, "Inference failed: ${e.message}")
                    lastFailureReasonRef.set("Inference error: ${e.message}")
                } finally {
                    inFlightInference.decrementAndGet()
                }
            }
        }
    }

    /**
     * Suspend until all enqueued inference work completes (or timeout).
     *
     * [inFlightInference] is incremented at enqueue time ([enqueueInference]) and
     * decremented when the consumer finishes (or skips) each segment. So
     * `inFlightInference == 0` means nothing is queued or in-flight — no race
     * window between channel.receive() and counter increment.
     *
     * The `inferenceChannel.isEmpty` check is a belt-and-suspenders guard for
     * edge cases where the counter and channel get out of sync.
     */
    private suspend fun awaitInferenceIdle(timeoutMs: Long) {
        val deadline = System.currentTimeMillis() + timeoutMs
        while (System.currentTimeMillis() < deadline) {
            if (inFlightInference.get() == 0 && inferenceChannel.isEmpty) return
            delay(10)
        }
    }

    // ── Buffer management ──

    private fun enqueueFloat(chunk: FloatArray) {
        bufferLock.lock()
        try {
            audioBuffer.addLast(chunk)
            bufferedSamples += chunk.size
        } finally {
            bufferLock.unlock()
        }
    }

    private fun getBufferedSampleCount(): Int {
        bufferLock.lock()
        try {
            return bufferedSamples
        } finally {
            bufferLock.unlock()
        }
    }

    private fun drainFloatBuffer(): FloatArray {
        bufferLock.lock()
        try {
            if (audioBuffer.isEmpty()) return FloatArray(0)
            val totalSize = bufferedSamples
            val merged = FloatArray(totalSize)
            var offset = 0
            while (audioBuffer.isNotEmpty()) {
                val chunk = audioBuffer.removeFirst()
                chunk.copyInto(merged, offset)
                offset += chunk.size
            }
            bufferedSamples = 0
            return merged
        } finally {
            bufferLock.unlock()
        }
    }

    // ── Lifecycle ──

    fun start() {
        sessionGeneration.incrementAndGet()
        synchronized(committedSegments) { committedSegments.clear(); transcriptBuilder.clear() }
        _transcript.value = ""
        lastFailureReasonRef.set(null)
        clearBuffer()
        inFlightInference.set(0) // Reset stale count from previous session

        vadLock.lock()
        try {
            vad?.reset()
        } finally {
            vadLock.unlock()
        }

        // Ensure inference scope is alive (may have been cancelled by release())
        if (!inferenceSupervisor.isActive) {
            inferenceSupervisor = SupervisorJob()
            inferenceScope = CoroutineScope(Dispatchers.Default + inferenceSupervisor)
        }

        // Drain any stale segments from a previous session
        while (inferenceChannel.tryReceive().isSuccess) { /* discard */ }

        // Launch serial inference consumer and wait for it to actually start executing.
        // On low-RAM devices, the Dispatchers.Default thread pool can be slow to schedule
        // the consumer coroutine; audio chunks arriving before the consumer loop starts
        // would be discarded, causing the first 3-4 seconds of speech to be lost.
        val consumerReady = kotlinx.coroutines.CompletableDeferred<Unit>()
        launchInferenceConsumer(consumerReady)

        recognizerDestroyed.set(false)
        isRunning = true

        // Wait briefly to ensure consumer is actually executing before audio recording starts.
        // CompletableDeferred.complete() is called as the first action inside the consumer loop.
        // Uses Thread.sleep polling instead of runBlocking to avoid blocking the main thread
        // coroutine dispatcher on 3GB devices (where runBlocking can freeze UI for 2-5s).
        val waitDeadline = System.currentTimeMillis() + 2000
        while (!consumerReady.isCompleted && System.currentTimeMillis() < waitDeadline) {
            Thread.sleep(10)
        }
        if (!consumerReady.isCompleted) {
            Log.w(TAG, "Inference consumer startup wait timed out after 2s")
        }
    }

    fun stop(): String {
        if (!stopLock.tryLock()) {
            // Another stop path is already draining — just return current transcript
            return synchronized(committedSegments) { committedSegments.joinToString(". ") }
        }
        try {
            isRunning = false
            // Feed any buffered leftover samples into VAD before flushing, so short
            // final utterances aren't lost at the boundary.
            // All segments route through the inference channel to preserve ordering —
            // stop-path segments queue behind any already-enqueued capture-time segments.
            feedBufferToVad()
            flushVad()
            // Process any audio that bypassed VAD (e.g., sub-window leftovers after flush)
            val remaining = drainFloatBuffer()
            if (remaining.size >= minSpeechSamples) {
                enqueueInference(remaining)
            }
            // Wait for the channel consumer to drain all queued segments (stop-path
            // segments are now behind earlier capture-time segments in the channel).
            val deadline = System.currentTimeMillis() + STOP_DRAIN_TIMEOUT_MS
            while ((inFlightInference.get() > 0 || !inferenceChannel.isEmpty)
                && System.currentTimeMillis() < deadline) {
                Thread.sleep(10)
            }
            return synchronized(committedSegments) {
                committedSegments.joinToString(". ")
            }
        } finally {
            stopLock.unlock()
        }
    }

    suspend fun stopAndAwait(timeoutMs: Long = 20_000L): String {
        if (!stopLock.tryLock()) {
            // Another stop path is already draining — wait for inference to finish and return
            awaitInferenceIdle(timeoutMs)
            return synchronized(committedSegments) { committedSegments.joinToString(". ") }
        }
        try {
            isRunning = false
            // Feed buffered leftovers into VAD before flushing.
            // All segments route through the inference channel to preserve ordering.
            feedBufferToVad()
            flushVad()
            // Process any remaining audio that bypassed VAD
            val remaining = drainFloatBuffer()
            if (remaining.size >= minSpeechSamples) {
                enqueueInference(remaining)
            }
            // Wait for all queued + in-flight inference to complete.
            // Stop-path segments are now behind earlier capture-time segments in the channel.
            awaitInferenceIdle(timeoutMs)
            return synchronized(committedSegments) {
                committedSegments.joinToString(". ")
            }
        } finally {
            stopLock.unlock()
        }
    }

    /**
     * Drain the audio buffer and feed complete VAD windows to the VAD instance.
     * Any sub-window remainder goes back into the buffer for direct processing.
     *
     * Detected speech segments are enqueued via [enqueueInference] (not decoded
     * synchronously) so they queue behind any already-pending capture-time segments,
     * preserving transcript ordering.
     */
    private fun feedBufferToVad() {
        val vadInstance = vad ?: return
        val buffered = drainFloatBuffer()
        if (buffered.isEmpty()) return

        vadLock.lock()
        try {
            var offset = 0
            while (offset + vadWindowSize <= buffered.size) {
                val window = buffered.copyOfRange(offset, offset + vadWindowSize)
                vadInstance.acceptWaveform(window)
                offset += vadWindowSize

                while (!vadInstance.empty()) {
                    val segment = vadInstance.front()
                    vadInstance.pop()
                    if (segment.samples.size >= minSpeechSamples) {
                        enqueueInference(segment.samples)
                    }
                }
            }
            // Put sub-window remainder back for direct processing after flush
            if (offset < buffered.size) {
                enqueueFloat(buffered.copyOfRange(offset, buffered.size))
            }
        } finally {
            vadLock.unlock()
        }
    }

    /**
     * Flush the VAD to emit any partially-accumulated speech segment.
     * Segments are enqueued via [enqueueInference] to preserve ordering.
     */
    private fun flushVad() {
        val vadInstance = vad ?: return
        vadLock.lock()
        try {
            vadInstance.flush()
            while (!vadInstance.empty()) {
                val segment = vadInstance.front()
                vadInstance.pop()
                if (segment.samples.size >= minSpeechSamples) {
                    enqueueInference(segment.samples)
                }
            }
        } catch (e: Exception) {
            Log.w(TAG, "VAD flush error: ${e.message}")
        } finally {
            vadLock.unlock()
        }
    }

    fun abort() {
        isRunning = false
        clearBuffer()
        vadLock.lock()
        try {
            vad?.reset()
        } finally {
            vadLock.unlock()
        }
    }

    /**
     * Release all native resources. Safe to call from any thread.
     *
     * If in-flight inference doesn't complete within [RELEASE_WAIT_TIMEOUT_MS],
     * the recognizer is NOT freed (leaked intentionally) to avoid SIGSEGV from
     * JNI calls on freed native memory. A warning is logged.
     */
    fun release() {
        isRunning = false
        recognizerDestroyed.set(true) // Prevent new JNI calls from in-flight coroutines

        // Cancel inference consumer and scope — this interrupts the channel loop
        inferenceConsumerJob?.cancel()
        inferenceConsumerJob = null
        inferenceSupervisor.cancel()

        // Drain any pending items from the channel so inFlightInference counter can settle
        while (inferenceChannel.tryReceive().isSuccess) {
            inFlightInference.decrementAndGet()
        }

        // Wait for in-flight coroutines that started before recognizerDestroyed was set.
        // JNI calls (rec.decode) are not cooperatively cancellable, so we must wait.
        val deadline = System.currentTimeMillis() + RELEASE_WAIT_TIMEOUT_MS
        while (inFlightInference.get() > 0 && System.currentTimeMillis() < deadline) {
            Thread.sleep(10)
        }

        clearBuffer()

        if (inFlightInference.get() > 0) {
            // Force the counter to zero — the scope is cancelled, no more consumers exist.
            // This prevents a stuck counter from leaking the recognizer on next release().
            val stale = inFlightInference.getAndSet(0)
            Log.e(TAG, "release() timed out with $stale in-flight refs — " +
                "scope cancelled, forcing counter reset and releasing recognizer")
            // With the scope fully cancelled, no coroutine can call into the recognizer.
            // It's safe to release even with stale counter, since the consumer is dead.
            try { recognizer?.release() } catch (e: Exception) {
                Log.w(TAG, "Error releasing recognizer after timeout: ${e.message}")
            }
            recognizer = null
        } else {
            try { recognizer?.release() } catch (e: Exception) { Log.w(TAG, "Error releasing recognizer: ${e.message}") }
            recognizer = null
        }

        vadLock.lock()
        try {
            try { vad?.release() } catch (e: Exception) { Log.w(TAG, "Error releasing VAD: ${e.message}") }
            vad = null
        } finally {
            vadLock.unlock()
        }

        _isLoaded.value = false
        synchronized(committedSegments) { committedSegments.clear(); transcriptBuilder.clear() }
        _transcript.value = ""
    }

    /**
     * Non-blocking release for use from the main thread.
     * Fires release() on a background thread and returns immediately.
     */
    fun releaseAsync(scope: CoroutineScope) {
        isRunning = false
        recognizerDestroyed.set(true)
        scope.launch(Dispatchers.Default) { release() }
    }

    fun consumeLastFailureReason(): String? {
        return lastFailureReasonRef.getAndSet(null)
    }

    private fun clearBuffer() {
        bufferLock.lock()
        try {
            audioBuffer.clear()
            bufferedSamples = 0
        } finally {
            bufferLock.unlock()
        }
    }

    companion object {
        private const val TAG = "SherpaASR"
        private const val RELEASE_WAIT_TIMEOUT_MS = 5_000L
        // Max time stop() will wait for the inference channel to drain.
        // Matches stopAndAwait default but applied as a polling deadline.
        private const val STOP_DRAIN_TIMEOUT_MS = 10_000L
    }
}
