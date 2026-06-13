package com.chartlite.app.asr

import android.Manifest
import android.annotation.SuppressLint
import android.content.Context
import android.content.pm.PackageManager
import android.app.ActivityManager
import android.media.AudioFormat
import android.media.AudioRecord
import android.media.MediaRecorder
import android.media.audiofx.AutomaticGainControl
import android.media.audiofx.NoiseSuppressor
import android.util.Log
import androidx.core.content.ContextCompat
import kotlinx.coroutines.*
import kotlinx.coroutines.Job
import kotlinx.coroutines.flow.MutableStateFlow
import kotlinx.coroutines.flow.StateFlow
import kotlin.math.abs

class AudioRecorder(private val context: Context) {

    companion object {
        const val SAMPLE_RATE = 16000
        const val CHANNEL_CONFIG = AudioFormat.CHANNEL_IN_MONO
        const val AUDIO_FORMAT = AudioFormat.ENCODING_PCM_16BIT
        private const val SILENCE_THRESHOLD = 500
        private const val DEFAULT_SILENCE_TIMEOUT_MS = 2000L
        private const val TAG = "AudioRecorder"
    }

    private var audioRecord: AudioRecord? = null
    private var automaticGainControl: AutomaticGainControl? = null
    private var noiseSuppressor: NoiseSuppressor? = null
    @Volatile private var tryPlatformAudioEffects = true
    private var recordingJob: Job? = null
    private var scope = CoroutineScope(Dispatchers.IO + SupervisorJob())
    private val audioLock = Any()

    private val _isRecording = MutableStateFlow(false)
    val isRecording: StateFlow<Boolean> = _isRecording

    private val _audioData = MutableStateFlow<ShortArray>(ShortArray(0))
    val audioData: StateFlow<ShortArray> = _audioData

    private val _recordingDurationMs = MutableStateFlow(0L)
    val recordingDurationMs: StateFlow<Long> = _recordingDurationMs

    private val _amplitude = MutableStateFlow(0f)
    val amplitude: StateFlow<Float> = _amplitude

    private var onChunkReady: ((ShortArray) -> Unit)? = null
    private var maxRecordingMs: Long = 10 * 60 * 1000L // 10 min default
    @Volatile private var silenceAutoStopEnabled: Boolean = true
    @Volatile private var silenceTimeoutMs: Long = DEFAULT_SILENCE_TIMEOUT_MS

    fun hasPermission(): Boolean {
        return ContextCompat.checkSelfPermission(
            context, Manifest.permission.RECORD_AUDIO
        ) == PackageManager.PERMISSION_GRANTED
    }

    fun setMaxRecordingMinutes(minutes: Int) {
        maxRecordingMs = minutes * 60 * 1000L
    }

    /**
     * Configure silence auto-stop behavior.
     *
     * Snippet dictation mode benefits from fast auto-stop on pauses.
     * Ambient full-encounter mode should disable auto-stop to avoid cutting off
     * natural conversation gaps between clinician and patient.
     */
    fun configureSilenceAutoStop(enabled: Boolean, timeoutMs: Long = DEFAULT_SILENCE_TIMEOUT_MS) {
        silenceAutoStopEnabled = enabled
        silenceTimeoutMs = timeoutMs.coerceAtLeast(500L)
    }

    fun setOnChunkReady(callback: (ShortArray) -> Unit) {
        onChunkReady = callback
    }

    fun start(): Boolean {
        if (_isRecording.value || !hasPermission()) return false

        // Ensure scope is alive (may have been cancelled by release())
        if (scope.coroutineContext[Job]?.isActive != true) {
            scope = CoroutineScope(Dispatchers.IO + SupervisorJob())
        }

        val bufferSize = AudioRecord.getMinBufferSize(SAMPLE_RATE, CHANNEL_CONFIG, AUDIO_FORMAT)
        if (bufferSize == AudioRecord.ERROR_BAD_VALUE || bufferSize == AudioRecord.ERROR) return false

        try {
            audioRecord = createAudioRecord(bufferSize * 2)
        } catch (e: Exception) {
            Log.e(TAG, "Failed to initialize AudioRecord", e)
            return false
        }

        if (audioRecord?.state != AudioRecord.STATE_INITIALIZED) {
            stopInternal()
            return false
        }

        configureAudioEffects(audioRecord)

        audioRecord?.startRecording()
        _isRecording.value = true
        _recordingDurationMs.value = 0L

        recordingJob = scope.launch {
            // Elevate thread priority for real-time audio capture — prevents
            // buffer overruns and dropped frames on loaded CPUs (Galaxy A03).
            android.os.Process.setThreadPriority(android.os.Process.THREAD_PRIORITY_URGENT_AUDIO)

            val chunkBuffer = ShortArray(SAMPLE_RATE / 4) // 0.25 second chunks for faster inference triggering
            var silenceStartMs: Long? = null
            val startTime = System.currentTimeMillis()
            var totalSamplesRecorded = 0

            while (isActive && _isRecording.value) {
                val read = audioRecord?.read(chunkBuffer, 0, chunkBuffer.size) ?: -1
                if (read <= 0) continue

                val chunk = chunkBuffer.copyOf(read)
                totalSamplesRecorded += read

                _recordingDurationMs.value = System.currentTimeMillis() - startTime

                // Single-pass: compute amplitude + RMS together to avoid iterating chunk twice
                var maxAmp = 0
                var sumSquares = 0.0
                for (s in chunk) {
                    val absVal = abs(s.toInt())
                    if (absVal > maxAmp) maxAmp = absVal
                    sumSquares += s.toDouble() * s.toDouble()
                }
                _amplitude.value = (maxAmp / Short.MAX_VALUE.toFloat()).coerceIn(0f, 1f)

                // Send chunk for streaming transcription
                onChunkReady?.invoke(chunk)

                // Silence detection using pre-computed RMS from above.
                // Disabled for ambient mode to preserve natural conversation pauses.
                if (silenceAutoStopEnabled) {
                    val rms = kotlin.math.sqrt(sumSquares / chunk.size)
                    if (rms < SILENCE_THRESHOLD) {
                        if (silenceStartMs == null) silenceStartMs = System.currentTimeMillis()
                        else if (System.currentTimeMillis() - silenceStartMs > silenceTimeoutMs) {
                            break // Auto-stop on sustained silence in snippet mode
                        }
                    } else {
                        silenceStartMs = null
                    }
                } else {
                    silenceStartMs = null
                }

                // Max recording duration
                if (_recordingDurationMs.value >= maxRecordingMs) break
            }

            _audioData.value = ShortArray(0) // Audio is consumed via chunks, not stored
            stopInternal()
        }

        return true
    }

    fun stop() {
        recordingJob?.cancel()
        recordingJob = null
        stopInternal()
    }

    private fun stopInternal() {
        val record = synchronized(audioLock) {
            val activeRecord = audioRecord
            audioRecord = null
            _isRecording.value = false
            activeRecord
        } ?: return

        try {
            record.stop()
        } catch (e: IllegalStateException) {
            Log.w(TAG, "AudioRecord.stop() failed", e)
        }
        releaseAudioEffects()
        record.release()
    }

    fun release() {
        stop()
        scope.cancel()
    }

    @SuppressLint("MissingPermission") // Permission checked by ASREngine before recording starts
    private fun createAudioRecord(bufferSize: Int): AudioRecord {
        val sources = listOf(
            MediaRecorder.AudioSource.VOICE_RECOGNITION,
            MediaRecorder.AudioSource.MIC
        ).distinct()

        var lastError: Exception? = null
        for (source in sources) {
            try {
                val record = AudioRecord(
                    source,
                    SAMPLE_RATE,
                    CHANNEL_CONFIG,
                    AUDIO_FORMAT,
                    bufferSize
                )
                if (record.state == AudioRecord.STATE_INITIALIZED) {
                    Log.d(TAG, "Using audio source ${audioSourceName(source)} for ASR")
                    return record
                }
                record.release()
            } catch (e: Exception) {
                lastError = e
            }
        }
        throw lastError ?: Exception("Unable to initialize AudioRecord")
    }

    private fun configureAudioEffects(record: AudioRecord?) {
        val sessionId = record?.audioSessionId ?: return
        releaseAudioEffects()
        if (!shouldUsePlatformAudioEffects()) {
            return
        }
        automaticGainControl = runCatching {
            AutomaticGainControl.create(sessionId)?.apply { enabled = true }
        }.onFailure {
            Log.w(TAG, "Disabling AGC attempts after allocation/init failure: ${it.message}")
            tryPlatformAudioEffects = false
        }.getOrNull()
        noiseSuppressor = runCatching {
            NoiseSuppressor.create(sessionId)?.apply { enabled = true }
        }.onFailure {
            Log.w(TAG, "Disabling noise suppressor attempts after allocation/init failure: ${it.message}")
            tryPlatformAudioEffects = false
        }.getOrNull()
        if (automaticGainControl == null && noiseSuppressor == null) {
            tryPlatformAudioEffects = false
        }
    }

    private fun shouldUsePlatformAudioEffects(): Boolean {
        if (!tryPlatformAudioEffects) return false
        val am = context.getSystemService(Context.ACTIVITY_SERVICE) as ActivityManager
        val memInfo = ActivityManager.MemoryInfo()
        am.getMemoryInfo(memInfo)
        val totalRamGb = memInfo.totalMem / (1024.0 * 1024.0 * 1024.0)
        if (am.isLowRamDevice || totalRamGb <= 3.5) {
            tryPlatformAudioEffects = false
            Log.d(TAG, "Skipping AGC/NoiseSuppressor on low-memory device")
            return false
        }
        return true
    }

    private fun releaseAudioEffects() {
        automaticGainControl?.release()
        automaticGainControl = null
        noiseSuppressor?.release()
        noiseSuppressor = null
    }

    private fun audioSourceName(source: Int): String = when (source) {
        MediaRecorder.AudioSource.VOICE_RECOGNITION -> "VOICE_RECOGNITION"
        MediaRecorder.AudioSource.MIC -> "MIC"
        else -> source.toString()
    }
}
