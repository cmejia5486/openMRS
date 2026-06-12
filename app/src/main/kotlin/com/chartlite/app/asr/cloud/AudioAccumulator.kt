package com.chartlite.app.asr.cloud

import android.util.Log
import java.io.ByteArrayOutputStream
import java.io.File
import java.io.FileOutputStream
import java.nio.ByteBuffer
import java.nio.ByteOrder

/**
 * Accumulates raw PCM audio chunks during recording and outputs WAV format.
 *
 * Phase 1 uses WAV for all providers (simple, universally accepted).
 * Phase 2 will add Opus/Ogg compression for store-and-forward bandwidth savings.
 *
 * Audio spec: 16kHz mono 16-bit signed PCM (matching AudioRecorder).
 */
class AudioAccumulator(
    private val sampleRate: Int = 16000,
    private val channels: Int = 1,
    private val bitsPerSample: Int = 16,
    private val maxBytes: Long = 25_000_000L // 25MB default (OpenAI limit)
) {

    companion object {
        private const val TAG = "AudioAccumulator"
        private const val WAV_HEADER_SIZE = 44
    }

    private val pcmBuffer = ByteArrayOutputStream()
    private var totalSamples = 0L
    private var isFull = false

    /** Total accumulated PCM bytes (excluding WAV header) */
    val pcmByteCount: Int get() = pcmBuffer.size()

    /** Estimated recording duration in milliseconds */
    val durationMs: Long get() = totalSamples * 1000L / sampleRate

    /** Whether the accumulator has reached its size limit */
    val isAtCapacity: Boolean get() = isFull

    /**
     * Add a PCM audio chunk (ShortArray from AudioRecorder).
     * Returns false if the accumulator is full and the chunk was dropped.
     */
    fun addChunk(chunk: ShortArray): Boolean {
        if (isFull) return false

        val byteCount = chunk.size * 2 // 16-bit = 2 bytes per sample
        if (pcmBuffer.size() + byteCount + WAV_HEADER_SIZE > maxBytes) {
            isFull = true
            Log.w(TAG, "Accumulator at capacity (${pcmBuffer.size()} bytes). Dropping chunk.")
            return false
        }

        // Convert ShortArray to little-endian byte array
        val byteBuffer = ByteBuffer.allocate(byteCount).order(ByteOrder.LITTLE_ENDIAN)
        for (sample in chunk) {
            byteBuffer.putShort(sample)
        }
        pcmBuffer.write(byteBuffer.array())
        totalSamples += chunk.size

        return true
    }

    /**
     * Export accumulated audio as a WAV byte array.
     * WAV format is accepted by all three cloud ASR providers.
     */
    fun toWav(): ByteArray {
        val pcmData = pcmBuffer.toByteArray()
        val dataSize = pcmData.size
        val fileSize = dataSize + WAV_HEADER_SIZE - 8

        val buffer = ByteBuffer.allocate(WAV_HEADER_SIZE + dataSize).order(ByteOrder.LITTLE_ENDIAN)

        // RIFF header
        buffer.put("RIFF".toByteArray())
        buffer.putInt(fileSize)
        buffer.put("WAVE".toByteArray())

        // fmt chunk
        buffer.put("fmt ".toByteArray())
        buffer.putInt(16)                           // Subchunk1Size (PCM = 16)
        buffer.putShort(1)                          // AudioFormat (PCM = 1)
        buffer.putShort(channels.toShort())         // NumChannels
        buffer.putInt(sampleRate)                   // SampleRate
        buffer.putInt(sampleRate * channels * bitsPerSample / 8) // ByteRate
        buffer.putShort((channels * bitsPerSample / 8).toShort()) // BlockAlign
        buffer.putShort(bitsPerSample.toShort())    // BitsPerSample

        // data chunk
        buffer.put("data".toByteArray())
        buffer.putInt(dataSize)
        buffer.put(pcmData)

        return buffer.array()
    }

    /**
     * Write accumulated audio as WAV to a file.
     * For store-and-forward: caller is responsible for encrypting the file.
     */
    fun writeToFile(file: File) {
        val wavData = toWav()
        FileOutputStream(file).use { it.write(wavData) }
        Log.d(TAG, "Wrote ${wavData.size} bytes WAV to ${file.name}")
    }

    /** Reset the accumulator for a new recording */
    fun reset() {
        pcmBuffer.reset()
        totalSamples = 0L
        isFull = false
    }
}
