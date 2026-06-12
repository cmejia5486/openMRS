package com.chartlite.app.asr

import android.app.ActivityManager
import android.content.Context
import android.net.wifi.WifiManager
import android.os.Build
import android.os.PowerManager
import android.util.Log
import com.chartlite.app.config.AppConfig
import kotlinx.coroutines.*
import kotlinx.coroutines.flow.MutableStateFlow
import kotlinx.coroutines.flow.StateFlow
import okhttp3.OkHttpClient
import okhttp3.Request
import java.io.File
import java.io.FileOutputStream
import java.security.MessageDigest
import java.util.concurrent.TimeUnit

/**
 * Downloads ONNX model and vocabulary files with resume support and SHA-256 verification.
 *
 * Supports multi-file model architectures (CTC, Moonshine, Transducer).
 * Files are stored in `context.noBackupFilesDir/models/` so they won't be included
 * in Android auto-backup (models are large and re-downloadable).
 */
class ModelDownloader(private val context: Context) {
    private data class DownloadResult(
        val usedResume: Boolean
    )

    sealed class DownloadState {
        data object Idle : DownloadState()
        data class Downloading(val bytesDownloaded: Long, val totalBytes: Long) : DownloadState()
        data object Verifying : DownloadState()
        data object Complete : DownloadState()
        data class Error(val message: String) : DownloadState()
        data object Paused : DownloadState()
    }

    /** Model architecture types supported by the download system. */
    enum class ModelArchitecture { CTC, CTC_MEDASR, MOONSHINE_V2, TRANSDUCER, SENSE_VOICE }

    /** A single downloadable ONNX artifact within a model tier. */
    data class ModelArtifact(
        val filename: String,
        val url: String,
        val sha256: String
    )

    private val _state = MutableStateFlow<DownloadState>(DownloadState.Idle)
    val state: StateFlow<DownloadState> = _state

    val modelsDir = File(context.noBackupFilesDir, "models").apply { mkdirs() }
    private val client = OkHttpClient.Builder()
        .connectTimeout(30, TimeUnit.SECONDS)
        .readTimeout(60, TimeUnit.SECONDS)
        .build()

    private var downloadJob: Job? = null
    private val scope = CoroutineScope(SupervisorJob() + Dispatchers.IO)
    @Volatile private var verifiedArtifactsFingerprint: String? = null

    // Cached AppConfig to avoid re-creating EncryptedSharedPreferences on every call.
    private val appConfig by lazy { AppConfig(context) }

    // Legacy single-file accessors (used by existing code for CTC models)
    val modelFile: File get() = File(modelsDir, "model.int8.onnx")
    val vocabFile: File get() = File(modelsDir, "tokens.txt")

    fun isModelDownloaded(): Boolean {
        val tier = configuredTier() ?: return modelFile.exists() && modelFile.length() > 0
        return tier.artifacts.all { artifact ->
            val file = File(modelsDir, artifact.filename)
            file.exists() && file.length() > 0
        }
    }

    fun isVocabDownloaded(): Boolean = vocabFile.exists() && vocabFile.length() > 0

    fun isReady(): Boolean {
        if (!isModelDownloaded() || !isVocabDownloaded()) return false
        return try {
            verifyInstalledArtifacts()
            true
        } catch (e: IllegalStateException) {
            Log.w(TAG, "Offline ASR not ready: ${e.message}")
            false
        }
    }

    /**
     * Fast readiness check suitable for the main thread. Checks that:
     * 1. All artifact files exist and have non-zero size
     * 2. Vocab file exists and has non-zero size
     * 3. A valid tier is configured
     *
     * Does NOT verify SHA-256 hashes (which can take seconds for large models).
     * Use [isReady] for full verification on a background thread.
     */
    fun isReadyFast(): Boolean {
        if (!isModelDownloaded() || !isVocabDownloaded()) return false
        // If we've previously verified, trust the fingerprint cache
        if (verifiedArtifactsFingerprint != null) return true
        // Otherwise just check that a valid tier is configured
        return configuredTier() != null
    }

    fun modelSizeBytes(): Long {
        val tier = configuredTier()
        return if (tier != null) {
            tier.artifacts.sumOf { File(modelsDir, it.filename).let { f -> if (f.exists()) f.length() else 0L } }
        } else {
            if (modelFile.exists()) modelFile.length() else 0
        }
    }

    /**
     * Start downloading all model artifacts and vocab file. Supports HTTP Range resume.
     */
    fun startDownload(
        modelUrl: String = "",  // Legacy param, ignored for multi-file tiers
        vocabUrl: String = "",  // Legacy param, ignored for multi-file tiers
        expectedSha256: String = "",
        expectedVocabSha256: String = ""
    ) {
        if (downloadJob?.isActive == true) return

        val tier = configuredTier()
        if (tier == null) {
            // Legacy single-file path
            if (modelUrl.isBlank()) {
                _state.value = DownloadState.Error("Model URL not configured. Set it in Settings.")
                return
            }
            startLegacyDownload(modelUrl, vocabUrl, expectedSha256, expectedVocabSha256)
            return
        }

        if (!tier.isDownloadable) {
            _state.value = DownloadState.Error("Selected tier is not downloadable.")
            return
        }

        downloadJob = scope.launch {
            // Note: wake locks removed — ModelDownloadService foreground service
            // keeps the process alive during screen-off / Doze mode.
            try {
                // Clean up files from a different tier to avoid stale artifacts
                cleanModelFiles(tier)

                // Download vocab
                _state.value = DownloadState.Downloading(0, -1)
                downloadVocabFile(tier.vocabUrl, tier.vocabSha256)

                // Download each model artifact
                var totalDownloaded = 0L
                val totalSize = tier.sizeMb.toLong() * 1024 * 1024
                for ((index, artifact) in tier.artifacts.withIndex()) {
                    val targetFile = File(modelsDir, artifact.filename)
                    if (targetFile.exists() && targetFile.length() > 0) {
                        // Already downloaded (e.g., resuming after partial tier download)
                        val actualSha = sha256(targetFile)
                        if (actualSha.equals(artifact.sha256, ignoreCase = true)) {
                            totalDownloaded += targetFile.length()
                            continue
                        }
                        // Hash mismatch — re-download
                        targetFile.delete()
                    }

                    val tmpFile = File(modelsDir, "${artifact.filename}.tmp")
                    var resumeFromByte = if (tmpFile.exists()) tmpFile.length() else 0L
                    var verified = false
                    var verificationError: String? = null

                    for (attempt in 1..2) {
                        _state.value = DownloadState.Downloading(
                            totalDownloaded + resumeFromByte,
                            totalSize
                        )
                        val downloadResult = downloadFile(artifact.url, tmpFile, resumeFromByte) { bytesWritten ->
                            _state.value = DownloadState.Downloading(totalDownloaded + bytesWritten, totalSize)
                        }

                        _state.value = DownloadState.Verifying
                        val actualSha = sha256(tmpFile)
                        if (actualSha.equals(artifact.sha256, ignoreCase = true)) {
                            verified = true
                            break
                        }

                        verificationError = "SHA-256 mismatch for ${artifact.filename}. " +
                            "Expected: ${artifact.sha256.take(12)}... Got: ${actualSha.take(12)}..."

                        if (downloadResult.usedResume && attempt == 1) {
                            Log.w(TAG, "$verificationError Retrying from scratch.")
                            tmpFile.delete()
                            resumeFromByte = 0L
                            continue
                        }

                        tmpFile.delete()
                        _state.value = DownloadState.Error(verificationError)
                        return@launch
                    }

                    if (!verified) {
                        tmpFile.delete()
                        _state.value = DownloadState.Error(verificationError ?: "SHA-256 verification failed.")
                        return@launch
                    }

                    // Atomic rename
                    if (!tmpFile.renameTo(targetFile)) {
                        tmpFile.copyTo(targetFile, overwrite = true)
                        tmpFile.delete()
                    }
                    totalDownloaded += targetFile.length()
                }

                clearVerifiedArtifactsFingerprint()
                verifyInstalledArtifacts()
                _state.value = DownloadState.Complete
            } catch (e: CancellationException) {
                _state.value = DownloadState.Paused
            } catch (e: Exception) {
                _state.value = DownloadState.Error(toUserFacingDownloadError(e))
            }
        }
    }

    /**
     * Legacy single-file download path for backward compatibility and custom URLs.
     */
    private fun startLegacyDownload(
        modelUrl: String,
        vocabUrl: String,
        expectedSha256: String,
        expectedVocabSha256: String
    ) {
        val pinnedModelSha = resolvePinnedModelSha256(modelUrl, expectedSha256)
        if (pinnedModelSha == null) {
            _state.value = DownloadState.Error("Trusted SHA-256 is not configured for the selected ASR model.")
            return
        }
        val pinnedVocabSha = if (vocabUrl.isBlank()) {
            null
        } else {
            resolvePinnedVocabSha256(vocabUrl, expectedVocabSha256)
                ?: run {
                    _state.value = DownloadState.Error("Trusted SHA-256 is not configured for the selected ASR vocabulary.")
                    return
                }
        }

        downloadJob = scope.launch {
            val pm = context.getSystemService(Context.POWER_SERVICE) as PowerManager
            val wakeLock = pm.newWakeLock(
                PowerManager.PARTIAL_WAKE_LOCK,
                "ChartLite::ASRDownload"
            ).apply { acquire(ASR_DOWNLOAD_WAKELOCK_TIMEOUT_MS) }
            val wifiLock = acquireWifiLock("ChartLite::ASRDownloadWifi")

            try {
                if (vocabUrl.isNotBlank()) {
                    _state.value = DownloadState.Downloading(0, -1)
                    downloadVocabFile(vocabUrl, pinnedVocabSha!!)
                }

                if (!modelFile.exists() || modelFile.length() == 0L) {
                    val tmpFile = File(modelsDir, "model.int8.onnx.tmp")
                    var resumeFromByte = if (tmpFile.exists()) tmpFile.length() else 0L
                    var verified = false
                    var verificationError: String? = null

                    for (attempt in 1..2) {
                        _state.value = DownloadState.Downloading(resumeFromByte, -1)
                        val downloadResult = downloadFile(modelUrl, tmpFile, resumeFromByte)

                        _state.value = DownloadState.Verifying
                        val actualSha = sha256(tmpFile)
                        if (actualSha.equals(pinnedModelSha, ignoreCase = true)) {
                            verified = true
                            break
                        }

                        verificationError = "SHA-256 mismatch. Expected: ${pinnedModelSha.take(12)}... Got: ${actualSha.take(12)}..."

                        if (downloadResult.usedResume && attempt == 1) {
                            Log.w(TAG, "$verificationError Retrying from scratch.")
                            tmpFile.delete()
                            resumeFromByte = 0L
                            continue
                        }

                        tmpFile.delete()
                        _state.value = DownloadState.Error(verificationError)
                        return@launch
                    }

                    if (!verified) {
                        tmpFile.delete()
                        _state.value = DownloadState.Error(verificationError ?: "SHA-256 verification failed.")
                        return@launch
                    }

                    if (!tmpFile.renameTo(modelFile)) {
                        tmpFile.copyTo(modelFile, overwrite = true)
                        tmpFile.delete()
                    }
                }

                clearVerifiedArtifactsFingerprint()
                verifyInstalledArtifacts()
                _state.value = DownloadState.Complete
            } catch (e: CancellationException) {
                _state.value = DownloadState.Paused
            } catch (e: Exception) {
                _state.value = DownloadState.Error(toUserFacingDownloadError(e))
            } finally {
                try {
                    if (wifiLock?.isHeld == true) wifiLock.release()
                } catch (_: Exception) {}
                if (wakeLock.isHeld) wakeLock.release()
            }
        }
    }

    fun cancel() {
        downloadJob?.cancel()
        _state.value = DownloadState.Paused
    }

    fun retry(
        modelUrl: String = "",
        vocabUrl: String = "",
        expectedSha256: String = "",
        expectedVocabSha256: String = ""
    ) {
        startDownload(modelUrl, vocabUrl, expectedSha256, expectedVocabSha256)
    }

    fun deleteModel() {
        cancel()
        // Delete all known model artifact filenames
        val knownFiles = ModelTier.entries.flatMap { tier ->
            tier.artifacts.map { it.filename } +
                tier.artifacts.map { "${it.filename}.tmp" }
        }.toSet() + setOf(
            "model.int8.onnx", "model.int8.onnx.tmp",
            "omni_asr.onnx", "omni_asr.onnx.tmp",
            "tokens.txt", "tokens.txt.tmp",
            // Legacy Moonshine v1 files
            "preprocess.onnx", "preprocess.onnx.tmp",
            "encode.int8.onnx", "encode.int8.onnx.tmp",
            "uncached_decode.int8.onnx", "uncached_decode.int8.onnx.tmp",
            "cached_decode.int8.onnx", "cached_decode.int8.onnx.tmp",
            // Legacy files
            "mms_asr.onnx", "mms_asr.onnx.tmp", "vocab.json"
        )
        knownFiles.forEach { File(modelsDir, it).delete() }
        clearVerifiedArtifactsFingerprint()
        _state.value = DownloadState.Idle
    }

    /**
     * Clean up model files that don't belong to the given tier.
     * Called before downloading a new tier to avoid stale artifacts from a different architecture.
     */
    private fun cleanModelFiles(tier: ModelTier) {
        val keepFiles = tier.artifacts.map { it.filename }.toSet() +
            tier.artifacts.map { "${it.filename}.tmp" }.toSet() +
            setOf("tokens.txt", "tokens.txt.tmp", "silero_vad.onnx")

        modelsDir.listFiles()?.forEach { file ->
            if (file.name !in keepFiles && (file.name.endsWith(".onnx") || file.name.endsWith(".onnx.tmp") ||
                    file.name.endsWith(".ort") || file.name.endsWith(".ort.tmp"))) {
                Log.d(TAG, "Cleaning stale model file: ${file.name}")
                file.delete()
            }
        }
    }

    /**
     * Import a single ONNX model file (for CTC / CTC_MEDASR single-file tiers).
     */
    fun importModelFile(sourceFile: File, expectedSha256: String = ""): Boolean {
        if (!sourceFile.exists() || sourceFile.length() == 0L) {
            _state.value = DownloadState.Error("Source model file not found or empty")
            return false
        }

        return try {
            _state.value = DownloadState.Verifying

            val expected = normalizeSha256(expectedSha256)
            if (expected == null) {
                _state.value = DownloadState.Error("Trusted SHA-256 is not configured for the selected ASR model.")
                return false
            }
            val actualSha = sha256(sourceFile)
            if (!actualSha.equals(expected, ignoreCase = true)) {
                _state.value = DownloadState.Error(
                    "SHA-256 mismatch. Expected: ${expected.take(12)}... Got: ${actualSha.take(12)}..."
                )
                return false
            }

            sourceFile.copyTo(modelFile, overwrite = true)
            if (vocabFile.exists()) {
                Log.w(TAG, "Removing existing tokens.txt after model import; import matching vocab next.")
                vocabFile.delete()
            }
            clearVerifiedArtifactsFingerprint()
            _state.value = DownloadState.Paused
            true
        } catch (e: Exception) {
            _state.value = DownloadState.Error("Model import failed: ${e.message}")
            false
        }
    }

    /**
     * Import a directory of model artifacts for multi-file tiers (Moonshine, Transducer).
     *
     * The [sourceDir] should contain all ONNX files required by the tier plus tokens.txt.
     * Each file is verified against the tier's pinned SHA-256.
     *
     * @return true if all artifacts + vocab were imported and verified.
     */
    fun importModelDirectory(sourceDir: File): Boolean {
        if (!sourceDir.exists() || !sourceDir.isDirectory) {
            _state.value = DownloadState.Error("Source directory not found")
            return false
        }

        val tier = configuredTier()
        if (tier == null) {
            _state.value = DownloadState.Error("No ASR tier configured. Select a tier in Settings first.")
            return false
        }

        return try {
            _state.value = DownloadState.Verifying

            // Clean stale files
            cleanModelFiles(tier)

            // Copy and verify each artifact
            for (artifact in tier.artifacts) {
                val srcFile = File(sourceDir, artifact.filename)
                if (!srcFile.exists() || srcFile.length() == 0L) {
                    _state.value = DownloadState.Error(
                        "Missing artifact: ${artifact.filename}. " +
                            "The ${tier.label} tier requires ${tier.artifacts.size} model files."
                    )
                    return false
                }
                val expectedSha = normalizeSha256(artifact.sha256)
                if (expectedSha == null) {
                    _state.value = DownloadState.Error("No pinned SHA-256 for ${artifact.filename}")
                    return false
                }
                val actualSha = sha256(srcFile)
                if (!actualSha.equals(expectedSha, ignoreCase = true)) {
                    _state.value = DownloadState.Error(
                        "SHA-256 mismatch for ${artifact.filename}. " +
                            "Expected: ${expectedSha.take(12)}... Got: ${actualSha.take(12)}..."
                    )
                    return false
                }
                srcFile.copyTo(File(modelsDir, artifact.filename), overwrite = true)
            }

            // Copy and verify vocab
            val srcVocab = File(sourceDir, "tokens.txt")
            if (srcVocab.exists() && srcVocab.length() > 0) {
                val expectedVocabSha = normalizeSha256(tier.vocabSha256)
                if (expectedVocabSha != null) {
                    val actualVocabSha = sha256(srcVocab)
                    if (!actualVocabSha.equals(expectedVocabSha, ignoreCase = true)) {
                        _state.value = DownloadState.Error(
                            "Vocabulary SHA-256 mismatch. " +
                                "Expected: ${expectedVocabSha.take(12)}... Got: ${actualVocabSha.take(12)}..."
                        )
                        return false
                    }
                    srcVocab.copyTo(vocabFile, overwrite = true)
                }
            }

            clearVerifiedArtifactsFingerprint()
            _state.value = if (isReady()) DownloadState.Complete else DownloadState.Paused
            true
        } catch (e: Exception) {
            _state.value = DownloadState.Error("Directory import failed: ${e.message}")
            false
        }
    }

    /**
     * Whether the configured tier requires multi-file import (Moonshine / Transducer).
     */
    fun isMultiFileTier(): Boolean {
        val tier = configuredTier() ?: return false
        return tier.artifacts.size > 1
    }

    /**
     * List of artifact filenames required by the configured tier.
     */
    fun requiredArtifactFilenames(): List<String> {
        val tier = configuredTier() ?: return listOf("model.int8.onnx")
        return tier.artifacts.map { it.filename }
    }

    fun importVocabFile(sourceFile: File, expectedSha256: String = ""): Boolean {
        if (!sourceFile.exists() || sourceFile.length() == 0L) {
            _state.value = DownloadState.Error("Source vocabulary file not found or empty")
            return false
        }

        return try {
            _state.value = DownloadState.Verifying
            val expected = normalizeSha256(expectedSha256)
            if (expected == null) {
                _state.value = DownloadState.Error("Trusted SHA-256 is not configured for the selected ASR vocabulary.")
                return false
            }
            val actualSha = sha256(sourceFile)
            if (!actualSha.equals(expected, ignoreCase = true)) {
                _state.value = DownloadState.Error(
                    "SHA-256 mismatch. Expected: ${expected.take(12)}... Got: ${actualSha.take(12)}..."
                )
                return false
            }
            sourceFile.copyTo(vocabFile, overwrite = true)
            clearVerifiedArtifactsFingerprint()
            _state.value = if (isReady()) DownloadState.Complete else DownloadState.Paused
            true
        } catch (e: Exception) {
            _state.value = DownloadState.Error("Vocab import failed: ${e.message}")
            false
        }
    }

    fun importFromFile(
        sourceFile: File,
        expectedSha256: String = "",
        expectedVocabSha256: String = ""
    ): Boolean {
        val importedModel = importModelFile(sourceFile, expectedSha256)
        if (!importedModel) return false

        return try {
            val vocabSource = File(sourceFile.parent, "tokens.txt")
            val legacyVocab = File(sourceFile.parent, "vocab.json")
            val actualVocab = when {
                vocabSource.exists() -> vocabSource
                legacyVocab.exists() -> legacyVocab
                else -> null
            }
            actualVocab?.let { importVocabFile(it, expectedVocabSha256) }
            _state.value = if (isReady()) DownloadState.Complete else DownloadState.Paused
            true
        } catch (e: Exception) {
            _state.value = DownloadState.Error("Import failed: ${e.message}")
            false
        }
    }

    fun refreshState() {
        _state.value = when {
            isModelDownloaded() && isVocabDownloaded() -> {
                try {
                    verifyInstalledArtifacts()
                    DownloadState.Complete
                } catch (e: IllegalStateException) {
                    DownloadState.Error(e.message ?: "Offline ASR verification failed")
                }
            }
            hasTmpFiles() -> DownloadState.Paused
            else -> {
                // Auto-detect sideloaded ASR model on external storage / microSD
                val sideloadDir = scanExternalStorageForModel()
                if (sideloadDir != null) {
                    Log.i(TAG, "Found sideloaded ASR model: ${sideloadDir.absolutePath}")
                    scope.launch(Dispatchers.IO) {
                        importModelDirectory(sideloadDir)
                    }
                    DownloadState.Verifying
                } else {
                    DownloadState.Idle
                }
            }
        }
    }

    /**
     * Scan external storage (microSD, USB OTG) for sideloaded ASR model files.
     *
     * For LMIC zero-connectivity deployments, models can be pre-loaded onto a microSD card.
     * Place model files at: `<sdcard>/Android/data/com.chartlite.app/files/chartlite/`
     *
     * For multi-file tiers (Moonshine, Transducer), all artifacts + tokens.txt must be present.
     * For single-file tiers, the ONNX file + tokens.txt must be present.
     *
     * Uses scoped storage ([Context.getExternalFilesDirs]) — no extra permissions needed.
     */
    fun scanExternalStorageForModel(): File? {
        val tier = configuredTier() ?: return null
        val allDirs = context.getExternalFilesDirs(null) ?: return null
        val externalDirs = allDirs.filterNotNull().drop(1)
        if (externalDirs.isEmpty()) return null

        for (dir in externalDirs) {
            val chartliteDir = File(dir, "chartlite")
            if (!chartliteDir.isDirectory) continue

            // Check if all required artifacts are present
            val allPresent = tier.artifacts.all { artifact ->
                File(chartliteDir, artifact.filename).let { it.exists() && it.length() > 0 }
            }
            if (allPresent) {
                Log.d(TAG, "Sideloaded ASR model found at: ${chartliteDir.absolutePath} (${tier.artifacts.size} artifacts)")
                return chartliteDir
            }
        }
        return null
    }

    private fun hasTmpFiles(): Boolean {
        return modelsDir.listFiles()?.any { it.name.endsWith(".tmp") } ?: false
    }

    private suspend fun downloadVocabFile(url: String, expectedSha256: String) {
        val tmpVocab = File(modelsDir, "tokens.txt.tmp")
        if (tmpVocab.exists()) tmpVocab.delete()

        downloadFile(url, tmpVocab, null)
        if (!tmpVocab.exists() || tmpVocab.length() <= 0L) {
            throw Exception("Downloaded vocabulary is empty")
        }
        val actualSha = sha256(tmpVocab)
        if (!actualSha.equals(expectedSha256, ignoreCase = true)) {
            tmpVocab.delete()
            throw Exception(
                "Vocabulary SHA-256 mismatch. Expected: ${expectedSha256.take(12)}... Got: ${actualSha.take(12)}..."
            )
        }

        if (!tmpVocab.renameTo(vocabFile)) {
            tmpVocab.copyTo(vocabFile, overwrite = true)
            tmpVocab.delete()
        }
        clearVerifiedArtifactsFingerprint()
    }

    private suspend fun downloadFile(
        url: String,
        targetFile: File,
        resumeFromByte: Long?,
        onProgress: ((Long) -> Unit)? = null
    ): DownloadResult {
        val requestBuilder = Request.Builder().url(url)

        val startByte = resumeFromByte ?: 0L
        if (startByte > 0) {
            requestBuilder.addHeader("Range", "bytes=$startByte-")
        }

        client.newCall(requestBuilder.build()).execute().use { response ->
            if (!response.isSuccessful && response.code != 206) {
                throw Exception("HTTP ${response.code}: ${response.message}")
            }

            val body = response.body ?: throw Exception("Empty response body")
            val contentLength = body.contentLength()
            val usedResume = startByte > 0 && response.code == 206
            val totalBytes = if (contentLength > 0) {
                if (usedResume) contentLength + startByte else contentLength
            } else -1L

            val outputStream = if (usedResume) {
                FileOutputStream(targetFile, true)
            } else {
                FileOutputStream(targetFile)
            }

            var bytesWritten = if (usedResume) startByte else 0L
            val buffer = ByteArray(8192)
            var lastUpdateTime = 0L

            body.byteStream().use { input ->
                outputStream.use { output ->
                    while (true) {
                        yield()

                        val read = input.read(buffer)
                        if (read == -1) break

                        output.write(buffer, 0, read)
                        bytesWritten += read

                        val now = System.currentTimeMillis()
                        if (now - lastUpdateTime >= 500) {
                            if (onProgress != null) {
                                onProgress(bytesWritten)
                            } else {
                                _state.value = DownloadState.Downloading(bytesWritten, totalBytes)
                            }
                            lastUpdateTime = now
                        }
                    }
                }
            }
            // Always emit final progress
            if (onProgress != null) {
                onProgress(bytesWritten)
            } else {
                _state.value = DownloadState.Downloading(bytesWritten, totalBytes)
            }
            return DownloadResult(usedResume = usedResume)
        }
    }

    // ── Hardware detection & tier recommendation ──

    /**
     * Model tiers with multi-file artifact support.
     *
     * Each tier defines its architecture, downloadable artifacts (with pinned SHA-256),
     * vocab file, and hardware recommendations.
     */
    enum class ModelTier(
        val label: String,
        val architecture: ModelArchitecture,
        val artifacts: List<ModelArtifact>,
        val vocabUrl: String,
        val vocabSha256: String,
        val sizeMb: Int,
        val description: String
    ) {
        MOONSHINE_TINY(
            label = "Moonshine Tiny v2 (English)",
            architecture = ModelArchitecture.MOONSHINE_V2,
            artifacts = listOf(
                ModelArtifact("encoder_model.ort", AppConfig.MOONSHINE_TINY_ENCODER_URL, AppConfig.MOONSHINE_TINY_ENCODER_SHA256),
                ModelArtifact("decoder_model_merged.ort", AppConfig.MOONSHINE_TINY_DECODER_URL, AppConfig.MOONSHINE_TINY_DECODER_SHA256),
            ),
            vocabUrl = AppConfig.MOONSHINE_TINY_VOCAB_URL,
            vocabSha256 = AppConfig.MOONSHINE_TINY_VOCAB_SHA256,
            sizeMb = 43,
            description = "Ultra-light English ASR (43 MB). Streaming support. Fast on low-RAM devices."
        ),
        MOONSHINE_BASE(
            label = "Moonshine Base v2 (English)",
            architecture = ModelArchitecture.MOONSHINE_V2,
            artifacts = listOf(
                ModelArtifact("encoder_model.ort", AppConfig.MOONSHINE_BASE_ENCODER_URL, AppConfig.MOONSHINE_BASE_ENCODER_SHA256),
                ModelArtifact("decoder_model_merged.ort", AppConfig.MOONSHINE_BASE_DECODER_URL, AppConfig.MOONSHINE_BASE_DECODER_SHA256),
            ),
            vocabUrl = AppConfig.MOONSHINE_BASE_VOCAB_URL,
            vocabSha256 = AppConfig.MOONSHINE_BASE_VOCAB_SHA256,
            sizeMb = 140,
            description = "English ASR with ~7.4% WER. Good accuracy-to-size ratio."
        ),
        MEDICAL_ENGLISH(
            label = "medASR English (medical)",
            architecture = ModelArchitecture.CTC_MEDASR,
            artifacts = listOf(
                ModelArtifact("model.int8.onnx", AppConfig.DEFAULT_MEDASR_EN_MODEL_URL, AppConfig.DEFAULT_MEDASR_EN_MODEL_SHA256),
            ),
            vocabUrl = AppConfig.DEFAULT_MEDASR_EN_VOCAB_URL,
            vocabSha256 = AppConfig.DEFAULT_MEDASR_EN_VOCAB_SHA256,
            sizeMb = 154,
            description = "English medical ASR with low medical WER. English-only."
        ),
        LITE(
            label = "Omnilingual 300M (1600+ langs)",
            architecture = ModelArchitecture.CTC,
            artifacts = listOf(
                ModelArtifact("model.int8.onnx", AppConfig.DEFAULT_MODEL_URL, AppConfig.DEFAULT_MODEL_SHA256),
            ),
            vocabUrl = AppConfig.DEFAULT_VOCAB_URL,
            vocabSha256 = AppConfig.DEFAULT_VOCAB_SHA256,
            sizeMb = 365,
            description = "1600+ languages, 300M params INT8. Good for 2-4 GB RAM devices."
        ),
        SENSE_VOICE(
            label = "SenseVoice Small (ZH/EN/JA/KO/YUE)",
            architecture = ModelArchitecture.SENSE_VOICE,
            artifacts = listOf(
                ModelArtifact("model.int8.onnx", AppConfig.SENSE_VOICE_MODEL_URL, AppConfig.SENSE_VOICE_MODEL_SHA256),
            ),
            vocabUrl = AppConfig.SENSE_VOICE_VOCAB_URL,
            vocabSha256 = AppConfig.SENSE_VOICE_VOCAB_SHA256,
            sizeMb = 239,
            description = "Chinese, English, Japanese, Korean, Cantonese. Optimized for CJK."
        ),
        PARAKEET_EN(
            label = "Parakeet TDT v3 (English + EU)",
            architecture = ModelArchitecture.TRANSDUCER,
            artifacts = listOf(
                ModelArtifact("encoder.int8.onnx", AppConfig.PARAKEET_EN_ENCODER_URL, AppConfig.PARAKEET_EN_ENCODER_SHA256),
                ModelArtifact("decoder.int8.onnx", AppConfig.PARAKEET_EN_DECODER_URL, AppConfig.PARAKEET_EN_DECODER_SHA256),
                ModelArtifact("joiner.int8.onnx", AppConfig.PARAKEET_EN_JOINER_URL, AppConfig.PARAKEET_EN_JOINER_SHA256),
            ),
            vocabUrl = AppConfig.PARAKEET_EN_VOCAB_URL,
            vocabSha256 = AppConfig.PARAKEET_EN_VOCAB_SHA256,
            sizeMb = 671,
            description = "Best English accuracy + 25 EU languages. Auto-punctuation. Needs 4+ GB RAM."
        ),
        STANDARD(
            label = "Omnilingual 1B (1600+ langs)",
            architecture = ModelArchitecture.CTC,
            artifacts = listOf(
                ModelArtifact("model.int8.onnx", AppConfig.DEFAULT_STANDARD_MODEL_URL, AppConfig.DEFAULT_STANDARD_MODEL_SHA256),
            ),
            vocabUrl = AppConfig.DEFAULT_STANDARD_VOCAB_URL,
            vocabSha256 = AppConfig.DEFAULT_STANDARD_VOCAB_SHA256,
            sizeMb = 1030,
            description = "1600+ languages, 1B params INT8. Higher accuracy, needs 4+ GB RAM."
        );

        val isDownloadable: Boolean get() = artifacts.all { it.url.isNotBlank() } && vocabUrl.isNotBlank()
        val isTrusted: Boolean get() = artifacts.all { it.sha256.isNotBlank() } && vocabSha256.isNotBlank()

        /** Non-technical display name for simplified UI (e.g., setup wizard). */
        val friendlyName: String get() = when (this) {
            MOONSHINE_TINY -> "Voice Tiny"
            MOONSHINE_BASE -> "Voice Standard"
            MEDICAL_ENGLISH -> "Medical English"
            LITE -> "Multilingual (300M)"
            SENSE_VOICE -> "CJK Languages"
            PARAKEET_EN -> "English HD"
            STANDARD -> "Multilingual (1B)"
        }

        // Backward-compatible accessors for SettingsScreen and AppConfig matching
        val modelUrl: String get() = artifacts.firstOrNull()?.url ?: ""
        val modelSha256: String get() = artifacts.firstOrNull()?.sha256 ?: ""
    }

    /**
     * A model tier ranked for a specific device and language.
     */
    data class RankedTier(
        val tier: ModelTier,
        val rank: Int,
        val isCompatible: Boolean,
        val reason: String
    )

    /**
     * Rank all model tiers for the current device and language.
     * Returns all tiers sorted: compatible ranked first, then incompatible.
     */
    fun rankTiersForDevice(language: String): List<RankedTier> {
        val ramGb = deviceRamGb()
        val langLower = language.trim().lowercase()
        val isEnglish = langLower.startsWith("en")
        val isCjk = langLower.startsWith("zh") || langLower.startsWith("ja") ||
            langLower.startsWith("ko") || langLower.startsWith("yue")

        data class ScoredTier(
            val tier: ModelTier,
            val score: Int,
            val compatible: Boolean,
            val reason: String
        )

        val scored = ModelTier.entries.map { tier ->
            val minRamGb = when (tier) {
                ModelTier.MOONSHINE_TINY -> 1.0
                ModelTier.MOONSHINE_BASE -> 2.0
                ModelTier.MEDICAL_ENGLISH -> 2.0
                ModelTier.LITE -> 2.0
                ModelTier.SENSE_VOICE -> 3.0
                ModelTier.PARAKEET_EN -> 4.0
                ModelTier.STANDARD -> 4.0
            }
            val compatible = ramGb >= minRamGb

            // Score: higher = better fit. Language match is most important.
            var score = 0
            var reason = ""

            // Language fit (0-100)
            when (tier) {
                ModelTier.MOONSHINE_TINY, ModelTier.MOONSHINE_BASE,
                ModelTier.MEDICAL_ENGLISH, ModelTier.PARAKEET_EN -> {
                    if (isEnglish) { score += 80; reason = "English" }
                    else { score -= 100; reason = "English-only" }
                }
                ModelTier.SENSE_VOICE -> {
                    if (isCjk) { score += 90; reason = "CJK optimized" }
                    else if (isEnglish) { score += 40; reason = "Supports English" }
                    else { score -= 50; reason = "ZH/EN/JA/KO/YUE only" }
                }
                ModelTier.LITE, ModelTier.STANDARD -> {
                    if (!isEnglish) { score += 70; reason = "1600+ languages" }
                    else { score += 30; reason = "Multilingual" }
                }
            }

            // Accuracy bonus (0-50)
            score += when (tier) {
                ModelTier.PARAKEET_EN -> 50   // 1.69% WER
                ModelTier.STANDARD -> 35      // Best multilingual
                ModelTier.MEDICAL_ENGLISH -> 40 // Low medical WER
                ModelTier.MOONSHINE_BASE -> 30  // ~7.4% WER
                ModelTier.SENSE_VOICE -> 35    // Good CJK accuracy
                ModelTier.LITE -> 20           // Decent
                ModelTier.MOONSHINE_TINY -> 10  // ~12% WER
            }

            // Size efficiency bonus (smaller is better for constrained devices)
            if (ramGb < 3.0) {
                score += when {
                    tier.sizeMb <= 50 -> 20
                    tier.sizeMb <= 160 -> 10
                    else -> 0
                }
            }

            // Incompatible penalty
            if (!compatible) {
                reason = "Requires ${minRamGb.toInt()}+ GB RAM"
            }

            ScoredTier(tier, score, compatible, reason)
        }

        // Sort: compatible first (by score desc), then incompatible (by score desc)
        val sorted = scored.sortedWith(
            compareByDescending<ScoredTier> { it.compatible }
                .thenByDescending { it.score }
        )

        return sorted.mapIndexed { index, st ->
            val rank = if (st.compatible) {
                sorted.take(index + 1).count { it.compatible }
            } else {
                sorted.count { it.compatible } + sorted.drop(sorted.count { it.compatible }).take(index - sorted.count { it.compatible } + 1).size
            }
            RankedTier(st.tier, rank, st.compatible, st.reason)
        }
    }

    fun recommendedTier(): ModelTier {
        return rankTiersForDevice(appConfig.language).firstOrNull { it.isCompatible }?.tier
            ?: ModelTier.MOONSHINE_TINY
    }

    fun deviceRamGb(): Double {
        val am = context.getSystemService(Context.ACTIVITY_SERVICE) as ActivityManager
        val memInfo = ActivityManager.MemoryInfo()
        am.getMemoryInfo(memInfo)
        return memInfo.totalMem / (1024.0 * 1024.0 * 1024.0)
    }

    fun deviceName(): String = "${Build.MANUFACTURER} ${Build.MODEL}"

    fun defaultTierForLanguage(language: String, nonEnglishTier: ModelTier = recommendedTier()): ModelTier {
        return rankTiersForDevice(language).firstOrNull { it.isCompatible }?.tier
            ?: ModelTier.MOONSHINE_TINY
    }

    private fun sha256(file: File): String {
        val digest = MessageDigest.getInstance("SHA-256")
        file.inputStream().use { input ->
            val buffer = ByteArray(8192)
            var read: Int
            while (input.read(buffer).also { read = it } != -1) {
                digest.update(buffer, 0, read)
            }
        }
        return digest.digest().joinToString("") { "%02x".format(it) }
    }

    private fun resolvePinnedModelSha256(modelUrl: String, configuredSha: String): String? {
        return normalizeSha256(configuredSha)
            ?: modelTierForModelUrl(modelUrl)?.modelSha256?.let(::normalizeSha256)
    }

    private fun resolvePinnedVocabSha256(vocabUrl: String, configuredSha: String): String? {
        return normalizeSha256(configuredSha)
            ?: modelTierForVocabUrl(vocabUrl)?.vocabSha256?.let(::normalizeSha256)
    }

    private fun modelTierForModelUrl(modelUrl: String): ModelTier? =
        ModelTier.entries.firstOrNull { it.modelUrl == modelUrl.trim() && it.isTrusted }

    private fun modelTierForVocabUrl(vocabUrl: String): ModelTier? =
        ModelTier.entries.firstOrNull { it.vocabUrl == vocabUrl.trim() && it.isTrusted }

    fun configuredTier(): ModelTier? {
        return ModelTier.entries.firstOrNull {
            it.modelUrl == appConfig.modelDownloadUrl.trim() &&
                it.vocabUrl == appConfig.vocabDownloadUrl.trim() &&
                it.isTrusted
        }
    }

    private fun normalizeSha256(raw: String): String? {
        val cleaned = raw.trim().lowercase()
        return if (Regex("^[a-f0-9]{64}$").matches(cleaned)) cleaned else null
    }

    private fun verifyInstalledArtifacts() {
        if (!isModelDownloaded() || !isVocabDownloaded()) {
            throw IllegalStateException("Offline ASR files are incomplete.")
        }
        val tier = configuredTier()
            ?: throw IllegalStateException("Trusted ASR tier is not configured. Select one of the built-in speech tiers.")

        // Build fingerprint from all artifacts
        val fingerprint = buildString {
            append(tier.name)
            for (artifact in tier.artifacts) {
                val file = File(modelsDir, artifact.filename)
                append(':')
                append(file.absolutePath)
                append(':')
                append(file.length())
                append(':')
                append(file.lastModified())
            }
            append(':')
            append(vocabFile.absolutePath)
            append(':')
            append(vocabFile.length())
            append(':')
            append(vocabFile.lastModified())
        }
        if (verifiedArtifactsFingerprint == fingerprint) return

        // Verify each artifact
        for (artifact in tier.artifacts) {
            val file = File(modelsDir, artifact.filename)
            val expectedSha = normalizeSha256(artifact.sha256)
                ?: throw IllegalStateException("Trusted SHA-256 is not configured for ${artifact.filename}.")
            val actualSha = sha256(file)
            if (!actualSha.equals(expectedSha, ignoreCase = true)) {
                throw IllegalStateException(
                    "Installed ${artifact.filename} does not match the trusted release file. Re-download or re-import it."
                )
            }
        }

        // Verify vocab
        val expectedVocabSha = normalizeSha256(tier.vocabSha256)
            ?: throw IllegalStateException("Trusted SHA-256 is not configured for the selected ASR vocabulary.")
        val actualVocabSha = sha256(vocabFile)
        if (!actualVocabSha.equals(expectedVocabSha, ignoreCase = true)) {
            throw IllegalStateException(
                "Installed ASR vocabulary does not match the trusted release file. Re-download or re-import tokens.txt."
            )
        }

        verifiedArtifactsFingerprint = fingerprint
    }

    private fun clearVerifiedArtifactsFingerprint() {
        verifiedArtifactsFingerprint = null
    }

    private fun toUserFacingDownloadError(e: Exception): String {
        val raw = e.message?.trim().orEmpty()
        val lowered = raw.lowercase()
        return when {
            lowered.contains("software caused connection abort") ||
                lowered.contains("connection reset") ||
                lowered.contains("stream was reset") ||
                lowered.contains("unexpected end of stream") ||
                lowered.contains("timeout") -> {
                "Connection dropped during download (often when phone sleeps). Keep screen on and tap Retry to resume."
            }
            raw.isNotBlank() -> raw
            else -> "Download failed"
        }
    }

    private fun acquireWifiLock(tag: String): WifiManager.WifiLock? {
        return try {
            val wifiManager = context.applicationContext.getSystemService(Context.WIFI_SERVICE) as? WifiManager
                ?: return null
            val lock = runCatching {
                wifiManager.createWifiLock(WifiManager.WIFI_MODE_FULL_HIGH_PERF, tag)
            }.getOrElse {
                wifiManager.createWifiLock(WifiManager.WIFI_MODE_FULL, tag)
            }
            lock.setReferenceCounted(false)
            lock.acquire()
            lock
        } catch (e: Exception) {
            Log.w(TAG, "Unable to acquire Wi-Fi lock for ASR download", e)
            null
        }
    }

    companion object {
        private const val TAG = "ModelDownloader"
        private const val ASR_DOWNLOAD_WAKELOCK_TIMEOUT_MS = 6L * 60L * 60L * 1000L
    }
}
