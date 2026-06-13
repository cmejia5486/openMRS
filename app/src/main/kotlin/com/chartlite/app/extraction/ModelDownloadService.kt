package com.chartlite.app.extraction

import android.app.Notification
import android.app.NotificationChannel
import android.app.NotificationManager
import android.app.Service
import android.content.Context
import android.content.Intent
import android.content.pm.ServiceInfo
import android.os.Build
import android.os.IBinder
import android.util.Log
import com.chartlite.app.App
import com.chartlite.app.asr.ModelDownloader
import kotlinx.coroutines.*
import kotlinx.coroutines.flow.collectLatest
import kotlinx.coroutines.flow.combine

/**
 * Foreground service that keeps model downloads alive when the screen is off.
 *
 * Without a foreground service, Android Doze mode can suspend OkHttp downloads
 * even with a PARTIAL_WAKE_LOCK. This service shows a persistent notification
 * with download progress and self-stops when all downloads finish.
 *
 * Usage:
 *   ModelDownloadService.start(context, "both")  // "asr", "llm", or "both"
 *
 * The actual download logic remains in ModelDownloader / LlmModelManager —
 * this service only keeps the process alive and updates the notification.
 */
class ModelDownloadService : Service() {

    private val scope = CoroutineScope(SupervisorJob() + Dispatchers.IO)
    private var progressJob: Job? = null

    override fun onBind(intent: Intent?): IBinder? = null

    override fun onCreate() {
        super.onCreate()
        createNotificationChannel()
    }

    override fun onStartCommand(intent: Intent?, flags: Int, startId: Int): Int {
        if (intent?.action == ACTION_STOP) {
            Log.d(TAG, "Received stop action")
            stopSelf()
            return START_NOT_STICKY
        }

        val downloadType = intent?.getStringExtra(EXTRA_DOWNLOAD_TYPE) ?: "both"
        Log.d(TAG, "Starting download service: type=$downloadType")

        val notification = buildNotification("Preparing download…", -1, -1)
        if (Build.VERSION.SDK_INT >= Build.VERSION_CODES.UPSIDE_DOWN_CAKE) {
            startForeground(NOTIFICATION_ID, notification, ServiceInfo.FOREGROUND_SERVICE_TYPE_DATA_SYNC)
        } else {
            startForeground(NOTIFICATION_ID, notification)
        }

        val app = application as App

        // Start the requested downloads (they're no-ops if already running)
        when (downloadType) {
            "asr" -> startAsrDownload(app)
            "llm" -> app.llmModelManager.startDownload()
            "both" -> {
                startAsrDownload(app)
                // LLM will be chained after ASR completes (handled by caller's coroutine)
            }
        }

        // Observe progress and update notification
        progressJob?.cancel()
        progressJob = scope.launch {
            val nm = getSystemService(NotificationManager::class.java)
            var lastUpdateMs = 0L

            combine(
                app.asr.modelDownloader.state,
                app.llmModelManager.state
            ) { asrState, llmState -> asrState to llmState }
                .collectLatest { (asrState, llmState) ->
                    // Throttle notification updates to 1/sec
                    val now = System.currentTimeMillis()
                    if (now - lastUpdateMs < 1000 && !isTerminalState(asrState, llmState)) return@collectLatest
                    lastUpdateMs = now

                    val (text, downloaded, total) = buildProgressText(asrState, llmState)
                    nm.notify(NOTIFICATION_ID, buildNotification(text, downloaded, total))

                    if (isTerminalState(asrState, llmState)) {
                        // Give the notification a moment to show final state
                        delay(2000)
                        stopSelf()
                    }
                }
        }

        return START_STICKY
    }

    override fun onDestroy() {
        Log.d(TAG, "ModelDownloadService destroyed")
        progressJob?.cancel()
        scope.cancel()
        super.onDestroy()
    }

    private fun startAsrDownload(app: App) {
        val config = app.appConfig
        app.asr.modelDownloader.startDownload(
            expectedSha256 = config.modelExpectedSha256,
            expectedVocabSha256 = config.vocabExpectedSha256
        )
    }

    // ── Notification ──

    private fun createNotificationChannel() {
        val channel = NotificationChannel(
            CHANNEL_ID,
            "Model Downloads",
            NotificationManager.IMPORTANCE_LOW
        ).apply {
            description = "AI model download progress"
            setShowBadge(false)
        }
        val nm = getSystemService(NotificationManager::class.java)
        nm.createNotificationChannel(channel)
    }

    private fun buildNotification(text: String, downloaded: Long, total: Long): Notification {
        val builder = Notification.Builder(this, CHANNEL_ID)
            .setContentTitle("ChartLite")
            .setContentText(text)
            .setSmallIcon(android.R.drawable.stat_sys_download)
            .setOngoing(true)

        if (total > 0 && downloaded >= 0) {
            val progress = ((downloaded * 100) / total).toInt().coerceIn(0, 100)
            builder.setProgress(100, progress, false)
        } else if (downloaded >= 0 && total < 0) {
            builder.setProgress(0, 0, true) // indeterminate
        }

        return builder.build()
    }

    // ── Progress helpers ──

    private data class ProgressInfo(val text: String, val downloaded: Long, val total: Long)

    private fun buildProgressText(
        asrState: ModelDownloader.DownloadState,
        llmState: LlmModelManager.ModelState
    ): ProgressInfo {
        // ASR downloading
        if (asrState is ModelDownloader.DownloadState.Downloading) {
            val mb = asrState.bytesDownloaded / (1024 * 1024)
            val totalMb = if (asrState.totalBytes > 0) asrState.totalBytes / (1024 * 1024) else -1L
            val text = if (totalMb > 0) "Downloading ASR model… ${mb}/${totalMb} MB" else "Downloading ASR model… ${mb} MB"
            return ProgressInfo(text, asrState.bytesDownloaded, asrState.totalBytes)
        }
        if (asrState is ModelDownloader.DownloadState.Verifying) {
            return ProgressInfo("Verifying ASR model…", -1, -1)
        }

        // LLM downloading
        if (llmState is LlmModelManager.ModelState.Downloading) {
            val mb = llmState.bytesDownloaded / (1024 * 1024)
            val totalMb = if (llmState.totalBytes > 0) llmState.totalBytes / (1024 * 1024) else -1L
            val text = if (totalMb > 0) "Downloading LLM model… ${mb}/${totalMb} MB" else "Downloading LLM model… ${mb} MB"
            return ProgressInfo(text, llmState.bytesDownloaded, llmState.totalBytes)
        }
        if (llmState is LlmModelManager.ModelState.Verifying) {
            return ProgressInfo("Verifying LLM model…", -1, -1)
        }
        if (llmState is LlmModelManager.ModelState.Installing) {
            val mb = llmState.bytesProcessed / (1024 * 1024)
            val totalMb = if (llmState.totalBytes > 0) llmState.totalBytes / (1024 * 1024) else -1L
            val text = if (totalMb > 0) "Installing LLM model… ${mb}/${totalMb} MB" else "Installing LLM model… ${mb} MB"
            return ProgressInfo(text, llmState.bytesProcessed, llmState.totalBytes)
        }

        // Terminal states
        val asrDone = asrState is ModelDownloader.DownloadState.Complete || asrState is ModelDownloader.DownloadState.Idle
        val llmDone = llmState is LlmModelManager.ModelState.Ready
        val asrErr = asrState is ModelDownloader.DownloadState.Error
        val llmErr = llmState is LlmModelManager.ModelState.Error

        return when {
            asrErr || llmErr -> ProgressInfo("Download failed", -1, -1)
            asrDone && llmDone -> ProgressInfo("All models ready", -1, -1)
            else -> ProgressInfo("Preparing download…", -1, -1)
        }
    }

    private fun isTerminalState(
        asrState: ModelDownloader.DownloadState,
        llmState: LlmModelManager.ModelState
    ): Boolean {
        val asrTerminal = asrState is ModelDownloader.DownloadState.Complete ||
            asrState is ModelDownloader.DownloadState.Idle ||
            asrState is ModelDownloader.DownloadState.Error
        val llmTerminal = llmState is LlmModelManager.ModelState.Ready ||
            llmState is LlmModelManager.ModelState.NotDownloaded ||
            llmState is LlmModelManager.ModelState.Error
        return asrTerminal && llmTerminal
    }

    companion object {
        private const val TAG = "ModelDownloadService"
        private const val CHANNEL_ID = "model_download"
        private const val NOTIFICATION_ID = 9002
        const val ACTION_STOP = "com.chartlite.app.extraction.STOP_DOWNLOAD"
        const val EXTRA_DOWNLOAD_TYPE = "download_type"

        fun start(context: Context, downloadType: String = "both") {
            val intent = Intent(context, ModelDownloadService::class.java)
                .putExtra(EXTRA_DOWNLOAD_TYPE, downloadType)
            context.startForegroundService(intent)
        }

        fun stop(context: Context) {
            val intent = Intent(context, ModelDownloadService::class.java).apply {
                action = ACTION_STOP
            }
            context.startService(intent)
        }
    }
}
