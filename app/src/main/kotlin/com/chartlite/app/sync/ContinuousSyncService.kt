package com.chartlite.app.sync

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
import kotlinx.coroutines.*
import kotlinx.coroutines.flow.collectLatest

/**
 * Foreground service that maintains continuous P2P sync between clinic stations.
 *
 * When running:
 * 1. Advertises + discovers peers using facility-scoped service ID
 * 2. Auto-accepts connections from same-facility devices
 * 3. Watches local DB for changes via SyncTrigger (Room InvalidationTracker)
 * 4. On any local change, pushes a delta to all connected peers
 * 5. On receiving data from peers, merges it (with trigger suppressed to prevent echo)
 * 6. Shows persistent notification with connected device count
 * 7. Auto-reconnects on disconnect
 */
class ContinuousSyncService : Service() {

    private val scope = CoroutineScope(SupervisorJob() + Dispatchers.IO)
    private var syncTrigger: SyncTrigger? = null
    private var peerCountJob: Job? = null

    override fun onBind(intent: Intent?): IBinder? = null

    override fun onCreate() {
        super.onCreate()
        Log.d(TAG, "ContinuousSyncService created")
        createNotificationChannel()
    }

    override fun onStartCommand(intent: Intent?, flags: Int, startId: Int): Int {
        when (intent?.action) {
            ACTION_STOP -> {
                Log.d(TAG, "Received stop action")
                stopSelf()
                return START_NOT_STICKY
            }
        }

        val app = application as App
        val syncEngine = app.syncEngine
        val facilityId = app.appConfig.facilityId

        if (facilityId.isBlank()) {
            Log.w(TAG, "No facility ID configured, stopping service")
            stopSelf()
            return START_NOT_STICKY
        }

        // Start as foreground service
        val notification = buildNotification(0)
        if (Build.VERSION.SDK_INT >= Build.VERSION_CODES.UPSIDE_DOWN_CAKE) {
            startForeground(NOTIFICATION_ID, notification, ServiceInfo.FOREGROUND_SERVICE_TYPE_CONNECTED_DEVICE)
        } else {
            startForeground(NOTIFICATION_ID, notification)
        }

        // Configure sync engine for continuous mode
        syncEngine.autoAcceptConnections = true

        // Start discovery with facility-scoped service ID
        syncEngine.startDiscovery(facilityId)
        Log.d(TAG, "Started continuous sync for facility: ${facilityId.take(8)}")

        // Set up SyncTrigger to watch for local DB changes
        syncTrigger = SyncTrigger(
            database = app.database,
            debounceMs = 500L,
            scope = scope,
            onTriggered = {
                if (!syncEngine.suppressTrigger) {
                    scope.launch {
                        Log.d(TAG, "Local DB change detected, pushing delta")
                        syncEngine.pushDelta()
                    }
                }
            }
        ).also { it.start() }

        // Observe connected peer count to update notification
        peerCountJob?.cancel()
        peerCountJob = scope.launch {
            syncEngine.connectedEndpoints.collectLatest { endpoints ->
                val notification = buildNotification(endpoints.size)
                val nm = getSystemService(NotificationManager::class.java)
                nm.notify(NOTIFICATION_ID, notification)
            }
        }

        return START_STICKY
    }

    override fun onDestroy() {
        Log.d(TAG, "ContinuousSyncService destroyed")
        val app = application as App
        val syncEngine = app.syncEngine

        // Tear down
        syncTrigger?.stop()
        syncTrigger = null
        peerCountJob?.cancel()
        syncEngine.autoAcceptConnections = false
        syncEngine.stopDiscovery()
        syncEngine.disconnect()
        scope.cancel()
        super.onDestroy()
    }

    private fun createNotificationChannel() {
        val channel = NotificationChannel(
            CHANNEL_ID,
            "Clinic Sync",
            NotificationManager.IMPORTANCE_LOW
        ).apply {
            description = "Continuous sync between clinic stations"
            setShowBadge(false)
        }
        val nm = getSystemService(NotificationManager::class.java)
        nm.createNotificationChannel(channel)
    }

    private fun buildNotification(peerCount: Int): Notification {
        val text = if (peerCount == 0) {
            "Searching for clinic devices…"
        } else {
            "Syncing with $peerCount device${if (peerCount != 1) "s" else ""}"
        }

        return Notification.Builder(this, CHANNEL_ID)
            .setContentTitle("ChartLite Sync")
            .setContentText(text)
            .setSmallIcon(android.R.drawable.stat_notify_sync)
            .setOngoing(true)
            .build()
    }

    companion object {
        private const val TAG = "ContinuousSyncService"
        private const val CHANNEL_ID = "continuous_sync"
        private const val NOTIFICATION_ID = 9001
        const val ACTION_STOP = "com.chartlite.app.sync.STOP"

        fun start(context: Context) {
            val intent = Intent(context, ContinuousSyncService::class.java)
            context.startForegroundService(intent)
        }

        fun stop(context: Context) {
            val intent = Intent(context, ContinuousSyncService::class.java).apply {
                action = ACTION_STOP
            }
            context.startService(intent)
        }

        /** Check if service should be running based on config. */
        fun shouldRun(app: App): Boolean {
            return app.appConfig.isMultiStation && app.appConfig.facilityId.isNotBlank()
        }
    }
}
