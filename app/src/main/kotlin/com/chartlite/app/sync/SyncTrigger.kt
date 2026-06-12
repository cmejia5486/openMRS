package com.chartlite.app.sync

import android.util.Log
import androidx.room.InvalidationTracker
import com.chartlite.app.database.AppDatabase
import kotlinx.coroutines.*

/**
 * Watches Room database tables for changes and triggers a callback after a debounce period.
 * Used by ContinuousSyncService to detect local DB changes and push deltas to peers.
 *
 * Has a [suppress] flag to prevent echo: set true before merging remote data, false after.
 * This prevents received sync data from triggering an immediate re-push.
 */
class SyncTrigger(
    private val database: AppDatabase,
    private val debounceMs: Long = 500L,
    private val scope: CoroutineScope,
    private val onTriggered: () -> Unit
) {
    private var debounceJob: Job? = null
    private var registered = false

    /**
     * When true, database changes are ignored (used during merge to prevent echo).
     * SyncEngine sets this before/after merging remote data.
     */
    @Volatile
    var suppress = false

    private val observer = object : InvalidationTracker.Observer(
        arrayOf("patients", "encounters", "visits")
    ) {
        override fun onInvalidated(tables: Set<String>) {
            if (suppress) {
                Log.d(TAG, "Change detected in $tables but suppressed (merging remote data)")
                return
            }
            Log.d(TAG, "Change detected in tables: $tables — scheduling delta push")
            debounceJob?.cancel()
            debounceJob = scope.launch {
                delay(debounceMs)
                onTriggered()
            }
        }
    }

    fun start() {
        if (registered) return
        database.invalidationTracker.addObserver(observer)
        registered = true
        Log.d(TAG, "Started watching patients, encounters, visits tables")
    }

    fun stop() {
        if (!registered) return
        debounceJob?.cancel()
        database.invalidationTracker.removeObserver(observer)
        registered = false
        Log.d(TAG, "Stopped watching tables")
    }

    companion object {
        private const val TAG = "SyncTrigger"
    }
}
