package com.lyecdevelopers.sync.data.sync

import android.content.Context
import androidx.hilt.work.HiltWorker
import androidx.work.CoroutineWorker
import androidx.work.ForegroundInfo
import androidx.work.WorkerParameters
import com.lyecdevelopers.core.data.local.entity.EncounterEntity
import com.lyecdevelopers.core.data.notifications.SyncNotificationHelper
import com.lyecdevelopers.core.data.remote.FormApi
import com.lyecdevelopers.core.model.encounter.EncounterPayload
import com.lyecdevelopers.core.utils.AppLogger
import com.lyecdevelopers.core.utils.NotificationConstants.ENCOUNTER_SYNC_NOTIFICATION_ID
import com.lyecdevelopers.core.utils.NotificationConstants.SYNC_NOTIFICATION_CHANNEL_DESCRIPTION
import com.lyecdevelopers.core.utils.NotificationConstants.SYNC_NOTIFICATION_CHANNEL_ID
import com.lyecdevelopers.core.utils.NotificationConstants.SYNC_NOTIFICATION_CHANNEL_NAME
import com.lyecdevelopers.sync.domain.usecase.SyncUseCase
import dagger.assisted.Assisted
import dagger.assisted.AssistedInject
import kotlinx.coroutines.flow.catch

@HiltWorker
class EncountersSyncWorker @AssistedInject constructor(
    @Assisted appContext: Context,
    @Assisted workerParams: WorkerParameters,
    private val syncUseCase: SyncUseCase,
    private val api: FormApi,
    private val notificationHelper: SyncNotificationHelper,
) : CoroutineWorker(appContext, workerParams) {

    override suspend fun doWork(): Result {
        AppLogger.d("🔄 EncountersSyncWorker started")

        val initialNotification = notificationHelper.createNotification(
            SYNC_NOTIFICATION_CHANNEL_ID,
            SYNC_NOTIFICATION_CHANNEL_NAME,
            SYNC_NOTIFICATION_CHANNEL_DESCRIPTION,
            "Syncing Encounter Data",
            "Starting synchronization..."
        )
        val foregroundInfo = ForegroundInfo(ENCOUNTER_SYNC_NOTIFICATION_ID, initialNotification)
        setForeground(foregroundInfo)

        return try {
            var shouldRetry = false
            var totalEncountersToSync = 0
            var syncedEncountersCount = 0

            syncUseCase.getUnsynced().catch { e ->
                AppLogger.e("❌ DB read failed: ${e.message}")
                shouldRetry = true
                val errorNotification = notificationHelper.createNotification(
                    SYNC_NOTIFICATION_CHANNEL_ID,
                    SYNC_NOTIFICATION_CHANNEL_NAME,
                    SYNC_NOTIFICATION_CHANNEL_DESCRIPTION,
                    "Encounter Sync Failed",
                    "Error reading local data: ${e.message}"
                )
                notificationHelper.notify(ENCOUNTER_SYNC_NOTIFICATION_ID, errorNotification)
            }.collect { unsyncedList ->
                totalEncountersToSync = unsyncedList.size

                if (totalEncountersToSync == 0) {
                    AppLogger.d("✅ No unsynced encounters. Nothing to sync.")
                    val completedNotification = notificationHelper.createNotification(
                        SYNC_NOTIFICATION_CHANNEL_ID,
                        SYNC_NOTIFICATION_CHANNEL_NAME,
                        SYNC_NOTIFICATION_CHANNEL_DESCRIPTION,
                        "Encounter Sync Complete",
                        "No unsynced encounters found.",
                        1,
                        1
                    )
                    notificationHelper.notify(ENCOUNTER_SYNC_NOTIFICATION_ID, completedNotification)
                } else {
                    AppLogger.d("🔄 Syncing $totalEncountersToSync unsynced encounters...")

                    notificationHelper.notify(
                        ENCOUNTER_SYNC_NOTIFICATION_ID, notificationHelper.createNotification(
                            SYNC_NOTIFICATION_CHANNEL_ID,
                            SYNC_NOTIFICATION_CHANNEL_NAME,
                            SYNC_NOTIFICATION_CHANNEL_DESCRIPTION,
                            "Syncing Encounter Data",
                            "Syncing 0 of $totalEncountersToSync encounters...",
                            0,
                            totalEncountersToSync
                        )
                    )

                    unsyncedList.forEach { entity ->
                        try {
                            val payload = buildEncounterPayload(entity)
                            val response = api.saveEncounter(payload)

                            if (response.isSuccessful) {
                                syncUseCase.markSynced(entity).catch { markErr ->
                                    AppLogger.e("⚠️ Mark local failed: ${markErr.message}")
                                    shouldRetry = true
                                }.collect {
                                    syncedEncountersCount++
                                }
                            } else {
                                AppLogger.e(
                                    "❌ API rejected encounter ${entity.id}: ${response.code()} ${response.message()}"
                                )
                                shouldRetry = true
                            }
                        } catch (e: Exception) {
                            AppLogger.e("❌ Error syncing encounter ${entity.id}: ${e.message}")
                            shouldRetry = true
                        }

                        notificationHelper.notify(
                            ENCOUNTER_SYNC_NOTIFICATION_ID, notificationHelper.createNotification(
                                SYNC_NOTIFICATION_CHANNEL_ID,
                                SYNC_NOTIFICATION_CHANNEL_NAME,
                                SYNC_NOTIFICATION_CHANNEL_DESCRIPTION,
                                "Syncing Encounter Data",
                                "Syncing $syncedEncountersCount of $totalEncountersToSync encounters...",
                                syncedEncountersCount,
                                totalEncountersToSync
                            )
                        )
                    }
                }
            }

            if (shouldRetry) {
                AppLogger.d("🔁 Retrying EncountersSyncWorker...")
                notificationHelper.notify(
                    ENCOUNTER_SYNC_NOTIFICATION_ID, notificationHelper.createNotification(
                        SYNC_NOTIFICATION_CHANNEL_ID,
                        SYNC_NOTIFICATION_CHANNEL_NAME,
                        SYNC_NOTIFICATION_CHANNEL_DESCRIPTION,
                        "Encounter Sync Needs Retry",
                        "Some encounters failed to sync. Retrying...",
                        syncedEncountersCount,
                        totalEncountersToSync
                    )
                )
                Result.retry()
            } else {
                AppLogger.d("✅ EncountersSyncWorker success")
                notificationHelper.notify(
                    ENCOUNTER_SYNC_NOTIFICATION_ID, notificationHelper.createNotification(
                        SYNC_NOTIFICATION_CHANNEL_ID,
                        SYNC_NOTIFICATION_CHANNEL_NAME,
                        SYNC_NOTIFICATION_CHANNEL_DESCRIPTION,
                        "Encounter Sync Complete",
                        "All $syncedEncountersCount encounters synced successfully.",
                        syncedEncountersCount,
                        totalEncountersToSync
                    )
                )
                Result.success()
            }

        } catch (e: Exception) {
            AppLogger.e("❌ EncountersSyncWorker failed: ${e.localizedMessage}")
            notificationHelper.notify(
                ENCOUNTER_SYNC_NOTIFICATION_ID, notificationHelper.createNotification(
                    SYNC_NOTIFICATION_CHANNEL_ID,
                    SYNC_NOTIFICATION_CHANNEL_NAME,
                    SYNC_NOTIFICATION_CHANNEL_DESCRIPTION,
                    "Encounter Sync Failed",
                    "Synchronization error: ${e.localizedMessage}"
                )
            )
            Result.retry()
        }
    }

    private fun buildEncounterPayload(entity: EncounterEntity): EncounterPayload {
        return EncounterPayload(
            uuid = entity.id,
            visitUuid = entity.visitUuid,
            encounterType = entity.encounterTypeUuid,
            encounterDatetime = entity.encounterDatetime,
            patientUuid = entity.patientUuid,
            locationUuid = entity.locationUuid,
            provider = entity.providerUuid,
            obs = entity.obs,
            orders = entity.orders,
            formUuid = entity.formUuid,
        )
    }
}




