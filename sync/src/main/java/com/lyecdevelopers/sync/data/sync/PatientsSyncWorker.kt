package com.lyecdevelopers.sync.data.sync

import android.content.Context
import androidx.hilt.work.HiltWorker
import androidx.work.CoroutineWorker
import androidx.work.ForegroundInfo
import androidx.work.WorkerParameters
import ca.uhn.fhir.context.FhirContext
import com.lyecdevelopers.core.data.notifications.SyncNotificationHelper
import com.lyecdevelopers.core.data.remote.FormApi
import com.lyecdevelopers.core.utils.AppLogger
import com.lyecdevelopers.core.utils.NotificationConstants.PATIENT_SYNC_NOTIFICATION_ID
import com.lyecdevelopers.core.utils.NotificationConstants.SYNC_NOTIFICATION_CHANNEL_DESCRIPTION
import com.lyecdevelopers.core.utils.NotificationConstants.SYNC_NOTIFICATION_CHANNEL_ID
import com.lyecdevelopers.core.utils.NotificationConstants.SYNC_NOTIFICATION_CHANNEL_NAME
import com.lyecdevelopers.form.utils.toFhirPatient
import com.lyecdevelopers.sync.domain.usecase.SyncUseCase
import dagger.assisted.Assisted
import dagger.assisted.AssistedInject
import kotlinx.coroutines.flow.catch
import okhttp3.MediaType.Companion.toMediaType
import okhttp3.RequestBody.Companion.toRequestBody
import org.hl7.fhir.r4.model.Patient


@HiltWorker
class PatientsSyncWorker @AssistedInject constructor(
    @Assisted appContext: Context,
    @Assisted workerParams: WorkerParameters,
    private val syncUseCase: SyncUseCase,
    private val api: FormApi,
    private val notificationHelper: SyncNotificationHelper,
) : CoroutineWorker(appContext, workerParams) {

    override suspend fun doWork(): Result {
        AppLogger.d("🔄 PatientsSyncWorker started")

        val initialNotification = notificationHelper.createNotification(
            SYNC_NOTIFICATION_CHANNEL_ID,
            SYNC_NOTIFICATION_CHANNEL_NAME,
            SYNC_NOTIFICATION_CHANNEL_DESCRIPTION,
            "Syncing Patient Data",
            "Starting synchronization..."
        )
        val foregroundInfo = ForegroundInfo(PATIENT_SYNC_NOTIFICATION_ID, initialNotification)
        setForeground(foregroundInfo)

        return try {
            var shouldRetry = false
            var totalPatientsToSync = 0
            var syncedPatientsCount = 0

            syncUseCase.getEligibleUnsyncedPatients().catch { e ->
                AppLogger.e("❌ DB read failed: ${e.message}")
                shouldRetry = true
                val errorNotification = notificationHelper.createNotification(
                    SYNC_NOTIFICATION_CHANNEL_ID,
                    SYNC_NOTIFICATION_CHANNEL_NAME,
                    SYNC_NOTIFICATION_CHANNEL_DESCRIPTION,
                    "Patient Sync Failed",
                    "Error reading local data: ${e.message}"
                )
                notificationHelper.notify(PATIENT_SYNC_NOTIFICATION_ID, errorNotification)
            }.collect { unsyncedList ->
                totalPatientsToSync = unsyncedList.size

                if (totalPatientsToSync == 0) {
                    AppLogger.d("✅ No unsynced patients. Nothing to sync.")
                    val completedNotification = notificationHelper.createNotification(
                        SYNC_NOTIFICATION_CHANNEL_ID,
                        SYNC_NOTIFICATION_CHANNEL_NAME,
                        SYNC_NOTIFICATION_CHANNEL_DESCRIPTION,
                        "Patient Sync Complete",
                        "No unsynced patients found.",
                        1, 1
                    )
                    notificationHelper.notify(PATIENT_SYNC_NOTIFICATION_ID, completedNotification)
                } else {
                    AppLogger.d("🔄 Syncing $totalPatientsToSync unsynced patients...")

                    notificationHelper.notify(
                        PATIENT_SYNC_NOTIFICATION_ID,
                        notificationHelper.createNotification(
                            SYNC_NOTIFICATION_CHANNEL_ID,
                            SYNC_NOTIFICATION_CHANNEL_NAME,
                            SYNC_NOTIFICATION_CHANNEL_DESCRIPTION,
                            "Syncing Patient Data",
                            "Syncing 0 of $totalPatientsToSync patients...",
                            0, totalPatientsToSync
                        )
                    )

                    unsyncedList.forEach { entity ->
                        try {
                            val fhirPatient: Patient = entity.toFhirPatient()
                            val patientJson = FhirContext.forR4().newJsonParser()
                                .encodeResourceToString(fhirPatient)
                            val requestBody = patientJson.toRequestBody(
                                "application/fhir+json".toMediaType()
                            )

                            val response = api.savePatient(
                                fhirPatient.idElement.idPart, requestBody
                            )

                            if (response.isSuccessful) {
                                syncUseCase.markSyncedPatient(entity).catch { markErr ->
                                    AppLogger.e("⚠️ Mark local failed: ${markErr.message}")
                                    shouldRetry = true
                                }.collect {
                                    AppLogger.d("✅ Patient ${entity.id} marked synced.")
                                    syncedPatientsCount++
                                }
                            } else {
                                AppLogger.e("❌ API rejected: ${response.code()} ${response.message()}")
                                shouldRetry = true
                            }

                        } catch (e: Exception) {
                            AppLogger.e("❌ Error syncing patient ${entity.id}: ${e.message}")
                            shouldRetry = true
                        }

                        notificationHelper.notify(
                            PATIENT_SYNC_NOTIFICATION_ID,
                            notificationHelper.createNotification(
                                SYNC_NOTIFICATION_CHANNEL_ID,
                                SYNC_NOTIFICATION_CHANNEL_NAME,
                                SYNC_NOTIFICATION_CHANNEL_DESCRIPTION,
                                "Syncing Patient Data",
                                "Syncing $syncedPatientsCount of $totalPatientsToSync patients...",
                                syncedPatientsCount,
                                totalPatientsToSync
                            )
                        )
                    }
                }
            }

            if (shouldRetry) {
                AppLogger.d("🔁 Retrying PatientsSyncWorker...")
                val retryNotification = notificationHelper.createNotification(
                    SYNC_NOTIFICATION_CHANNEL_ID,
                    SYNC_NOTIFICATION_CHANNEL_NAME,
                    SYNC_NOTIFICATION_CHANNEL_DESCRIPTION,
                    "Patient Sync Needs Retry",
                    "Some patients failed to sync. Retrying...",
                    syncedPatientsCount,
                    totalPatientsToSync
                )
                notificationHelper.notify(PATIENT_SYNC_NOTIFICATION_ID, retryNotification)
                Result.retry()
            } else {
                AppLogger.d("✅ PatientsSyncWorker success")
                val successNotification = notificationHelper.createNotification(
                    SYNC_NOTIFICATION_CHANNEL_ID,
                    SYNC_NOTIFICATION_CHANNEL_NAME,
                    SYNC_NOTIFICATION_CHANNEL_DESCRIPTION,
                    "Patient Sync Complete",
                    "All $syncedPatientsCount patients synced successfully.",
                    syncedPatientsCount,
                    totalPatientsToSync
                )
                notificationHelper.notify(PATIENT_SYNC_NOTIFICATION_ID, successNotification)
                Result.success()
            }

        } catch (e: Exception) {
            AppLogger.e("❌ PatientsSyncWorker failed: ${e.localizedMessage}")
            val failedNotification = notificationHelper.createNotification(
                SYNC_NOTIFICATION_CHANNEL_ID,
                SYNC_NOTIFICATION_CHANNEL_NAME,
                SYNC_NOTIFICATION_CHANNEL_DESCRIPTION,
                "Patient Sync Failed",
                "Synchronization encountered an error: ${e.localizedMessage}"
            )
            notificationHelper.notify(PATIENT_SYNC_NOTIFICATION_ID, failedNotification)
            Result.retry()
        }
    }
}


