package com.chartlite.app.extraction

import com.chartlite.app.database.dao.ExtractionQueueDao
import com.chartlite.app.database.entity.ExtractionQueueEntity
import com.chartlite.app.model.StructuredEncounter
import com.google.gson.Gson
import com.google.gson.reflect.TypeToken
import kotlinx.coroutines.flow.Flow
import kotlinx.coroutines.flow.map
import java.time.Instant
import java.util.UUID

class ExtractionQueueRepository(
    private val dao: ExtractionQueueDao
) {
    enum class QueueStatus {
        QUEUED,
        PROCESSING,
        READY,
        FAILED,
        SAVED
    }

    data class QueueItem(
        val id: String,
        val transcript: String,
        val patientId: String,
        val providerId: String,
        val facilityId: String,
        val visitId: String?,
        val stationType: String?,
        val status: QueueStatus,
        val isUrgent: Boolean,
        val deferredReview: Boolean,
        val draftNote: String?,
        val noteStrategyUsed: String?,
        val strategyUsed: String?,
        val fallbacksAttempted: List<String>,
        val encounter: StructuredEncounter?,
        val errorMessage: String?,
        val savedEncounterId: String?,
        val createdAt: Instant,
        val updatedAt: Instant
    )

    private val gson = Gson()

    fun observeActiveItems(): Flow<List<QueueItem>> =
        dao.observeActiveItems().map { items -> items.map(::toQueueItem) }

    suspend fun enqueue(
        transcript: String,
        patientId: String,
        providerId: String,
        facilityId: String,
        visitId: String? = null,
        stationType: String? = null,
        urgent: Boolean = false,
        deferredReview: Boolean = false
    ): String {
        val now = System.currentTimeMillis()
        val item = ExtractionQueueEntity(
            id = UUID.randomUUID().toString(),
            transcript = transcript,
            patientId = patientId,
            providerId = providerId,
            facilityId = facilityId,
            visitId = visitId,
            stationType = stationType,
            status = QueueStatus.QUEUED.name,
            isUrgent = urgent,
            deferredReview = deferredReview,
            createdAt = now,
            updatedAt = now
        )
        dao.insert(item)
        return item.id
    }

    suspend fun getItem(id: String): QueueItem? = dao.getById(id)?.let(::toQueueItem)

    suspend fun getQueuedItems(): List<QueueItem> =
        dao.getByStatuses(listOf(QueueStatus.QUEUED.name)).map(::toQueueItem)

    suspend fun markProcessing(id: String) {
        update(id) { item ->
            item.copy(
                status = QueueStatus.PROCESSING.name,
                errorMessage = null,
                updatedAt = System.currentTimeMillis()
            )
        }
    }

    suspend fun markNoteGenerated(id: String, note: String, strategyUsed: String) {
        update(id) { item ->
            item.copy(
                draftNote = note,
                noteStrategyUsed = strategyUsed,
                updatedAt = System.currentTimeMillis()
            )
        }
    }

    suspend fun markReady(
        id: String,
        result: ExtractionOrchestrator.ExtractionResult
    ) {
        update(id) { item ->
            item.copy(
                status = QueueStatus.READY.name,
                strategyUsed = result.strategyUsed,
                fallbacksAttempted = gson.toJson(result.fallbacksAttempted),
                structuredEncounter = gson.toJson(result.encounter),
                errorMessage = null,
                updatedAt = System.currentTimeMillis()
            )
        }
    }

    suspend fun markFailed(id: String, message: String?) {
        update(id) { item ->
            item.copy(
                status = QueueStatus.FAILED.name,
                errorMessage = message?.take(500),
                updatedAt = System.currentTimeMillis()
            )
        }
    }

    suspend fun retry(id: String) {
        update(id, ::resetForRetry)
    }

    suspend fun recoverInterruptedProcessing(): Int {
        val now = System.currentTimeMillis()
        val interruptedItems = dao.getByStatuses(listOf(QueueStatus.PROCESSING.name))
        interruptedItems.forEach { item ->
            dao.update(
                resetForRetry(item).copy(updatedAt = now)
            )
        }
        return interruptedItems.size
    }

    suspend fun delete(id: String) {
        dao.deleteById(id)
    }

    suspend fun markSaved(id: String, savedEncounterId: String) {
        update(id) { item ->
            item.copy(
                status = QueueStatus.SAVED.name,
                savedEncounterId = savedEncounterId,
                updatedAt = System.currentTimeMillis()
            )
        }
    }

    private suspend fun update(
        id: String,
        transform: (ExtractionQueueEntity) -> ExtractionQueueEntity
    ) {
        val item = dao.getById(id) ?: return
        dao.update(transform(item))
    }

    private fun resetForRetry(item: ExtractionQueueEntity): ExtractionQueueEntity =
        item.copy(
            status = QueueStatus.QUEUED.name,
            draftNote = null,
            noteStrategyUsed = null,
            strategyUsed = null,
            fallbacksAttempted = "[]",
            structuredEncounter = null,
            errorMessage = null,
            savedEncounterId = null,
            updatedAt = System.currentTimeMillis()
        )

    private fun toQueueItem(entity: ExtractionQueueEntity): QueueItem {
        val status = runCatching {
            QueueStatus.valueOf(entity.status)
        }.getOrDefault(QueueStatus.FAILED)
        val fallbacks = runCatching {
            gson.fromJson<List<String>>(
                entity.fallbacksAttempted,
                object : TypeToken<List<String>>() {}.type
            ) ?: emptyList()
        }.getOrDefault(emptyList())
        val encounter = runCatching {
            entity.structuredEncounter?.let {
                gson.fromJson(it, StructuredEncounter::class.java)
            }
        }.getOrNull()
        return QueueItem(
            id = entity.id,
            transcript = entity.transcript,
            patientId = entity.patientId,
            providerId = entity.providerId,
            facilityId = entity.facilityId,
            visitId = entity.visitId,
            stationType = entity.stationType,
            status = status,
            isUrgent = entity.isUrgent,
            deferredReview = entity.deferredReview,
            draftNote = entity.draftNote,
            noteStrategyUsed = entity.noteStrategyUsed,
            strategyUsed = entity.strategyUsed,
            fallbacksAttempted = fallbacks,
            encounter = encounter,
            errorMessage = entity.errorMessage,
            savedEncounterId = entity.savedEncounterId,
            createdAt = Instant.ofEpochMilli(entity.createdAt),
            updatedAt = Instant.ofEpochMilli(entity.updatedAt)
        )
    }
}
