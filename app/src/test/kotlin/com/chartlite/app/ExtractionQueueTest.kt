package com.chartlite.app

import com.chartlite.app.database.dao.ExtractionQueueDao
import com.chartlite.app.database.entity.ExtractionQueueEntity
import com.chartlite.app.extraction.ExtractionOrchestrator
import com.chartlite.app.extraction.ExtractionQueue
import com.chartlite.app.extraction.ExtractionQueueRepository
import com.chartlite.app.extraction.ExtractionStrategy
import kotlinx.coroutines.CoroutineScope
import kotlinx.coroutines.SupervisorJob
import kotlinx.coroutines.cancel
import kotlinx.coroutines.flow.Flow
import kotlinx.coroutines.flow.MutableStateFlow
import kotlinx.coroutines.ExperimentalCoroutinesApi
import kotlinx.coroutines.test.StandardTestDispatcher
import kotlinx.coroutines.test.advanceUntilIdle
import kotlinx.coroutines.test.runTest
import org.junit.Assert.assertEquals
import org.junit.Assert.assertNull
import org.junit.Test

class ExtractionQueueTest {

    @Test
    @OptIn(ExperimentalCoroutinesApi::class)
    fun `process batch recovers interrupted processing entry`() = runTest {
        val dao = FakeExtractionQueueDao()
        val repository = ExtractionQueueRepository(dao)
        val queueId = "queue-1"
        dao.insert(
            ExtractionQueueEntity(
                id = queueId,
                transcript = "patient has pneumonia",
                patientId = "P001",
                providerId = "DR001",
                facilityId = "FAC001",
                status = ExtractionQueueRepository.QueueStatus.PROCESSING.name
            )
        )

        val queueScope = CoroutineScope(SupervisorJob() + StandardTestDispatcher(testScheduler))
        try {
            val queue = ExtractionQueue(
                orchestrator = ExtractionOrchestrator(
                    strategies = listOf(FailingStrategy()),
                    timeoutMs = 1_000L
                ),
                repository = repository,
                scope = queueScope
            )

            queue.processBatch()
            advanceUntilIdle()

            assertNull(queue.getResult(queueId))
            assertEquals(
                ExtractionQueueRepository.QueueStatus.FAILED,
                repository.getItem(queueId)?.status
            )
        } finally {
            queueScope.cancel()
        }
    }

    @Test
    fun `recover interrupted processing only resets processing rows`() = runTest {
        val dao = FakeExtractionQueueDao()
        val repository = ExtractionQueueRepository(dao)
        val processingId = "processing"
        val readyId = "ready"

        dao.insert(
            ExtractionQueueEntity(
                id = processingId,
                transcript = "processing row",
                patientId = "P001",
                providerId = "DR001",
                facilityId = "FAC001",
                status = ExtractionQueueRepository.QueueStatus.PROCESSING.name,
                strategyUsed = "Qwen"
            )
        )
        dao.insert(
            ExtractionQueueEntity(
                id = readyId,
                transcript = "ready row",
                patientId = "P002",
                providerId = "DR001",
                facilityId = "FAC001",
                status = ExtractionQueueRepository.QueueStatus.READY.name,
                strategyUsed = "Regex"
            )
        )

        val recovered = repository.recoverInterruptedProcessing()

        assertEquals(1, recovered)
        assertEquals(
            ExtractionQueueRepository.QueueStatus.QUEUED,
            repository.getItem(processingId)?.status
        )
        assertEquals("[]", dao.getById(processingId)?.fallbacksAttempted)
        assertEquals(
            ExtractionQueueRepository.QueueStatus.READY,
            repository.getItem(readyId)?.status
        )
    }

    private class FailingStrategy : ExtractionStrategy {
        override val name = "Failing Strategy"

        override suspend fun isAvailable(): Boolean = true

        override suspend fun extract(
            transcript: String,
            patientId: String,
            providerId: String,
            facilityId: String
        ) = throw IllegalStateException("Simulated failure")
    }

    private class FakeExtractionQueueDao : ExtractionQueueDao {
        private val items = linkedMapOf<String, ExtractionQueueEntity>()
        private val flow = MutableStateFlow<List<ExtractionQueueEntity>>(emptyList())

        override suspend fun insert(item: ExtractionQueueEntity) {
            items[item.id] = item
            emit()
        }

        override suspend fun update(item: ExtractionQueueEntity) {
            items[item.id] = item
            emit()
        }

        override suspend fun getById(id: String): ExtractionQueueEntity? = items[id]

        override fun observeActiveItems(): Flow<List<ExtractionQueueEntity>> = flow

        override suspend fun getByStatuses(statuses: List<String>): List<ExtractionQueueEntity> =
            items.values
                .filter { it.status in statuses }
                .sortedBy { it.createdAt }

        override suspend fun deleteById(id: String) {
            items.remove(id)
            emit()
        }

        private fun emit() {
            flow.value = items.values
                .filter { it.status != ExtractionQueueRepository.QueueStatus.SAVED.name }
                .sortedByDescending { it.createdAt }
        }
    }
}
