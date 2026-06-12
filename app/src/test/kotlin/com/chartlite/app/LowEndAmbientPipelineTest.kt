package com.chartlite.app

import com.chartlite.app.database.dao.ExtractionQueueDao
import com.chartlite.app.database.entity.ExtractionQueueEntity
import com.chartlite.app.extraction.AmbientTranscriptOptimizer
import com.chartlite.app.extraction.ExtractionOrchestrator
import com.chartlite.app.extraction.ExtractionQueue
import com.chartlite.app.extraction.ExtractionQueueRepository
import com.chartlite.app.extraction.ExtractionStrategy
import com.chartlite.app.model.StructuredEncounter
import kotlinx.coroutines.CoroutineScope
import kotlinx.coroutines.ExperimentalCoroutinesApi
import kotlinx.coroutines.SupervisorJob
import kotlinx.coroutines.cancel
import kotlinx.coroutines.flow.Flow
import kotlinx.coroutines.flow.MutableStateFlow
import kotlinx.coroutines.test.StandardTestDispatcher
import kotlinx.coroutines.test.advanceUntilIdle
import kotlinx.coroutines.test.runTest
import org.junit.Assert.assertEquals
import org.junit.Assert.assertTrue
import org.junit.Test
import java.time.Instant

/**
 * Acceptance-style tests for the low-end ambient -> batch -> review workflow.
 *
 * These tests stay pure JVM and avoid Android/native dependencies, but they
 * codify the behavior we rely on for constrained-device note processing.
 */
class LowEndAmbientPipelineTest {

    @Test
    fun `ambient transcript compaction retains medication and follow up for batch extraction`() {
        val transcript =
            "okay okay. patient has fever and cough for three days. patient has fever and cough for three days. " +
                "um alright. start amoxicillin 500 mg three times daily for five days. " +
                "follow up in three days if not improving."

        val optimized = AmbientTranscriptOptimizer.optimize(transcript, charBudget = 180)

        assertTrue(optimized.duplicateSegmentsRemoved >= 1)
        assertTrue(optimized.fillerSegmentsRemoved >= 1)
        assertTrue(optimized.optimizedTranscript.contains("amoxicillin 500 mg"))
        assertTrue(optimized.optimizedTranscript.contains("follow up"))
    }

    @Test
    @OptIn(ExperimentalCoroutinesApi::class)
    fun `deferred ambient note is queued for later batch review`() = runTest {
        val dao = FakeExtractionQueueDao()
        val repository = ExtractionQueueRepository(dao)
        val queueScope = CoroutineScope(SupervisorJob() + StandardTestDispatcher(testScheduler))

        try {
            val queue = ExtractionQueue(
                orchestrator = ExtractionOrchestrator(
                    strategies = listOf(NullLlmStrategy("Qwen 3.5 0.8B (on-device)")),
                    timeoutMs = 1_000L
                ),
                repository = repository,
                scope = queueScope
            )

            val queueId = queue.enqueue(
                transcript = "Child with fever and cough. Start amoxicillin 500 mg. Follow up in three days.",
                patientId = "P001",
                providerId = "DR001",
                facilityId = "FAC001",
                deferredReview = true
            )

            advanceUntilIdle()

            val item = repository.getItem(queueId)

            assertEquals(ExtractionQueueRepository.QueueStatus.QUEUED, item?.status)
            assertTrue(item?.deferredReview == true)
            assertEquals(
                "Child with fever and cough. Start amoxicillin 500 mg. Follow up in three days.",
                item?.transcript
            )
        } finally {
            queueScope.cancel()
        }
    }

    @Test
    fun `orchestrator falls back to regex style strategy when on-device extraction returns null`() = runTest {
        val qwen = NullLlmStrategy("Qwen 3.5 0.8B (on-device)")
        val regex = SuccessfulRegexStrategy()
        val orchestrator = ExtractionOrchestrator(
            strategies = listOf(qwen, regex),
            timeoutMs = 1_000L
        )

        val result = orchestrator.extract(
            transcript = "Patient has fever and cough. Start amoxicillin and review in three days.",
            patientId = "P001",
            providerId = "DR001",
            facilityId = "FAC001"
        )

        assertEquals("Regex", result.strategyUsed)
        assertEquals(listOf("Qwen 3.5 0.8B (on-device) (returned no usable result)"), result.fallbacksAttempted)
        assertTrue(result.encounter.freeTextNote.contains("regex"))
    }

    private class NullLlmStrategy(
        override val name: String
    ) : ExtractionStrategy {
        override suspend fun isAvailable(): Boolean = true

        override suspend fun extract(
            transcript: String,
            patientId: String,
            providerId: String,
            facilityId: String
        ): StructuredEncounter? = null
    }

    private class SuccessfulRegexStrategy : ExtractionStrategy {
        override val name: String = "Regex"
        override val isLlmBased: Boolean = false

        override suspend fun isAvailable(): Boolean = true

        override suspend fun extract(
            transcript: String,
            patientId: String,
            providerId: String,
            facilityId: String
        ): StructuredEncounter = makeEncounter(
            patientId = patientId,
            providerId = providerId,
            facilityId = facilityId,
            transcript = transcript,
            freeTextNote = "regex extraction fallback"
        )
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

    companion object {
        private fun makeEncounter(
            patientId: String,
            providerId: String,
            facilityId: String,
            transcript: String,
            freeTextNote: String
        ) = StructuredEncounter(
            id = "enc-${patientId.lowercase()}",
            patientId = patientId,
            providerId = providerId,
            facilityId = facilityId,
            timestamp = Instant.now(),
            transcript = transcript,
            medications = emptyList(),
            diagnoses = emptyList(),
            vitals = null,
            allergies = emptyList(),
            followUp = null,
            referral = null,
            freeTextNote = freeTextNote,
            extractionConfidence = 0.8f
        )
    }
}
