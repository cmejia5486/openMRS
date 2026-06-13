package com.chartlite.app

import com.chartlite.app.extraction.ExtractionOrchestrator
import com.chartlite.app.extraction.ExtractionStrategy
import com.chartlite.app.extraction.VitalsExtractor
import com.chartlite.app.model.*
import kotlinx.coroutines.delay
import kotlinx.coroutines.test.runTest
import org.junit.Assert.*
import org.junit.Test
import java.time.Instant

class ExtractionOrchestratorTest {

    private fun makeEncounter(source: String) = StructuredEncounter(
        id = "test-$source",
        patientId = "P001",
        providerId = "DR001",
        facilityId = "FAC001",
        timestamp = Instant.now(),
        transcript = "test transcript",
        medications = emptyList(),
        diagnoses = listOf(Diagnosis("J18.9", "Pneumonia", true, 0.9f)),
        vitals = null,
        allergies = emptyList(),
        followUp = null,
        referral = null,
        freeTextNote = source,
        extractionConfidence = 0.9f
    )

    private class AlwaysAvailableStrategy(
        override val name: String,
        private val encounter: StructuredEncounter?
    ) : ExtractionStrategy {
        override suspend fun isAvailable() = true
        override suspend fun extract(
            transcript: String, patientId: String, providerId: String, facilityId: String
        ) = encounter
    }

    private class UnavailableStrategy(override val name: String) : ExtractionStrategy {
        override suspend fun isAvailable() = false
        override suspend fun extract(
            transcript: String, patientId: String, providerId: String, facilityId: String
        ): StructuredEncounter? = throw IllegalStateException("Should not be called")
    }

    private class FailingStrategy(override val name: String) : ExtractionStrategy {
        override suspend fun isAvailable() = true
        override suspend fun extract(
            transcript: String, patientId: String, providerId: String, facilityId: String
        ): StructuredEncounter? = throw RuntimeException("Simulated failure")
    }

    private class SlowStrategy(
        override val name: String,
        private val delayMs: Long
    ) : ExtractionStrategy {
        override suspend fun isAvailable() = true
        override suspend fun extract(
            transcript: String, patientId: String, providerId: String, facilityId: String
        ): StructuredEncounter? {
            delay(delayMs)
            return null
        }
    }

    @Test
    fun `uses first available strategy`() = runTest {
        val orchestrator = ExtractionOrchestrator(
            strategies = listOf(
                AlwaysAvailableStrategy("Primary", makeEncounter("primary")),
                AlwaysAvailableStrategy("Fallback", makeEncounter("fallback"))
            )
        )

        val result = orchestrator.extract("transcript", "P001", "DR001", "FAC001")
        assertEquals("Primary", result.strategyUsed)
        assertTrue(result.fallbacksAttempted.isEmpty())
    }

    @Test
    fun `skips unavailable strategy`() = runTest {
        val orchestrator = ExtractionOrchestrator(
            strategies = listOf(
                UnavailableStrategy("Gemini Nano"),
                AlwaysAvailableStrategy("Qwen", makeEncounter("qwen")),
                AlwaysAvailableStrategy("Regex", makeEncounter("regex"))
            )
        )

        val result = orchestrator.extract("transcript", "P001", "DR001", "FAC001")
        assertEquals("Qwen", result.strategyUsed)
        assertTrue(result.fallbacksAttempted.isEmpty())
    }

    @Test
    fun `falls through on null result`() = runTest {
        val orchestrator = ExtractionOrchestrator(
            strategies = listOf(
                AlwaysAvailableStrategy("LLM", null), // returns null
                AlwaysAvailableStrategy("Regex", makeEncounter("regex"))
            )
        )

        val result = orchestrator.extract("transcript", "P001", "DR001", "FAC001")
        assertEquals("Regex", result.strategyUsed)
        assertEquals(1, result.fallbacksAttempted.size)
        assertTrue(result.fallbacksAttempted.first().contains("LLM"))
    }

    @Test
    fun `falls through on exception`() = runTest {
        val orchestrator = ExtractionOrchestrator(
            strategies = listOf(
                FailingStrategy("LLM"),
                AlwaysAvailableStrategy("Regex", makeEncounter("regex"))
            )
        )

        val result = orchestrator.extract("transcript", "P001", "DR001", "FAC001")
        assertEquals("Regex", result.strategyUsed)
        assertEquals(1, result.fallbacksAttempted.size)
        assertTrue(result.fallbacksAttempted.first().contains("LLM"))
    }

    @Test
    fun `records multiple fallbacks`() = runTest {
        val orchestrator = ExtractionOrchestrator(
            strategies = listOf(
                AlwaysAvailableStrategy("Strategy A", null),
                FailingStrategy("Strategy B"),
                AlwaysAvailableStrategy("Strategy C", makeEncounter("c"))
            )
        )

        val result = orchestrator.extract("transcript", "P001", "DR001", "FAC001")
        assertEquals("Strategy C", result.strategyUsed)
        assertEquals(2, result.fallbacksAttempted.size)
        assertTrue(result.fallbacksAttempted[0].contains("Strategy A"))
        assertTrue(result.fallbacksAttempted[1].contains("Strategy B"))
    }

    @Test
    fun `returns empty encounter when all strategies fail`() = runTest {
        val orchestrator = ExtractionOrchestrator(
            strategies = listOf(
                AlwaysAvailableStrategy("A", null),
                FailingStrategy("B")
            )
        )

        val result = orchestrator.extract("transcript", "P001", "DR001", "FAC001")
        assertEquals("none (all failed)", result.strategyUsed)
        assertEquals("P001", result.encounter.patientId)
        assertEquals(0f, result.encounter.extractionConfidence)
    }

    @Test
    fun `timeout causes fallback`() = runTest {
        val orchestrator = ExtractionOrchestrator(
            strategies = listOf(
                SlowStrategy("Slow LLM", 5000),
                AlwaysAvailableStrategy("Regex", makeEncounter("regex"))
            ),
            timeoutMs = 100 // 100ms timeout
        )

        val result = orchestrator.extract("transcript", "P001", "DR001", "FAC001")
        assertEquals("Regex", result.strategyUsed)
        assertEquals(1, result.fallbacksAttempted.size)
        assertTrue(result.fallbacksAttempted.first().contains("Slow LLM"))
    }

    @Test
    fun `llm vitals are preserved when regex merge is disabled`() = runTest {
        val llmEncounter = makeEncounter("llm").copy(
            vitals = VitalSigns(systolicBP = 123, diastolicBP = 77)
        )
        val orchestrator = ExtractionOrchestrator(
            strategies = listOf(AlwaysAvailableStrategy("Qwen", llmEncounter)),
            vitalsExtractor = VitalsExtractor(),
            mergeRegexVitalsIntoLlmResults = false
        )

        val result = orchestrator.extract("BP 140/90", "P001", "DR001", "FAC001")

        assertEquals(123, result.encounter.vitals?.systolicBP)
        assertEquals(77, result.encounter.vitals?.diastolicBP)
    }

    @Test
    fun `regex vitals override llm vitals when merge is enabled`() = runTest {
        val llmEncounter = makeEncounter("llm").copy(
            vitals = VitalSigns(systolicBP = 123, diastolicBP = 77)
        )
        val orchestrator = ExtractionOrchestrator(
            strategies = listOf(AlwaysAvailableStrategy("Qwen", llmEncounter)),
            vitalsExtractor = VitalsExtractor(),
            mergeRegexVitalsIntoLlmResults = true
        )

        val result = orchestrator.extract("BP 140/90", "P001", "DR001", "FAC001")

        assertEquals(140, result.encounter.vitals?.systolicBP)
        assertEquals(90, result.encounter.vitals?.diastolicBP)
    }
}
