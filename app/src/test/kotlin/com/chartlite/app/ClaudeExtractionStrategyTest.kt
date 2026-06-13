package com.chartlite.app

import com.chartlite.app.extraction.ExtractionOrchestrator
import com.chartlite.app.extraction.ExtractionStrategy
import com.chartlite.app.extraction.TranscriptValidator
import com.chartlite.app.model.*
import kotlinx.coroutines.test.runTest
import org.junit.Assert.*
import org.junit.Test
import java.time.Instant

/**
 * Tests for the transcript validation + orchestrator integration,
 * and Claude API request construction (unit-testable parts).
 *
 * Note: ClaudeExtractionStrategy itself requires Android context for network checks,
 * so we test the orchestrator-level behavior here.
 */
class ClaudeExtractionStrategyTest {

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

    private class TrackingStrategy(
        override val name: String,
        private val encounter: StructuredEncounter?
    ) : ExtractionStrategy {
        var wasCalled = false
        override suspend fun isAvailable() = true
        override suspend fun extract(
            transcript: String, patientId: String, providerId: String, facilityId: String
        ): StructuredEncounter? {
            wasCalled = true
            return encounter
        }
    }

    // Minimal non-LLM strategy stand-in (like RegexExtractionStrategy)
    private class FakeRegexStrategy : ExtractionStrategy {
        override val name = "Regex"
        override val isLlmBased = false
        var wasCalled = false
        override suspend fun isAvailable() = true
        override suspend fun extract(
            transcript: String, patientId: String, providerId: String, facilityId: String
        ): StructuredEncounter {
            wasCalled = true
            return StructuredEncounter(
                id = "regex-fallback",
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
                freeTextNote = "regex extraction",
                extractionConfidence = 0.3f
            )
        }
    }

    @Test
    fun `orchestrator still uses LLM strategies for gibberish warning transcript`() = runTest {
        val llmStrategy = TrackingStrategy("Claude (cloud)", makeEncounter("claude"))
        val regexStrategy = FakeRegexStrategy()
        val validator = TranscriptValidator()

        val orchestrator = ExtractionOrchestrator(
            strategies = listOf(llmStrategy, regexStrategy),
            transcriptValidator = validator
        )

        val result = orchestrator.extract("njklhkjhljkhlkhlkjhkjlh brrr tttss", "P001", "DR001", "FAC001")

        assertTrue("LLM strategy should still be called for soft validation failures", llmStrategy.wasCalled)
        assertFalse("Regex should not be needed when LLM succeeds", regexStrategy.wasCalled)
        assertEquals("Claude (cloud)", result.strategyUsed)
    }

    @Test
    fun `orchestrator uses LLM strategies for valid transcript`() = runTest {
        val llmStrategy = TrackingStrategy("Claude (cloud)", makeEncounter("claude"))
        val regexStrategy = FakeRegexStrategy()
        val validator = TranscriptValidator()

        val orchestrator = ExtractionOrchestrator(
            strategies = listOf(llmStrategy, regexStrategy),
            transcriptValidator = validator
        )

        val result = orchestrator.extract("Patient has fever and cough for three days", "P001", "DR001", "FAC001")

        assertTrue("LLM strategy should be called for valid transcript", llmStrategy.wasCalled)
        assertEquals("Claude (cloud)", result.strategyUsed)
    }

    @Test
    fun `orchestrator works without validator`() = runTest {
        val llmStrategy = TrackingStrategy("Claude (cloud)", makeEncounter("claude"))
        val regexStrategy = FakeRegexStrategy()

        // No validator — gibberish goes through to LLM
        val orchestrator = ExtractionOrchestrator(
            strategies = listOf(llmStrategy, regexStrategy),
            transcriptValidator = null
        )

        val result = orchestrator.extract("njklhkjhljkhlkhlkjhkjlh brrr tttss", "P001", "DR001", "FAC001")

        assertTrue("LLM should be called when no validator", llmStrategy.wasCalled)
        assertEquals("Claude (cloud)", result.strategyUsed)
    }

    @Test
    fun `orchestrator skips llm strategies for too short transcript`() = runTest {
        val claudeStrategy = TrackingStrategy("Claude (cloud)", makeEncounter("claude"))
        val qwenStrategy = TrackingStrategy("Qwen", makeEncounter("qwen"))
        val regexStrategy = FakeRegexStrategy()
        val validator = TranscriptValidator()

        val orchestrator = ExtractionOrchestrator(
            strategies = listOf(claudeStrategy, qwenStrategy, regexStrategy),
            transcriptValidator = validator
        )

        val result = orchestrator.extract("hi", "P001", "DR001", "FAC001")

        assertEquals("Regex", result.strategyUsed)
        assertEquals(2, result.fallbacksAttempted.size)
        assertTrue(result.fallbacksAttempted[0].contains("Claude"))
        assertTrue(result.fallbacksAttempted[1].contains("Qwen"))
        assertFalse(claudeStrategy.wasCalled)
        assertFalse(qwenStrategy.wasCalled)
        assertTrue(regexStrategy.wasCalled)
    }
}
