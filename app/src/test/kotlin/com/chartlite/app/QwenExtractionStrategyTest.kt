package com.chartlite.app

import com.chartlite.app.extraction.QwenExtractionStrategy
import org.junit.Assert.assertEquals
import org.junit.Assert.assertFalse
import org.junit.Assert.assertTrue
import org.junit.Test

class QwenExtractionStrategyTest {

    @Test
    fun `primed retry prompt preserves chat prompt assistant prefix`() {
        val prompt = "<|im_start|>system\nRules\n<|im_end|>\n<|im_start|>user\nTranscript\n<|im_end|>\n<|im_start|>assistant\n{"

        val primed = QwenExtractionStrategy.buildPrimedRetryPrompt(prompt)

        assertEquals(prompt.trimEnd(), primed)
    }

    @Test
    fun `merge primed response prepends opening brace when model omits it`() {
        val merged = QwenExtractionStrategy.mergePrimedResponse("  \"chief_complaint\": \"fever\"\n}")
        assertEquals("{\"chief_complaint\": \"fever\"\n}", merged)
    }

    @Test
    fun `merge primed response does not duplicate opening brace`() {
        val merged = QwenExtractionStrategy.mergePrimedResponse("{\"chief_complaint\": \"fever\"}")
        assertEquals("{\"chief_complaint\": \"fever\"}", merged)
    }

    @Test
    fun `prepare transcript keeps raw transcript when under budget`() {
        val prepared = QwenExtractionStrategy.prepareTranscriptForInference(
            transcript = "Patient has fever. Smoker. Follow up in three days.",
            charBudget = 500
        )

        assertEquals("Patient has fever. Smoker. Follow up in three days.", prepared.text)
        assertFalse(prepared.compacted)
        assertEquals(0, prepared.fillerSegmentsRemoved)
        assertEquals(0, prepared.duplicateSegmentsRemoved)
    }

    @Test
    fun `prepare transcript compacts only when over budget`() {
        val longTranscript =
            "okay okay. patient has fever and cough. patient has fever and cough. " +
                "um. follow up in three days if not improving."

        val prepared = QwenExtractionStrategy.prepareTranscriptForInference(
            transcript = longTranscript,
            charBudget = 70
        )

        assertTrue(prepared.compacted)
        assertTrue(prepared.preparedChars <= 70)
        assertTrue(prepared.duplicateSegmentsRemoved >= 1 || prepared.fillerSegmentsRemoved >= 1 || prepared.clippedToBudget)
    }

    @Test
    fun `response preview normalizes whitespace and clips output`() {
        val preview = QwenExtractionStrategy.responsePreview(
            "line one\n\nline   two\t\tline three",
            maxChars = 18
        )

        assertEquals("line one line two ", preview)
    }

    @Test
    fun `normalize model response strips assistant wrapper and restores opening brace`() {
        val normalized = QwenExtractionStrategy.normalizeModelResponse(
            "<|im_start|>assistant\n  \"chief_complaint\": \"child has fever\"\n}\n<|im_end|>"
        )

        assertEquals("{\"chief_complaint\": \"child has fever\"\n}", normalized)
    }

    @Test
    fun `usable note heuristic accepts headed note with body`() {
        val note = """
            ## Chief Complaint
            - Fever and cough

            ## Plan
            - Start amoxicillin and review in 3 days
        """.trimIndent()

        assertTrue(QwenExtractionStrategy.looksLikeUsableNote(note))
    }

    @Test
    fun `usable note heuristic rejects nearly empty note`() {
        val note = """
            ## Chief Complaint
            -
        """.trimIndent()

        assertFalse(QwenExtractionStrategy.looksLikeUsableNote(note))
    }
}
