package com.chartlite.app

import com.chartlite.app.extraction.AmbientTranscriptOptimizer
import org.junit.Assert.assertEquals
import org.junit.Assert.assertFalse
import org.junit.Assert.assertTrue
import org.junit.Test

class AmbientTranscriptOptimizerTest {

    @Test
    fun `removes filler and duplicate ambient segments`() {
        val transcript =
            "okay okay. patient has fever for three days. patient has fever for three days. " +
                "um alright. start paracetamol 500 mg three times daily."

        val result = AmbientTranscriptOptimizer.optimize(transcript, charBudget = 300)

        assertTrue(result.optimizedTranscript.contains("patient has fever for three days"))
        assertTrue(result.optimizedTranscript.contains("paracetamol 500 mg"))
        assertFalse(result.optimizedTranscript.contains("okay okay"))
        assertEquals(1, result.duplicateSegmentsRemoved)
        assertTrue(result.fillerSegmentsRemoved >= 1)
    }

    @Test
    fun `keeps medication and follow up plan when budget is tight`() {
        val transcript =
            "hello hello. okay. patient reports cough for five days with fever. " +
                "alright. the chest is clear today. okay okay. " +
                "start amoxicillin 500 mg three times daily for five days. " +
                "follow up in three days if not improving."

        val result = AmbientTranscriptOptimizer.optimize(transcript, charBudget = 150)

        assertTrue(result.clippedToBudget)
        assertTrue(result.optimizedTranscript.contains("amoxicillin 500 mg"))
        assertTrue(result.optimizedTranscript.contains("follow up"))
    }
}
