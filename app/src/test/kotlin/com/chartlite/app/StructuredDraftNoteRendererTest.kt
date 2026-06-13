package com.chartlite.app

import com.chartlite.app.extraction.StructuredDraftNoteRenderer
import com.chartlite.app.model.Diagnosis
import com.chartlite.app.model.FollowUp
import com.chartlite.app.model.Investigation
import com.chartlite.app.model.Medication
import com.chartlite.app.model.StructuredEncounter
import com.chartlite.app.model.VitalSigns
import org.junit.Assert.assertFalse
import org.junit.Assert.assertNull
import org.junit.Assert.assertTrue
import org.junit.Test
import java.time.Instant

class StructuredDraftNoteRendererTest {

    @Test
    fun `renderer builds markdown note from extracted fields`() {
        val encounter = StructuredEncounter(
            id = "enc-1",
            patientId = "pat-1",
            providerId = "prov-1",
            facilityId = "fac-1",
            timestamp = Instant.parse("2026-03-20T00:00:00Z"),
            transcript = "child with fever and cough",
            medications = listOf(
                Medication(
                    formularyCode = "AMX001",
                    name = "Amoxicillin",
                    dose = 500f,
                    unit = "mg",
                    frequency = "three times daily",
                    duration = 5,
                    route = "PO"
                )
            ),
            diagnoses = emptyList(),
            vitals = VitalSigns(temperature = 38.2f, pulse = 104),
            allergies = listOf("Penicillin"),
            followUp = FollowUp(days = 3, reason = "if not improving"),
            referral = null,
            freeTextNote = "Fever and cough",
            extractionConfidence = 0.8f,
            examFindings = listOf("Chest clear", "No wheeze"),
            investigations = listOf(Investigation(test = "Malaria RDT", result = "Negative")),
            plan = listOf("Oral fluids", "Rest"),
            socialHistory = listOf("Lives with family"),
            suggestedDiagnoses = listOf(Diagnosis("J18.9", "Pneumonia", isPrimary = true))
        )

        val note = StructuredDraftNoteRenderer.render(encounter)

        requireNotNull(note)
        assertTrue(note.contains("## Chief Complaint"))
        assertTrue(note.contains("- Fever and cough"))
        assertTrue(note.contains("## Vitals"))
        assertTrue(note.contains("Temperature: 38.2 C"))
        assertTrue(note.contains("## Assessment"))
        assertTrue(note.contains("Suggested diagnosis: Pneumonia"))
        assertTrue(note.contains("Medication: Amoxicillin 500 mg"))
        assertTrue(note.contains("## Follow-up"))
    }

    @Test
    fun `renderer returns null for empty encounter`() {
        val encounter = StructuredEncounter(
            id = "enc-2",
            patientId = "pat-1",
            providerId = "prov-1",
            facilityId = "fac-1",
            timestamp = Instant.parse("2026-03-20T00:00:00Z"),
            transcript = "",
            medications = emptyList(),
            diagnoses = emptyList(),
            vitals = null,
            allergies = emptyList(),
            followUp = null,
            referral = null,
            freeTextNote = "",
            extractionConfidence = 0f
        )

        val note = StructuredDraftNoteRenderer.render(encounter)

        assertNull(note)
    }

    @Test
    fun `renderer does not invent nkda`() {
        val encounter = StructuredEncounter(
            id = "enc-3",
            patientId = "pat-1",
            providerId = "prov-1",
            facilityId = "fac-1",
            timestamp = Instant.parse("2026-03-20T00:00:00Z"),
            transcript = "",
            medications = emptyList(),
            diagnoses = emptyList(),
            vitals = null,
            allergies = emptyList(),
            followUp = null,
            referral = null,
            freeTextNote = "Headache",
            extractionConfidence = 0.5f
        )

        val note = StructuredDraftNoteRenderer.render(encounter)

        requireNotNull(note)
        assertFalse(note.contains("NKDA"))
    }
}
