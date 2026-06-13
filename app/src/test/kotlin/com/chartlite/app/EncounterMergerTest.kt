package com.chartlite.app

import com.chartlite.app.extraction.EncounterMerger
import com.chartlite.app.model.*
import org.junit.Assert.*
import org.junit.Test
import java.time.Instant

class EncounterMergerTest {

    private fun buildEncounter(
        id: String = "enc-001",
        medications: List<Medication> = emptyList(),
        diagnoses: List<Diagnosis> = emptyList(),
        vitals: VitalSigns? = null,
        allergies: List<String> = emptyList(),
        followUp: FollowUp? = null,
        referral: Referral? = null,
        transcript: String = "",
        freeTextNote: String = "",
        confidence: Float = 0.8f
    ) = StructuredEncounter(
        id = id,
        patientId = "KFMT-4WRN",
        providerId = "prov-001",
        facilityId = "fac-001",
        timestamp = Instant.parse("2025-06-15T10:30:00Z"),
        transcript = transcript,
        medications = medications,
        diagnoses = diagnoses,
        vitals = vitals,
        allergies = allergies,
        followUp = followUp,
        referral = referral,
        freeTextNote = freeTextNote,
        extractionConfidence = confidence
    )

    // ── Medication merging ──

    @Test
    fun `merge adds new medications from snippet`() {
        val base = buildEncounter(medications = listOf(
            Medication("0001", "Amoxicillin", 500f, "mg", "TDS", 7, "PO", 0.9f)
        ))
        val snippet = buildEncounter(medications = listOf(
            Medication("0005", "Amlodipine", 5f, "mg", "OD", 30, "PO", 0.85f)
        ))
        val merged = EncounterMerger.merge(base, snippet)
        assertEquals(2, merged.medications.size)
        assertTrue(merged.medications.any { it.formularyCode == "0001" })
        assertTrue(merged.medications.any { it.formularyCode == "0005" })
    }

    @Test
    fun `merge keeps higher confidence medication on duplicate`() {
        val base = buildEncounter(medications = listOf(
            Medication("0001", "Amoxicillin", 500f, "mg", "TDS", 7, "PO", 0.7f)
        ))
        val snippet = buildEncounter(medications = listOf(
            Medication("0001", "Amoxicillin", 500f, "mg", "BD", 5, "PO", 0.9f)
        ))
        val merged = EncounterMerger.merge(base, snippet)
        assertEquals(1, merged.medications.size)
        assertEquals(0.9f, merged.medications[0].confidence)
        assertEquals("BD", merged.medications[0].frequency) // Snippet's higher-confidence version wins
    }

    @Test
    fun `merge preserves base medication when its confidence is higher`() {
        val base = buildEncounter(medications = listOf(
            Medication("0001", "Amoxicillin", 500f, "mg", "TDS", 7, "PO", 0.95f)
        ))
        val snippet = buildEncounter(medications = listOf(
            Medication("0001", "Amoxicillin", 250f, "mg", "BD", 5, "PO", 0.6f)
        ))
        val merged = EncounterMerger.merge(base, snippet)
        assertEquals(1, merged.medications.size)
        assertEquals(0.95f, merged.medications[0].confidence)
        assertEquals("TDS", merged.medications[0].frequency) // Base's higher-confidence version kept
    }

    // ── Diagnosis merging ──

    @Test
    fun `merge adds new diagnoses from snippet`() {
        val base = buildEncounter(diagnoses = listOf(
            Diagnosis("I10", "Hypertension", true, 0.9f)
        ))
        val snippet = buildEncounter(diagnoses = listOf(
            Diagnosis("E11.9", "Diabetes", false, 0.8f)
        ))
        val merged = EncounterMerger.merge(base, snippet)
        assertEquals(2, merged.diagnoses.size)
    }

    @Test
    fun `merge deduplicates diagnoses by ICD-10 code`() {
        val base = buildEncounter(diagnoses = listOf(
            Diagnosis("I10", "Hypertension", true, 0.7f)
        ))
        val snippet = buildEncounter(diagnoses = listOf(
            Diagnosis("I10", "Hypertension", false, 0.9f)
        ))
        val merged = EncounterMerger.merge(base, snippet)
        assertEquals(1, merged.diagnoses.size)
        assertEquals(0.9f, merged.diagnoses[0].confidence) // Higher confidence wins
    }

    // ── Vitals merging ──

    @Test
    fun `merge vitals - snippet overrides base values`() {
        val base = buildEncounter(vitals = VitalSigns(systolicBP = 120, diastolicBP = 80, pulse = 75))
        val snippet = buildEncounter(vitals = VitalSigns(systolicBP = 168, diastolicBP = 98))
        val merged = EncounterMerger.merge(base, snippet)
        assertNotNull(merged.vitals)
        assertEquals(168, merged.vitals!!.systolicBP)  // Snippet overrides
        assertEquals(98, merged.vitals!!.diastolicBP)   // Snippet overrides
        assertEquals(75, merged.vitals!!.pulse)          // Base preserved (snippet null)
    }

    @Test
    fun `merge vitals - null snippet preserves base`() {
        val base = buildEncounter(vitals = VitalSigns(systolicBP = 120, pulse = 75))
        val snippet = buildEncounter(vitals = null)
        val merged = EncounterMerger.merge(base, snippet)
        assertNotNull(merged.vitals)
        assertEquals(120, merged.vitals!!.systolicBP)
        assertEquals(75, merged.vitals!!.pulse)
    }

    @Test
    fun `merge vitals - null base with snippet`() {
        val base = buildEncounter(vitals = null)
        val snippet = buildEncounter(vitals = VitalSigns(temperature = 38.5f))
        val merged = EncounterMerger.merge(base, snippet)
        assertNotNull(merged.vitals)
        assertEquals(38.5f, merged.vitals!!.temperature!!, 0.01f)
    }

    @Test
    fun `merge vitals - both null stays null`() {
        val base = buildEncounter(vitals = null)
        val snippet = buildEncounter(vitals = null)
        val merged = EncounterMerger.merge(base, snippet)
        assertNull(merged.vitals)
    }

    // ── Allergies merging ──

    @Test
    fun `merge unions allergies and deduplicates`() {
        val base = buildEncounter(allergies = listOf("penicillin", "nsaid"))
        val snippet = buildEncounter(allergies = listOf("nsaid", "latex"))
        val merged = EncounterMerger.merge(base, snippet)
        assertEquals(3, merged.allergies.size)
        assertTrue(merged.allergies.containsAll(listOf("penicillin", "nsaid", "latex")))
    }

    @Test
    fun `merge with empty allergies`() {
        val base = buildEncounter(allergies = listOf("penicillin"))
        val snippet = buildEncounter(allergies = emptyList())
        val merged = EncounterMerger.merge(base, snippet)
        assertEquals(1, merged.allergies.size)
        assertEquals("penicillin", merged.allergies[0])
    }

    // ── Follow-up merging ──

    @Test
    fun `merge follow-up - last non-null wins`() {
        val base = buildEncounter(followUp = FollowUp(7, "review"))
        val snippet = buildEncounter(followUp = FollowUp(14, "lab results"))
        val merged = EncounterMerger.merge(base, snippet)
        assertEquals(14, merged.followUp!!.days)
        assertEquals("lab results", merged.followUp!!.reason)
    }

    @Test
    fun `merge follow-up - null snippet preserves base`() {
        val base = buildEncounter(followUp = FollowUp(7, "review"))
        val snippet = buildEncounter(followUp = null)
        val merged = EncounterMerger.merge(base, snippet)
        assertEquals(7, merged.followUp!!.days)
    }

    @Test
    fun `merge follow-up - snippet sets when base is null`() {
        val base = buildEncounter(followUp = null)
        val snippet = buildEncounter(followUp = FollowUp(14))
        val merged = EncounterMerger.merge(base, snippet)
        assertEquals(14, merged.followUp!!.days)
    }

    // ── Referral merging ──

    @Test
    fun `merge referral - last non-null wins`() {
        val base = buildEncounter(referral = Referral("hospital", "cardiology", "routine"))
        val snippet = buildEncounter(referral = Referral("specialist", "nephrology", "urgent"))
        val merged = EncounterMerger.merge(base, snippet)
        assertEquals("specialist", merged.referral!!.type)
        assertEquals("nephrology", merged.referral!!.specialty)
        assertEquals("urgent", merged.referral!!.urgency)
    }

    @Test
    fun `merge referral - null snippet preserves base`() {
        val base = buildEncounter(referral = Referral("hospital", "cardiology", "routine"))
        val snippet = buildEncounter(referral = null)
        val merged = EncounterMerger.merge(base, snippet)
        assertEquals("cardiology", merged.referral!!.specialty)
    }

    // ── Transcript concatenation ──

    @Test
    fun `merge concatenates transcripts with newline`() {
        val base = buildEncounter(transcript = "BP 168 over 98")
        val snippet = buildEncounter(transcript = "amoxicillin 500mg TDS")
        val merged = EncounterMerger.merge(base, snippet)
        assertEquals("BP 168 over 98\namoxicillin 500mg TDS", merged.transcript)
    }

    @Test
    fun `merge skips blank transcripts in concatenation`() {
        val base = buildEncounter(transcript = "BP 168 over 98")
        val snippet = buildEncounter(transcript = "")
        val merged = EncounterMerger.merge(base, snippet)
        assertEquals("BP 168 over 98", merged.transcript)
    }

    // ── Confidence averaging ──

    @Test
    fun `merge averages extraction confidence`() {
        val base = buildEncounter(confidence = 0.8f)
        val snippet = buildEncounter(confidence = 0.6f)
        val merged = EncounterMerger.merge(base, snippet)
        assertEquals(0.7f, merged.extractionConfidence, 0.01f)
    }

    // ── Identity preservation ──

    @Test
    fun `merge keeps base encounter id and metadata`() {
        val base = buildEncounter(id = "enc-base-001")
        val snippet = buildEncounter(id = "enc-snippet-999")
        val merged = EncounterMerger.merge(base, snippet)
        assertEquals("enc-base-001", merged.id)
        assertEquals("KFMT-4WRN", merged.patientId)
        assertEquals("prov-001", merged.providerId)
        assertEquals("fac-001", merged.facilityId)
    }

    // ── Multi-snippet sequential merge ──

    @Test
    fun `three snippets merged sequentially accumulate all data`() {
        val snippet1 = buildEncounter(
            vitals = VitalSigns(systolicBP = 168, diastolicBP = 98, pulse = 92),
            transcript = "BP 168 over 98, pulse 92"
        )
        val snippet2 = buildEncounter(
            medications = listOf(
                Medication("0001", "Amoxicillin", 500f, "mg", "TDS", 7, "PO", 0.85f)
            ),
            transcript = "amoxicillin 500mg three times daily for 7 days"
        )
        val snippet3 = buildEncounter(
            diagnoses = listOf(
                Diagnosis("I10", "Hypertension", true, 0.9f)
            ),
            followUp = FollowUp(14, "review BP"),
            transcript = "diagnosis hypertension, follow up 2 weeks"
        )

        var accumulated = snippet1
        accumulated = EncounterMerger.merge(accumulated, snippet2)
        accumulated = EncounterMerger.merge(accumulated, snippet3)

        // All data accumulated
        assertEquals(168, accumulated.vitals!!.systolicBP)
        assertEquals(98, accumulated.vitals!!.diastolicBP)
        assertEquals(92, accumulated.vitals!!.pulse)
        assertEquals(1, accumulated.medications.size)
        assertEquals("Amoxicillin", accumulated.medications[0].name)
        assertEquals(1, accumulated.diagnoses.size)
        assertEquals("I10", accumulated.diagnoses[0].icd10Code)
        assertEquals(14, accumulated.followUp!!.days)

        // Transcript accumulated
        assertTrue(accumulated.transcript.contains("BP 168 over 98"))
        assertTrue(accumulated.transcript.contains("amoxicillin"))
        assertTrue(accumulated.transcript.contains("hypertension"))
    }

    // ── Empty snippet handling ──

    @Test
    fun `merge with empty snippet is essentially no-op`() {
        val base = buildEncounter(
            medications = listOf(Medication("0001", "Amoxicillin", 500f, "mg", "TDS", 7, "PO", 0.9f)),
            diagnoses = listOf(Diagnosis("I10", "Hypertension", true, 0.85f)),
            vitals = VitalSigns(systolicBP = 130, pulse = 80),
            allergies = listOf("penicillin"),
            followUp = FollowUp(7),
            transcript = "existing data"
        )
        val emptySnippet = buildEncounter()
        val merged = EncounterMerger.merge(base, emptySnippet)

        assertEquals(1, merged.medications.size)
        assertEquals(1, merged.diagnoses.size)
        assertEquals(130, merged.vitals!!.systolicBP)
        assertEquals(80, merged.vitals!!.pulse)
        assertEquals(1, merged.allergies.size)
        assertEquals(7, merged.followUp!!.days)
    }

    // ── mergeVitals standalone ──

    @Test
    fun `mergeVitals combines fields from both`() {
        val base = VitalSigns(systolicBP = 120, diastolicBP = 80)
        val snippet = VitalSigns(temperature = 38.5f, pulse = 92)
        val merged = EncounterMerger.mergeVitals(base, snippet)
        assertNotNull(merged)
        assertEquals(120, merged!!.systolicBP)       // From base
        assertEquals(80, merged.diastolicBP)          // From base
        assertEquals(38.5f, merged.temperature!!, 0.01f) // From snippet
        assertEquals(92, merged.pulse)                 // From snippet
    }
}
