package com.chartlite.app

import com.chartlite.app.extraction.ClinicalExtractor
import com.chartlite.app.model.*
import org.junit.Assert.*
import org.junit.Before
import org.junit.Test

class ClinicalExtractorTest {

    private lateinit var extractor: ClinicalExtractor

    private val testFormulary = Formulary(
        version = "test",
        country = "ZA",
        drugs = listOf(
            FormularyDrug("0001", "Amoxicillin", listOf("amoxil", "amoxicillin", "amoxycillin", "amox"),
                listOf("250mg", "500mg"), "PO", "antibiotic", "S4"),
            FormularyDrug("0002", "Metformin", listOf("metformin", "glucophage", "metfin"),
                listOf("500mg", "850mg", "1000mg"), "PO", "antidiabetic", "S3"),
            FormularyDrug("0003", "Paracetamol", listOf("paracetamol", "panado", "acetaminophen", "tylenol"),
                listOf("500mg", "1000mg"), "PO", "analgesic", "S0"),
            FormularyDrug("0004", "Ibuprofen", listOf("ibuprofen", "brufen", "nurofen"),
                listOf("200mg", "400mg"), "PO", "nsaid", "S1"),
            FormularyDrug("0005", "Amlodipine", listOf("amlodipine", "norvasc"),
                listOf("5mg", "10mg"), "PO", "antihypertensive", "S3"),
        )
    )

    private val testIcd10 = ICD10Index(
        version = "test",
        codes = listOf(
            ICD10Entry("J06.9", "Acute upper respiratory infection, unspecified",
                listOf("upper respiratory", "URTI", "cold", "flu", "cough fever", "sore throat"),
                mapOf("zu" to listOf("umkhuhlane", "isifuba"))),
            ICD10Entry("J18.9", "Pneumonia, unspecified organism",
                listOf("pneumonia", "chest infection", "lower respiratory", "LRTI"),
                mapOf("zu" to listOf("inyumoniya"))),
            ICD10Entry("R11", "Nausea and vomiting",
                listOf("vomiting", "vomit", "nausea"),
                mapOf()),
            ICD10Entry("E11", "Type 2 diabetes mellitus",
                listOf("type 2 diabetes", "diabetes mellitus", "sugar diabetes", "T2DM", "diabetes type 2"),
                mapOf("zu" to listOf("ushukela"))),
            ICD10Entry("I10", "Essential hypertension",
                listOf("hypertension", "high blood pressure", "HTN", "elevated blood pressure"),
                mapOf()),
        )
    )

    @Before
    fun setup() {
        extractor = ClinicalExtractor(testFormulary, testIcd10)
    }

    // ── Full Pipeline ──

    @Test
    fun `extract produces encounter with medications and diagnoses`() {
        val encounter = extractor.extract(
            "patient has pneumonia prescribe amoxicillin 500mg twice daily for 7 days",
            "PAT-001", "DR-001", "FAC-001"
        )
        assertTrue("Should extract at least one medication", encounter.medications.isNotEmpty())
        assertTrue("Should extract at least one suggested diagnosis", encounter.suggestedDiagnoses.isNotEmpty())
        assertTrue("Confirmed diagnoses are clinician-selected only", encounter.diagnoses.isEmpty())
        assertEquals("Amoxicillin", encounter.medications[0].name)
    }

    @Test
    fun `extract populates patient provider and facility IDs`() {
        val encounter = extractor.extract(
            "patient has pneumonia",
            "PAT-123", "DR-456", "FAC-789"
        )
        assertEquals("PAT-123", encounter.patientId)
        assertEquals("DR-456", encounter.providerId)
        assertEquals("FAC-789", encounter.facilityId)
    }

    @Test
    fun `extract assigns a UUID as encounter id`() {
        val encounter = extractor.extract(
            "patient has pneumonia",
            "PAT-001", "DR-001", "FAC-001"
        )
        assertTrue("ID should be non-blank", encounter.id.isNotBlank())
        // UUID format: 8-4-4-4-12 hex chars
        assertTrue("ID should look like a UUID",
            encounter.id.matches(Regex("[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}")))
    }

    @Test
    fun `extract captures transcript verbatim`() {
        val transcript = "patient presents with cough and fever bp 120/80"
        val encounter = extractor.extract(transcript, "P", "D", "F")
        assertEquals(transcript, encounter.transcript)
    }

    // ── Allergy Extraction ──

    @Test
    fun `extracts allergy from allergic to pattern`() {
        val encounter = extractor.extract(
            "patient is allergic to penicillin",
            "P", "D", "F"
        )
        assertTrue("Should find penicillin allergy",
            encounter.allergies.any { it.contains("penicillin") })
    }

    @Test
    fun `extracts allergy from known allergy to pattern`() {
        val encounter = extractor.extract(
            "known allergy to sulfa",
            "P", "D", "F"
        )
        assertTrue("Should find sulfa allergy",
            encounter.allergies.any { it.contains("sulfa") })
    }

    @Test
    fun `extracts distinct allergies without duplicates`() {
        val encounter = extractor.extract(
            "patient is allergic to penicillin. penicillin allergy noted.",
            "P", "D", "F"
        )
        val penicillinCount = encounter.allergies.count { it.contains("penicillin") }
        assertEquals("Penicillin should appear only once due to distinct()", 1, penicillinCount)
    }

    @Test
    fun `returns empty allergies when none mentioned`() {
        val encounter = extractor.extract(
            "patient presents with headache",
            "P", "D", "F"
        )
        assertTrue("Allergies should be empty", encounter.allergies.isEmpty())
    }

    // ── Follow-Up Extraction ──

    @Test
    fun `extracts follow up come back in 7 days`() {
        val encounter = extractor.extract(
            "come back in 7 days",
            "P", "D", "F"
        )
        assertNotNull("Should find follow-up", encounter.followUp)
        assertEquals(7, encounter.followUp!!.days)
    }

    @Test
    fun `extracts follow up in 2 weeks as 14 days`() {
        val encounter = extractor.extract(
            "follow-up in 2 weeks",
            "P", "D", "F"
        )
        assertNotNull("Should find follow-up", encounter.followUp)
        assertEquals(14, encounter.followUp!!.days)
    }

    @Test
    fun `extracts follow up return in 1 month as 30 days`() {
        val encounter = extractor.extract(
            "return in 1 month",
            "P", "D", "F"
        )
        assertNotNull("Should find follow-up", encounter.followUp)
        assertEquals(30, encounter.followUp!!.days)
    }

    @Test
    fun `follow up is null when not mentioned`() {
        val encounter = extractor.extract(
            "patient has headache prescribe paracetamol 500mg",
            "P", "D", "F"
        )
        assertNull("Follow-up should be null", encounter.followUp)
    }

    @Test
    fun `vector store does not add diagnosis guesses in regex fallback`() {
        val vectorStore = com.chartlite.app.extraction.ClinicalVectorStore(testIcd10, testFormulary)
        vectorStore.buildIndex()
        val conservativeExtractor = ClinicalExtractor(testFormulary, testIcd10, vectorStore)

        val encounter = conservativeExtractor.extract(
            "good morning doctor please come back in three days if not improving",
            "P", "D", "F"
        )

        assertTrue("Fallback suggestions should stay empty without explicit diagnosis evidence",
            encounter.suggestedDiagnoses.isEmpty())
    }

    // ── Referral Extraction ──

    @Test
    fun `extracts referral to hospital`() {
        val encounter = extractor.extract(
            "refer patient to hospital for further care",
            "P", "D", "F"
        )
        assertNotNull("Should find referral", encounter.referral)
        assertEquals("hospital", encounter.referral!!.type)
    }

    @Test
    fun `extracts urgent referral`() {
        val encounter = extractor.extract(
            "urgent refer to hospital",
            "P", "D", "F"
        )
        assertNotNull("Should find referral", encounter.referral)
        assertEquals("urgent", encounter.referral!!.urgency)
    }

    @Test
    fun `extracts emergency referral from emergent keyword`() {
        val encounter = extractor.extract(
            "emergent refer to hospital immediately",
            "P", "D", "F"
        )
        assertNotNull("Should find referral", encounter.referral)
        assertEquals("emergency", encounter.referral!!.urgency)
    }

    @Test
    fun `extracts referral specialty cardiologist`() {
        val encounter = extractor.extract(
            "refer to cardiologist for evaluation",
            "P", "D", "F"
        )
        assertNotNull("Should find referral", encounter.referral)
        assertEquals("cardiologist", encounter.referral!!.specialty)
    }

    @Test
    fun `referral is null when refer keyword absent`() {
        val encounter = extractor.extract(
            "patient should see a specialist next week",
            "P", "D", "F"
        )
        assertNull("Referral should be null without 'refer' keyword", encounter.referral)
    }

    // ── Confidence and Edge Cases ──

    @Test
    fun `extraction confidence is between 0 and 1`() {
        val encounter = extractor.extract(
            "patient has pneumonia prescribe amoxicillin 500mg twice daily",
            "P", "D", "F"
        )
        assertTrue("Confidence should be >= 0", encounter.extractionConfidence >= 0f)
        assertTrue("Confidence should be <= 1", encounter.extractionConfidence <= 1f)
    }

    @Test
    fun `confidence is 0 point 5 when nothing extracted`() {
        val encounter = extractor.extract(
            "the quick brown fox jumped over the lazy dog",
            "P", "D", "F"
        )
        assertEquals("Should default to 0.5 when no meds or dx found",
            0.5f, encounter.extractionConfidence, 0.01f)
    }

    @Test
    fun `handles empty transcript gracefully`() {
        val encounter = extractor.extract("", "P", "D", "F")
        assertTrue("Medications should be empty", encounter.medications.isEmpty())
        assertTrue("Diagnoses should be empty", encounter.diagnoses.isEmpty())
        assertTrue("Allergies should be empty", encounter.allergies.isEmpty())
        assertNull("Follow-up should be null", encounter.followUp)
        assertNull("Referral should be null", encounter.referral)
        assertEquals(0.5f, encounter.extractionConfidence, 0.01f)
    }

    @Test
    fun `transcript with only vitals has 0 point 5 confidence`() {
        val encounter = extractor.extract(
            "bp 130/85 temp 37.2 pulse 78",
            "P", "D", "F"
        )
        // Vitals do not contribute to medication/diagnosis confidence list
        assertEquals("Should be 0.5 when only vitals present",
            0.5f, encounter.extractionConfidence, 0.01f)
    }

    @Test
    fun `freeTextNote builds concise ambient summary`() {
        val transcript = "patient has pneumonia allergic to penicillin come back in 7 days"
        val encounter = extractor.extract(transcript, "P", "D", "F")
        assertTrue(encounter.freeTextNote.contains("Chief concern:"))
        assertTrue(encounter.freeTextNote.contains("Suggested diagnoses:"))
        assertTrue(encounter.freeTextNote.contains("Follow-up planned in 7 days"))
        assertTrue(encounter.freeTextNote.length <= 1000)
    }

    @Test
    fun `freeTextNote skips greeting and negated vomiting in fallback summary`() {
        val transcript = """
            Good morning doctor. The child has had fever and cough for three days. No vomiting.
            Okay, let us start amoxicillin 500 mg three times daily for five days and paracetamol as needed.
            Please come back in three days if not improving.
        """.trimIndent()

        val encounter = extractor.extract(transcript, "P", "D", "F")

        assertTrue(encounter.freeTextNote.contains("Chief concern: The child has had fever and cough for three days"))
        assertFalse(encounter.freeTextNote.contains("Chief concern: Good morning doctor"))
        assertFalse(encounter.suggestedDiagnoses.any { it.icd10Code == "R11" })
    }
}
