package com.chartlite.app

import com.chartlite.app.billing.SOAPNoteGenerator
import com.chartlite.app.billing.SOAPNoteGenerator.SOAPNote
import com.chartlite.app.model.*
import org.junit.Assert.*
import org.junit.Test

class SOAPNoteGeneratorTest {

    // ───────────────────────────────────────────────
    // Helper — generate with sensible defaults
    // ───────────────────────────────────────────────

    private fun generate(
        encounter: com.chartlite.app.database.entity.EncounterEntity =
            TestFixtures.buildEncounterEntity(),
        diagnoses: List<Diagnosis> = TestFixtures.sampleDiagnoses(),
        medications: List<Medication> = TestFixtures.sampleMedications(),
        vitals: VitalSigns? = TestFixtures.sampleVitals(),
        allergies: List<String> = listOf("penicillin"),
        alerts: List<CDSSAlert> = emptyList(),
        patientName: String = "Sipho Dlamini",
        providerName: String = "Dr. Nkosi"
    ): SOAPNote = SOAPNoteGenerator.generate(
        encounter, diagnoses, medications, vitals, allergies, alerts, patientName, providerName
    )

    // ═══════════════════════════════════════════════
    //  SUBJECTIVE section
    // ═══════════════════════════════════════════════

    @Test
    fun `subjective contains chief complaint header`() {
        val note = generate()
        assertTrue(note.subjective.contains("Chief Complaint"))
    }

    @Test
    fun `subjective includes transcript text as chief complaint`() {
        val note = generate()
        assertTrue(note.subjective.contains("cough and fever"))
    }

    @Test
    fun `subjective truncates chief complaint around 300 chars`() {
        val longTranscript = "A".repeat(500)
        val enc = TestFixtures.buildEncounterEntity(transcript = longTranscript)
        val note = generate(encounter = enc)
        // The quoted chief complaint should not contain all 500 chars
        val quotedSection = note.subjective.substringAfter("\"").substringBefore("\"")
        assertTrue(quotedSection.length <= 310)
    }

    @Test
    fun `subjective contains HPI header`() {
        val note = generate()
        assertTrue(note.subjective.contains("History of Present Illness"))
    }

    @Test
    fun `subjective uses freeTextNote when present`() {
        val enc = TestFixtures.buildEncounterEntity(
            transcript = "original transcript",
            freeTextNote = "Free text note override"
        )
        val note = generate(encounter = enc)
        assertTrue(note.subjective.contains("Free text note override"))
    }

    @Test
    fun `subjective falls back to transcript when freeTextNote is blank`() {
        val enc = TestFixtures.buildEncounterEntity(
            transcript = "transcript content here",
            freeTextNote = ""
        )
        val note = generate(encounter = enc)
        assertTrue(note.subjective.contains("transcript content here"))
    }

    @Test
    fun `subjective shows allergies when provided`() {
        val note = generate(allergies = listOf("penicillin", "aspirin"))
        assertTrue(note.subjective.contains("penicillin"))
        assertTrue(note.subjective.contains("aspirin"))
    }

    @Test
    fun `subjective shows NKDA when no allergies`() {
        val note = generate(allergies = emptyList())
        assertTrue(note.subjective.contains("NKDA"))
    }

    @Test
    fun `subjective shows default HPI text when transcript is blank`() {
        val enc = TestFixtures.buildEncounterEntity(transcript = "", freeTextNote = "")
        val note = generate(encounter = enc)
        assertTrue(note.subjective.contains("Per clinical encounter documentation"))
    }

    // ═══════════════════════════════════════════════
    //  OBJECTIVE section — vital signs
    // ═══════════════════════════════════════════════

    @Test
    fun `objective contains vital signs header`() {
        val note = generate()
        assertTrue(note.objective.contains("Vital Signs"))
    }

    @Test
    fun `objective shows BP with category`() {
        val note = generate()
        // 130/85 => Stage 1 Hypertension (130 >= 130)
        assertTrue(note.objective.contains("130/85 mmHg"))
        assertTrue(note.objective.contains("Stage 1 Hypertension"))
    }

    @Test
    fun `objective shows normal BP category`() {
        val vitals = VitalSigns(systolicBP = 118, diastolicBP = 75)
        val note = generate(vitals = vitals)
        assertTrue(note.objective.contains("Normal"))
    }

    @Test
    fun `objective shows elevated BP category`() {
        val vitals = VitalSigns(systolicBP = 125, diastolicBP = 78)
        val note = generate(vitals = vitals)
        assertTrue(note.objective.contains("Elevated"))
    }

    @Test
    fun `objective shows stage 2 hypertension`() {
        val vitals = VitalSigns(systolicBP = 145, diastolicBP = 95)
        val note = generate(vitals = vitals)
        assertTrue(note.objective.contains("Stage 2 Hypertension"))
    }

    @Test
    fun `objective shows hypertensive crisis`() {
        val vitals = VitalSigns(systolicBP = 185, diastolicBP = 125)
        val note = generate(vitals = vitals)
        assertTrue(note.objective.contains("HYPERTENSIVE CRISIS"))
    }

    @Test
    fun `objective flags tachycardia when pulse above 100`() {
        val vitals = VitalSigns(pulse = 110)
        val note = generate(vitals = vitals)
        assertTrue(note.objective.contains("tachycardic"))
    }

    @Test
    fun `objective flags bradycardia when pulse below 60`() {
        val vitals = VitalSigns(pulse = 55)
        val note = generate(vitals = vitals)
        assertTrue(note.objective.contains("bradycardic"))
    }

    @Test
    fun `objective shows regular pulse for normal range`() {
        val vitals = VitalSigns(pulse = 80)
        val note = generate(vitals = vitals)
        assertTrue(note.objective.contains("regular"))
    }

    @Test
    fun `objective flags febrile temperature above 38`() {
        val vitals = VitalSigns(temperature = 39.2f)
        val note = generate(vitals = vitals)
        assertTrue(note.objective.contains("febrile"))
    }

    @Test
    fun `objective shows afebrile for normal temperature`() {
        val vitals = VitalSigns(temperature = 36.8f)
        val note = generate(vitals = vitals)
        assertTrue(note.objective.contains("afebrile"))
    }

    @Test
    fun `objective flags hypoxic SpO2 below 95`() {
        val vitals = VitalSigns(oxygenSaturation = 91)
        val note = generate(vitals = vitals)
        assertTrue(note.objective.contains("hypoxic"))
    }

    @Test
    fun `objective shows normal SpO2 at or above 95`() {
        val vitals = VitalSigns(oxygenSaturation = 98)
        val note = generate(vitals = vitals)
        assertTrue(note.objective.contains("normal"))
    }

    @Test
    fun `objective calculates and categorises BMI`() {
        val vitals = VitalSigns(weight = 72f, height = 175f)
        val note = generate(vitals = vitals)
        // BMI = 72 / (1.75^2) = 23.5 => Normal
        assertTrue(note.objective.contains("BMI"))
        assertTrue(note.objective.contains("Normal"))
    }

    @Test
    fun `objective shows overweight BMI category`() {
        val vitals = VitalSigns(weight = 85f, height = 170f)
        val note = generate(vitals = vitals)
        // BMI = 85 / (1.70^2) = 29.4 => Overweight
        assertTrue(note.objective.contains("Overweight"))
    }

    @Test
    fun `objective shows not recorded when vitals are null`() {
        val note = generate(vitals = null)
        assertTrue(note.objective.contains("Not recorded"))
    }

    // ═══════════════════════════════════════════════
    //  ASSESSMENT section
    // ═══════════════════════════════════════════════

    @Test
    fun `assessment lists diagnoses with ICD-10 codes`() {
        val note = generate()
        assertTrue(note.assessment.contains("J18.9"))
        assertTrue(note.assessment.contains("I10"))
    }

    @Test
    fun `assessment marks primary diagnosis`() {
        val note = generate()
        assertTrue(note.assessment.contains("[PRIMARY]"))
    }

    @Test
    fun `assessment shows confidence percentage`() {
        val note = generate()
        // 0.9f => "90%"
        assertTrue(note.assessment.contains("90%"))
    }

    @Test
    fun `assessment shows no formal diagnoses when list is empty`() {
        val note = generate(diagnoses = emptyList())
        assertTrue(note.assessment.contains("No formal diagnoses"))
    }

    @Test
    fun `assessment includes CDSS alerts`() {
        val alerts = listOf(
            CDSSAlert(AlertSeverity.CRITICAL, "drug-allergy", "Penicillin allergy alert")
        )
        val note = generate(alerts = alerts)
        assertTrue(note.assessment.contains("CRITICAL"))
        assertTrue(note.assessment.contains("Penicillin allergy alert"))
    }

    @Test
    fun `assessment includes warning severity alerts`() {
        val alerts = listOf(
            CDSSAlert(AlertSeverity.WARNING, "dosage", "High dose warning")
        )
        val note = generate(alerts = alerts)
        assertTrue(note.assessment.contains("WARNING"))
        assertTrue(note.assessment.contains("High dose warning"))
    }

    @Test
    fun `assessment includes info severity alerts`() {
        val alerts = listOf(
            CDSSAlert(AlertSeverity.INFO, "guideline", "Consider screening")
        )
        val note = generate(alerts = alerts)
        assertTrue(note.assessment.contains("INFO"))
    }

    // ═══════════════════════════════════════════════
    //  PLAN section
    // ═══════════════════════════════════════════════

    @Test
    fun `plan lists medications with dosage`() {
        val note = generate()
        assertTrue(note.plan.contains("Amoxicillin"))
        assertTrue(note.plan.contains("500"))
        assertTrue(note.plan.contains("TDS"))
    }

    @Test
    fun `plan includes duration in days`() {
        val note = generate()
        assertTrue(note.plan.contains("7 days"))
    }

    @Test
    fun `plan shows follow-up information`() {
        val note = generate()
        assertTrue(note.plan.contains("Return in 7 days"))
    }

    @Test
    fun `plan shows follow-up reason when provided`() {
        val note = generate()
        assertTrue(note.plan.contains("review chest X-ray"))
    }

    @Test
    fun `plan shows referral when present`() {
        val enc = TestFixtures.buildEncounterEntity(
            referralType = "specialist",
            referralSpecialty = "cardiology",
            referralUrgency = "urgent",
            referralReason = "Uncontrolled hypertension"
        )
        val note = generate(encounter = enc)
        assertTrue(note.plan.contains("Refer to"))
        assertTrue(note.plan.contains("cardiology"))
        assertTrue(note.plan.contains("urgent"))
        assertTrue(note.plan.contains("Uncontrolled hypertension"))
    }

    @Test
    fun `plan includes patient education for each diagnosis`() {
        val note = generate()
        assertTrue(note.plan.contains("Patient Education"))
        assertTrue(note.plan.contains("Pneumonia"))
        assertTrue(note.plan.contains("hypertension"))
    }

    @Test
    fun `plan includes medication instructions note when meds present`() {
        val note = generate()
        assertTrue(note.plan.contains("Medication instructions provided"))
    }

    // ═══════════════════════════════════════════════
    //  fullText and wordCount
    // ═══════════════════════════════════════════════

    @Test
    fun `fullText contains all four SOAP section headers`() {
        val note = generate()
        assertTrue(note.fullText.contains("SUBJECTIVE"))
        assertTrue(note.fullText.contains("OBJECTIVE"))
        assertTrue(note.fullText.contains("ASSESSMENT"))
        assertTrue(note.fullText.contains("PLAN"))
    }

    @Test
    fun `fullText contains patient name`() {
        val note = generate(patientName = "Sipho Dlamini")
        assertTrue(note.fullText.contains("Sipho Dlamini"))
    }

    @Test
    fun `fullText contains provider name`() {
        val note = generate(providerName = "Dr. Nkosi")
        assertTrue(note.fullText.contains("Dr. Nkosi"))
    }

    @Test
    fun `fullText contains facility ID`() {
        val note = generate()
        assertTrue(note.fullText.contains("fac-001"))
    }

    @Test
    fun `fullText contains ChartLite signature`() {
        val note = generate()
        assertTrue(note.fullText.contains("ChartLite"))
    }

    @Test
    fun `fullText contains electronically signed line`() {
        val note = generate(providerName = "Dr. Nkosi")
        assertTrue(note.fullText.contains("Electronically signed by Dr. Nkosi"))
    }

    @Test
    fun `wordCount is positive for a non-empty note`() {
        val note = generate()
        assertTrue(note.wordCount > 0)
    }

    @Test
    fun `wordCount matches whitespace split of fullText`() {
        val note = generate()
        val expected = note.fullText.split("\\s+".toRegex()).size
        assertEquals(expected, note.wordCount)
    }

    @Test
    fun `wordCount increases with more content`() {
        val minimal = generate(
            diagnoses = emptyList(),
            medications = emptyList(),
            vitals = null,
            allergies = emptyList(),
            alerts = emptyList()
        )
        val full = generate()
        assertTrue(full.wordCount > minimal.wordCount)
    }
}
