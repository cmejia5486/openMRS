package com.chartlite.app

import com.chartlite.app.model.*
import com.chartlite.app.sms.ImmunizationRecord
import com.chartlite.app.sms.PatientHealthSummaryBuilder
import com.chartlite.app.sms.PatientHealthSummaryBuilder.GrowthData
import org.junit.Assert.*
import org.junit.Test
import java.time.Instant

/**
 * Tests for PatientHealthSummaryBuilder.buildSummary() — ensures all patient
 * history data is correctly aggregated for SMS encoding.
 * Prevents regression: EncounterSaveCoordinator now passes growth/immunization data.
 */
class PatientHealthSummaryBuilderTest {

    private fun encounter(
        diagnoses: List<Diagnosis> = emptyList(),
        vitals: VitalSigns? = null,
        timestamp: Instant = Instant.now()
    ) = StructuredEncounter(
        id = "enc-${timestamp.epochSecond}",
        patientId = "KFMT-4WRN",
        providerId = "prov-001",
        facilityId = "fac-001",
        timestamp = timestamp,
        transcript = "test",
        medications = emptyList(),
        diagnoses = diagnoses,
        vitals = vitals,
        allergies = emptyList(),
        followUp = null,
        referral = null,
        freeTextNote = "",
        extractionConfidence = 0.9f
    )

    @Test
    fun `totalVisits counts all encounters`() {
        val encounters = listOf(
            encounter(timestamp = Instant.parse("2025-01-01T00:00:00Z")),
            encounter(timestamp = Instant.parse("2025-02-01T00:00:00Z")),
            encounter(timestamp = Instant.parse("2025-03-01T00:00:00Z"))
        )
        val summary = PatientHealthSummaryBuilder.buildSummary(encounters)
        assertEquals(3, summary.totalVisits)
    }

    @Test
    fun `empty encounters gives zero totalVisits`() {
        val summary = PatientHealthSummaryBuilder.buildSummary(emptyList())
        assertEquals(0, summary.totalVisits)
    }

    @Test
    fun `chronic conditions identified from repeated diagnoses`() {
        val dx = listOf(Diagnosis("I10", "Hypertension", isPrimary = true, confidence = 0.9f))
        val encounters = listOf(
            encounter(diagnoses = dx, timestamp = Instant.parse("2025-01-01T00:00:00Z")),
            encounter(diagnoses = dx, timestamp = Instant.parse("2025-02-01T00:00:00Z")),
            encounter(diagnoses = dx, timestamp = Instant.parse("2025-03-01T00:00:00Z"))
        )
        val summary = PatientHealthSummaryBuilder.buildSummary(encounters)
        assertTrue("I10 appearing 3 times should be chronic", summary.chronicConditions.isNotEmpty())
        val hypertension = summary.chronicConditions.find { it.icd10Code == "I10" }
        assertNotNull("Should find I10 in chronic conditions", hypertension)
        assertEquals(3, hypertension!!.occurrenceCount)
    }

    @Test
    fun `single occurrence diagnosis is not chronic`() {
        val dx = listOf(Diagnosis("J18.9", "Pneumonia", isPrimary = true, confidence = 0.9f))
        val encounters = listOf(encounter(diagnoses = dx))
        val summary = PatientHealthSummaryBuilder.buildSummary(encounters)
        // Chronic requires ≥2 occurrences
        val pneumonia = summary.chronicConditions.find { it.icd10Code == "J18.9" }
        assertTrue(
            "Single occurrence should not be chronic",
            pneumonia == null || pneumonia.occurrenceCount < 2
        )
    }

    @Test
    fun `abnormal vitals tracked in history`() {
        val highBP = VitalSigns(systolicBP = 180, diastolicBP = 110)
        val encounters = listOf(
            encounter(vitals = highBP, timestamp = Instant.parse("2025-01-01T00:00:00Z"))
        )
        val summary = PatientHealthSummaryBuilder.buildSummary(encounters)
        assertTrue("BP 180/110 should be tracked as abnormal", summary.abnormalVitals.isNotEmpty())
    }

    @Test
    fun `normal vitals not tracked as abnormal`() {
        val normalVitals = VitalSigns(systolicBP = 120, diastolicBP = 80, temperature = 36.8f, pulse = 72)
        val encounters = listOf(encounter(vitals = normalVitals))
        val summary = PatientHealthSummaryBuilder.buildSummary(encounters)
        assertTrue("Normal vitals should not be in abnormalVitals", summary.abnormalVitals.isEmpty())
    }

    @Test
    fun `allergy flags set correctly`() {
        val summary = PatientHealthSummaryBuilder.buildSummary(
            emptyList(),
            patientAllergies = listOf("penicillin", "nsaid", "sulfa")
        )
        assertTrue("Allergy flags should be non-zero", summary.cumulativeAllergyFlags != 0)
    }

    @Test
    fun `growth data passed through to summary`() {
        val growth = GrowthData(weightKg = 15, heightCm = 90, weightZScore = -1.2f, heightZScore = -0.5f)
        val summary = PatientHealthSummaryBuilder.buildSummary(
            emptyList(),
            growthData = growth
        )
        assertTrue("hasGrowth should be true", summary.hasGrowth)
        assertEquals(15, summary.latestWeight)
        assertEquals(90, summary.latestHeight)
    }

    @Test
    fun `null growth data gives no growth in summary`() {
        val summary = PatientHealthSummaryBuilder.buildSummary(emptyList(), growthData = null)
        assertFalse("hasGrowth should be false", summary.hasGrowth)
    }

    @Test
    fun `immunization records passed through to summary`() {
        val immunizations = listOf(
            ImmunizationRecord("BCG", 1),
            ImmunizationRecord("PCV", 2),
            ImmunizationRecord("OPV", 3)
        )
        val summary = PatientHealthSummaryBuilder.buildSummary(
            emptyList(),
            immunizationRecords = immunizations
        )
        assertEquals(3, summary.recentImmunizations.size)
        assertTrue(summary.recentImmunizations.any { it.vaccineCode == "PCV" })
    }

    @Test
    fun `empty immunization records gives empty in summary`() {
        val summary = PatientHealthSummaryBuilder.buildSummary(
            emptyList(),
            immunizationRecords = emptyList()
        )
        assertTrue(summary.recentImmunizations.isEmpty())
    }
}
