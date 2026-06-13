package com.chartlite.app

import com.chartlite.app.model.*
import com.chartlite.app.sms.BinaryEncoder
import com.chartlite.app.sms.PatientHealthSummaryBuilder
import com.chartlite.app.sms.VitalType
import org.junit.Assert.*
import org.junit.Test
import java.time.Instant

class PatientHealthSummaryTest {

    private fun buildEncounter(
        id: String = "enc-001",
        timestamp: Instant = Instant.parse("2025-06-15T10:30:00Z"),
        diagnoses: List<Diagnosis> = emptyList(),
        medications: List<Medication> = emptyList(),
        vitals: VitalSigns? = null,
        allergies: List<String> = emptyList()
    ): StructuredEncounter {
        return StructuredEncounter(
            id = id,
            patientId = "KFMT-4WRN",
            providerId = "prov-001",
            facilityId = "fac-001",
            timestamp = timestamp,
            transcript = "transcript",
            medications = medications,
            diagnoses = diagnoses,
            vitals = vitals,
            allergies = allergies,
            followUp = null,
            referral = null,
            freeTextNote = "",
            extractionConfidence = 0.9f
        )
    }

    // ── Total visits ──

    @Test
    fun `total visits counts all encounters`() {
        val encounters = (1..7).map { buildEncounter(id = "enc-$it") }
        val summary = PatientHealthSummaryBuilder.buildSummary(encounters)
        assertEquals(7, summary.totalVisits)
    }

    @Test
    fun `empty encounters list gives zero visits`() {
        val summary = PatientHealthSummaryBuilder.buildSummary(emptyList())
        assertEquals(0, summary.totalVisits)
    }

    // ── Chronic conditions ──

    @Test
    fun `diagnosis appearing once is NOT chronic`() {
        val encounters = listOf(
            buildEncounter(diagnoses = listOf(
                Diagnosis("J18.9", "Pneumonia", true, 0.9f)
            ))
        )
        val summary = PatientHealthSummaryBuilder.buildSummary(encounters)
        assertTrue(summary.chronicConditions.isEmpty())
    }

    @Test
    fun `diagnosis appearing in 2+ encounters is chronic`() {
        val encounters = listOf(
            buildEncounter(id = "enc-1", diagnoses = listOf(
                Diagnosis("I10", "Hypertension", true, 0.9f)
            )),
            buildEncounter(id = "enc-2", diagnoses = listOf(
                Diagnosis("I10", "Hypertension", true, 0.85f)
            ))
        )
        val summary = PatientHealthSummaryBuilder.buildSummary(encounters)
        assertEquals(1, summary.chronicConditions.size)
        assertEquals("I10", summary.chronicConditions[0].icd10Code)
        assertEquals(2, summary.chronicConditions[0].occurrenceCount)
    }

    @Test
    fun `same diagnosis in same encounter counted once`() {
        // Even if a diagnosis appears twice in the same encounter, it counts as 1
        val encounters = listOf(
            buildEncounter(id = "enc-1", diagnoses = listOf(
                Diagnosis("I10", "Hypertension", true, 0.9f),
                Diagnosis("I10", "Hypertension (duplicate)", false, 0.7f)
            )),
            buildEncounter(id = "enc-2", diagnoses = listOf(
                Diagnosis("I10", "Hypertension", true, 0.85f)
            ))
        )
        val summary = PatientHealthSummaryBuilder.buildSummary(encounters)
        assertEquals(1, summary.chronicConditions.size)
        assertEquals(2, summary.chronicConditions[0].occurrenceCount) // Not 3
    }

    @Test
    fun `chronic conditions sorted by frequency descending`() {
        val encounters = (1..5).map {
            buildEncounter(
                id = "enc-$it",
                diagnoses = listOf(
                    Diagnosis("I10", "Hypertension", true, 0.9f)
                ) + if (it <= 3) listOf(Diagnosis("E11.9", "Diabetes", false, 0.8f)) else emptyList()
            )
        }
        val summary = PatientHealthSummaryBuilder.buildSummary(encounters)
        assertEquals(2, summary.chronicConditions.size)
        assertEquals("I10", summary.chronicConditions[0].icd10Code)
        assertEquals(5, summary.chronicConditions[0].occurrenceCount)
        assertEquals("E11.9", summary.chronicConditions[1].icd10Code)
        assertEquals(3, summary.chronicConditions[1].occurrenceCount)
    }

    @Test
    fun `chronic conditions capped at 5`() {
        // Create 7 different diagnoses each appearing 2+ times
        val encounters = (1..3).map { visit ->
            buildEncounter(
                id = "enc-$visit",
                diagnoses = (1..7).map {
                    Diagnosis("J0$it", "Diagnosis $it", it == 1, 0.8f)
                }
            )
        }
        val summary = PatientHealthSummaryBuilder.buildSummary(encounters)
        assertTrue(summary.chronicConditions.size <= 5)
    }

    // ── Abnormal vitals ──

    @Test
    fun `normal vitals produce no abnormal entries`() {
        val encounters = listOf(
            buildEncounter(vitals = VitalSigns(
                systolicBP = 120, diastolicBP = 80,
                temperature = 37.0f, pulse = 75
            ))
        )
        val summary = PatientHealthSummaryBuilder.buildSummary(encounters)
        assertTrue(summary.abnormalVitals.isEmpty())
    }

    @Test
    fun `high systolic BP detected as abnormal`() {
        val encounters = listOf(
            buildEncounter(vitals = VitalSigns(systolicBP = 160, diastolicBP = 80))
        )
        val summary = PatientHealthSummaryBuilder.buildSummary(encounters)
        assertEquals(1, summary.abnormalVitals.size)
        assertEquals(VitalType.SYSTOLIC_BP, summary.abnormalVitals[0].type)
        // Encoded as 160-60 = 100
        assertEquals(100, summary.abnormalVitals[0].rawValue)
    }

    @Test
    fun `low systolic BP detected as abnormal`() {
        val encounters = listOf(
            buildEncounter(vitals = VitalSigns(systolicBP = 85, diastolicBP = 55))
        )
        val summary = PatientHealthSummaryBuilder.buildSummary(encounters)
        // Both systolic ≤90 and diastolic ≤60 are abnormal
        assertTrue(summary.abnormalVitals.any { it.type == VitalType.SYSTOLIC_BP })
        assertTrue(summary.abnormalVitals.any { it.type == VitalType.DIASTOLIC_BP })
    }

    @Test
    fun `high temperature detected as abnormal`() {
        val encounters = listOf(
            buildEncounter(vitals = VitalSigns(temperature = 39.5f))
        )
        val summary = PatientHealthSummaryBuilder.buildSummary(encounters)
        assertEquals(1, summary.abnormalVitals.size)
        assertEquals(VitalType.TEMPERATURE, summary.abnormalVitals[0].type)
        // Encoded as (39.5 - 35.0) * 10 = 45
        assertEquals(45, summary.abnormalVitals[0].rawValue)
    }

    @Test
    fun `tachycardia detected as abnormal`() {
        val encounters = listOf(
            buildEncounter(vitals = VitalSigns(pulse = 115))
        )
        val summary = PatientHealthSummaryBuilder.buildSummary(encounters)
        assertEquals(1, summary.abnormalVitals.size)
        assertEquals(VitalType.PULSE, summary.abnormalVitals[0].type)
        assertEquals(115, summary.abnormalVitals[0].rawValue)
    }

    @Test
    fun `bradycardia detected as abnormal`() {
        val encounters = listOf(
            buildEncounter(vitals = VitalSigns(pulse = 48))
        )
        val summary = PatientHealthSummaryBuilder.buildSummary(encounters)
        assertEquals(1, summary.abnormalVitals.size)
        assertEquals(VitalType.PULSE, summary.abnormalVitals[0].type)
        assertEquals(48, summary.abnormalVitals[0].rawValue)
    }

    @Test
    fun `most recent abnormal vital kept per type`() {
        val encounters = listOf(
            buildEncounter(
                id = "enc-old",
                timestamp = Instant.parse("2025-01-01T10:00:00Z"),
                vitals = VitalSigns(systolicBP = 180) // older, higher
            ),
            buildEncounter(
                id = "enc-new",
                timestamp = Instant.parse("2025-06-15T10:00:00Z"),
                vitals = VitalSigns(systolicBP = 150) // newer, lower
            )
        )
        val summary = PatientHealthSummaryBuilder.buildSummary(encounters)
        // Should keep the most recent (June 2025) abnormal reading
        val systolicAbnormal = summary.abnormalVitals.find { it.type == VitalType.SYSTOLIC_BP }
        assertNotNull(systolicAbnormal)
        // 150 - 60 = 90
        assertEquals(90, systolicAbnormal!!.rawValue)
        assertEquals(6, systolicAbnormal.date.monthValue)
    }

    @Test
    fun `abnormal vitals capped at 5`() {
        // Can't have more than 4 types (SYSTOLIC, DIASTOLIC, TEMP, PULSE) since WEIGHT is skipped
        val encounters = listOf(
            buildEncounter(vitals = VitalSigns(
                systolicBP = 180, diastolicBP = 100,
                temperature = 40.0f, pulse = 130
            ))
        )
        val summary = PatientHealthSummaryBuilder.buildSummary(encounters)
        assertTrue(summary.abnormalVitals.size <= 5)
    }

    // ── Cumulative allergies ──

    @Test
    fun `allergy flags unioned across encounters`() {
        val encounters = listOf(
            buildEncounter(id = "enc-1", allergies = listOf("penicillin")),
            buildEncounter(id = "enc-2", allergies = listOf("nsaid")),
            buildEncounter(id = "enc-3", allergies = listOf("latex"))
        )
        val summary = PatientHealthSummaryBuilder.buildSummary(encounters)
        // penicillin = bit 7, nsaid = bit 5, latex = bit 4
        assertTrue(summary.cumulativeAllergyFlags and (1 shl 7) != 0) // penicillin
        assertTrue(summary.cumulativeAllergyFlags and (1 shl 5) != 0) // nsaid
        assertTrue(summary.cumulativeAllergyFlags and (1 shl 4) != 0) // latex
    }

    @Test
    fun `patient-level allergies included in cumulative flags`() {
        val encounters = listOf(
            buildEncounter(id = "enc-1", allergies = listOf("penicillin"))
        )
        val summary = PatientHealthSummaryBuilder.buildSummary(encounters, listOf("opioid"))
        assertTrue(summary.cumulativeAllergyFlags and (1 shl 7) != 0) // penicillin from encounter
        assertTrue(summary.cumulativeAllergyFlags and (1 shl 2) != 0) // opioid from patient level
    }

    @Test
    fun `unknown allergy sets 'other' flag`() {
        val encounters = listOf(
            buildEncounter(id = "enc-1", allergies = listOf("shellfish"))
        )
        val summary = PatientHealthSummaryBuilder.buildSummary(encounters)
        assertTrue(summary.cumulativeAllergyFlags and 1 != 0) // bit 0 = other
    }

    @Test
    fun `no allergies gives zero flags`() {
        val encounters = listOf(buildEncounter(allergies = emptyList()))
        val summary = PatientHealthSummaryBuilder.buildSummary(encounters)
        assertEquals(0, summary.cumulativeAllergyFlags)
    }

    // ── End-to-end: summary → encode → decode ──

    @Test
    fun `full pipeline - build summary then encode-decode round trip`() {
        // Simulate a patient with 4 encounters over time
        val encounters = listOf(
            buildEncounter(
                id = "enc-1",
                timestamp = Instant.parse("2025-01-10T09:00:00Z"),
                diagnoses = listOf(Diagnosis("I10", "Hypertension", true, 0.9f)),
                vitals = VitalSigns(systolicBP = 155, diastolicBP = 95, temperature = 37.0f, pulse = 78),
                allergies = listOf("penicillin")
            ),
            buildEncounter(
                id = "enc-2",
                timestamp = Instant.parse("2025-03-15T10:00:00Z"),
                diagnoses = listOf(
                    Diagnosis("I10", "Hypertension", true, 0.85f),
                    Diagnosis("E11.9", "Diabetes", false, 0.8f)
                ),
                vitals = VitalSigns(systolicBP = 145, diastolicBP = 88, temperature = 36.8f, pulse = 80),
                allergies = listOf("sulfa")
            ),
            buildEncounter(
                id = "enc-3",
                timestamp = Instant.parse("2025-05-20T11:00:00Z"),
                diagnoses = listOf(
                    Diagnosis("I10", "Hypertension", true, 0.9f),
                    Diagnosis("E11.9", "Diabetes", false, 0.85f)
                ),
                vitals = VitalSigns(systolicBP = 135, diastolicBP = 82, temperature = 37.1f, pulse = 75)
            ),
            buildEncounter(
                id = "enc-4",
                timestamp = Instant.parse("2025-06-15T10:30:00Z"),
                diagnoses = listOf(
                    Diagnosis("J18.9", "Pneumonia", true, 0.9f),
                    Diagnosis("I10", "Hypertension", false, 0.85f)
                ),
                medications = listOf(
                    Medication("0001", "Amoxicillin", 500f, "mg", "TDS", 7, "PO", 0.85f)
                ),
                vitals = VitalSigns(systolicBP = 142, diastolicBP = 88, temperature = 38.5f, pulse = 92, weight = 70f),
                allergies = listOf("penicillin")
            )
        )

        // Build summary
        val summary = PatientHealthSummaryBuilder.buildSummary(
            encounters,
            patientAllergies = listOf("nsaid")
        )

        // Verify summary
        assertEquals(4, summary.totalVisits)
        // I10 appears in all 4 encounters, E11.9 in 2 → both chronic
        assertTrue(summary.chronicConditions.any { it.icd10Code == "I10" && it.occurrenceCount == 4 })
        assertTrue(summary.chronicConditions.any { it.icd10Code == "E11.9" && it.occurrenceCount == 2 })
        // J18.9 only once → not chronic
        assertFalse(summary.chronicConditions.any { it.icd10Code == "J18.9" })

        // Abnormal vitals: most recent abnormal systolic is enc-4 (142 ≥ 140)
        assertTrue(summary.abnormalVitals.any { it.type == VitalType.SYSTOLIC_BP })

        // Cumulative allergies: penicillin + sulfa + nsaid
        assertTrue(summary.cumulativeAllergyFlags and (1 shl 7) != 0) // penicillin
        assertTrue(summary.cumulativeAllergyFlags and (1 shl 6) != 0) // sulfa
        assertTrue(summary.cumulativeAllergyFlags and (1 shl 5) != 0) // nsaid

        // Encode with v2
        val currentEncounter = encounters.last()
        val bytes = BinaryEncoder.encodeWithHistory(currentEncounter, summary)
        assertTrue(bytes.size <= 92)

        // Decode
        val decoded = BinaryEncoder.decodeV2(bytes)

        // Verify encounter portion
        assertEquals(2025, decoded.encounter.date.year)
        assertEquals(6, decoded.encounter.date.monthValue)
        assertEquals(142, decoded.encounter.systolicBP)

        // Verify health history
        assertEquals(4, decoded.totalVisits)
        assertEquals(2, decoded.chronicConditions.size)
        assertTrue(decoded.abnormalVitals.isNotEmpty())
        // Cumulative allergy flags survive round-trip
        assertTrue((decoded.cumulativeAllergyFlags and (1 shl 7)) != 0)
        assertTrue((decoded.cumulativeAllergyFlags and (1 shl 6)) != 0)
        assertTrue((decoded.cumulativeAllergyFlags and (1 shl 5)) != 0)
    }
}
