package com.chartlite.app

import com.chartlite.app.model.*
import com.chartlite.app.sms.*
import org.junit.Assert.*
import org.junit.Test
import java.time.Instant
import java.time.LocalDate

class BinaryEncoderV2Test {

    private fun buildEncounter(
        diagnoses: List<Diagnosis> = listOf(
            Diagnosis("J18.9", "Pneumonia", isPrimary = true, confidence = 0.9f)
        ),
        medications: List<Medication> = listOf(
            Medication("0001", "Amoxicillin", 500f, "mg", "TDS", 7, "PO", 0.85f)
        ),
        vitals: VitalSigns? = VitalSigns(
            systolicBP = 130, diastolicBP = 85,
            temperature = 38.5f, pulse = 92, weight = 70f
        ),
        allergies: List<String> = listOf("penicillin"),
        followUp: FollowUp? = FollowUp(7, "review"),
        referral: Referral? = null,
        freeTextNote: String = "test note",
        timestamp: Instant = Instant.parse("2025-06-15T10:30:00Z")
    ): StructuredEncounter {
        return StructuredEncounter(
            id = "enc-001",
            patientId = "KFMT-4WRN",
            providerId = "prov-001",
            facilityId = "fac-001",
            timestamp = timestamp,
            transcript = "test transcript",
            medications = medications,
            diagnoses = diagnoses,
            vitals = vitals,
            allergies = allergies,
            followUp = followUp,
            referral = referral,
            freeTextNote = freeTextNote,
            extractionConfidence = 0.85f
        )
    }

    private fun buildSummaryWithChronics(): PatientHealthSummary {
        return PatientHealthSummary(
            totalVisits = 5,
            chronicConditions = listOf(
                ChronicCondition("I10", 4),    // Hypertension seen 4 times
                ChronicCondition("E11.9", 3)   // Diabetes seen 3 times
            ),
            abnormalVitals = listOf(
                AbnormalVital(
                    LocalDate.of(2025, 6, 10),
                    VitalType.SYSTOLIC_BP,
                    100  // Encoded: 160 - 60 = 100
                ),
                AbnormalVital(
                    LocalDate.of(2025, 5, 20),
                    VitalType.PULSE,
                    110  // Pulse is stored as-is (no offset)
                )
            ),
            cumulativeAllergyFlags = 0xA0 // penicillin (bit 7) + nsaid (bit 5)
        )
    }

    private fun buildEmptySummary(): PatientHealthSummary {
        return PatientHealthSummary(
            totalVisits = 1,
            chronicConditions = emptyList(),
            abnormalVitals = emptyList(),
            cumulativeAllergyFlags = 0
        )
    }

    // ── Basic v2 encode/decode ──

    @Test
    fun `v2 encode starts with version byte 0x02`() {
        val enc = buildEncounter()
        val summary = buildEmptySummary()
        val bytes = BinaryEncoder.encodeWithHistory(enc, summary)
        assertEquals(0x02.toByte(), bytes[0])
    }

    @Test
    fun `v2 encode produces at most 92 bytes`() {
        val enc = buildEncounter()
        val summary = buildSummaryWithChronics()
        val bytes = BinaryEncoder.encodeWithHistory(enc, summary)
        assertTrue("V2 payload should be ≤92 bytes, was ${bytes.size}", bytes.size <= 92)
    }

    @Test
    fun `v2 encode-decode round trip preserves encounter date`() {
        val enc = buildEncounter()
        val summary = buildEmptySummary()
        val bytes = BinaryEncoder.encodeWithHistory(enc, summary)
        val decoded = BinaryEncoder.decodeV2(bytes)
        assertEquals(2025, decoded.encounter.date.year)
        assertEquals(6, decoded.encounter.date.monthValue)
        assertEquals(15, decoded.encounter.date.dayOfMonth)
    }

    @Test
    fun `v2 encode-decode round trip preserves vitals`() {
        val enc = buildEncounter()
        val summary = buildEmptySummary()
        val bytes = BinaryEncoder.encodeWithHistory(enc, summary)
        val decoded = BinaryEncoder.decodeV2(bytes)
        assertEquals(130, decoded.encounter.systolicBP)
        assertEquals(85, decoded.encounter.diastolicBP)
        assertEquals(38.5f, decoded.encounter.temperature, 0.2f)
        assertEquals(70, decoded.encounter.weight)
        assertEquals(92, decoded.encounter.pulse)
    }

    @Test
    fun `v2 encode-decode preserves medications`() {
        val enc = buildEncounter()
        val summary = buildEmptySummary()
        val bytes = BinaryEncoder.encodeWithHistory(enc, summary)
        val decoded = BinaryEncoder.decodeV2(bytes)
        assertEquals(1, decoded.encounter.medications.size)
    }

    @Test
    fun `v2 encode-decode preserves follow-up`() {
        val enc = buildEncounter(followUp = FollowUp(14, "review"))
        val summary = buildEmptySummary()
        val bytes = BinaryEncoder.encodeWithHistory(enc, summary)
        val decoded = BinaryEncoder.decodeV2(bytes)
        assertEquals(14, decoded.encounter.followUpDays)
    }

    // ── Health history section ──

    @Test
    fun `v2 encode-decode preserves total visit count`() {
        val enc = buildEncounter()
        val summary = buildSummaryWithChronics()
        val bytes = BinaryEncoder.encodeWithHistory(enc, summary)
        val decoded = BinaryEncoder.decodeV2(bytes)
        assertEquals(5, decoded.totalVisits)
    }

    @Test
    fun `v2 encode-decode preserves chronic conditions`() {
        val enc = buildEncounter()
        val summary = buildSummaryWithChronics()
        val bytes = BinaryEncoder.encodeWithHistory(enc, summary)
        val decoded = BinaryEncoder.decodeV2(bytes)
        assertEquals(2, decoded.chronicConditions.size)
        // Verify occurrence counts survived the round trip
        assertEquals(4, decoded.chronicConditions[0].occurrenceCount)
        assertEquals(3, decoded.chronicConditions[1].occurrenceCount)
    }

    @Test
    fun `v2 encode-decode preserves abnormal vitals`() {
        val enc = buildEncounter()
        val summary = buildSummaryWithChronics()
        val bytes = BinaryEncoder.encodeWithHistory(enc, summary)
        val decoded = BinaryEncoder.decodeV2(bytes)
        assertEquals(2, decoded.abnormalVitals.size)

        // Check systolic BP
        val systolic = decoded.abnormalVitals[0]
        assertEquals(0, systolic.vitalType) // SYSTOLIC_BP ordinal
        assertEquals("Systolic BP", systolic.vitalLabel)
        // rawValue=100, display should be 100+60=160 mmHg
        assertEquals("160 mmHg", systolic.displayValue)

        // Check pulse
        val pulse = decoded.abnormalVitals[1]
        assertEquals(3, pulse.vitalType) // PULSE ordinal
        assertEquals("110 bpm", pulse.displayValue)
    }

    @Test
    fun `v2 encode-decode preserves abnormal vital dates`() {
        val enc = buildEncounter()
        val summary = buildSummaryWithChronics()
        val bytes = BinaryEncoder.encodeWithHistory(enc, summary)
        val decoded = BinaryEncoder.decodeV2(bytes)

        val systolicDate = decoded.abnormalVitals[0].date
        assertEquals(2025, systolicDate.year)
        assertEquals(6, systolicDate.monthValue)
        assertEquals(10, systolicDate.dayOfMonth)
    }

    @Test
    fun `v2 encode-decode preserves cumulative allergy flags`() {
        val enc = buildEncounter()
        val summary = buildSummaryWithChronics()
        val bytes = BinaryEncoder.encodeWithHistory(enc, summary)
        val decoded = BinaryEncoder.decodeV2(bytes)
        // 0xA0 = penicillin (bit 7) + nsaid (bit 5)
        assertEquals(0xA0, decoded.cumulativeAllergyFlags)
    }

    // ── Empty history ──

    @Test
    fun `v2 with empty history has zero chronic conditions`() {
        val enc = buildEncounter()
        val summary = buildEmptySummary()
        val bytes = BinaryEncoder.encodeWithHistory(enc, summary)
        val decoded = BinaryEncoder.decodeV2(bytes)
        assertTrue(decoded.chronicConditions.isEmpty())
        assertTrue(decoded.abnormalVitals.isEmpty())
        assertEquals(1, decoded.totalVisits)
    }

    // ── CRC integrity ──

    @Test
    fun `v2 tampered payload fails CRC check`() {
        val enc = buildEncounter()
        val summary = buildSummaryWithChronics()
        val bytes = BinaryEncoder.encodeWithHistory(enc, summary)
        bytes[15] = (bytes[15].toInt() xor 0xFF).toByte()
        assertThrows(IllegalArgumentException::class.java) {
            BinaryEncoder.decodeV2(bytes)
        }
    }

    // ── Backward compatibility ──

    @Test
    fun `v1 decode still works when called with v1 payload`() {
        val enc = buildEncounter()
        val v1Bytes = BinaryEncoder.encode(enc)
        val decoded = BinaryEncoder.decode(v1Bytes)
        assertEquals(2025, decoded.date.year)
        assertEquals(130, decoded.systolicBP)
    }

    @Test
    fun `decode dispatches v2 payload correctly`() {
        val enc = buildEncounter()
        val summary = buildSummaryWithChronics()
        val v2Bytes = BinaryEncoder.encodeWithHistory(enc, summary)
        // BinaryEncoder.decode() should detect v2 and delegate to decodeV2()
        val decoded = BinaryEncoder.decode(v2Bytes)
        // Should return the encounter portion
        assertEquals(2025, decoded.date.year)
        assertEquals(130, decoded.systolicBP)
    }

    // ── DecryptResult sealed class ──

    @Test
    fun `DecryptResult V1 wraps decoded encounter`() {
        val enc = buildEncounter()
        val bytes = BinaryEncoder.encode(enc)
        val decoded = BinaryEncoder.decode(bytes)
        val result = DecryptResult.V1(decoded)
        assertTrue(result is DecryptResult.V1)
        assertEquals(130, (result as DecryptResult.V1).encounter.systolicBP)
    }

    @Test
    fun `DecryptResult V2 wraps decoded v2 data`() {
        val enc = buildEncounter()
        val summary = buildSummaryWithChronics()
        val bytes = BinaryEncoder.encodeWithHistory(enc, summary)
        val decoded = BinaryEncoder.decodeV2(bytes)
        val result = DecryptResult.V2(decoded)
        assertTrue(result is DecryptResult.V2)
        assertEquals(5, (result as DecryptResult.V2).data.totalVisits)
    }

    // ── Max capacity ──

    @Test
    fun `v2 with max chronic conditions and abnormal vitals fits in 92 bytes`() {
        val enc = buildEncounter()
        val summary = PatientHealthSummary(
            totalVisits = 255,
            chronicConditions = (1..5).map { ChronicCondition("J0$it", 10 + it) },
            abnormalVitals = listOf(
                AbnormalVital(LocalDate.of(2025, 1, 1), VitalType.SYSTOLIC_BP, 100),
                AbnormalVital(LocalDate.of(2025, 2, 1), VitalType.DIASTOLIC_BP, 65),
                AbnormalVital(LocalDate.of(2025, 3, 1), VitalType.TEMPERATURE, 35),
                AbnormalVital(LocalDate.of(2025, 4, 1), VitalType.PULSE, 110),
                AbnormalVital(LocalDate.of(2025, 5, 1), VitalType.WEIGHT, 120)
            ),
            cumulativeAllergyFlags = 0xFF
        )
        val bytes = BinaryEncoder.encodeWithHistory(enc, summary)
        assertTrue("Max v2 should be ≤92 bytes, was ${bytes.size}", bytes.size <= 92)

        // Verify round-trip
        val decoded = BinaryEncoder.decodeV2(bytes)
        assertEquals(255, decoded.totalVisits)
        assertEquals(5, decoded.chronicConditions.size)
        assertEquals(5, decoded.abnormalVitals.size)
        assertEquals(0xFF, decoded.cumulativeAllergyFlags)
    }
}
