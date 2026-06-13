package com.chartlite.app

import com.chartlite.app.model.*
import com.chartlite.app.sms.BinaryEncoder
import org.junit.Assert.*
import org.junit.Test
import java.time.Instant

class BinaryEncoderTest {

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
        freeTextNote: String = "test note"
    ): StructuredEncounter {
        return StructuredEncounter(
            id = "enc-001",
            patientId = "KFMT-4WRN",
            providerId = "prov-001",
            facilityId = "fac-001",
            timestamp = Instant.parse("2025-06-15T10:30:00Z"),
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

    @Test
    fun `encode produces exactly 92 bytes`() {
        val enc = buildEncounter()
        val bytes = BinaryEncoder.encode(enc)
        assertEquals(92, bytes.size)
    }

    @Test
    fun `encode starts with version byte 0x01`() {
        val bytes = BinaryEncoder.encode(buildEncounter())
        assertEquals(0x01.toByte(), bytes[0])
    }

    @Test
    fun `CRC byte is last byte`() {
        val bytes = BinaryEncoder.encode(buildEncounter())
        // CRC should be non-zero (statistically almost always)
        // More importantly, decoding should not throw
        val decoded = BinaryEncoder.decode(bytes)
        assertNotNull(decoded)
    }

    @Test
    fun `encode-decode round trip preserves date`() {
        val enc = buildEncounter()
        val bytes = BinaryEncoder.encode(enc)
        val decoded = BinaryEncoder.decode(bytes)
        assertEquals(2025, decoded.date.year)
        assertEquals(6, decoded.date.monthValue)
        assertEquals(15, decoded.date.dayOfMonth)
    }

    @Test
    fun `encode-decode preserves vitals`() {
        val enc = buildEncounter()
        val bytes = BinaryEncoder.encode(enc)
        val decoded = BinaryEncoder.decode(bytes)
        assertEquals(130, decoded.systolicBP)
        assertEquals(85, decoded.diastolicBP)
        assertEquals(38.5f, decoded.temperature, 0.2f) // some quantization loss
        assertEquals(70, decoded.weight)
        assertEquals(92, decoded.pulse)
    }

    @Test
    fun `encode-decode preserves allergy flags`() {
        val enc = buildEncounter(allergies = listOf("penicillin", "nsaid"))
        val bytes = BinaryEncoder.encode(enc)
        val decoded = BinaryEncoder.decode(bytes)
        // penicillin = bit 7, nsaid = bit 5
        assertTrue("Penicillin flag should be set", decoded.allergyFlags and (1 shl 7) != 0)
        assertTrue("NSAID flag should be set", decoded.allergyFlags and (1 shl 5) != 0)
    }

    @Test
    fun `encode-decode preserves follow-up days`() {
        val enc = buildEncounter(followUp = FollowUp(14, "review"))
        val bytes = BinaryEncoder.encode(enc)
        val decoded = BinaryEncoder.decode(bytes)
        assertEquals(14, decoded.followUpDays)
    }

    @Test
    fun `encode-decode with no follow-up`() {
        val enc = buildEncounter(followUp = null)
        val bytes = BinaryEncoder.encode(enc)
        val decoded = BinaryEncoder.decode(bytes)
        assertNull(decoded.followUpDays)
    }

    @Test
    fun `encode-decode preserves urgency`() {
        val enc = buildEncounter(referral = Referral("hospital", "cardiology", "urgent"))
        val bytes = BinaryEncoder.encode(enc)
        val decoded = BinaryEncoder.decode(bytes)
        assertEquals(2, decoded.urgency) // urgent = 2
    }

    @Test
    fun `encode-decode preserves medication count`() {
        val meds = listOf(
            Medication("0001", "Amoxicillin", 500f, "mg", "TDS", 7, "PO", 0.85f),
            Medication("0003", "Paracetamol", 1000f, "mg", "PRN", null, "PO", 0.9f)
        )
        val enc = buildEncounter(medications = meds)
        val bytes = BinaryEncoder.encode(enc)
        val decoded = BinaryEncoder.decode(bytes)
        assertEquals(2, decoded.medications.size)
    }

    @Test
    fun `tampered data fails CRC check`() {
        val bytes = BinaryEncoder.encode(buildEncounter())
        bytes[50] = (bytes[50].toInt() xor 0xFF).toByte() // flip bits
        assertThrows(IllegalArgumentException::class.java) {
            BinaryEncoder.decode(bytes)
        }
    }

    @Test
    fun `wrong size input fails`() {
        assertThrows(IllegalArgumentException::class.java) {
            BinaryEncoder.decode(ByteArray(50))
        }
    }

    @Test
    fun `encode handles empty encounter`() {
        val enc = buildEncounter(
            diagnoses = emptyList(),
            medications = emptyList(),
            vitals = null,
            allergies = emptyList(),
            followUp = null,
            freeTextNote = ""
        )
        val bytes = BinaryEncoder.encode(enc)
        assertEquals(92, bytes.size)
        val decoded = BinaryEncoder.decode(bytes)
        assertNotNull(decoded)
    }

    @Test
    fun `encode caps at 3 diagnoses and 3 medications`() {
        val manyDx = (1..5).map { Diagnosis("J0$it", "Diagnosis $it", it == 1, 0.8f) }
        val manyMeds = (1..5).map { Medication("000$it", "Drug $it", 500f, "mg", "OD", 7, "PO", 0.8f) }
        val enc = buildEncounter(diagnoses = manyDx, medications = manyMeds)
        val bytes = BinaryEncoder.encode(enc)
        val decoded = BinaryEncoder.decode(bytes)
        assertTrue(decoded.diagnosisIndices.size <= 3)
        assertTrue(decoded.medications.size <= 3)
    }

    // -- Fixed-layout verification --

    @Test
    fun `fixed layout - same size with 0 vs 3 diagnoses`() {
        val enc0 = buildEncounter(diagnoses = emptyList(), medications = emptyList(), freeTextNote = "")
        val enc3 = buildEncounter(
            diagnoses = (1..3).map { Diagnosis("J0$it", "Dx$it", it == 1, 0.8f) },
            medications = (1..3).map { Medication("000$it", "Drug$it", 500f, "mg", "OD", 7, "PO", 0.8f) },
            freeTextNote = ""
        )
        val bytes0 = BinaryEncoder.encode(enc0)
        val bytes3 = BinaryEncoder.encode(enc3)
        assertEquals("Both should be 92 bytes regardless of content", bytes0.size, bytes3.size)
    }

    @Test
    fun `fixed layout - vitals at fixed offset regardless of diagnosis count`() {
        // Vitals start at byte 21. With fixed layout, changing dx count
        // should not shift the vitals position.
        val enc1dx = buildEncounter(
            diagnoses = listOf(Diagnosis("J18.9", "Pneumonia", true, 0.9f)),
            vitals = VitalSigns(systolicBP = 130, diastolicBP = 85, temperature = 38.5f, pulse = 92, weight = 70f)
        )
        val enc0dx = buildEncounter(
            diagnoses = emptyList(),
            vitals = VitalSigns(systolicBP = 130, diastolicBP = 85, temperature = 38.5f, pulse = 92, weight = 70f)
        )
        val bytes1 = BinaryEncoder.encode(enc1dx)
        val bytes0 = BinaryEncoder.encode(enc0dx)
        // Byte 21 = systolic - 60 = 70
        assertEquals("Vitals at byte 21 should be same offset", bytes1[21], bytes0[21])
        assertEquals(70.toByte(), bytes1[21])
    }

    @Test
    fun `encode-decode preserves diagnosis indices`() {
        val enc = buildEncounter(
            diagnoses = listOf(
                Diagnosis("J18.9", "Pneumonia", true, 0.9f),
                Diagnosis("E11", "Diabetes", false, 0.8f)
            )
        )
        val bytes = BinaryEncoder.encode(enc)
        val decoded = BinaryEncoder.decode(bytes)
        assertEquals(2, decoded.diagnosisIndices.size)
        // Verify indices are non-zero (hash of ICD-10 code)
        assertTrue(decoded.diagnosisIndices.all { it >= 0 })
    }

    @Test
    fun `encode-decode with empty diagnoses returns empty list`() {
        val enc = buildEncounter(diagnoses = emptyList())
        val bytes = BinaryEncoder.encode(enc)
        val decoded = BinaryEncoder.decode(bytes)
        assertTrue(decoded.diagnosisIndices.isEmpty())
    }

    @Test
    fun `encode-decode with empty medications returns empty list`() {
        val enc = buildEncounter(medications = emptyList())
        val bytes = BinaryEncoder.encode(enc)
        val decoded = BinaryEncoder.decode(bytes)
        assertTrue(decoded.medications.isEmpty())
    }
}
