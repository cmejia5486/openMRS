package com.chartlite.app

import com.chartlite.app.billing.ClaimEngine
import com.chartlite.app.model.Diagnosis
import com.chartlite.app.model.Medication
import com.chartlite.app.model.VitalSigns
import org.junit.Assert.*
import org.junit.Test

class ClaimEngineTest {

    // ── E/M Level Calculation ──

    @Test
    fun `EM level 1 for empty encounter`() {
        // 0 dx (0) + no vitals (0) + 0 meds (0) = score 0 -> level 1
        val claim = ClaimEngine.generateClaim(
            encounterId = "test-001",
            diagnoses = emptyList(),
            medications = emptyList(),
            vitals = null
        )
        assertEquals(1, claim.emLevel)
        assertEquals("99211", claim.emCode)
    }

    @Test
    fun `EM level 1 for single high-confidence diagnosis only`() {
        // 1 dx with conf>0.8 (1) + no vitals (0) + 0 meds (0) = score 1 -> level 1
        val claim = ClaimEngine.generateClaim(
            encounterId = "test-002",
            diagnoses = listOf(Diagnosis("J06.9", "URTI", isPrimary = true, confidence = 0.95f)),
            medications = emptyList(),
            vitals = null
        )
        assertEquals(1, claim.emLevel)
    }

    @Test
    fun `EM level 2 for single diagnosis with few vitals and no meds`() {
        // 1 dx conf>0.8 (1) + vitals with 2 non-null of 5 fields (1) + 0 meds (0) = score 2 -> level 2
        val vitals = VitalSigns(systolicBP = 120, pulse = 72)
        val claim = ClaimEngine.generateClaim(
            encounterId = "test-003",
            diagnoses = listOf(Diagnosis("J06.9", "URTI", isPrimary = true, confidence = 0.9f)),
            medications = emptyList(),
            vitals = vitals
        )
        assertEquals(2, claim.emLevel)
        assertEquals("99212", claim.emCode)
    }

    @Test
    fun `EM level 2 for single diagnosis with meds and no vitals`() {
        // 1 dx conf>0.8 (1) + no vitals (0) + 2 meds (1) = score 2 -> level 2
        val claim = ClaimEngine.generateClaim(
            encounterId = "test-004",
            diagnoses = listOf(Diagnosis("J18.9", "Pneumonia", isPrimary = true, confidence = 0.9f)),
            medications = TestFixtures.sampleMedications(),
            vitals = null
        )
        assertEquals(2, claim.emLevel)
    }

    @Test
    fun `EM level 3 for two diagnoses with comprehensive vitals`() {
        // 2 dx (2) + vitals with 3+ fields (2) + 0 meds (0) = score 4 -> level 3
        val vitals = VitalSigns(systolicBP = 130, temperature = 37.5f, pulse = 80)
        val claim = ClaimEngine.generateClaim(
            encounterId = "test-005",
            diagnoses = TestFixtures.sampleDiagnoses(),
            medications = emptyList(),
            vitals = vitals
        )
        assertEquals(3, claim.emLevel)
        assertEquals("99213", claim.emCode)
    }

    @Test
    fun `EM level 4 for two diagnoses with vitals and medications`() {
        // 2 dx (2) + comprehensive vitals (2) + 2 meds (1) = score 5 -> level 3
        // Need more: 2 dx (2) + comprehensive vitals (2) + 3 meds (2) = score 6 -> level 4
        val vitals = VitalSigns(systolicBP = 130, temperature = 37.5f, pulse = 82, weight = 75f)
        val meds = listOf(
            Medication("0001", "Amoxicillin", 500f, "mg", "TDS", 7, "PO", 0.85f),
            Medication("0003", "Paracetamol", 1000f, "mg", "PRN", null, "PO", 0.9f),
            Medication("0005", "Amlodipine", 5f, "mg", "OD", 30, "PO", 0.9f)
        )
        val claim = ClaimEngine.generateClaim(
            encounterId = "test-006",
            diagnoses = TestFixtures.sampleDiagnoses(),
            medications = meds,
            vitals = vitals
        )
        assertEquals(4, claim.emLevel)
        assertEquals("99214", claim.emCode)
    }

    @Test
    fun `EM level 5 for complex encounter with many diagnoses and meds`() {
        // 5 dx (4) + comprehensive vitals (2) + 5 meds (3) = score 9 -> level 5
        val diagnoses = listOf(
            Diagnosis("J18.9", "Pneumonia", isPrimary = true, confidence = 0.9f),
            Diagnosis("I10", "Hypertension", confidence = 0.85f),
            Diagnosis("E11.9", "Type 2 DM", confidence = 0.8f),
            Diagnosis("N39.0", "UTI", confidence = 0.75f),
            Diagnosis("K21.0", "GERD", confidence = 0.7f)
        )
        val meds = listOf(
            Medication("0001", "Amoxicillin", 500f, "mg", "TDS", 7, "PO", 0.85f),
            Medication("0002", "Metformin", 500f, "mg", "BD", 30, "PO", 0.9f),
            Medication("0003", "Paracetamol", 1000f, "mg", "PRN", null, "PO", 0.9f),
            Medication("0005", "Amlodipine", 5f, "mg", "OD", 30, "PO", 0.9f),
            Medication("0007", "Omeprazole", 20f, "mg", "OD", 30, "PO", 0.85f)
        )
        val claim = ClaimEngine.generateClaim(
            encounterId = "test-007",
            diagnoses = diagnoses,
            medications = meds,
            vitals = TestFixtures.sampleVitals()
        )
        assertEquals(5, claim.emLevel)
        assertEquals("99215", claim.emCode)
    }

    @Test
    fun `referral increases EM level`() {
        // Without referral: 1 dx conf>0.8 (1) + no vitals (0) + 2 meds (1) = score 2 -> level 2
        // With referral: score 2 + 1 = 3 -> level 2 still
        // Use a case where +1 pushes across a boundary:
        // 2 dx (2) + comprehensive vitals (2) + 1 med (1) = score 5 -> level 3
        // With referral: score 6 -> level 4
        val vitals = VitalSigns(systolicBP = 130, temperature = 37.5f, pulse = 82, weight = 75f)
        val meds = listOf(Medication("0001", "Amoxicillin", 500f, "mg", "TDS", 7, "PO", 0.85f))

        val claimWithout = ClaimEngine.generateClaim(
            encounterId = "test-008a",
            diagnoses = TestFixtures.sampleDiagnoses(),
            medications = meds,
            vitals = vitals,
            hasReferral = false
        )
        val claimWith = ClaimEngine.generateClaim(
            encounterId = "test-008b",
            diagnoses = TestFixtures.sampleDiagnoses(),
            medications = meds,
            vitals = vitals,
            hasReferral = true
        )
        assertTrue(
            "Referral should increase or maintain E/M level",
            claimWith.emLevel >= claimWithout.emLevel
        )
        assertEquals(3, claimWithout.emLevel)
        assertEquals(4, claimWith.emLevel)
    }

    @Test
    fun `comprehensive vitals increase EM data score`() {
        // Sparse vitals (2 of 5 fields): data score = 1
        // Comprehensive vitals (4 of 5 fields): data score = 2
        val sparse = VitalSigns(systolicBP = 120, pulse = 72)
        val comprehensive = VitalSigns(systolicBP = 120, temperature = 37.0f, pulse = 72, weight = 65f)
        val dx = listOf(
            Diagnosis("J18.9", "Pneumonia", isPrimary = true, confidence = 0.9f),
            Diagnosis("I10", "Hypertension", confidence = 0.85f)
        )
        val meds = listOf(Medication("0001", "Amoxicillin", 500f, "mg", "TDS", 7, "PO", 0.85f))
        // sparse: 2 dx (2) + sparse vitals (1) + 1 med (1) = 4 -> level 3
        // comprehensive: 2 dx (2) + comprehensive vitals (2) + 1 med (1) = 5 -> level 3
        val claimSparse = ClaimEngine.generateClaim("test-009a", dx, meds, sparse)
        val claimComp = ClaimEngine.generateClaim("test-009b", dx, meds, comprehensive)
        // Both map to level 3 (score 4 and 5 respectively), but the internal score differs
        assertTrue(claimComp.emLevel >= claimSparse.emLevel)
    }

    // ── Claim Line Generation: CPT Mapping ──

    @Test
    fun `pneumonia J18 maps to chest X-ray 71046`() {
        val dx = listOf(Diagnosis("J18.9", "Pneumonia", isPrimary = true, confidence = 0.9f))
        val claim = ClaimEngine.generateClaim("test-cpt-01", dx, emptyList(), null)
        val cptCodes = claim.claimLines.map { it.cptCode }
        assertTrue("Should contain chest X-ray code 71046", "71046" in cptCodes)
    }

    @Test
    fun `hypertension I10 maps to ECG 93000`() {
        val dx = listOf(Diagnosis("I10", "Hypertension", isPrimary = true, confidence = 0.9f))
        val claim = ClaimEngine.generateClaim("test-cpt-02", dx, emptyList(), null)
        val cptCodes = claim.claimLines.map { it.cptCode }
        assertTrue("Should contain ECG code 93000", "93000" in cptCodes)
    }

    @Test
    fun `diabetes E11 maps to HbA1c 83036`() {
        val dx = listOf(Diagnosis("E11.9", "Type 2 DM", isPrimary = true, confidence = 0.9f))
        val claim = ClaimEngine.generateClaim("test-cpt-03", dx, emptyList(), null)
        val cptCodes = claim.claimLines.map { it.cptCode }
        assertTrue("Should contain HbA1c code 83036", "83036" in cptCodes)
    }

    @Test
    fun `UTI N39 maps to urinalysis 81001`() {
        val dx = listOf(Diagnosis("N39.0", "UTI", isPrimary = true, confidence = 0.9f))
        val claim = ClaimEngine.generateClaim("test-cpt-04", dx, emptyList(), null)
        val cptCodes = claim.claimLines.map { it.cptCode }
        assertTrue("Should contain urinalysis code 81001", "81001" in cptCodes)
    }

    @Test
    fun `depression F32 maps to psychotherapy 90834`() {
        val dx = listOf(Diagnosis("F32.1", "Depression", isPrimary = true, confidence = 0.9f))
        val claim = ClaimEngine.generateClaim("test-cpt-05", dx, emptyList(), null)
        val cptCodes = claim.claimLines.map { it.cptCode }
        assertTrue("Should contain psychotherapy code 90834", "90834" in cptCodes)
    }

    @Test
    fun `abscess L02 maps to I and D 10060`() {
        val dx = listOf(Diagnosis("L02.0", "Abscess", isPrimary = true, confidence = 0.9f))
        val claim = ClaimEngine.generateClaim("test-cpt-06", dx, emptyList(), null)
        val cptCodes = claim.claimLines.map { it.cptCode }
        assertTrue("Should contain I&D code 10060", "10060" in cptCodes)
    }

    @Test
    fun `duplicate EM code from diagnosis mapping is skipped`() {
        // J06 maps to 99213 which is the same as E/M level 3 code
        // If the E/M level is 3 (code 99213), then J06 diagnosis mapping should be skipped
        // 2 dx (2) + comprehensive vitals (2) + 0 meds (0) = score 4 -> level 3 (99213)
        val dx = listOf(
            Diagnosis("J06.9", "URTI", isPrimary = true, confidence = 0.9f),
            Diagnosis("I10", "Hypertension", confidence = 0.85f)
        )
        val vitals = VitalSigns(systolicBP = 130, temperature = 37.0f, pulse = 80)
        val claim = ClaimEngine.generateClaim("test-cpt-07", dx, emptyList(), vitals)
        // E/M level 3 -> 99213, J06 also maps to 99213 so it should be skipped
        val count99213 = claim.claimLines.count { it.cptCode == "99213" }
        assertEquals("99213 should appear only once (E/M, not duplicated from J06 mapping)", 1, count99213)
    }

    @Test
    fun `multiple diagnoses produce multiple CPT lines`() {
        val dx = listOf(
            Diagnosis("J18.9", "Pneumonia", isPrimary = true, confidence = 0.9f),
            Diagnosis("N39.0", "UTI", confidence = 0.85f)
        )
        val claim = ClaimEngine.generateClaim("test-cpt-08", dx, emptyList(), null)
        val cptCodes = claim.claimLines.map { it.cptCode }
        assertTrue("Should contain chest X-ray 71046", "71046" in cptCodes)
        assertTrue("Should contain urinalysis 81001", "81001" in cptCodes)
    }

    // ── Claim Line Generation: Medication Admin Codes ──

    @Test
    fun `IM route adds injection admin code 96372`() {
        val meds = listOf(Medication("0001", "Amoxicillin", 500f, "mg", "TDS", 7, "im", 0.85f))
        val dx = listOf(Diagnosis("J18.9", "Pneumonia", isPrimary = true, confidence = 0.9f))
        val claim = ClaimEngine.generateClaim("test-med-01", dx, meds, null)
        val cptCodes = claim.claimLines.map { it.cptCode }
        assertTrue("Should contain IM injection code 96372", "96372" in cptCodes)
    }

    @Test
    fun `SC route adds injection admin code 96372`() {
        val meds = listOf(Medication("0008", "Insulin", 10f, "units", "BD", 30, "sc", 0.9f))
        val dx = listOf(Diagnosis("E11.9", "Type 2 DM", isPrimary = true, confidence = 0.9f))
        val claim = ClaimEngine.generateClaim("test-med-02", dx, meds, null)
        val cptCodes = claim.claimLines.map { it.cptCode }
        assertTrue("Should contain SC injection code 96372", "96372" in cptCodes)
    }

    @Test
    fun `IV route adds infusion admin code 96365`() {
        val meds = listOf(Medication("0010", "Normal saline", 1000f, "ml", "STAT", 1, "iv", 0.9f))
        val dx = listOf(Diagnosis("A09", "Gastroenteritis", isPrimary = true, confidence = 0.9f))
        val claim = ClaimEngine.generateClaim("test-med-03", dx, meds, null)
        val cptCodes = claim.claimLines.map { it.cptCode }
        assertTrue("Should contain IV infusion code 96365", "96365" in cptCodes)
    }

    @Test
    fun `nebulizer route adds inhalation code 94640`() {
        val meds = listOf(Medication("0006", "Salbutamol", 5f, "mg", "STAT", 1, "nebulizer", 0.9f))
        val dx = listOf(Diagnosis("J45", "Asthma", isPrimary = true, confidence = 0.9f))
        val claim = ClaimEngine.generateClaim("test-med-04", dx, meds, null)
        val cptCodes = claim.claimLines.map { it.cptCode }
        assertTrue("Should contain nebulizer code 94640", "94640" in cptCodes)
    }

    @Test
    fun `oral route does not add non-oral admin code`() {
        val meds = listOf(Medication("0001", "Amoxicillin", 500f, "mg", "TDS", 7, "oral", 0.85f))
        val dx = listOf(Diagnosis("J18.9", "Pneumonia", isPrimary = true, confidence = 0.9f))
        val claim = ClaimEngine.generateClaim("test-med-05", dx, meds, null)
        val adminCodes = setOf("96372", "96365", "94640")
        val hasAdminCode = claim.claimLines.any { it.cptCode in adminCodes }
        assertFalse("Oral meds should not produce non-oral admin codes", hasAdminCode)
    }

    @Test
    fun `med admin line includes modifier 59`() {
        val meds = listOf(Medication("0001", "Amoxicillin", 500f, "mg", "TDS", 7, "im", 0.85f))
        val dx = listOf(Diagnosis("J18.9", "Pneumonia", isPrimary = true, confidence = 0.9f))
        val claim = ClaimEngine.generateClaim("test-med-06", dx, meds, null)
        val adminLine = claim.claimLines.find { it.cptCode == "96372" }
        assertNotNull("Should have an IM admin line", adminLine)
        assertEquals("59", adminLine!!.modifier)
    }

    // ── Claim Line Generation: Vitals Documentation ──

    @Test
    fun `comprehensive vitals adds 99000 documentation code`() {
        // Vitals with 4+ non-null of (systolicBP, temperature, pulse, weight, oxygenSaturation, respiratoryRate)
        val vitals = TestFixtures.sampleVitals() // has all 6 fields populated -> >=4
        val claim = ClaimEngine.generateClaim(
            "test-vitals-01",
            TestFixtures.sampleDiagnoses(),
            emptyList(),
            vitals
        )
        val cptCodes = claim.claimLines.map { it.cptCode }
        assertTrue("Should contain vitals documentation code 99000", "99000" in cptCodes)
    }

    @Test
    fun `sparse vitals does not add 99000`() {
        // Only 3 non-null of the 6 checked fields -> <4
        val vitals = VitalSigns(systolicBP = 120, pulse = 72, temperature = 37.0f)
        val claim = ClaimEngine.generateClaim(
            "test-vitals-02",
            TestFixtures.sampleDiagnoses(),
            emptyList(),
            vitals
        )
        val cptCodes = claim.claimLines.map { it.cptCode }
        assertFalse("Sparse vitals should not produce 99000", "99000" in cptCodes)
    }

    @Test
    fun `null vitals does not add 99000`() {
        val claim = ClaimEngine.generateClaim(
            "test-vitals-03",
            TestFixtures.sampleDiagnoses(),
            emptyList(),
            null
        )
        val cptCodes = claim.claimLines.map { it.cptCode }
        assertFalse("Null vitals should not produce 99000", "99000" in cptCodes)
    }

    @Test
    fun `99000 line has tariff 65 ZAR`() {
        val claim = ClaimEngine.generateClaim(
            "test-vitals-04",
            TestFixtures.sampleDiagnoses(),
            emptyList(),
            TestFixtures.sampleVitals()
        )
        val vitalsLine = claim.claimLines.find { it.cptCode == "99000" }
        assertNotNull("Should have vitals documentation line", vitalsLine)
        assertEquals(65.0, vitalsLine!!.tariffZAR, 0.01)
        assertEquals(4.40, vitalsLine.tariffUSD, 0.01)
    }

    // ── Tariff & Metadata ──

    @Test
    fun `total ZAR is sum of all claim lines`() {
        val claim = ClaimEngine.generateClaim(
            "test-tariff-01",
            TestFixtures.sampleDiagnoses(),
            TestFixtures.sampleMedications(),
            TestFixtures.sampleVitals()
        )
        val expectedTotal = claim.claimLines.sumOf { it.tariffZAR * it.units }
        assertEquals(expectedTotal, claim.totalZAR, 0.01)
    }

    @Test
    fun `total USD is sum of all claim lines`() {
        val claim = ClaimEngine.generateClaim(
            "test-tariff-02",
            TestFixtures.sampleDiagnoses(),
            TestFixtures.sampleMedications(),
            TestFixtures.sampleVitals()
        )
        val expectedTotal = claim.claimLines.sumOf { it.tariffUSD * it.units }
        assertEquals(expectedTotal, claim.totalUSD, 0.01)
    }

    @Test
    fun `EM level 1 tariff is 280 ZAR`() {
        val claim = ClaimEngine.generateClaim("test-tariff-03", emptyList(), emptyList(), null)
        val emLine = claim.claimLines.first()
        assertEquals("99211", emLine.cptCode)
        assertEquals(280.0, emLine.tariffZAR, 0.01)
        assertEquals(18.90, emLine.tariffUSD, 0.01)
    }

    @Test
    fun `EM level 3 tariff is 520 ZAR`() {
        // 2 dx (2) + comprehensive vitals (2) + 0 meds (0) = score 4 -> level 3
        val vitals = VitalSigns(systolicBP = 130, temperature = 37.0f, pulse = 80)
        val claim = ClaimEngine.generateClaim(
            "test-tariff-04",
            TestFixtures.sampleDiagnoses(),
            emptyList(),
            vitals
        )
        assertEquals(3, claim.emLevel)
        val emLine = claim.claimLines.first()
        assertEquals(520.0, emLine.tariffZAR, 0.01)
        assertEquals(35.15, emLine.tariffUSD, 0.01)
    }

    @Test
    fun `EM level 5 tariff is 985 ZAR`() {
        val diagnoses = (1..5).map {
            Diagnosis("J${10 + it}", "Diagnosis $it", isPrimary = it == 1, confidence = 0.9f)
        }
        val meds = (1..5).map {
            Medication("000$it", "Drug $it", 500f, "mg", "OD", 7, "PO", 0.8f)
        }
        val claim = ClaimEngine.generateClaim(
            "test-tariff-05",
            diagnoses,
            meds,
            TestFixtures.sampleVitals()
        )
        assertEquals(5, claim.emLevel)
        val emLine = claim.claimLines.first()
        assertEquals(985.0, emLine.tariffZAR, 0.01)
        assertEquals(66.55, emLine.tariffUSD, 0.01)
    }

    @Test
    fun `claimId format is CLM dash first 8 chars uppercased`() {
        val claim = ClaimEngine.generateClaim(
            "enc-test-001",
            TestFixtures.sampleDiagnoses(),
            emptyList(),
            null
        )
        assertEquals("CLM-ENC-TEST", claim.claimId)
    }

    @Test
    fun `claimId truncates long encounter IDs to 8 chars`() {
        val claim = ClaimEngine.generateClaim(
            "abcdefghijklmnop",
            TestFixtures.sampleDiagnoses(),
            emptyList(),
            null
        )
        assertEquals("CLM-ABCDEFGH", claim.claimId)
    }

    @Test
    fun `payerType is Medical Aid for za`() {
        val claim = ClaimEngine.generateClaim(
            "test-payer-01",
            TestFixtures.sampleDiagnoses(),
            emptyList(),
            null,
            countryCode = "za"
        )
        assertEquals("Medical Aid", claim.payerType)
    }

    @Test
    fun `payerType is Insurance for non-za countries`() {
        listOf("ke", "ng", "us", "gb", "et").forEach { code ->
            val claim = ClaimEngine.generateClaim(
                "test-payer-$code",
                TestFixtures.sampleDiagnoses(),
                emptyList(),
                null,
                countryCode = code
            )
            assertEquals("Insurance", claim.payerType)
        }
    }

    // ── Edge Cases ──

    @Test
    fun `empty diagnoses still produces EM line`() {
        val claim = ClaimEngine.generateClaim("test-edge-01", emptyList(), emptyList(), null)
        assertTrue("Should have at least one claim line (E/M)", claim.claimLines.isNotEmpty())
        assertEquals("99211", claim.claimLines[0].cptCode)
    }

    @Test
    fun `unknown ICD-10 prefix produces no extra CPT line`() {
        val dx = listOf(Diagnosis("Z99.9", "Unknown code", isPrimary = true, confidence = 0.9f))
        val claim = ClaimEngine.generateClaim("test-edge-02", dx, emptyList(), null)
        // Only the E/M line should exist (Z99 is not in the mapping)
        assertEquals("Should only have E/M line for unmapped code", 1, claim.claimLines.size)
    }

    @Test
    fun `null route on medication is treated as oral`() {
        val meds = listOf(Medication("0001", "Amoxicillin", 500f, "mg", "TDS", 7, null, 0.85f))
        val dx = listOf(Diagnosis("J18.9", "Pneumonia", isPrimary = true, confidence = 0.9f))
        val claim = ClaimEngine.generateClaim("test-edge-03", dx, meds, null)
        val adminCodes = setOf("96372", "96365", "94640")
        val hasAdminCode = claim.claimLines.any { it.cptCode in adminCodes }
        assertFalse("Null route should be treated as oral (no admin code)", hasAdminCode)
    }

    @Test
    fun `first claim line is always the EM code`() {
        val claim = ClaimEngine.generateClaim(
            "test-edge-04",
            TestFixtures.sampleDiagnoses(),
            TestFixtures.sampleMedications(),
            TestFixtures.sampleVitals()
        )
        val firstLine = claim.claimLines.first()
        assertTrue("First line description should start with E/M:", firstLine.description.startsWith("E/M:"))
    }

    @Test
    fun `icd10Pointers on EM line contain all diagnosis codes`() {
        val dx = listOf(
            Diagnosis("J18.9", "Pneumonia", isPrimary = true, confidence = 0.9f),
            Diagnosis("I10", "Hypertension", confidence = 0.85f),
            Diagnosis("E11.9", "DM type 2", confidence = 0.8f)
        )
        val claim = ClaimEngine.generateClaim("test-edge-05", dx, emptyList(), null)
        val emLine = claim.claimLines.first()
        assertEquals(3, emLine.icd10Pointers.size)
        assertTrue(emLine.icd10Pointers.containsAll(listOf("J18.9", "I10", "E11.9")))
    }
}
