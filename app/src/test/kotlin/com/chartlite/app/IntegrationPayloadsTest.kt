package com.chartlite.app

import com.chartlite.app.billing.ClaimEngine
import com.chartlite.app.billing.IntegrationPayloads
import com.chartlite.app.billing.IntegrationPayloads.DiseaseBurden
import com.chartlite.app.model.*
import org.junit.Assert.*
import org.junit.Test

class IntegrationPayloadsTest {

    // ───────────────────────────────────────────────
    // Shared helpers
    // ───────────────────────────────────────────────

    private val enc = TestFixtures.buildEncounterEntity()
    private val diagnoses = TestFixtures.sampleDiagnoses()
    private val medications = TestFixtures.sampleMedications()

    private fun defaultClaim(): ClaimEngine.ClaimPreview =
        ClaimEngine.generateClaim(
            encounterId = enc.id,
            diagnoses = diagnoses,
            medications = medications,
            vitals = TestFixtures.sampleVitals()
        )

    // ═══════════════════════════════════════════════
    //  build837PClaim
    // ═══════════════════════════════════════════════

    @Test
    fun `837P contains ISA segment`() {
        val claim = defaultClaim()
        val output = IntegrationPayloads.build837PClaim(enc, claim, diagnoses, "Sipho Dlamini", "Dr. Nkosi")
        assertTrue(output.contains("ISA*"))
    }

    @Test
    fun `837P contains GS segment`() {
        val claim = defaultClaim()
        val output = IntegrationPayloads.build837PClaim(enc, claim, diagnoses, "Sipho Dlamini", "Dr. Nkosi")
        assertTrue(output.contains("GS*HC*CHARTLITE"))
    }

    @Test
    fun `837P contains ST segment with version`() {
        val claim = defaultClaim()
        val output = IntegrationPayloads.build837PClaim(enc, claim, diagnoses, "Sipho Dlamini", "Dr. Nkosi")
        assertTrue(output.contains("ST*837*0001*005010X222A1"))
    }

    @Test
    fun `837P contains provider name in NM1 segment`() {
        val claim = defaultClaim()
        val output = IntegrationPayloads.build837PClaim(enc, claim, diagnoses, "Sipho Dlamini", "Dr. Nkosi")
        assertTrue(output.contains("NM1*85*1*Dr. Nkosi"))
    }

    @Test
    fun `837P contains patient name and ID in subscriber segment`() {
        val claim = defaultClaim()
        val output = IntegrationPayloads.build837PClaim(enc, claim, diagnoses, "Sipho Dlamini", "Dr. Nkosi")
        assertTrue(output.contains("NM1*IL*1*Sipho Dlamini"))
        assertTrue(output.contains("KFMT-4WRN"))
    }

    @Test
    fun `837P uses ABK qualifier for principal diagnosis`() {
        val claim = defaultClaim()
        val output = IntegrationPayloads.build837PClaim(enc, claim, diagnoses, "Sipho Dlamini", "Dr. Nkosi")
        assertTrue(output.contains("HI*ABK:J18.9"))
    }

    @Test
    fun `837P uses ABF qualifier for secondary diagnosis`() {
        val claim = defaultClaim()
        val output = IntegrationPayloads.build837PClaim(enc, claim, diagnoses, "Sipho Dlamini", "Dr. Nkosi")
        assertTrue(output.contains("HI*ABF:I10"))
    }

    @Test
    fun `837P contains service lines with SV1 segments`() {
        val claim = defaultClaim()
        val output = IntegrationPayloads.build837PClaim(enc, claim, diagnoses, "Sipho Dlamini", "Dr. Nkosi")
        assertTrue(output.contains("SV1*HC:"))
    }

    @Test
    fun `837P contains LX line numbers`() {
        val claim = defaultClaim()
        val output = IntegrationPayloads.build837PClaim(enc, claim, diagnoses, "Sipho Dlamini", "Dr. Nkosi")
        assertTrue(output.contains("LX*1"))
    }

    @Test
    fun `837P contains closing SE GE IEA segments`() {
        val claim = defaultClaim()
        val output = IntegrationPayloads.build837PClaim(enc, claim, diagnoses, "Sipho Dlamini", "Dr. Nkosi")
        assertTrue(output.contains("SE*"))
        assertTrue(output.contains("GE*1*1"))
        assertTrue(output.contains("IEA*1*000000001"))
    }

    @Test
    fun `837P includes claim totals in ZAR and USD`() {
        val claim = defaultClaim()
        val output = IntegrationPayloads.build837PClaim(enc, claim, diagnoses, "Sipho Dlamini", "Dr. Nkosi")
        assertTrue(output.contains("Total ZAR: R"))
        assertTrue(output.contains("Total USD: $"))
    }

    @Test
    fun `837P shows E-M level and code`() {
        val claim = defaultClaim()
        val output = IntegrationPayloads.build837PClaim(enc, claim, diagnoses, "Sipho Dlamini", "Dr. Nkosi")
        assertTrue(output.contains("E/M Level:"))
        assertTrue(output.contains(claim.emCode))
    }

    // ═══════════════════════════════════════════════
    //  buildFHIRMedicationRequests
    // ═══════════════════════════════════════════════

    @Test
    fun `FHIR bundle contains resourceType Bundle`() {
        val output = IntegrationPayloads.buildFHIRMedicationRequests(
            enc, medications, diagnoses, "Sipho Dlamini", "Dr. Nkosi"
        )
        assertTrue(output.contains("\"resourceType\": \"Bundle\""))
    }

    @Test
    fun `FHIR bundle type is transaction`() {
        val output = IntegrationPayloads.buildFHIRMedicationRequests(
            enc, medications, diagnoses, "Sipho Dlamini", "Dr. Nkosi"
        )
        assertTrue(output.contains("\"type\": \"transaction\""))
    }

    @Test
    fun `FHIR bundle contains MedicationRequest entries`() {
        val output = IntegrationPayloads.buildFHIRMedicationRequests(
            enc, medications, diagnoses, "Sipho Dlamini", "Dr. Nkosi"
        )
        assertTrue(output.contains("\"resourceType\": \"MedicationRequest\""))
    }

    @Test
    fun `FHIR bundle contains dosageInstruction`() {
        val output = IntegrationPayloads.buildFHIRMedicationRequests(
            enc, medications, diagnoses, "Sipho Dlamini", "Dr. Nkosi"
        )
        assertTrue(output.contains("\"dosageInstruction\""))
    }

    @Test
    fun `FHIR bundle contains dispenseRequest for meds with duration`() {
        val output = IntegrationPayloads.buildFHIRMedicationRequests(
            enc, medications, diagnoses, "Sipho Dlamini", "Dr. Nkosi"
        )
        assertTrue(output.contains("\"dispenseRequest\""))
        assertTrue(output.contains("expectedSupplyDuration"))
    }

    @Test
    fun `FHIR bundle includes reasonCode from diagnoses`() {
        val output = IntegrationPayloads.buildFHIRMedicationRequests(
            enc, medications, diagnoses, "Sipho Dlamini", "Dr. Nkosi"
        )
        assertTrue(output.contains("\"reasonCode\""))
        assertTrue(output.contains("J18.9"))
    }

    @Test
    fun `FHIR bundle contains patient reference`() {
        val output = IntegrationPayloads.buildFHIRMedicationRequests(
            enc, medications, diagnoses, "Sipho Dlamini", "Dr. Nkosi"
        )
        assertTrue(output.contains("\"reference\": \"Patient/KFMT-4WRN\""))
    }

    @Test
    fun `FHIR bundle contains pharmacy routing summary`() {
        val output = IntegrationPayloads.buildFHIRMedicationRequests(
            enc, medications, diagnoses, "Sipho Dlamini", "Dr. Nkosi"
        )
        assertTrue(output.contains("Pharmacy Routing"))
        assertTrue(output.contains("Medications: 2"))
    }

    // ═══════════════════════════════════════════════
    //  buildDHIS2DataValueSets
    // ═══════════════════════════════════════════════

    @Test
    fun `DHIS2 contains dataSet identifier`() {
        val output = IntegrationPayloads.buildDHIS2DataValueSets(
            "fac-001", "202406", listOf(enc),
            listOf("Pneumonia" to 10), listOf("Amoxicillin" to 8), 50
        )
        assertTrue(output.contains("PHC_MONTHLY_REPORT"))
    }

    @Test
    fun `DHIS2 contains OPD visit indicators`() {
        val output = IntegrationPayloads.buildDHIS2DataValueSets(
            "fac-001", "202406", listOf(enc),
            listOf("Pneumonia" to 10), listOf("Amoxicillin" to 8), 50
        )
        assertTrue(output.contains("OPD_TOTAL_VISITS"))
        assertTrue(output.contains("OPD_NEW_PATIENTS"))
        assertTrue(output.contains("OPD_REVISITS"))
    }

    @Test
    fun `DHIS2 revisits is non-negative even when totalPatients exceeds encounters`() {
        val output = IntegrationPayloads.buildDHIS2DataValueSets(
            "fac-001", "202406", listOf(enc),
            emptyList(), emptyList(), 100 // totalPatients > encounters.size
        )
        // coerceAtLeast(0) should keep it non-negative
        assertTrue(output.contains("\"value\": \"0\""))
    }

    @Test
    fun `DHIS2 contains morbidity data elements`() {
        val topDx = listOf("Pneumonia" to 12, "Hypertension" to 9)
        val output = IntegrationPayloads.buildDHIS2DataValueSets(
            "fac-001", "202406", listOf(enc), topDx, emptyList(), 50
        )
        assertTrue(output.contains("MORBIDITY_1"))
        assertTrue(output.contains("MORBIDITY_2"))
        assertTrue(output.contains("Pneumonia"))
    }

    @Test
    fun `DHIS2 contains drug dispensed data elements`() {
        val topMeds = listOf("Amoxicillin" to 20)
        val output = IntegrationPayloads.buildDHIS2DataValueSets(
            "fac-001", "202406", listOf(enc), emptyList(), topMeds, 50
        )
        assertTrue(output.contains("DRUG_DISPENSED_1"))
        assertTrue(output.contains("Amoxicillin"))
    }

    @Test
    fun `DHIS2 counts referrals from encounters`() {
        val encWithReferral = TestFixtures.buildEncounterEntity(referralType = "specialist")
        val output = IntegrationPayloads.buildDHIS2DataValueSets(
            "fac-001", "202406", listOf(encWithReferral),
            emptyList(), emptyList(), 1
        )
        assertTrue(output.contains("REFERRALS_OUT"))
        assertTrue(output.contains("\"value\": \"1\""))
    }

    @Test
    fun `DHIS2 metadata section shows facility and period`() {
        val output = IntegrationPayloads.buildDHIS2DataValueSets(
            "fac-001", "202406", listOf(enc),
            emptyList(), emptyList(), 1
        )
        assertTrue(output.contains("Org Unit: fac-001"))
        assertTrue(output.contains("Period: 202406"))
    }

    // ═══════════════════════════════════════════════
    //  buildPopulationHealth
    // ═══════════════════════════════════════════════

    @Test
    fun `population health groups by ICD-10 chapter`() {
        val dx = listOf(
            "J18.9" to "Pneumonia",
            "J06.9" to "URTI",
            "I10" to "Hypertension"
        )
        val result = IntegrationPayloads.buildPopulationHealth(dx, 100)
        val chapters = result.map { it.chapter }
        assertTrue(chapters.contains("Respiratory"))
        assertTrue(chapters.contains("Cardiovascular"))
    }

    @Test
    fun `population health merges A and B codes into Infectious chapter`() {
        val dx = listOf(
            "A09" to "Gastroenteritis",
            "B50" to "Malaria"
        )
        val result = IntegrationPayloads.buildPopulationHealth(dx, 100)
        assertEquals(1, result.size)
        assertEquals("Infectious & Parasitic", result[0].chapter)
        assertEquals(2, result[0].count)
    }

    @Test
    fun `population health calculates percentage correctly`() {
        val dx = listOf(
            "J18.9" to "Pneumonia",
            "J06.9" to "URTI"
        )
        val result = IntegrationPayloads.buildPopulationHealth(dx, 200)
        val respiratory = result.first { it.chapter == "Respiratory" }
        assertEquals(1.0f, respiratory.percentage, 0.01f) // 2/200 * 100 = 1.0%
    }

    @Test
    fun `population health sorts burdens by count descending`() {
        val dx = listOf(
            "I10" to "Hypertension",
            "J18.9" to "Pneumonia",
            "J06.9" to "URTI",
            "J45" to "Asthma"
        )
        val result = IntegrationPayloads.buildPopulationHealth(dx, 100)
        // Respiratory has 3 entries, Cardiovascular has 1
        assertEquals("Respiratory", result[0].chapter)
        assertEquals("Cardiovascular", result[1].chapter)
    }

    @Test
    fun `population health conditions within chapter sorted by count descending`() {
        val dx = listOf(
            "J18.9" to "Pneumonia",
            "J18.9" to "Pneumonia",
            "J06.9" to "URTI"
        )
        val result = IntegrationPayloads.buildPopulationHealth(dx, 100)
        val respiratory = result.first { it.chapter == "Respiratory" }
        assertEquals("Pneumonia", respiratory.conditions[0].first)
        assertEquals(2, respiratory.conditions[0].second)
    }

    @Test
    fun `population health returns empty list for no diagnoses`() {
        val result = IntegrationPayloads.buildPopulationHealth(emptyList(), 100)
        assertTrue(result.isEmpty())
    }

    @Test
    fun `population health handles zero totalEncounters gracefully`() {
        val dx = listOf("J18.9" to "Pneumonia")
        val result = IntegrationPayloads.buildPopulationHealth(dx, 0)
        assertEquals(0f, result[0].percentage, 0.001f)
    }

    @Test
    fun `population health chapterCode is first letter of ICD-10`() {
        val dx = listOf("E11.9" to "Type 2 DM")
        val result = IntegrationPayloads.buildPopulationHealth(dx, 50)
        assertEquals("E", result[0].chapterCode)
        assertEquals("Endocrine/Metabolic", result[0].chapter)
    }
}
