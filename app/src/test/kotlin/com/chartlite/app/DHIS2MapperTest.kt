package com.chartlite.app

import com.chartlite.app.database.entity.*
import com.chartlite.app.integration.DHIS2Config
import com.chartlite.app.integration.DHIS2Mapper
import org.junit.Assert.*
import org.junit.Test

class DHIS2MapperTest {

    private val testConfig = DHIS2Config(
        serverUrl = "https://dhis2.test.org",
        username = "admin",
        password = "pass",
        orgUnitId = "ORG_001"
    )

    // ── Config Tests ─────────────────────────────────────────────

    @Test
    fun `DHIS2Config isConfigured when all required fields set`() {
        assertTrue(testConfig.isConfigured)
    }

    @Test
    fun `DHIS2Config not configured when serverUrl blank`() {
        assertFalse(DHIS2Config.EMPTY.isConfigured)
    }

    @Test
    fun `DHIS2Config not configured when password blank`() {
        val config = testConfig.copy(password = "")
        assertFalse(config.isConfigured)
    }

    @Test
    fun `DHIS2Config toString does not expose password`() {
        val config = testConfig.copy(password = "s3cret123")
        val str = config.toString()
        assertFalse("Password should not appear in toString", str.contains("s3cret123"))
        assertTrue("Masked password should appear", str.contains("***"))
    }

    @Test
    fun `DHIS2Config apiUrl appends trailing slash and api`() {
        assertEquals("https://dhis2.test.org/api/", testConfig.apiUrl)
    }

    @Test
    fun `DHIS2Config apiUrl handles trailing slash in serverUrl`() {
        val config = testConfig.copy(serverUrl = "https://dhis2.test.org/")
        assertEquals("https://dhis2.test.org/api/", config.apiUrl)
    }

    // ── Monthly Report Tests ─────────────────────────────────────

    @Test
    fun `buildMonthlyReport includes OPD indicators`() {
        val encounters = listOf(
            makeEncounter("e1"),
            makeEncounter("e2"),
            makeEncounter("e3")
        )

        val report = DHIS2Mapper.buildMonthlyReport(
            config = testConfig, period = "202603",
            encounters = encounters, labOrders = emptyList(),
            referrals = emptyList(), immunizations = emptyList(),
            stockItems = emptyList(), patientCount = 2
        )

        assertEquals("PHC_MONTHLY_REPORT", report.dataSet)
        assertEquals("202603", report.period)
        assertEquals("ORG_001", report.orgUnit)

        val opdVisits = report.dataValues.first { it.dataElement == "OPD_TOTAL_VISITS" }
        assertEquals("3", opdVisits.value)

        val opdNew = report.dataValues.first { it.dataElement == "OPD_NEW_PATIENTS" }
        assertEquals("2", opdNew.value)
    }

    @Test
    fun `buildMonthlyReport includes referral counts`() {
        val referrals = listOf(
            makeReferral("r1", urgency = "ROUTINE"),
            makeReferral("r2", urgency = "EMERGENCY"),
            makeReferral("r3", urgency = "EMERGENCY")
        )

        val report = DHIS2Mapper.buildMonthlyReport(
            config = testConfig, period = "202603",
            encounters = emptyList(), labOrders = emptyList(),
            referrals = referrals, immunizations = emptyList(),
            stockItems = emptyList(), patientCount = 0
        )

        val totalRef = report.dataValues.first { it.dataElement == "REFERRALS_OUT" }
        assertEquals("3", totalRef.value)

        val emergencyRef = report.dataValues.first { it.dataElement == "REFERRALS_EMERGENCY" }
        assertEquals("2", emergencyRef.value)
    }

    @Test
    fun `buildMonthlyReport includes lab indicators`() {
        val labs = listOf(
            makeLabOrder("l1", testCode = "CBC", status = "RESULTED"),
            makeLabOrder("l2", testCode = "HIV_RAPID", status = "RESULTED", isAbnormal = true),
            makeLabOrder("l3", testCode = "CBC", status = "ORDERED"),
            makeLabOrder("l4", testCode = "RDT_MALARIA", status = "CANCELLED")
        )

        val report = DHIS2Mapper.buildMonthlyReport(
            config = testConfig, period = "202603",
            encounters = emptyList(), labOrders = labs,
            referrals = emptyList(), immunizations = emptyList(),
            stockItems = emptyList(), patientCount = 0
        )

        val labTotal = report.dataValues.first { it.dataElement == "LAB_ORDERS_TOTAL" }
        assertEquals("3", labTotal.value) // 4 minus 1 cancelled

        val labResulted = report.dataValues.first { it.dataElement == "LAB_RESULTS_RECEIVED" }
        assertEquals("2", labResulted.value)

        val hivTests = report.dataValues.first { it.dataElement == "HIV_TESTS_CONDUCTED" }
        assertEquals("1", hivTests.value)

        val hivPositive = report.dataValues.first { it.dataElement == "HIV_TESTS_POSITIVE" }
        assertEquals("1", hivPositive.value)
    }

    @Test
    fun `buildMonthlyReport includes immunization indicators`() {
        val immunizations = listOf(
            makeImmunization("i1", vaccineCode = "BCG", vaccineName = "BCG"),
            makeImmunization("i2", vaccineCode = "OPV1", vaccineName = "Oral Polio 1"),
            makeImmunization("i3", vaccineCode = "BCG", vaccineName = "BCG")
        )

        val report = DHIS2Mapper.buildMonthlyReport(
            config = testConfig, period = "202603",
            encounters = emptyList(), labOrders = emptyList(),
            referrals = emptyList(), immunizations = immunizations,
            stockItems = emptyList(), patientCount = 0
        )

        val bcg = report.dataValues.first { it.dataElement == "IMM_BCG" }
        assertEquals("2", bcg.value)

        val opv = report.dataValues.first { it.dataElement == "IMM_OPV1" }
        assertEquals("1", opv.value)
    }

    @Test
    fun `buildMonthlyReport includes stock alerts`() {
        val items = listOf(
            makeStockItem("s1", quantity = 100, reorderLevel = 50),
            makeStockItem("s2", quantity = 10, reorderLevel = 50),
            makeStockItem("s3", quantity = 0, reorderLevel = 20)
        )

        val report = DHIS2Mapper.buildMonthlyReport(
            config = testConfig, period = "202603",
            encounters = emptyList(), labOrders = emptyList(),
            referrals = emptyList(), immunizations = emptyList(),
            stockItems = items, patientCount = 0
        )

        val lowStock = report.dataValues.first { it.dataElement == "STOCK_LOW_COUNT" }
        assertEquals("2", lowStock.value) // s2 and s3

        val outOfStock = report.dataValues.first { it.dataElement == "STOCK_OUT_COUNT" }
        assertEquals("1", outOfStock.value)
    }

    // ── Tracker Event Tests ──────────────────────────────────────

    @Test
    fun `mapEncounterToEvent creates correct tracker event`() {
        val encounter = makeEncounter("e1")
        val event = DHIS2Mapper.mapEncounterToEvent(encounter, "ORG_001")

        assertEquals("CLINICAL_ENCOUNTER", event.program)
        assertEquals("CONSULTATION", event.programStage)
        assertEquals("ORG_001", event.orgUnit)
        assertEquals("COMPLETED", event.status)

        val patientDv = event.dataValues.first { it.dataElement == "PATIENT_ID" }
        assertEquals("patient1", patientDv.value)
    }

    @Test
    fun `mapLabOrderToEvent includes test details`() {
        val lab = makeLabOrder("l1", testCode = "CBC", status = "RESULTED", resultValue = "12.5")
        val event = DHIS2Mapper.mapLabOrderToEvent(lab, "ORG_001")

        assertEquals("LAB_REGISTER", event.program)
        assertEquals("LAB_TEST", event.programStage)

        val testCode = event.dataValues.first { it.dataElement == "TEST_CODE" }
        assertEquals("CBC", testCode.value)

        val resultVal = event.dataValues.first { it.dataElement == "RESULT_VALUE" }
        assertEquals("12.5", resultVal.value)
    }

    @Test
    fun `mapImmunizationToEvent includes vaccine details`() {
        val imm = makeImmunization("i1", vaccineCode = "BCG", vaccineName = "BCG")
        val event = DHIS2Mapper.mapImmunizationToEvent(imm, "ORG_001")

        assertEquals("EPI_REGISTER", event.program)

        val vaccineCode = event.dataValues.first { it.dataElement == "VACCINE_CODE" }
        assertEquals("BCG", vaccineCode.value)

        val dose = event.dataValues.first { it.dataElement == "DOSE_NUMBER" }
        assertEquals("1", dose.value)
    }

    // ── JSON Serialization Tests ─────────────────────────────────

    @Test
    fun `toJson DataValueSet produces valid JSON structure`() {
        val dvs = DHIS2Mapper.DataValueSet(
            dataSet = "TEST_DS",
            period = "202601",
            orgUnit = "ORG_001",
            completeDate = "2026-01-31",
            dataValues = listOf(
                DHIS2Mapper.DataValue("ELEM1", value = "100"),
                DHIS2Mapper.DataValue("ELEM2", value = "200", comment = "Test")
            )
        )

        val json = DHIS2Mapper.toJson(dvs)
        assertTrue(json.contains("\"dataSet\": \"TEST_DS\""))
        assertTrue(json.contains("\"period\": \"202601\""))
        assertTrue(json.contains("\"orgUnit\": \"ORG_001\""))
        assertTrue(json.contains("\"ELEM1\""))
        assertTrue(json.contains("\"comment\": \"Test\""))
    }

    @Test
    fun `toJson TrackerEvent produces valid JSON structure`() {
        val event = DHIS2Mapper.TrackerEvent(
            program = "TEST_PROG",
            programStage = "STAGE_1",
            orgUnit = "ORG_001",
            eventDate = "2026-01-15",
            dataValues = listOf(DHIS2Mapper.DataValue("DV1", value = "val1"))
        )

        val json = DHIS2Mapper.toJson(event)
        assertTrue(json.contains("\"program\": \"TEST_PROG\""))
        assertTrue(json.contains("\"programStage\": \"STAGE_1\""))
        assertTrue(json.contains("\"eventDate\": \"2026-01-15\""))
        assertTrue(json.contains("\"DV1\""))
    }

    @Test
    fun `toJson escapes special characters in values`() {
        val dvs = DHIS2Mapper.DataValueSet(
            dataSet = "TEST_DS",
            period = "202601",
            orgUnit = "ORG_001",
            completeDate = "2026-01-31",
            dataValues = listOf(
                DHIS2Mapper.DataValue("ELEM1", value = "He said \"hello\""),
                DHIS2Mapper.DataValue("ELEM2", value = "Line1\nLine2", comment = "Tab\there")
            )
        )

        val json = DHIS2Mapper.toJson(dvs)
        // Verify special chars are escaped, not raw
        assertTrue(json.contains("He said \\\"hello\\\""))
        assertTrue(json.contains("Line1\\nLine2"))
        assertTrue(json.contains("Tab\\there"))
        // Verify it does NOT contain unescaped quotes in value
        assertFalse(json.contains("\"He said \"hello\"\""))
    }

    // ── Helper Factories ─────────────────────────────────────────

    private fun makeEncounter(id: String) = EncounterEntity(
        id = id, patientId = "patient1", providerId = "provider1",
        facilityId = "fac1", timestamp = System.currentTimeMillis(),
        transcript = "Patient presents with headache"
    )

    private fun makeReferral(id: String, urgency: String = "ROUTINE") = ReferralEntity(
        id = id, visitId = "v1", patientId = "p1", fromProviderId = "prov1",
        fromFacilityId = "fac1", toFacility = "Hospital", toDepartment = null,
        urgency = urgency, reason = "Test", clinicalNotes = null,
        status = "PENDING",
        referredAt = System.currentTimeMillis(), updatedAt = System.currentTimeMillis()
    )

    private fun makeLabOrder(
        id: String, testCode: String = "CBC", status: String = "ORDERED",
        isAbnormal: Boolean? = null, resultValue: String? = null
    ) = LabOrderEntity(
        id = id, visitId = "v1", patientId = "p1",
        testCode = testCode, testName = testCode, orderedBy = "u1",
        status = status, priority = "ROUTINE",
        resultValue = resultValue, resultUnit = null, referenceRange = null,
        isAbnormal = isAbnormal, notes = null,
        orderedAt = System.currentTimeMillis(),
        collectedAt = null, resultedAt = null, resultedBy = null
    )

    private fun makeImmunization(id: String, vaccineCode: String, vaccineName: String) = ImmunizationEntity(
        id = id, patientId = "p1", vaccineCode = vaccineCode, vaccineName = vaccineName,
        doseNumber = 1, administeredAt = System.currentTimeMillis(),
        administeredBy = "u1", batchNumber = null, site = null,
        nextDoseCode = null, nextDoseDueDate = null, facilityId = "fac1"
    )

    private fun makeStockItem(id: String, quantity: Int, reorderLevel: Int) = StockItemEntity(
        id = id, facilityId = "fac1", drugCode = "DRUG_$id", drugName = "Drug $id",
        quantityOnHand = quantity, reorderLevel = reorderLevel, unit = "tablets",
        batchNumber = null, expiryDate = null,
        lastUpdatedBy = "u1", lastUpdatedAt = System.currentTimeMillis()
    )
}
