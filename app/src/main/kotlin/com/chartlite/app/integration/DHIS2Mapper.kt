package com.chartlite.app.integration

import com.chartlite.app.database.entity.*
import com.chartlite.app.model.LabOrderStatus
import java.time.Instant
import java.time.LocalDate
import java.time.ZoneId
import java.time.format.DateTimeFormatter

/**
 * Maps internal ChartLite entities to DHIS2 data values and tracker events.
 *
 * Supports two DHIS2 data models:
 * 1. Aggregate (dataValueSets) — monthly indicator reports
 * 2. Tracker (trackedEntityInstances + events) — individual patient records
 *
 * Data element IDs follow DHIS2 naming convention but must be mapped to
 * actual DHIS2 metadata UIDs during deployment.
 */
object DHIS2Mapper {

    // ── Aggregate Data Values ────────────────────────────────────────

    data class DataValue(
        val dataElement: String,
        val categoryOptionCombo: String = "",
        val value: String,
        val comment: String? = null
    )

    data class DataValueSet(
        val dataSet: String,
        val period: String,
        val orgUnit: String,
        val completeDate: String,
        val dataValues: List<DataValue>
    )

    /**
     * Build aggregate monthly report from facility data.
     */
    fun buildMonthlyReport(
        config: DHIS2Config,
        period: String,
        encounters: List<EncounterEntity>,
        labOrders: List<LabOrderEntity>,
        referrals: List<ReferralEntity>,
        immunizations: List<ImmunizationEntity>,
        stockItems: List<StockItemEntity>,
        patientCount: Int
    ): DataValueSet {
        val dataValues = mutableListOf<DataValue>()

        // OPD indicators
        dataValues.add(DataValue("OPD_TOTAL_VISITS", value = "${encounters.size}"))
        dataValues.add(DataValue("OPD_NEW_PATIENTS", value = "$patientCount"))

        // Referrals
        val referralCount = referrals.size
        dataValues.add(DataValue("REFERRALS_OUT", value = "$referralCount"))
        val emergencyReferrals = referrals.count { it.urgency == "EMERGENCY" }
        dataValues.add(DataValue("REFERRALS_EMERGENCY", value = "$emergencyReferrals"))

        // Lab indicators
        val labOrdered = labOrders.count { it.status != LabOrderStatus.CANCELLED.name }
        val labResulted = labOrders.count { it.status == LabOrderStatus.RESULTED.name }
        dataValues.add(DataValue("LAB_ORDERS_TOTAL", value = "$labOrdered"))
        dataValues.add(DataValue("LAB_RESULTS_RECEIVED", value = "$labResulted"))

        // HIV testing (if applicable)
        val hivTests = labOrders.filter { it.testCode.contains("HIV", ignoreCase = true) }
        if (hivTests.isNotEmpty()) {
            dataValues.add(DataValue("HIV_TESTS_CONDUCTED", value = "${hivTests.size}"))
            val hivPositive = hivTests.count { it.isAbnormal == true }
            dataValues.add(DataValue("HIV_TESTS_POSITIVE", value = "$hivPositive"))
        }

        // Malaria testing
        val malariaTests = labOrders.filter { it.testCode.contains("MALARIA", ignoreCase = true) }
        if (malariaTests.isNotEmpty()) {
            dataValues.add(DataValue("MALARIA_TESTS_CONDUCTED", value = "${malariaTests.size}"))
            val malariaPositive = malariaTests.count { it.isAbnormal == true }
            dataValues.add(DataValue("MALARIA_TESTS_POSITIVE", value = "$malariaPositive"))
        }

        // Immunization indicators
        val vaccineGroups = immunizations.groupBy { it.vaccineCode }
        vaccineGroups.forEach { (code, records) ->
            dataValues.add(DataValue(
                "IMM_${code.uppercase()}",
                value = "${records.size}",
                comment = records.firstOrNull()?.vaccineName ?: code
            ))
        }

        // Stock alerts
        val lowStockItems = stockItems.filter { it.quantityOnHand <= it.reorderLevel }
        val outOfStockItems = stockItems.filter { it.quantityOnHand == 0 }
        dataValues.add(DataValue("STOCK_LOW_COUNT", value = "${lowStockItems.size}"))
        dataValues.add(DataValue("STOCK_OUT_COUNT", value = "${outOfStockItems.size}"))

        return DataValueSet(
            dataSet = config.dataSetId,
            period = period,
            orgUnit = config.orgUnitId,
            completeDate = LocalDate.now().toString(),
            dataValues = dataValues
        )
    }

    // ── Tracker: Patient Events ──────────────────────────────────────

    data class TrackerEvent(
        val program: String,
        val programStage: String,
        val orgUnit: String,
        val eventDate: String,
        val status: String = "COMPLETED",
        val dataValues: List<DataValue>
    )

    /**
     * Map an encounter to a DHIS2 tracker event.
     */
    fun mapEncounterToEvent(
        encounter: EncounterEntity,
        orgUnit: String,
        program: String = "CLINICAL_ENCOUNTER"
    ): TrackerEvent {
        val eventDate = DateTimeFormatter.ISO_LOCAL_DATE
            .format(Instant.ofEpochMilli(encounter.timestamp).atZone(ZoneId.systemDefault()))

        val dataValues = mutableListOf(
            DataValue("ENCOUNTER_TYPE", value = encounter.stationType ?: "GENERAL"),
            DataValue("PROVIDER_ID", value = encounter.providerId),
            DataValue("PATIENT_ID", value = encounter.patientId)
        )

        // Use transcript excerpt as chief complaint summary
        val cc = encounter.freeTextNote.ifBlank { encounter.transcript }
        if (cc.isNotBlank()) {
            dataValues.add(DataValue("CHIEF_COMPLAINT", value = cc.take(250)))
        }

        return TrackerEvent(
            program = program,
            programStage = "CONSULTATION",
            orgUnit = orgUnit,
            eventDate = eventDate,
            dataValues = dataValues
        )
    }

    /**
     * Map a lab order to a DHIS2 tracker event.
     */
    fun mapLabOrderToEvent(
        labOrder: LabOrderEntity,
        orgUnit: String,
        program: String = "LAB_REGISTER"
    ): TrackerEvent {
        val eventDate = DateTimeFormatter.ISO_LOCAL_DATE
            .format(Instant.ofEpochMilli(labOrder.orderedAt).atZone(ZoneId.systemDefault()))

        val dataValues = mutableListOf(
            DataValue("TEST_CODE", value = labOrder.testCode),
            DataValue("TEST_NAME", value = labOrder.testName),
            DataValue("STATUS", value = labOrder.status),
            DataValue("PRIORITY", value = labOrder.priority)
        )

        labOrder.resultValue?.let { dataValues.add(DataValue("RESULT_VALUE", value = it)) }
        labOrder.resultUnit?.let { dataValues.add(DataValue("RESULT_UNIT", value = it)) }
        labOrder.isAbnormal?.let { dataValues.add(DataValue("IS_ABNORMAL", value = it.toString())) }

        return TrackerEvent(
            program = program,
            programStage = "LAB_TEST",
            orgUnit = orgUnit,
            eventDate = eventDate,
            dataValues = dataValues
        )
    }

    /**
     * Map an immunization record to a DHIS2 tracker event.
     */
    fun mapImmunizationToEvent(
        immunization: ImmunizationEntity,
        orgUnit: String,
        program: String = "EPI_REGISTER"
    ): TrackerEvent {
        val eventDate = DateTimeFormatter.ISO_LOCAL_DATE
            .format(Instant.ofEpochMilli(immunization.administeredAt).atZone(ZoneId.systemDefault()))

        val dataValues = mutableListOf(
            DataValue("VACCINE_CODE", value = immunization.vaccineCode),
            DataValue("VACCINE_NAME", value = immunization.vaccineName),
            DataValue("DOSE_NUMBER", value = "${immunization.doseNumber}"),
            DataValue("PATIENT_ID", value = immunization.patientId)
        )

        immunization.batchNumber?.let { dataValues.add(DataValue("BATCH_NUMBER", value = it)) }
        immunization.site?.let { dataValues.add(DataValue("ADMINISTRATION_SITE", value = it)) }

        return TrackerEvent(
            program = program,
            programStage = "VACCINATION",
            orgUnit = orgUnit,
            eventDate = eventDate,
            dataValues = dataValues
        )
    }

    // ── JSON Serialization ───────────────────────────────────────────

    /** Escape special characters for safe JSON string embedding. */
    private fun escapeJson(value: String): String = value
        .replace("\\", "\\\\")
        .replace("\"", "\\\"")
        .replace("\n", "\\n")
        .replace("\r", "\\r")
        .replace("\t", "\\t")

    /**
     * Serialize DataValueSet to DHIS2-compatible JSON string.
     */
    fun toJson(dvs: DataValueSet): String {
        return buildString {
            appendLine("{")
            appendLine("  \"dataSet\": \"${escapeJson(dvs.dataSet)}\",")
            appendLine("  \"completeDate\": \"${escapeJson(dvs.completeDate)}\",")
            appendLine("  \"period\": \"${escapeJson(dvs.period)}\",")
            appendLine("  \"orgUnit\": \"${escapeJson(dvs.orgUnit)}\",")
            appendLine("  \"dataValues\": [")
            dvs.dataValues.forEachIndexed { i, dv ->
                val comma = if (i < dvs.dataValues.size - 1) "," else ""
                val comment = dv.comment?.let { ", \"comment\": \"${escapeJson(it)}\"" } ?: ""
                val coc = if (dv.categoryOptionCombo.isNotBlank()) ", \"categoryOptionCombo\": \"${escapeJson(dv.categoryOptionCombo)}\"" else ""
                appendLine("    {\"dataElement\": \"${escapeJson(dv.dataElement)}\", \"value\": \"${escapeJson(dv.value)}\"$coc$comment}$comma")
            }
            appendLine("  ]")
            appendLine("}")
        }
    }

    /**
     * Serialize TrackerEvent to DHIS2-compatible JSON string.
     */
    fun toJson(event: TrackerEvent): String {
        return buildString {
            appendLine("{")
            appendLine("  \"program\": \"${escapeJson(event.program)}\",")
            appendLine("  \"programStage\": \"${escapeJson(event.programStage)}\",")
            appendLine("  \"orgUnit\": \"${escapeJson(event.orgUnit)}\",")
            appendLine("  \"eventDate\": \"${escapeJson(event.eventDate)}\",")
            appendLine("  \"status\": \"${escapeJson(event.status)}\",")
            appendLine("  \"dataValues\": [")
            event.dataValues.forEachIndexed { i, dv ->
                val comma = if (i < event.dataValues.size - 1) "," else ""
                appendLine("    {\"dataElement\": \"${escapeJson(dv.dataElement)}\", \"value\": \"${escapeJson(dv.value)}\"}$comma")
            }
            appendLine("  ]")
            appendLine("}")
        }
    }
}
