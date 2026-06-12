package com.chartlite.app.export

import android.content.Context
import android.content.Intent
import android.os.Environment
import androidx.core.content.FileProvider
import com.chartlite.app.database.EncounterRepository
import com.chartlite.app.database.entity.EncounterEntity
import com.chartlite.app.database.entity.PatientEntity
import com.chartlite.app.model.*
import com.google.gson.GsonBuilder
import java.io.File
import java.time.Instant
import java.time.ZoneOffset
import java.time.format.DateTimeFormatter

/**
 * Exports clinical data in FHIR R4 Bundle (JSON) and CSV formats.
 *
 * Export-only: FHIR Bundles are generated on-demand for external systems
 * (DHIS2, OpenMRS, hospital EMRs). No FHIR processing runs during
 * normal on-device clinical workflow — all on-device storage uses Room + SQLCipher.
 */
class DataExporter(
    private val context: Context,
    private val encounterRepository: EncounterRepository
) {

    private val gson = GsonBuilder().setPrettyPrinting().create()
    private val dateFormatter = DateTimeFormatter.ISO_LOCAL_DATE.withZone(ZoneOffset.UTC)

    /**
     * Export a single encounter as a FHIR Bundle JSON.
     */
    fun exportEncounterAsFHIR(encounter: StructuredEncounter, patient: PatientEntity): String {
        val bundle = buildFHIRBundle(encounter, patient)
        return gson.toJson(bundle)
    }

    /**
     * Export all encounters for a patient as a FHIR Bundle JSON.
     */
    suspend fun exportPatientAsFHIR(patient: PatientEntity): String {
        val entities = encounterRepository.getByPatientId(patient.id)
        val encounters = entities.map { encounterRepository.toStructuredEncounter(it) }

        val entries = mutableListOf<Map<String, Any>>()

        // Patient resource
        entries.add(mapOf(
            "resource" to buildPatientResource(patient),
            "request" to mapOf("method" to "PUT", "url" to "Patient/${patient.id}")
        ))

        // Encounter + related resources
        for (enc in encounters) {
            entries.addAll(buildEncounterEntries(enc))
        }

        val bundle = mapOf(
            "resourceType" to "Bundle",
            "type" to "transaction",
            "timestamp" to Instant.now().toString(),
            "entry" to entries
        )

        return gson.toJson(bundle)
    }

    /**
     * Export encounters as CSV.
     */
    suspend fun exportEncountersAsCSV(encounters: List<EncounterEntity>): String {
        val sb = StringBuilder()
        sb.appendLine("date,patient_id,diagnoses,medications,systolic_bp,diastolic_bp,temperature,pulse,weight,spo2,follow_up_days")

        for (entity in encounters) {
            val enc = encounterRepository.toStructuredEncounter(entity)
            val date = dateFormatter.format(enc.timestamp)
            val dx = enc.diagnoses.joinToString("; ") { "${it.icd10Code} ${it.description}" }
            val meds = enc.medications.joinToString("; ") {
                "${it.name} ${it.dose ?: ""}${it.unit ?: ""} ${it.frequency ?: ""}"
            }
            sb.appendLine(
                "$date,${enc.patientId},\"$dx\",\"$meds\"," +
                "${enc.vitals?.systolicBP ?: ""},${enc.vitals?.diastolicBP ?: ""}," +
                "${enc.vitals?.temperature ?: ""},${enc.vitals?.pulse ?: ""}," +
                "${enc.vitals?.weight ?: ""},${enc.vitals?.oxygenSaturation ?: ""}," +
                "${enc.followUp?.days ?: ""}"
            )
        }
        return sb.toString()
    }

    /**
     * Save export string to file and return share intent.
     */
    fun saveAndShare(content: String, filename: String, mimeType: String): Intent {
        val exportDir = File(context.filesDir, "exports")
        exportDir.mkdirs()
        val file = File(exportDir, filename)
        file.writeText(content)

        val uri = FileProvider.getUriForFile(
            context,
            "${context.packageName}.fileprovider",
            file
        )

        return Intent(Intent.ACTION_SEND).apply {
            type = mimeType
            putExtra(Intent.EXTRA_STREAM, uri)
            addFlags(Intent.FLAG_GRANT_READ_URI_PERMISSION)
        }
    }

    private fun buildFHIRBundle(encounter: StructuredEncounter, patient: PatientEntity): Map<String, Any> {
        val entries = mutableListOf<Map<String, Any>>()
        entries.add(mapOf(
            "resource" to buildPatientResource(patient),
            "request" to mapOf("method" to "PUT", "url" to "Patient/${patient.id}")
        ))
        entries.addAll(buildEncounterEntries(encounter))

        return mapOf(
            "resourceType" to "Bundle",
            "type" to "transaction",
            "timestamp" to encounter.timestamp.toString(),
            "entry" to entries
        )
    }

    private fun buildPatientResource(patient: PatientEntity): Map<String, Any?> {
        return mapOf(
            "resourceType" to "Patient",
            "id" to patient.id,
            "identifier" to listOf(mapOf("value" to patient.id)),
            "name" to listOf(mapOf(
                "family" to patient.lastName,
                "given" to listOf(patient.firstName)
            )),
            "gender" to patient.gender,
            "birthDate" to patient.dateOfBirth,
            "telecom" to listOfNotNull(
                patient.phoneNumber?.let { mapOf("system" to "phone", "value" to it) }
            )
        )
    }

    private fun buildEncounterEntries(encounter: StructuredEncounter): List<Map<String, Any>> {
        val entries = mutableListOf<Map<String, Any>>()

        // Encounter resource
        entries.add(mapOf(
            "resource" to mapOf(
                "resourceType" to "Encounter",
                "id" to encounter.id,
                "status" to "finished",
                "class" to mapOf("code" to "AMB", "display" to "ambulatory"),
                "period" to mapOf("start" to encounter.timestamp.toString()),
                "subject" to mapOf("reference" to "Patient/${encounter.patientId}")
            ),
            "request" to mapOf("method" to "PUT", "url" to "Encounter/${encounter.id}")
        ))

        // Conditions (diagnoses)
        for (dx in encounter.diagnoses) {
            entries.add(mapOf(
                "resource" to mapOf(
                    "resourceType" to "Condition",
                    "code" to mapOf("coding" to listOf(mapOf(
                        "system" to "http://hl7.org/fhir/sid/icd-10",
                        "code" to dx.icd10Code,
                        "display" to dx.description
                    ))),
                    "subject" to mapOf("reference" to "Patient/${encounter.patientId}"),
                    "encounter" to mapOf("reference" to "Encounter/${encounter.id}")
                ),
                "request" to mapOf("method" to "POST", "url" to "Condition")
            ))
        }

        // MedicationRequests
        for (med in encounter.medications) {
            entries.add(mapOf(
                "resource" to mapOf(
                    "resourceType" to "MedicationRequest",
                    "status" to "active",
                    "intent" to "order",
                    "medicationCodeableConcept" to mapOf("text" to med.name),
                    "subject" to mapOf("reference" to "Patient/${encounter.patientId}"),
                    "encounter" to mapOf("reference" to "Encounter/${encounter.id}"),
                    "dosageInstruction" to listOf(mapOf(
                        "text" to "${med.dose ?: ""}${med.unit ?: ""} ${med.frequency ?: ""} ${med.route ?: ""}"
                    ))
                ),
                "request" to mapOf("method" to "POST", "url" to "MedicationRequest")
            ))
        }

        // Vital Observations
        encounter.vitals?.let { v ->
            val vitalEntries = listOfNotNull(
                v.systolicBP?.let { buildObservation("85354-9", "Blood pressure", it, "mmHg", encounter) },
                v.temperature?.let { buildObservation("8310-5", "Temperature", it, "Cel", encounter) },
                v.pulse?.let { buildObservation("8867-4", "Heart rate", it, "/min", encounter) },
                v.weight?.let { buildObservation("29463-7", "Weight", it, "kg", encounter) },
                v.oxygenSaturation?.let { buildObservation("2708-6", "SpO2", it, "%", encounter) }
            )
            entries.addAll(vitalEntries)
        }

        return entries
    }

    private fun buildObservation(
        loincCode: String, display: String, value: Number, unit: String,
        encounter: StructuredEncounter
    ): Map<String, Any> {
        return mapOf(
            "resource" to mapOf(
                "resourceType" to "Observation",
                "status" to "final",
                "code" to mapOf("coding" to listOf(mapOf(
                    "system" to "http://loinc.org", "code" to loincCode, "display" to display
                ))),
                "subject" to mapOf("reference" to "Patient/${encounter.patientId}"),
                "encounter" to mapOf("reference" to "Encounter/${encounter.id}"),
                "valueQuantity" to mapOf("value" to value, "unit" to unit)
            ),
            "request" to mapOf("method" to "POST", "url" to "Observation")
        )
    }
}
