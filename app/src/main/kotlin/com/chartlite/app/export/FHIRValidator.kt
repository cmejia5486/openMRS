package com.chartlite.app.export

import com.chartlite.app.database.entity.PatientEntity
import com.chartlite.app.model.*
import com.google.gson.GsonBuilder
import java.time.ZoneOffset
import java.time.format.DateTimeFormatter

/**
 * Validates and builds FHIR R4 Bundle resources from clinical encounters.
 *
 * FHIR is used as an EXPORT-ONLY format — no FHIR processing runs on-device
 * during normal clinical workflow. Bundles are generated on-demand when:
 * - Syncing to a DHIS2 server or hospital EMR over connectivity
 * - Sharing patient records via file export (Share intent)
 * - Regulatory data submission (e.g., HIPAA, POPIA compliance exports)
 *
 * On-device data storage uses Room + SQLCipher (not FHIR resources) for
 * performance on low-end hardware. The fhirResourceId field on clinical
 * entities stores the server-side reference after a successful export.
 *
 * Target: FHIR R4 (v4.0.1) — the version supported by DHIS2, OpenMRS,
 * and most African health information systems. R5/R6 export support can
 * be added when the ecosystem adopts it.
 */
object FHIRValidator {

    private val gson = GsonBuilder().setPrettyPrinting().create()
    private val dateFormatter = DateTimeFormatter.ISO_LOCAL_DATE.withZone(ZoneOffset.UTC)

    /**
     * Validate encounter and patient data for FHIR export.
     * Returns list of validation errors/warnings (empty = valid).
     */
    fun validate(encounter: StructuredEncounter, patient: PatientEntity): List<String> {
        val errors = mutableListOf<String>()

        // Patient validation
        if (patient.firstName.isBlank() && patient.lastName.isBlank()) {
            errors.add("Patient name is required (both first and last name are empty)")
        }
        if (patient.id.isBlank()) {
            errors.add("Patient ID is required")
        }
        if (patient.dateOfBirth.isNullOrBlank()) {
            errors.add("Patient date of birth is recommended for FHIR Patient resource")
        }

        // Encounter validation
        if (encounter.id.isBlank()) {
            errors.add("Encounter ID is required")
        }
        if (encounter.diagnoses.isEmpty()) {
            errors.add("No diagnoses found — Condition resources will be empty")
        }

        // Diagnosis code validation
        for (dx in encounter.diagnoses) {
            if (!dx.icd10Code.matches(Regex("[A-Z]\\d{2}(\\.\\d{1,2})?"))) {
                errors.add("Invalid ICD-10 code format: ${dx.icd10Code}")
            }
        }

        // Medication validation
        for (med in encounter.medications) {
            if (med.name.isBlank()) {
                errors.add("Medication name is required for MedicationRequest")
            }
        }

        // Vital sign LOINC code validation
        encounter.vitals?.let { v ->
            if (v.systolicBP != null && (v.systolicBP < 60 || v.systolicBP > 260)) {
                errors.add("Systolic BP ${v.systolicBP} outside valid range (60-260)")
            }
            if (v.diastolicBP != null && (v.diastolicBP < 30 || v.diastolicBP > 160)) {
                errors.add("Diastolic BP ${v.diastolicBP} outside valid range (30-160)")
            }
            if (v.temperature != null && (v.temperature < 34f || v.temperature > 42f)) {
                errors.add("Temperature ${v.temperature} outside valid range (34-42)")
            }
        }

        return errors
    }

    /**
     * Build a validated FHIR R4 Bundle JSON string.
     */
    fun buildValidatedBundle(encounter: StructuredEncounter, patient: PatientEntity): String {
        val entries = mutableListOf<Map<String, Any>>()

        // Patient resource
        entries.add(mapOf(
            "resource" to buildPatientResource(patient),
            "request" to mapOf("method" to "PUT", "url" to "Patient/${patient.id}")
        ))

        // Encounter resource
        entries.add(mapOf(
            "resource" to mapOf(
                "resourceType" to "Encounter",
                "id" to encounter.id,
                "status" to "finished",
                "class" to mapOf(
                    "system" to "http://terminology.hl7.org/CodeSystem/v3-ActCode",
                    "code" to "AMB",
                    "display" to "ambulatory"
                ),
                "period" to mapOf("start" to encounter.timestamp.toString()),
                "subject" to mapOf("reference" to "Patient/${encounter.patientId}"),
                "participant" to listOf(mapOf(
                    "individual" to mapOf("reference" to "Practitioner/${encounter.providerId}")
                ))
            ),
            "request" to mapOf("method" to "PUT", "url" to "Encounter/${encounter.id}")
        ))

        // Condition resources (diagnoses)
        for (dx in encounter.diagnoses) {
            entries.add(mapOf(
                "resource" to mapOf(
                    "resourceType" to "Condition",
                    "clinicalStatus" to mapOf(
                        "coding" to listOf(mapOf(
                            "system" to "http://terminology.hl7.org/CodeSystem/condition-clinical",
                            "code" to "active"
                        ))
                    ),
                    "verificationStatus" to mapOf(
                        "coding" to listOf(mapOf(
                            "system" to "http://terminology.hl7.org/CodeSystem/condition-ver-status",
                            "code" to if (dx.confidence >= 0.8f) "confirmed" else "provisional"
                        ))
                    ),
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

        // MedicationRequest resources
        for (med in encounter.medications) {
            val dosageText = buildString {
                if (med.dose != null) append("${med.dose}${med.unit ?: "mg"}")
                if (med.frequency != null) append(" ${med.frequency}")
                if (med.route != null) append(" ${med.route}")
                if (med.duration != null) append(" for ${med.duration} days")
            }.trim()

            entries.add(mapOf(
                "resource" to mapOf(
                    "resourceType" to "MedicationRequest",
                    "status" to "active",
                    "intent" to "order",
                    "medicationCodeableConcept" to mapOf("text" to med.name),
                    "subject" to mapOf("reference" to "Patient/${encounter.patientId}"),
                    "encounter" to mapOf("reference" to "Encounter/${encounter.id}"),
                    "dosageInstruction" to listOf(mapOf("text" to dosageText))
                ),
                "request" to mapOf("method" to "POST", "url" to "MedicationRequest")
            ))
        }

        // Observation resources (vitals)
        encounter.vitals?.let { v ->
            val vitals = listOfNotNull(
                v.systolicBP?.let { buildObservation("85354-9", "Blood pressure systolic", it, "mmHg", encounter) },
                v.diastolicBP?.let { buildObservation("8462-4", "Blood pressure diastolic", it, "mmHg", encounter) },
                v.temperature?.let { buildObservation("8310-5", "Body temperature", it, "Cel", encounter) },
                v.pulse?.let { buildObservation("8867-4", "Heart rate", it, "/min", encounter) },
                v.weight?.let { buildObservation("29463-7", "Body weight", it, "kg", encounter) },
                v.height?.let { buildObservation("8302-2", "Body height", it, "cm", encounter) },
                v.respiratoryRate?.let { buildObservation("9279-1", "Respiratory rate", it, "/min", encounter) },
                v.oxygenSaturation?.let { buildObservation("2708-6", "Oxygen saturation", it, "%", encounter) }
            )
            entries.addAll(vitals)
        }

        // AllergyIntolerance resources
        for (allergy in encounter.allergies) {
            entries.add(mapOf(
                "resource" to mapOf(
                    "resourceType" to "AllergyIntolerance",
                    "clinicalStatus" to mapOf(
                        "coding" to listOf(mapOf(
                            "system" to "http://terminology.hl7.org/CodeSystem/allergyintolerance-clinical",
                            "code" to "active"
                        ))
                    ),
                    "code" to mapOf("text" to allergy),
                    "patient" to mapOf("reference" to "Patient/${encounter.patientId}")
                ),
                "request" to mapOf("method" to "POST", "url" to "AllergyIntolerance")
            ))
        }

        val bundle = mapOf(
            "resourceType" to "Bundle",
            "type" to "transaction",
            "timestamp" to encounter.timestamp.toString(),
            "entry" to entries
        )

        return gson.toJson(bundle)
    }

    private fun buildPatientResource(patient: PatientEntity): Map<String, Any?> {
        return mapOf(
            "resourceType" to "Patient",
            "id" to patient.id,
            "identifier" to listOf(mapOf(
                "system" to "urn:afrimed:patient-id",
                "value" to patient.id
            )),
            "name" to listOf(mapOf(
                "family" to patient.lastName,
                "given" to listOf(patient.firstName)
            )),
            "gender" to patient.gender,
            "birthDate" to patient.dateOfBirth,
            "telecom" to listOfNotNull(
                patient.phoneNumber?.let { mapOf("system" to "phone", "value" to it, "use" to "mobile") }
            )
        )
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
                    "system" to "http://loinc.org",
                    "code" to loincCode,
                    "display" to display
                ))),
                "subject" to mapOf("reference" to "Patient/${encounter.patientId}"),
                "encounter" to mapOf("reference" to "Encounter/${encounter.id}"),
                "effectiveDateTime" to encounter.timestamp.toString(),
                "valueQuantity" to mapOf(
                    "value" to value,
                    "unit" to unit,
                    "system" to "http://unitsofmeasure.org",
                    "code" to unit
                )
            ),
            "request" to mapOf("method" to "POST", "url" to "Observation")
        )
    }
}
