package com.chartlite.app

import com.chartlite.app.database.entity.PatientEntity
import com.chartlite.app.export.FHIRValidator
import com.chartlite.app.model.*
import com.google.gson.Gson
import com.google.gson.JsonObject
import org.junit.Assert.*
import org.junit.Test
import java.time.Instant

class FHIRExportValidationTest {

    private val gson = Gson()

    private fun buildTestEncounter() = StructuredEncounter(
        id = "enc-test-001",
        patientId = "KFMT-4WRN",
        providerId = "prov-001",
        facilityId = "fac-001",
        timestamp = Instant.parse("2025-06-15T10:30:00Z"),
        transcript = "test",
        medications = listOf(
            Medication("0001", "Amoxicillin", 500f, "mg", "TDS", 7, "PO", 0.85f)
        ),
        diagnoses = listOf(
            Diagnosis("J18.9", "Pneumonia", isPrimary = true, confidence = 0.9f)
        ),
        vitals = VitalSigns(systolicBP = 130, diastolicBP = 85, temperature = 38.5f, pulse = 92),
        allergies = listOf("penicillin"),
        followUp = FollowUp(7, "review"),
        referral = null,
        freeTextNote = "Patient improving",
        extractionConfidence = 0.85f
    )

    private fun buildTestPatient() = PatientEntity(
        id = "KFMT-4WRN",
        firstName = "John",
        lastName = "Doe",
        dateOfBirth = "1990-01-15",
        gender = "male",
        phoneNumber = "+27821234567",
        nationalId = null,
        allergies = "penicillin",
        createdAt = System.currentTimeMillis()
    )

    @Test
    fun `FHIR bundle validates resourceType`() {
        val encounter = buildTestEncounter()
        val patient = buildTestPatient()
        val bundle = FHIRValidator.buildValidatedBundle(encounter, patient)
        val json = gson.fromJson(bundle, JsonObject::class.java)

        assertEquals("Bundle", json.get("resourceType").asString)
        assertEquals("transaction", json.get("type").asString)
        assertNotNull(json.get("timestamp"))
        assertTrue(json.has("entry"))
    }

    @Test
    fun `FHIR bundle contains Patient resource`() {
        val bundle = FHIRValidator.buildValidatedBundle(buildTestEncounter(), buildTestPatient())
        val json = gson.fromJson(bundle, JsonObject::class.java)
        val entries = json.getAsJsonArray("entry")

        val patientEntry = entries.firstOrNull {
            it.asJsonObject.getAsJsonObject("resource")
                .get("resourceType").asString == "Patient"
        }
        assertNotNull("Bundle should contain a Patient resource", patientEntry)

        val patientResource = patientEntry!!.asJsonObject.getAsJsonObject("resource")
        assertEquals("KFMT-4WRN", patientResource.get("id").asString)
        assertEquals("male", patientResource.get("gender").asString)
    }

    @Test
    fun `FHIR bundle contains Encounter resource`() {
        val bundle = FHIRValidator.buildValidatedBundle(buildTestEncounter(), buildTestPatient())
        val json = gson.fromJson(bundle, JsonObject::class.java)
        val entries = json.getAsJsonArray("entry")

        val encounterEntry = entries.firstOrNull {
            it.asJsonObject.getAsJsonObject("resource")
                .get("resourceType").asString == "Encounter"
        }
        assertNotNull("Bundle should contain an Encounter resource", encounterEntry)

        val resource = encounterEntry!!.asJsonObject.getAsJsonObject("resource")
        assertEquals("finished", resource.get("status").asString)
    }

    @Test
    fun `FHIR bundle contains Condition for each diagnosis`() {
        val bundle = FHIRValidator.buildValidatedBundle(buildTestEncounter(), buildTestPatient())
        val json = gson.fromJson(bundle, JsonObject::class.java)
        val entries = json.getAsJsonArray("entry")

        val conditions = entries.filter {
            it.asJsonObject.getAsJsonObject("resource")
                .get("resourceType").asString == "Condition"
        }
        assertEquals(1, conditions.size)

        val condResource = conditions[0].asJsonObject.getAsJsonObject("resource")
        val coding = condResource.getAsJsonObject("code")
            .getAsJsonArray("coding")[0].asJsonObject
        assertEquals("J18.9", coding.get("code").asString)
        assertEquals("http://hl7.org/fhir/sid/icd-10", coding.get("system").asString)
    }

    @Test
    fun `FHIR bundle contains MedicationRequest for each medication`() {
        val bundle = FHIRValidator.buildValidatedBundle(buildTestEncounter(), buildTestPatient())
        val json = gson.fromJson(bundle, JsonObject::class.java)
        val entries = json.getAsJsonArray("entry")

        val medRequests = entries.filter {
            it.asJsonObject.getAsJsonObject("resource")
                .get("resourceType").asString == "MedicationRequest"
        }
        assertEquals(1, medRequests.size)

        val medResource = medRequests[0].asJsonObject.getAsJsonObject("resource")
        assertEquals("active", medResource.get("status").asString)
        assertEquals("order", medResource.get("intent").asString)
    }

    @Test
    fun `FHIR bundle contains Observation for each vital`() {
        val bundle = FHIRValidator.buildValidatedBundle(buildTestEncounter(), buildTestPatient())
        val json = gson.fromJson(bundle, JsonObject::class.java)
        val entries = json.getAsJsonArray("entry")

        val observations = entries.filter {
            it.asJsonObject.getAsJsonObject("resource")
                .get("resourceType").asString == "Observation"
        }
        // systolicBP, diastolicBP, temperature, pulse = 4 observations
        // (weight, height, spo2, rr are null in the test encounter)
        assertEquals("Should have exactly 4 observations (sysBP, diaBP, temp, pulse)", 4, observations.size)

        // Verify LOINC codes are present
        for (obs in observations) {
            val resource = obs.asJsonObject.getAsJsonObject("resource")
            val coding = resource.getAsJsonObject("code")
                .getAsJsonArray("coding")[0].asJsonObject
            assertEquals("http://loinc.org", coding.get("system").asString)
            assertNotNull(coding.get("code"))
        }
    }

    @Test
    fun `FHIR bundle subject references are consistent`() {
        val bundle = FHIRValidator.buildValidatedBundle(buildTestEncounter(), buildTestPatient())
        val json = gson.fromJson(bundle, JsonObject::class.java)
        val entries = json.getAsJsonArray("entry")

        for (entry in entries) {
            val resource = entry.asJsonObject.getAsJsonObject("resource")
            val type = resource.get("resourceType").asString
            if (type in listOf("Condition", "MedicationRequest", "Observation", "Encounter")) {
                val subject = resource.getAsJsonObject("subject")
                if (subject != null) {
                    assertEquals("Patient/KFMT-4WRN", subject.get("reference").asString)
                }
            }
        }
    }

    @Test
    fun `FHIR validation detects missing required fields`() {
        val errors = FHIRValidator.validate(buildTestEncounter(), buildTestPatient())
        assertTrue("Valid encounter should have no errors", errors.isEmpty())
    }

    @Test
    fun `FHIR validation flags encounter without diagnoses`() {
        val encounter = buildTestEncounter().copy(diagnoses = emptyList())
        val errors = FHIRValidator.validate(encounter, buildTestPatient())
        assertTrue("Should warn about empty diagnoses",
            errors.any { it.contains("diagnos", ignoreCase = true) })
    }

    @Test
    fun `FHIR validation flags patient without name`() {
        val patient = buildTestPatient().copy(firstName = "", lastName = "")
        val errors = FHIRValidator.validate(buildTestEncounter(), patient)
        assertTrue("Should warn about missing patient name",
            errors.any { it.contains("name", ignoreCase = true) })
    }
}
