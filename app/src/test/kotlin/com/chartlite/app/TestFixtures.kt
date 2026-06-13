package com.chartlite.app

import com.chartlite.app.database.entity.EncounterEntity
import com.chartlite.app.model.*
import com.google.gson.Gson

object TestFixtures {
    val gson = Gson()

    val testFormulary = Formulary(
        version = "test",
        country = "ZA",
        drugs = listOf(
            FormularyDrug("0001", "Amoxicillin", listOf("amoxil", "amoxicillin"), listOf("250mg", "500mg"), "PO", "antibiotic", "S4"),
            FormularyDrug("0002", "Metformin", listOf("metformin", "glucophage"), listOf("500mg", "850mg"), "PO", "antidiabetic", "S3"),
            FormularyDrug("0003", "Paracetamol", listOf("paracetamol", "panado"), listOf("500mg", "1000mg"), "PO", "analgesic", "S0"),
            FormularyDrug("0004", "Ibuprofen", listOf("ibuprofen", "brufen"), listOf("200mg", "400mg"), "PO", "nsaid", "S1"),
            FormularyDrug("0005", "Amlodipine", listOf("amlodipine", "norvasc"), listOf("5mg", "10mg"), "PO", "antihypertensive", "S3"),
            FormularyDrug("0006", "Salbutamol", listOf("salbutamol", "ventolin"), listOf("100mcg"), "INH", "bronchodilator", "S2"),
            FormularyDrug("0007", "Omeprazole", listOf("omeprazole", "losec"), listOf("20mg", "40mg"), "PO", "ppi", "S3")
        )
    )

    val testIcd10 = ICD10Index(
        version = "test",
        codes = listOf(
            ICD10Entry("J18.9", "Pneumonia, unspecified", listOf("pneumonia", "chest infection", "lung infection"), emptyMap()),
            ICD10Entry("J06.9", "Upper respiratory infection", listOf("cold", "flu", "upper respiratory", "URTI"), emptyMap()),
            ICD10Entry("E11.9", "Type 2 diabetes mellitus", listOf("diabetes", "sugar", "glucose high", "type 2"), emptyMap()),
            ICD10Entry("I10", "Essential hypertension", listOf("hypertension", "high blood pressure", "BP high"), emptyMap()),
            ICD10Entry("N39.0", "Urinary tract infection", listOf("UTI", "urinary", "burning urination"), emptyMap()),
            ICD10Entry("K21.0", "Gastro-oesophageal reflux", listOf("reflux", "GERD", "heartburn", "acid"), emptyMap())
        )
    )

    fun sampleDiagnoses() = listOf(
        Diagnosis("J18.9", "Pneumonia, unspecified", isPrimary = true, confidence = 0.9f),
        Diagnosis("I10", "Essential hypertension", isPrimary = false, confidence = 0.85f)
    )

    fun sampleMedications() = listOf(
        Medication("0001", "Amoxicillin", 500f, "mg", "TDS", 7, "PO", 0.85f),
        Medication("0005", "Amlodipine", 5f, "mg", "OD", 30, "PO", 0.9f)
    )

    fun sampleVitals() = VitalSigns(
        systolicBP = 130, diastolicBP = 85, temperature = 37.2f,
        pulse = 82, weight = 75f, height = 170f,
        respiratoryRate = 18, oxygenSaturation = 97
    )

    fun sampleAlerts() = listOf(
        CDSSAlert(AlertSeverity.WARNING, "Dosage", "Amoxicillin dose at upper range", "medications")
    )

    fun buildEncounterEntity(
        id: String = "enc-test-001",
        patientId: String = "KFMT-4WRN",
        providerId: String = "prov-001",
        facilityId: String = "fac-001",
        timestamp: Long = 1718445000000L, // 2024-06-15T10:30:00Z
        transcript: String = "Patient presents with cough and fever for 3 days. History of hypertension.",
        diagnoses: List<Diagnosis> = sampleDiagnoses(),
        medications: List<Medication> = sampleMedications(),
        vitals: VitalSigns? = sampleVitals(),
        allergies: List<String> = listOf("penicillin"),
        alerts: List<CDSSAlert> = emptyList(),
        followUpDays: Int? = 7,
        followUpReason: String? = "review chest X-ray",
        referralType: String? = null,
        referralSpecialty: String? = null,
        referralUrgency: String? = null,
        referralReason: String? = null,
        freeTextNote: String = "",
        smsStatus: String? = null
    ) = EncounterEntity(
        id = id,
        patientId = patientId,
        providerId = providerId,
        facilityId = facilityId,
        timestamp = timestamp,
        transcript = transcript,
        medications = gson.toJson(medications),
        diagnoses = gson.toJson(diagnoses),
        vitals = vitals?.let { gson.toJson(it) },
        allergies = gson.toJson(allergies),
        cdssAlerts = gson.toJson(alerts),
        cdssAcknowledged = false,
        followUpDays = followUpDays,
        followUpReason = followUpReason,
        referralType = referralType,
        referralSpecialty = referralSpecialty,
        referralUrgency = referralUrgency,
        referralReason = referralReason,
        freeTextNote = freeTextNote,
        extractionConfidence = 0.85f,
        smsStatus = smsStatus
    )
}
