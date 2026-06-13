package com.chartlite.app.database.entity

import androidx.room.Entity
import androidx.room.ForeignKey
import androidx.room.Index
import androidx.room.PrimaryKey

@Entity(
    tableName = "patients",
    indices = [Index("lastName"), Index("phoneNumber"), Index("updatedAt")]
)
data class PatientEntity(
    @PrimaryKey val id: String,               // 8-char patient ID (KFMT-4WRN)
    val firstName: String,
    val lastName: String,
    val dateOfBirth: String? = null,           // ISO date or null
    val ageYears: Int? = null,                 // if DOB unknown
    val gender: String,                        // male, female, other
    val phoneNumber: String? = null,
    val nationalId: String? = null,
    val pin: String? = null,                   // Optional 4-digit PIN for shared-phone SMS encryption. Stored plaintext because PBKDF2 derivation requires it. DB is SQLCipher-encrypted at rest.
    val allergies: String = "[]",              // JSON array of strings
    val address: String? = null,
    val consentGiven: Boolean = false,
    val consentTimestamp: Long? = null,
    val createdAt: Long = System.currentTimeMillis(),
    val updatedAt: Long = System.currentTimeMillis()
)

@Entity(tableName = "providers")
data class ProviderEntity(
    @PrimaryKey val id: String,
    val name: String,
    val qualification: String,
    val facilityId: String,
    val createdAt: Long = System.currentTimeMillis()
)

@Entity(tableName = "facilities")
data class FacilityEntity(
    @PrimaryKey val id: String,
    val name: String,
    val address: String? = null,
    val type: String? = null,
    val createdAt: Long = System.currentTimeMillis()
)

@Entity(
    tableName = "encounters",
    foreignKeys = [
        ForeignKey(
            entity = PatientEntity::class,
            parentColumns = ["id"],
            childColumns = ["patientId"],
            onDelete = ForeignKey.CASCADE
        )
    ],
    indices = [Index("patientId"), Index("timestamp"), Index("providerId")]
)
data class EncounterEntity(
    @PrimaryKey val id: String,
    val patientId: String,
    val providerId: String,
    val facilityId: String,
    val timestamp: Long,
    val transcript: String,
    val medications: String = "[]",          // JSON array of Medication
    val diagnoses: String = "[]",            // JSON array of Diagnosis
    val vitals: String? = null,              // JSON VitalSigns or null
    val allergies: String = "[]",            // JSON array of strings
    val followUpDays: Int? = null,
    val followUpReason: String? = null,
    val referralType: String? = null,
    val referralSpecialty: String? = null,
    val referralUrgency: String? = null,
    val referralReason: String? = null,
    val freeTextNote: String = "",
    val extractionConfidence: Float = 0f,
    val cdssAlerts: String = "[]",           // JSON array of CDSSAlert
    val cdssAcknowledged: Boolean = false,
    val smsStatus: String? = null,           // PENDING, SENT, DELIVERED, FAILED
    val stationType: String? = null,        // ClinicStation.name (null = solo mode)
    val createdAt: Long = System.currentTimeMillis(),
    // Benchmark-driven categories (2026-03 architecture update)
    val examFindings: String = "[]",         // JSON array of strings
    val investigations: String = "[]",       // JSON array of Investigation
    val plan: String = "[]",                 // JSON array of strings
    val socialHistory: String = "[]",        // JSON array of strings
    val suggestedDiagnoses: String = "[]",   // JSON array of Diagnosis (LLM-suggested, needs clinician confirmation)
    val immunizations: String = "[]",        // JSON array of ExtractedImmunization
    val smsSummary: String? = null           // ≤19-char abbreviated visit summary for SMS wire format
)

@Entity(
    tableName = "visits",
    foreignKeys = [
        ForeignKey(
            entity = PatientEntity::class,
            parentColumns = ["id"],
            childColumns = ["patientId"],
            onDelete = ForeignKey.CASCADE
        )
    ],
    indices = [Index("patientId"), Index("status"), Index("visitDate")]
)
data class VisitEntity(
    @PrimaryKey val id: String,
    val patientId: String,
    val facilityId: String,
    val visitDate: String,                     // ISO date YYYY-MM-DD
    val status: String,                        // VisitStatus.name
    val currentStation: String? = null,        // ClinicStation.name
    val registeredBy: String? = null,          // providerId who registered
    val triagedBy: String? = null,             // providerId who triaged
    val consultedBy: String? = null,           // providerId who consulted
    val dispensedBy: String? = null,           // providerId who dispensed
    val triageEncounterId: String? = null,     // EncounterEntity.id for triage data
    val consultEncounterId: String? = null,    // EncounterEntity.id for consultation data
    val pharmacyNotes: String? = null,         // JSON: dispensed items, substitutions
    val priorityLevel: Int = 0,               // 0=normal, 1=priority, 2=emergency
    val chiefComplaint: String? = null,
    val createdAt: Long = System.currentTimeMillis(),
    val updatedAt: Long = System.currentTimeMillis()
)
