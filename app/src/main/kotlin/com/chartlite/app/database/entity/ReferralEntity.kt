package com.chartlite.app.database.entity

import androidx.room.Entity
import androidx.room.Index
import androidx.room.PrimaryKey

@Entity(
    tableName = "referrals",
    indices = [
        Index("patientId"),
        Index("visitId"),
        Index("status"),
        Index("fromFacilityId"),
        Index(value = ["fromFacilityId", "status"])
    ]
)
data class ReferralEntity(
    @PrimaryKey val id: String,
    val visitId: String,
    val patientId: String,
    val fromProviderId: String,
    val fromFacilityId: String,
    val toFacility: String,
    val toDepartment: String?,
    val urgency: String,         // ROUTINE, URGENT, EMERGENCY
    val reason: String,
    val clinicalNotes: String?,
    val status: String,          // PENDING, ACCEPTED, COMPLETED, CANCELLED
    val referredAt: Long,
    val updatedAt: Long,
    // Forward-compatible fields for AI agent integration and extensibility
    val metadata: String? = null,       // JSON blob for future extensibility without schema changes
    val sourceAgentId: String? = null,  // Non-null if created/modified by an AI agent
    val syncStatus: String? = null,     // PENDING, SYNCED, CONFLICT — for future multi-device sync
    val fhirResourceId: String? = null,  // FHIR R4 ServiceRequest reference for interoperability
    // Patient-facing referral fields
    val patientInstructions: String? = null,  // "Bring ID, clinic card, test results"
    val timeframeDays: Int? = null,           // Days within which patient should attend (0=today)
    val smsText: String? = null               // Plain-text SMS sent to patient (≤160 chars)
)
