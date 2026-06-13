package com.chartlite.app.database.entity

import androidx.room.Entity
import androidx.room.Index
import androidx.room.PrimaryKey

@Entity(
    tableName = "appointments",
    indices = [
        Index("patientId"),
        Index("facilityId"),
        Index("scheduledDate"),
        Index("status"),
        Index(value = ["facilityId", "scheduledDate"]),
        Index(value = ["facilityId", "scheduledDate", "status"])
    ]
)
data class AppointmentEntity(
    @PrimaryKey val id: String,
    val patientId: String,
    val providerId: String?,
    val facilityId: String,
    val scheduledDate: Long,     // Date only (start of day millis)
    val scheduledTime: String?,  // "HH:mm" or null for walk-in
    val durationMinutes: Int,
    val type: String,            // FOLLOW_UP, NEW_VISIT, LAB_REVIEW, CHRONIC_CARE, ANTENATAL, IMMUNIZATION
    val status: String,          // SCHEDULED, CHECKED_IN, IN_PROGRESS, COMPLETED, NO_SHOW, CANCELLED
    val notes: String?,
    val createdBy: String,
    val createdAt: Long,
    val updatedAt: Long,
    // Forward-compatible fields for AI agent integration and extensibility
    val metadata: String? = null,       // JSON blob for future extensibility without schema changes
    val sourceAgentId: String? = null,  // Non-null if created/modified by an AI agent
    val syncStatus: String? = null,     // PENDING, SYNCED, CONFLICT — for future multi-device sync
    val fhirResourceId: String? = null  // FHIR R4 Appointment reference for interoperability
)
