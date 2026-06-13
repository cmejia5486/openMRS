package com.chartlite.app.database.entity

import androidx.room.Entity
import androidx.room.Index
import androidx.room.PrimaryKey

@Entity(
    tableName = "lab_orders",
    indices = [
        Index("visitId"),
        Index("patientId"),
        Index("status"),
        Index("orderedAt"),
        Index(value = ["status", "orderedAt"]),
        Index(value = ["patientId", "status"])
    ]
)
data class LabOrderEntity(
    @PrimaryKey val id: String,
    val visitId: String,
    val patientId: String,
    val testCode: String,        // e.g., "CBC", "RDT_MALARIA", "HIV_SCREEN"
    val testName: String,
    val orderedBy: String,       // userId
    val status: String,          // ORDERED, COLLECTED, RESULTED, CANCELLED
    val priority: String,        // ROUTINE, URGENT, STAT
    val resultValue: String?,    // Free text or structured result
    val resultUnit: String?,
    val referenceRange: String?,
    val isAbnormal: Boolean?,
    val notes: String?,
    val orderedAt: Long,
    val collectedAt: Long?,
    val resultedAt: Long?,
    val resultedBy: String?,     // userId who entered the result
    // Forward-compatible fields for AI agent integration and extensibility
    val metadata: String? = null,       // JSON blob for future extensibility without schema changes
    val sourceAgentId: String? = null,  // Non-null if created/modified by an AI agent
    val syncStatus: String? = null,     // PENDING, SYNCED, CONFLICT — for future multi-device sync
    val fhirResourceId: String? = null  // FHIR R4 DiagnosticReport reference for interoperability
)
