package com.chartlite.app.database.entity

import androidx.room.Entity
import androidx.room.Index
import androidx.room.PrimaryKey

@Entity(
    tableName = "audit_logs",
    indices = [
        Index("userId"),
        Index("action"),
        Index("timestamp"),
        Index(value = ["userId", "action", "timestamp"]),
        Index(value = ["targetType", "targetId"])
    ]
)
data class AuditLogEntity(
    @PrimaryKey val id: String,
    val userId: String,
    val action: String,          // LOGIN, LOGOUT, FAILED_AUTH, CREATE_PATIENT, etc.
    val targetType: String?,     // PATIENT, ENCOUNTER, VISIT, USER, SETTING
    val targetId: String?,
    val details: String?,        // JSON with extra context
    val timestamp: Long = System.currentTimeMillis()
)
