package com.chartlite.app.database.entity

import androidx.room.Entity
import androidx.room.Index
import androidx.room.PrimaryKey

/**
 * Tracks every SMS sent to a patient — encrypted encounter summaries,
 * referral notifications, and appointment reminders.
 *
 * This creates a full communication audit trail as part of the health record.
 */
@Entity(
    tableName = "sms_logs",
    indices = [
        Index("patientId"),
        Index("encounterId"),
        Index("timestamp"),
        Index("messageType")
    ]
)
data class SmsLogEntity(
    @PrimaryKey val id: String,
    val patientId: String,
    val encounterId: String?,         // null for appointment reminders
    val recipientPhone: String,
    val messageType: String,          // ENCOUNTER, REFERRAL, REMINDER
    val contentSummary: String,       // Human-readable summary (NOT the encrypted payload)
    val status: String,               // SENT, FAILED
    val error: String? = null,
    val provider: String,             // NATIVE, TWILIO
    val timestamp: Long = System.currentTimeMillis()
)
