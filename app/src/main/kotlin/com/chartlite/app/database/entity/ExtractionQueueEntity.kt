package com.chartlite.app.database.entity

import androidx.room.Entity
import androidx.room.Index
import androidx.room.PrimaryKey

@Entity(
    tableName = "extraction_queue_items",
    indices = [
        Index("status"),
        Index("patientId"),
        Index("visitId"),
        Index("createdAt")
    ]
)
data class ExtractionQueueEntity(
    @PrimaryKey val id: String,
    val transcript: String,
    val patientId: String,
    val providerId: String,
    val facilityId: String,
    val visitId: String? = null,
    val stationType: String? = null,
    val status: String,
    val isUrgent: Boolean = false,
    val deferredReview: Boolean = false,
    val strategyUsed: String? = null,
    val fallbacksAttempted: String = "[]",
    val draftNote: String? = null,
    val noteStrategyUsed: String? = null,
    val structuredEncounter: String? = null,
    val errorMessage: String? = null,
    val savedEncounterId: String? = null,
    val createdAt: Long = System.currentTimeMillis(),
    val updatedAt: Long = System.currentTimeMillis()
)
