package com.chartlite.app.database.entity

import androidx.room.Entity
import androidx.room.Index
import androidx.room.PrimaryKey

@Entity(
    tableName = "fp_visits",
    indices = [
        Index("patientId"),
        Index("method"),
        Index("nextFollowUpDate")
    ]
)
data class FPVisitEntity(
    @PrimaryKey val id: String,
    val patientId: String,
    val visitId: String?,
    val method: String,           // COC, POP, INJECTABLE, IMPLANT, IUD, CONDOM, NATURAL, STERILIZATION, NONE
    val methodStartDate: Long?,
    val nextFollowUpDate: Long?,
    val sideEffects: String?,     // JSON list
    val counselingNotes: String?,
    val commodityDispensed: String?,
    val quantity: Int?,
    val providerId: String,
    val facilityId: String,
    val createdAt: Long,
    // Forward-compatible fields
    val metadata: String? = null,
    val sourceAgentId: String? = null,
    val syncStatus: String? = null,
    val fhirResourceId: String? = null
)
