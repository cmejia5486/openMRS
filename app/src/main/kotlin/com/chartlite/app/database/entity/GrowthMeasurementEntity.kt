package com.chartlite.app.database.entity

import androidx.room.Entity
import androidx.room.Index
import androidx.room.PrimaryKey

@Entity(
    tableName = "growth_measurements",
    indices = [
        Index("patientId"),
        Index("measuredAt")
    ]
)
data class GrowthMeasurementEntity(
    @PrimaryKey val id: String,
    val patientId: String,
    val visitId: String?,
    val weight: Float?,           // kg
    val height: Float?,           // cm
    val headCircumference: Float?, // cm (under 2 years)
    val muac: Float?,             // cm (mid-upper arm circumference)
    val measuredAt: Long,
    val measuredBy: String,
    val weightForAgeZ: Float?,    // Computed Z-score
    val heightForAgeZ: Float?,
    val bmiForAgeZ: Float?,
    // Forward-compatible fields
    val metadata: String? = null,
    val sourceAgentId: String? = null,
    val syncStatus: String? = null,
    val fhirResourceId: String? = null
)
