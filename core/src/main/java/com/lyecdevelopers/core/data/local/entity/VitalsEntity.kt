package com.lyecdevelopers.core.data.local.entity

import androidx.room.Entity
import androidx.room.ForeignKey
import androidx.room.Index
import androidx.room.PrimaryKey
import java.util.UUID

@Entity(
    tableName = "vitals", foreignKeys = [ForeignKey(
        entity = VisitEntity::class,
        parentColumns = ["id"],
        childColumns = ["visitUuid"],
        onDelete = ForeignKey.CASCADE
    ), ForeignKey(
        entity = PatientEntity::class,
        parentColumns = ["id"],
        childColumns = ["patientUuid"],
        onDelete = ForeignKey.CASCADE
    )], indices = [Index(value = ["visitUuid"]), Index(value = ["patientUuid"])]
)
data class VitalsEntity(
    @PrimaryKey val id: String = UUID.randomUUID().toString(),

    val patientUuid: String,

    val visitUuid: String? = null,

    val temperature: Double? = null,

    val bloodPressureSystolic: Int? = null,
    val bloodPressureDiastolic: Int? = null,

    val heartRate: Int? = null,
    val respirationRate: Int? = null,

    val spo2: Int? = null,

    val notes: String? = null,

    val weight: Double? = null,
    val height: Double? = null,

    val bmi: Double? = null,

    val muac: Double? = null,

    val dateRecorded: Long = System.currentTimeMillis(),

    )




