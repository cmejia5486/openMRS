package com.lyecdevelopers.core.data.local.entity

import androidx.room.Entity
import androidx.room.ForeignKey
import androidx.room.Index
import androidx.room.PrimaryKey
import com.lyecdevelopers.core.model.VisitStatus
import java.util.UUID


@Entity(
    tableName = "visits",
    foreignKeys = [ForeignKey(
        entity = PatientEntity::class,
        parentColumns = ["id"],
        childColumns = ["patientId"],
        onDelete = ForeignKey.CASCADE
    )], indices = [Index("patientId")]
)
data class VisitEntity(
    @PrimaryKey val id: String = UUID.randomUUID().toString(),
    val patientId: String,
    val type: String,
    val date: String,
    val status: VisitStatus,
    val notes: String? = null,
    val scheduledTime: String? = null,
)





