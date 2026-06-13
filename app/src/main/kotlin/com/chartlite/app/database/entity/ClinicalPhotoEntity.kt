package com.chartlite.app.database.entity

import androidx.room.Entity
import androidx.room.Index
import androidx.room.PrimaryKey

@Entity(
    tableName = "clinical_photos",
    indices = [
        Index("encounterId"),
        Index("patientId"),
        Index("patientId", "contentType")
    ]
)
data class ClinicalPhotoEntity(
    @PrimaryKey val id: String,
    val encounterId: String,
    val patientId: String,
    val contentType: String,
    val filePath: String,
    val extractedJson: String? = null,
    val capturedAt: Long = System.currentTimeMillis()
)
