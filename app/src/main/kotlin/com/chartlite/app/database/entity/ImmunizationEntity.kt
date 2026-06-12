package com.chartlite.app.database.entity

import androidx.room.Entity
import androidx.room.Index
import androidx.room.PrimaryKey

@Entity(
    tableName = "immunizations",
    indices = [
        Index("patientId"),
        Index("vaccineCode"),
        Index("administeredAt"),
        Index(value = ["patientId", "vaccineCode"])
    ]
)
data class ImmunizationEntity(
    @PrimaryKey val id: String,
    val patientId: String,
    val vaccineCode: String,      // e.g., "BCG", "OPV1", "PENTA3", "MEASLES1"
    val vaccineName: String,
    val doseNumber: Int,
    val administeredAt: Long,
    val administeredBy: String,
    val batchNumber: String?,
    val site: String?,            // "left_arm", "right_thigh", "oral"
    val nextDoseCode: String?,
    val nextDoseDueDate: Long?,
    val facilityId: String,
    // Forward-compatible fields
    val metadata: String? = null,
    val sourceAgentId: String? = null,
    val syncStatus: String? = null,
    val fhirResourceId: String? = null
)
