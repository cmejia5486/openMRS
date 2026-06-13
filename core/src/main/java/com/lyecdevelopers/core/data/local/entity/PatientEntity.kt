package com.lyecdevelopers.core.data.local.entity

import androidx.room.Entity
import androidx.room.PrimaryKey
import com.lyecdevelopers.core.model.VisitStatus
import java.util.UUID

@Entity(tableName = "patients")
data class PatientEntity(
    @PrimaryKey val id: String = UUID.randomUUID().toString(),
    val patientIdentifier: String,
    val firstName: String,
    val lastName: String,
    val gender: String,
    val dateOfBirth: String,
    val phoneNumber: String? = null,
    val address: String? = null,
    val status: VisitStatus,
    val synced: Boolean = false,
    val isEligibleForSync: Boolean = false,
    val isVoided: Boolean = false,
    val lastModified: Long = System.currentTimeMillis(),
)


fun mapToPatientEntity(map: Map<String, Any>): PatientEntity {
    fun safeString(key: String): String = map[key]?.toString() ?: ""

    val statusStr = safeString("status")
    val status = try {
        VisitStatus.valueOf(statusStr.uppercase())
    } catch (e: Exception) {
        VisitStatus.PENDING
    }

    return PatientEntity(
        id = map["UUID"]?.toString() ?: UUID.randomUUID().toString(),
        patientIdentifier = safeString("OpenMRS ID"),
        firstName = safeString("Given Name"),
        lastName = safeString("Family Name"),
        gender = safeString("Gender"),
        dateOfBirth = safeString("Birthdate"),
        phoneNumber = map["Telephone Number"]?.toString(),
        address = map["Village"]?.toString(),
        status = status,
        synced = map["synced"] as? Boolean ?: false
    )

}
