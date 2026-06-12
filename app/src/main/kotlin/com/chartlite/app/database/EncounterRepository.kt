package com.chartlite.app.database

import com.chartlite.app.auth.AuditLogger
import com.chartlite.app.database.dao.EncounterDao
import com.chartlite.app.database.entity.EncounterEntity
import com.chartlite.app.database.entity.effectiveEncounterTimeMillis
import com.chartlite.app.model.*
import com.chartlite.app.model.normalizedOrNull
import com.google.gson.Gson
import kotlinx.coroutines.flow.Flow
import java.util.UUID

class EncounterRepository(
    private val dao: EncounterDao,
    var auditLogger: AuditLogger? = null
) {

    private val gson = Gson()

    suspend fun save(
        encounter: StructuredEncounter,
        cdssAlerts: List<CDSSAlert> = emptyList(),
        stationType: String? = null
    ): String {
        val referral = encounter.referral.normalizedOrNull()
        val entity = EncounterEntity(
            id = encounter.id,
            patientId = encounter.patientId,
            providerId = encounter.providerId,
            facilityId = encounter.facilityId,
            timestamp = encounter.timestamp.toEpochMilli(),
            transcript = encounter.transcript,
            medications = gson.toJson(encounter.medications),
            diagnoses = gson.toJson(encounter.diagnoses),
            vitals = encounter.vitals?.let { gson.toJson(it) },
            allergies = gson.toJson(encounter.allergies),
            followUpDays = encounter.followUp?.days,
            followUpReason = encounter.followUp?.reason,
            referralType = referral?.type,
            referralSpecialty = referral?.specialty,
            referralUrgency = referral?.urgency,
            referralReason = referral?.reason,
            freeTextNote = encounter.freeTextNote,
            extractionConfidence = encounter.extractionConfidence,
            cdssAlerts = gson.toJson(cdssAlerts),
            stationType = stationType,
            examFindings = gson.toJson(encounter.examFindings),
            investigations = gson.toJson(encounter.investigations),
            plan = gson.toJson(encounter.plan),
            socialHistory = gson.toJson(encounter.socialHistory),
            suggestedDiagnoses = gson.toJson(encounter.suggestedDiagnoses),
            immunizations = gson.toJson(encounter.immunizations),
            smsSummary = encounter.smsSummary
        )
        dao.insert(entity)

        auditLogger?.log(
            "CREATE_ENCOUNTER",
            targetType = "ENCOUNTER",
            targetId = entity.id,
            details = """{"patientId":"${encounter.patientId}","dxCount":${encounter.diagnoses.size},"medCount":${encounter.medications.size}}"""
        )

        return entity.id
    }

    suspend fun getById(id: String): EncounterEntity? = dao.getById(id)

    suspend fun getByPatientId(patientId: String): List<EncounterEntity> =
        dao.getByPatientId(patientId)

    fun observeByPatientId(patientId: String): Flow<List<EncounterEntity>> =
        dao.observeByPatientId(patientId)

    suspend fun getRecent(limit: Int = 20): List<EncounterEntity> = dao.getRecent(limit)

    suspend fun getCountByDateRange(startMs: Long, endMs: Long): Int = dao.getCountByDateRange(startMs, endMs)

    fun observeAll(): Flow<List<EncounterEntity>> = dao.observeAll()

    suspend fun updateSmsStatus(encounterId: String, status: SMSStatus) {
        dao.updateSmsStatus(encounterId, status.name)
    }

    suspend fun getAll(): List<EncounterEntity> = dao.getAll()

    suspend fun getByDateRange(startMs: Long, endMs: Long): List<EncounterEntity> = dao.getByDateRange(startMs, endMs)

    suspend fun insertEntity(entity: EncounterEntity) = dao.insert(entity)

    suspend fun acknowledgeAlerts(encounterId: String) {
        dao.updateCdssAcknowledged(encounterId, true)
    }

    suspend fun updateDiagnoses(encounterId: String, diagnoses: List<Diagnosis>, suggestedDiagnoses: List<Diagnosis>) {
        dao.updateDiagnoses(encounterId, gson.toJson(diagnoses), gson.toJson(suggestedDiagnoses))
    }

    fun toStructuredEncounter(entity: EncounterEntity): StructuredEncounter {
        val encounterTimeMillis = entity.effectiveEncounterTimeMillis()
            ?: System.currentTimeMillis()
        return StructuredEncounter(
            id = entity.id,
            patientId = entity.patientId,
            providerId = entity.providerId,
            facilityId = entity.facilityId,
            timestamp = java.time.Instant.ofEpochMilli(encounterTimeMillis),
            transcript = entity.transcript,
            medications = gson.fromJson(entity.medications,
                object : com.google.gson.reflect.TypeToken<List<Medication>>() {}.type) ?: emptyList(),
            diagnoses = gson.fromJson(entity.diagnoses,
                object : com.google.gson.reflect.TypeToken<List<Diagnosis>>() {}.type) ?: emptyList(),
            vitals = entity.vitals?.let { gson.fromJson(it, VitalSigns::class.java) },
            allergies = gson.fromJson(entity.allergies,
                object : com.google.gson.reflect.TypeToken<List<String>>() {}.type) ?: emptyList(),
            followUp = entity.followUpDays?.let { FollowUp(it, entity.followUpReason) },
            referral = entity.referralType?.let {
                Referral(it, entity.referralSpecialty, entity.referralUrgency ?: "routine", entity.referralReason)
                    .normalizedOrNull()
            },
            freeTextNote = entity.freeTextNote,
            extractionConfidence = entity.extractionConfidence,
            examFindings = try {
                gson.fromJson(entity.examFindings,
                    object : com.google.gson.reflect.TypeToken<List<String>>() {}.type) ?: emptyList()
            } catch (_: Exception) { emptyList() },
            investigations = try {
                gson.fromJson(entity.investigations,
                    object : com.google.gson.reflect.TypeToken<List<Investigation>>() {}.type) ?: emptyList()
            } catch (_: Exception) { emptyList() },
            plan = try {
                gson.fromJson(entity.plan,
                    object : com.google.gson.reflect.TypeToken<List<String>>() {}.type) ?: emptyList()
            } catch (_: Exception) { emptyList() },
            socialHistory = try {
                gson.fromJson(entity.socialHistory,
                    object : com.google.gson.reflect.TypeToken<List<String>>() {}.type) ?: emptyList()
            } catch (_: Exception) { emptyList() },
            suggestedDiagnoses = try {
                gson.fromJson(entity.suggestedDiagnoses,
                    object : com.google.gson.reflect.TypeToken<List<Diagnosis>>() {}.type) ?: emptyList()
            } catch (_: Exception) { emptyList() },
            immunizations = try {
                gson.fromJson(entity.immunizations,
                    object : com.google.gson.reflect.TypeToken<List<ExtractedImmunization>>() {}.type) ?: emptyList()
            } catch (_: Exception) { emptyList() },
            smsSummary = entity.smsSummary
        )
    }
}
