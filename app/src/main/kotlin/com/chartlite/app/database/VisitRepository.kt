package com.chartlite.app.database

import com.chartlite.app.database.dao.VisitDao
import com.chartlite.app.database.entity.VisitEntity
import com.chartlite.app.model.ClinicStation
import com.chartlite.app.model.VisitStatus
import kotlinx.coroutines.flow.Flow
import java.time.LocalDate
import java.time.format.DateTimeFormatter
import java.util.UUID

class VisitRepository(private val dao: VisitDao) {

    private fun today(): String = LocalDate.now().format(DateTimeFormatter.ISO_LOCAL_DATE)

    /** Create a new visit when a patient is registered in multi-station mode. */
    suspend fun createVisit(patientId: String, facilityId: String, providerId: String): VisitEntity {
        val visit = VisitEntity(
            id = UUID.randomUUID().toString(),
            patientId = patientId,
            facilityId = facilityId,
            visitDate = today(),
            status = VisitStatus.AWAITING_TRIAGE.name,
            currentStation = ClinicStation.TRIAGE.name,
            registeredBy = providerId
        )
        dao.insert(visit)
        return visit
    }

    /** Advance a visit to the next station after the current station's work is done. */
    suspend fun advanceToNextStation(
        visitId: String,
        providerId: String,
        currentStation: ClinicStation,
        hasMedications: Boolean = true
    ) {
        val visit = dao.getById(visitId) ?: return
        val nextStatus = when (currentStation) {
            ClinicStation.REGISTRATION -> VisitStatus.AWAITING_TRIAGE
            ClinicStation.TRIAGE -> VisitStatus.AWAITING_CONSULT
            ClinicStation.CONSULTATION -> if (hasMedications) VisitStatus.AWAITING_PHARMACY else VisitStatus.COMPLETED
            ClinicStation.PHARMACY -> VisitStatus.COMPLETED
        }
        val nextStation = nextStatus.queueStation()

        val updated = visit.copy(
            status = nextStatus.name,
            currentStation = nextStation?.name,
            triagedBy = if (currentStation == ClinicStation.TRIAGE) providerId else visit.triagedBy,
            consultedBy = if (currentStation == ClinicStation.CONSULTATION) providerId else visit.consultedBy,
            dispensedBy = if (currentStation == ClinicStation.PHARMACY) providerId else visit.dispensedBy,
            updatedAt = System.currentTimeMillis()
        )
        dao.update(updated)
    }

    /** Link an encounter to a visit at a specific station. */
    suspend fun linkEncounter(visitId: String, encounterId: String, station: ClinicStation) {
        val visit = dao.getById(visitId) ?: return
        val updated = when (station) {
            ClinicStation.TRIAGE -> visit.copy(triageEncounterId = encounterId, updatedAt = System.currentTimeMillis())
            ClinicStation.CONSULTATION -> visit.copy(consultEncounterId = encounterId, updatedAt = System.currentTimeMillis())
            else -> visit.copy(updatedAt = System.currentTimeMillis())
        }
        dao.update(updated)
    }

    /** Set the chief complaint (usually at triage). */
    suspend fun setChiefComplaint(visitId: String, complaint: String) {
        val visit = dao.getById(visitId) ?: return
        dao.update(visit.copy(chiefComplaint = complaint, updatedAt = System.currentTimeMillis()))
    }

    /** Mark visit as in-progress at a station. */
    suspend fun markInProgress(visitId: String, station: ClinicStation) {
        val visit = dao.getById(visitId) ?: return
        dao.update(visit.copy(
            status = VisitStatus.inProgressStatus(station).name,
            currentStation = station.name,
            updatedAt = System.currentTimeMillis()
        ))
    }

    /** Mark a visit as completed. */
    suspend fun completeVisit(visitId: String, providerId: String) {
        val visit = dao.getById(visitId) ?: return
        dao.update(visit.copy(
            status = VisitStatus.COMPLETED.name,
            currentStation = null,
            dispensedBy = providerId,
            updatedAt = System.currentTimeMillis()
        ))
    }

    /** Set priority level (0=normal, 1=priority, 2=emergency). */
    suspend fun setPriority(visitId: String, level: Int) {
        val visit = dao.getById(visitId) ?: return
        dao.update(visit.copy(priorityLevel = level.coerceIn(0, 2), updatedAt = System.currentTimeMillis()))
    }

    /** Save pharmacy dispensing notes. */
    suspend fun savePharmacyNotes(visitId: String, notes: String) {
        val visit = dao.getById(visitId) ?: return
        dao.update(visit.copy(pharmacyNotes = notes, updatedAt = System.currentTimeMillis()))
    }

    /** Get queue for a specific station today. */
    suspend fun getQueueForStation(station: ClinicStation, facilityId: String): List<VisitEntity> {
        val statuses = VisitStatus.waitingStatuses(station).map { it.name }
        return dao.getQueueForStation(today(), statuses, facilityId)
    }

    /** Observe queue for a specific station today (real-time Flow). */
    fun observeQueue(station: ClinicStation, facilityId: String): Flow<List<VisitEntity>> {
        val statuses = VisitStatus.waitingStatuses(station).map { it.name }
        return dao.observeQueueForStation(today(), statuses, facilityId)
    }

    /** Get count of patients waiting at a station. */
    suspend fun getQueueCount(station: ClinicStation, facilityId: String): Int {
        val statuses = VisitStatus.waitingStatuses(station).map { it.name }
        return dao.getCountByStatuses(today(), facilityId, statuses)
    }

    /** All visits today. */
    suspend fun getTodayVisits(facilityId: String): List<VisitEntity> =
        dao.getTodayVisits(today(), facilityId)

    fun observeTodayVisits(facilityId: String): Flow<List<VisitEntity>> =
        dao.observeTodayVisits(today(), facilityId)

    /** Get today's count. */
    suspend fun getTodayCount(facilityId: String): Int =
        dao.getTodayCount(today(), facilityId)

    suspend fun getById(id: String): VisitEntity? = dao.getById(id)

    /** Get all visits for a patient (across all dates). Used by cross-facility sync. */
    suspend fun getByPatientId(patientId: String): List<VisitEntity> = dao.getByPatientId(patientId)

    fun observeById(id: String): Flow<VisitEntity?> = dao.observeById(id)

    /** Check if patient already has a visit today. */
    suspend fun getTodayVisitForPatient(patientId: String): VisitEntity? =
        dao.getTodayVisitForPatient(patientId, today())

    /** Get visits modified since a given timestamp (for incremental sync). */
    suspend fun getModifiedSince(since: Long, facilityId: String): List<VisitEntity> =
        dao.getModifiedSince(since, facilityId)

    /**
     * Merge a remote visit received via sync — uses upsert to insert-or-replace,
     * preserving the remote's updatedAt to prevent timestamp ping-pong.
     */
    suspend fun mergeFromSync(visit: VisitEntity) = dao.upsert(visit)
}
