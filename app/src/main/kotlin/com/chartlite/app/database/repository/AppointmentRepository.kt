package com.chartlite.app.database.repository

import com.chartlite.app.database.dao.AppointmentDao
import com.chartlite.app.database.dao.PatientDao
import com.chartlite.app.database.entity.AppointmentEntity
import com.chartlite.app.model.AppointmentStatus
import java.util.UUID

/**
 * Business logic for appointment scheduling, check-in, and completion.
 */
class AppointmentRepository(
    private val appointmentDao: AppointmentDao,
    private val patientDao: PatientDao? = null
) {

    suspend fun schedule(
        patientId: String,
        facilityId: String,
        scheduledDate: Long,
        type: String,
        createdBy: String,
        providerId: String? = null,
        scheduledTime: String? = null,
        durationMinutes: Int = 30,
        notes: String? = null
    ): AppointmentEntity {
        // Validate that the patient exists (FK enforcement)
        patientDao?.let { dao ->
            requireNotNull(dao.getById(patientId)) {
                "Cannot schedule appointment: patient '$patientId' not found"
            }
        }
        val now = System.currentTimeMillis()
        val appointment = AppointmentEntity(
            id = UUID.randomUUID().toString(),
            patientId = patientId,
            providerId = providerId,
            facilityId = facilityId,
            scheduledDate = scheduledDate,
            scheduledTime = scheduledTime,
            durationMinutes = durationMinutes,
            type = type,
            status = AppointmentStatus.SCHEDULED.name,
            notes = notes,
            createdBy = createdBy,
            createdAt = now,
            updatedAt = now
        )
        appointmentDao.insert(appointment)
        return appointment
    }

    suspend fun checkIn(appointmentId: String): Boolean {
        val appt = appointmentDao.getById(appointmentId) ?: return false
        if (appt.status != AppointmentStatus.SCHEDULED.name) return false
        appointmentDao.update(appt.copy(
            status = AppointmentStatus.CHECKED_IN.name,
            updatedAt = System.currentTimeMillis()
        ))
        return true
    }

    suspend fun startVisit(appointmentId: String): Boolean {
        val appt = appointmentDao.getById(appointmentId) ?: return false
        if (appt.status != AppointmentStatus.CHECKED_IN.name) return false
        appointmentDao.update(appt.copy(
            status = AppointmentStatus.IN_PROGRESS.name,
            updatedAt = System.currentTimeMillis()
        ))
        return true
    }

    suspend fun complete(appointmentId: String): Boolean {
        val appt = appointmentDao.getById(appointmentId) ?: return false
        if (appt.status != AppointmentStatus.IN_PROGRESS.name) return false
        appointmentDao.update(appt.copy(
            status = AppointmentStatus.COMPLETED.name,
            updatedAt = System.currentTimeMillis()
        ))
        return true
    }

    suspend fun markNoShow(appointmentId: String): Boolean {
        val appt = appointmentDao.getById(appointmentId) ?: return false
        if (appt.status != AppointmentStatus.SCHEDULED.name && appt.status != AppointmentStatus.CHECKED_IN.name) return false
        appointmentDao.update(appt.copy(
            status = AppointmentStatus.NO_SHOW.name,
            updatedAt = System.currentTimeMillis()
        ))
        return true
    }

    suspend fun cancel(appointmentId: String): Boolean {
        val appt = appointmentDao.getById(appointmentId) ?: return false
        if (appt.status == AppointmentStatus.COMPLETED.name || appt.status == AppointmentStatus.CANCELLED.name) return false
        appointmentDao.update(appt.copy(
            status = AppointmentStatus.CANCELLED.name,
            updatedAt = System.currentTimeMillis()
        ))
        return true
    }

    suspend fun updateMetadata(appointmentId: String, metadata: String) {
        val appt = appointmentDao.getById(appointmentId) ?: return
        appointmentDao.update(appt.copy(metadata = metadata, updatedAt = System.currentTimeMillis()))
    }

    suspend fun getByDate(facilityId: String, date: Long) = appointmentDao.getByDate(facilityId, date)
    suspend fun getByPatient(patientId: String) = appointmentDao.getByPatient(patientId)
    suspend fun getUpcoming(facilityId: String, fromDate: Long) = appointmentDao.getUpcoming(facilityId, fromDate)
    suspend fun getCountForDate(facilityId: String, date: Long) = appointmentDao.getCountForDate(facilityId, date)
    suspend fun getNextForDate(facilityId: String, date: Long) = appointmentDao.getNextForDate(facilityId, date)
    fun observeByDate(facilityId: String, date: Long) = appointmentDao.observeByDate(facilityId, date)
}
