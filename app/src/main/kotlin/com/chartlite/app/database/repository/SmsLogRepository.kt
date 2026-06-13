package com.chartlite.app.database.repository

import com.chartlite.app.database.dao.SmsLogDao
import com.chartlite.app.database.entity.SmsLogEntity
import java.util.UUID

class SmsLogRepository(private val dao: SmsLogDao) {

    /** Log an SMS that was sent (or failed). */
    suspend fun log(
        patientId: String,
        encounterId: String?,
        recipientPhone: String,
        messageType: String,
        contentSummary: String,
        status: String,
        error: String? = null,
        provider: String = "NATIVE"
    ) {
        dao.insert(
            SmsLogEntity(
                id = UUID.randomUUID().toString(),
                patientId = patientId,
                encounterId = encounterId,
                recipientPhone = recipientPhone,
                messageType = messageType,
                contentSummary = contentSummary,
                status = status,
                error = error,
                provider = provider
            )
        )
    }

    suspend fun getByPatientId(patientId: String) = dao.getByPatientId(patientId)
    suspend fun getByEncounterId(encounterId: String) = dao.getByEncounterId(encounterId)
    suspend fun getByType(type: String, limit: Int = 100) = dao.getByType(type, limit)
    suspend fun getRecent(limit: Int = 100) = dao.getRecent(limit)
    suspend fun getCountForPatient(patientId: String) = dao.getCountForPatient(patientId)
    suspend fun getByDateRange(startTime: Long, endTime: Long) = dao.getByDateRange(startTime, endTime)
}
