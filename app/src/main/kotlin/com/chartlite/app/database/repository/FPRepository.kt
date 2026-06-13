package com.chartlite.app.database.repository

import com.chartlite.app.database.dao.FPVisitDao
import com.chartlite.app.database.entity.FPVisitEntity
import java.util.UUID

/**
 * Business logic for family planning visit tracking and method management.
 */
class FPRepository(private val fpVisitDao: FPVisitDao) {

    suspend fun recordVisit(
        patientId: String,
        method: String,
        providerId: String,
        facilityId: String,
        visitId: String? = null,
        methodStartDate: Long? = null,
        nextFollowUpDate: Long? = null,
        sideEffects: String? = null,
        counselingNotes: String? = null,
        commodityDispensed: String? = null,
        quantity: Int? = null
    ): FPVisitEntity {
        val fpVisit = FPVisitEntity(
            id = UUID.randomUUID().toString(),
            patientId = patientId,
            visitId = visitId,
            method = method,
            methodStartDate = methodStartDate,
            nextFollowUpDate = nextFollowUpDate,
            sideEffects = sideEffects,
            counselingNotes = counselingNotes,
            commodityDispensed = commodityDispensed,
            quantity = quantity,
            providerId = providerId,
            facilityId = facilityId,
            createdAt = System.currentTimeMillis()
        )
        fpVisitDao.insert(fpVisit)
        return fpVisit
    }

    suspend fun getByPatient(patientId: String) = fpVisitDao.getByPatient(patientId)
    suspend fun getActiveMethod(patientId: String) = fpVisitDao.getActiveMethod(patientId)
    suspend fun getOverdueFollowUps() = fpVisitDao.getOverdueFollowUps(System.currentTimeMillis())
    fun observeByPatient(patientId: String) = fpVisitDao.observeByPatient(patientId)
}
