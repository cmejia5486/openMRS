package com.chartlite.app.database.repository

import com.chartlite.app.database.dao.LabOrderDao
import com.chartlite.app.database.entity.LabOrderEntity
import com.chartlite.app.model.LabOrderStatus
import java.util.UUID

/**
 * Business logic for lab orders: creation, status transitions, and result entry.
 */
class LabOrderRepository(private val labOrderDao: LabOrderDao) {

    suspend fun createOrder(
        visitId: String,
        patientId: String,
        testCode: String,
        testName: String,
        orderedBy: String,
        priority: String = "ROUTINE",
        notes: String? = null
    ): LabOrderEntity {
        val order = LabOrderEntity(
            id = UUID.randomUUID().toString(),
            visitId = visitId,
            patientId = patientId,
            testCode = testCode,
            testName = testName,
            orderedBy = orderedBy,
            status = LabOrderStatus.ORDERED.name,
            priority = priority,
            resultValue = null,
            resultUnit = null,
            referenceRange = null,
            isAbnormal = null,
            notes = notes,
            orderedAt = System.currentTimeMillis(),
            collectedAt = null,
            resultedAt = null,
            resultedBy = null
        )
        labOrderDao.insert(order)
        return order
    }

    suspend fun markCollected(orderId: String): Boolean {
        val order = labOrderDao.getById(orderId) ?: return false
        if (order.status != LabOrderStatus.ORDERED.name) return false
        labOrderDao.update(order.copy(
            status = LabOrderStatus.COLLECTED.name,
            collectedAt = System.currentTimeMillis()
        ))
        return true
    }

    suspend fun enterResult(
        orderId: String,
        resultValue: String,
        resultUnit: String?,
        referenceRange: String?,
        isAbnormal: Boolean?,
        resultedBy: String,
        notes: String? = null
    ): Boolean {
        val order = labOrderDao.getById(orderId) ?: return false
        if (order.status == LabOrderStatus.RESULTED.name ||
            order.status == LabOrderStatus.CANCELLED.name) return false
        labOrderDao.update(order.copy(
            status = LabOrderStatus.RESULTED.name,
            resultValue = resultValue,
            resultUnit = resultUnit,
            referenceRange = referenceRange,
            isAbnormal = isAbnormal,
            resultedAt = System.currentTimeMillis(),
            resultedBy = resultedBy,
            notes = notes ?: order.notes
        ))
        return true
    }

    suspend fun cancelOrder(orderId: String): Boolean {
        val order = labOrderDao.getById(orderId) ?: return false
        if (order.status == LabOrderStatus.RESULTED.name) return false
        labOrderDao.update(order.copy(status = LabOrderStatus.CANCELLED.name))
        return true
    }

    suspend fun getByVisitId(visitId: String) = labOrderDao.getByVisitId(visitId)
    suspend fun getByPatientId(patientId: String) = labOrderDao.getByPatientId(patientId)
    suspend fun getPending() = labOrderDao.getPending()
    suspend fun getPendingCount() = labOrderDao.getPendingCount()
    fun observeByPatientId(patientId: String) = labOrderDao.observeByPatientId(patientId)
    fun observePending() = labOrderDao.observePending()
}
