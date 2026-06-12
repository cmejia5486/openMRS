package com.chartlite.app.database.repository

import com.chartlite.app.database.dao.StockDao
import com.chartlite.app.database.entity.StockItemEntity
import com.chartlite.app.database.entity.StockTransactionEntity
import com.chartlite.app.model.StockTransactionType
import java.util.UUID

/**
 * Business logic for pharmacy stock management.
 * Handles receiving, dispensing, adjusting, and expiring stock.
 * Every quantity change is recorded as a transaction for audit trail.
 */
class StockRepository(private val stockDao: StockDao) {

    suspend fun addStockItem(
        facilityId: String,
        drugCode: String,
        drugName: String,
        initialQuantity: Int,
        reorderLevel: Int,
        unit: String,
        batchNumber: String? = null,
        expiryDate: Long? = null,
        performedBy: String
    ): StockItemEntity {
        val now = System.currentTimeMillis()
        val item = StockItemEntity(
            id = UUID.randomUUID().toString(),
            facilityId = facilityId,
            drugCode = drugCode,
            drugName = drugName,
            quantityOnHand = initialQuantity,
            reorderLevel = reorderLevel,
            unit = unit,
            batchNumber = batchNumber,
            expiryDate = expiryDate,
            lastUpdatedBy = performedBy,
            lastUpdatedAt = now
        )
        stockDao.insertItem(item)

        if (initialQuantity > 0) {
            recordTransaction(item.id, StockTransactionType.RECEIVED, initialQuantity, performedBy, "Initial stock")
        }
        return item
    }

    suspend fun receiveStock(itemId: String, quantity: Int, performedBy: String, notes: String? = null): Boolean {
        if (quantity <= 0) return false
        val rows = stockDao.atomicReceive(itemId, quantity, performedBy, System.currentTimeMillis())
        if (rows == 0) return false
        recordTransaction(itemId, StockTransactionType.RECEIVED, quantity, performedBy, notes)
        return true
    }

    suspend fun dispense(itemId: String, quantity: Int, performedBy: String, visitId: String? = null, notes: String? = null): Boolean {
        if (quantity <= 0) return false
        // Atomic: only decrements if sufficient stock exists (prevents TOCTOU race)
        val rows = stockDao.atomicDispense(itemId, quantity, performedBy, System.currentTimeMillis())
        if (rows == 0) return false
        recordTransaction(itemId, StockTransactionType.DISPENSED, -quantity, performedBy, notes, visitId)
        return true
    }

    suspend fun adjustStock(itemId: String, newQuantity: Int, performedBy: String, reason: String): Boolean {
        if (newQuantity < 0) return false
        val previousQty = stockDao.getQuantity(itemId) ?: return false
        val rows = stockDao.atomicAdjust(itemId, newQuantity, performedBy, System.currentTimeMillis())
        if (rows == 0) return false
        val diff = newQuantity - previousQty
        recordTransaction(itemId, StockTransactionType.ADJUSTED, diff, performedBy, reason)
        return true
    }

    suspend fun markExpired(itemId: String, performedBy: String): Boolean {
        val item = stockDao.getItemById(itemId) ?: return false
        val expiredQty = item.quantityOnHand
        stockDao.updateItem(item.copy(
            quantityOnHand = 0,
            lastUpdatedBy = performedBy,
            lastUpdatedAt = System.currentTimeMillis()
        ))
        recordTransaction(itemId, StockTransactionType.EXPIRED, -expiredQty, performedBy, "Batch expired")
        return true
    }

    suspend fun getByFacility(facilityId: String) = stockDao.getByFacility(facilityId)
    suspend fun getByDrugCode(facilityId: String, drugCode: String) = stockDao.getByDrugCode(facilityId, drugCode)
    suspend fun getLowStock(facilityId: String) = stockDao.getLowStock(facilityId)
    suspend fun getExpiringSoon(facilityId: String, daysAhead: Int = 30): List<StockItemEntity> {
        val cutoff = System.currentTimeMillis() + (daysAhead.toLong() * 86400000L)
        return stockDao.getExpiringSoon(facilityId, cutoff)
    }
    suspend fun getLowStockCount(facilityId: String) = stockDao.getLowStockCount(facilityId)
    fun observeLowStock(facilityId: String) = stockDao.observeLowStock(facilityId)
    suspend fun getTransactions(itemId: String) = stockDao.getTransactions(itemId)

    private suspend fun recordTransaction(
        stockItemId: String,
        type: StockTransactionType,
        quantity: Int,
        performedBy: String,
        notes: String? = null,
        referenceId: String? = null
    ) {
        stockDao.insertTransaction(
            StockTransactionEntity(
                id = UUID.randomUUID().toString(),
                stockItemId = stockItemId,
                transactionType = type.name,
                quantity = quantity,
                referenceId = referenceId,
                performedBy = performedBy,
                notes = notes,
                timestamp = System.currentTimeMillis()
            )
        )
    }
}
