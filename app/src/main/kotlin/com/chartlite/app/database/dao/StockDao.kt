package com.chartlite.app.database.dao

import androidx.room.*
import com.chartlite.app.database.entity.StockItemEntity
import com.chartlite.app.database.entity.StockTransactionEntity
import kotlinx.coroutines.flow.Flow

@Dao
abstract class StockDao {
    // Stock items
    @Insert(onConflict = OnConflictStrategy.ABORT)
    abstract suspend fun insertItem(item: StockItemEntity)

    @Update
    abstract suspend fun updateItem(item: StockItemEntity)

    @Query("SELECT * FROM stock_items WHERE id = :id")
    abstract suspend fun getItemById(id: String): StockItemEntity?

    @Query("SELECT * FROM stock_items WHERE facilityId = :facilityId ORDER BY drugName")
    abstract suspend fun getByFacility(facilityId: String): List<StockItemEntity>

    @Query("SELECT * FROM stock_items WHERE facilityId = :facilityId AND drugCode = :drugCode")
    abstract suspend fun getByDrugCode(facilityId: String, drugCode: String): StockItemEntity?

    @Query("SELECT * FROM stock_items WHERE facilityId = :facilityId AND quantityOnHand <= reorderLevel ORDER BY drugName")
    abstract suspend fun getLowStock(facilityId: String): List<StockItemEntity>

    @Query("SELECT * FROM stock_items WHERE facilityId = :facilityId AND expiryDate IS NOT NULL AND expiryDate <= :beforeDate ORDER BY expiryDate")
    abstract suspend fun getExpiringSoon(facilityId: String, beforeDate: Long): List<StockItemEntity>

    @Query("SELECT COUNT(*) FROM stock_items WHERE facilityId = :facilityId AND quantityOnHand <= reorderLevel")
    abstract suspend fun getLowStockCount(facilityId: String): Int

    @Query("SELECT * FROM stock_items WHERE facilityId = :facilityId AND quantityOnHand <= reorderLevel ORDER BY drugName")
    abstract fun observeLowStock(facilityId: String): Flow<List<StockItemEntity>>

    /** Atomic dispense: decrements quantity only if sufficient stock exists. Returns rows affected (0 = insufficient). */
    @Query("UPDATE stock_items SET quantityOnHand = quantityOnHand - :qty, lastUpdatedBy = :userId, lastUpdatedAt = :now WHERE id = :id AND quantityOnHand >= :qty")
    abstract suspend fun atomicDispense(id: String, qty: Int, userId: String, now: Long): Int

    /** Atomic receive: increments quantity. Returns rows affected. */
    @Query("UPDATE stock_items SET quantityOnHand = quantityOnHand + :qty, lastUpdatedBy = :userId, lastUpdatedAt = :now WHERE id = :id")
    abstract suspend fun atomicReceive(id: String, qty: Int, userId: String, now: Long): Int

    /** Atomic adjust: sets quantity to exact value. Returns previous quantity for diff calculation. */
    @Query("UPDATE stock_items SET quantityOnHand = :newQty, lastUpdatedBy = :userId, lastUpdatedAt = :now WHERE id = :id")
    abstract suspend fun atomicAdjust(id: String, newQty: Int, userId: String, now: Long): Int

    /** Get current quantity for a stock item (for diff calculation). */
    @Query("SELECT quantityOnHand FROM stock_items WHERE id = :id")
    abstract suspend fun getQuantity(id: String): Int?

    // Stock transactions
    @Insert
    abstract suspend fun insertTransaction(transaction: StockTransactionEntity)

    @Query("SELECT * FROM stock_transactions WHERE stockItemId = :stockItemId ORDER BY timestamp DESC")
    abstract suspend fun getTransactions(stockItemId: String): List<StockTransactionEntity>

    @Query("SELECT * FROM stock_transactions WHERE stockItemId = :stockItemId ORDER BY timestamp DESC LIMIT :limit")
    abstract suspend fun getRecentTransactions(stockItemId: String, limit: Int): List<StockTransactionEntity>

    /** Dispense stock and record the transaction atomically. Returns rows affected (0 = insufficient). */
    @Transaction
    open suspend fun dispenseWithLog(id: String, qty: Int, userId: String, now: Long, transaction: StockTransactionEntity): Int {
        val rows = atomicDispense(id, qty, userId, now)
        if (rows > 0) {
            insertTransaction(transaction)
        }
        return rows
    }

    /** Receive stock and record the transaction atomically. */
    @Transaction
    open suspend fun receiveWithLog(id: String, qty: Int, userId: String, now: Long, transaction: StockTransactionEntity): Int {
        val rows = atomicReceive(id, qty, userId, now)
        if (rows > 0) {
            insertTransaction(transaction)
        }
        return rows
    }

    /** Add a new stock item and record the initial transaction atomically. */
    @Transaction
    open suspend fun insertItemWithTransaction(item: StockItemEntity, transaction: StockTransactionEntity) {
        insertItem(item)
        insertTransaction(transaction)
    }
}
