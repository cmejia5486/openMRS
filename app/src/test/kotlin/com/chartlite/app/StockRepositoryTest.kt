package com.chartlite.app

import com.chartlite.app.database.dao.StockDao
import com.chartlite.app.database.entity.StockItemEntity
import com.chartlite.app.database.entity.StockTransactionEntity
import com.chartlite.app.database.repository.StockRepository
import com.chartlite.app.model.StockTransactionType
import kotlinx.coroutines.flow.Flow
import kotlinx.coroutines.flow.flowOf
import kotlinx.coroutines.runBlocking
import org.junit.Assert.*
import org.junit.Before
import org.junit.Test

class StockRepositoryTest {

    private lateinit var repo: StockRepository
    private lateinit var fakeDao: FakeStockDao

    @Before
    fun setup() {
        fakeDao = FakeStockDao()
        repo = StockRepository(fakeDao)
    }

    @Test
    fun `addStockItem creates item with initial quantity`() = runBlocking {
        val item = repo.addStockItem("fac1", "PARA500", "Paracetamol 500mg", 100, 20, "tablets", performedBy = "user1")
        assertEquals(100, item.quantityOnHand)
        assertEquals(20, item.reorderLevel)
        assertEquals("tablets", item.unit)
        // Should also create a RECEIVED transaction
        val txns = fakeDao.getTransactions(item.id)
        assertEquals(1, txns.size)
        assertEquals(StockTransactionType.RECEIVED.name, txns[0].transactionType)
        assertEquals(100, txns[0].quantity)
    }

    @Test
    fun `addStockItem with zero quantity creates no transaction`() = runBlocking {
        val item = repo.addStockItem("fac1", "AMOX", "Amoxicillin", 0, 10, "capsules", performedBy = "user1")
        assertEquals(0, item.quantityOnHand)
        val txns = fakeDao.getTransactions(item.id)
        assertEquals(0, txns.size)
    }

    @Test
    fun `receiveStock increases quantity`() = runBlocking {
        val item = repo.addStockItem("fac1", "PARA500", "Paracetamol", 50, 20, "tablets", performedBy = "user1")
        val result = repo.receiveStock(item.id, 30, "user1", "Supplier delivery")
        assertTrue(result)
        assertEquals(80, fakeDao.getItemById(item.id)!!.quantityOnHand)
    }

    @Test
    fun `receiveStock fails for non-existent item`() = runBlocking {
        assertFalse(repo.receiveStock("nonexistent", 10, "user1"))
    }

    @Test
    fun `receiveStock fails for zero quantity`() = runBlocking {
        val item = repo.addStockItem("fac1", "PARA500", "Paracetamol", 50, 20, "tablets", performedBy = "user1")
        assertFalse(repo.receiveStock(item.id, 0, "user1"))
    }

    @Test
    fun `receiveStock fails for negative quantity`() = runBlocking {
        val item = repo.addStockItem("fac1", "PARA500", "Paracetamol", 50, 20, "tablets", performedBy = "user1")
        assertFalse(repo.receiveStock(item.id, -5, "user1"))
    }

    @Test
    fun `dispense decreases quantity`() = runBlocking {
        val item = repo.addStockItem("fac1", "PARA500", "Paracetamol", 50, 20, "tablets", performedBy = "user1")
        val result = repo.dispense(item.id, 10, "user1", visitId = "visit1")
        assertTrue(result)
        assertEquals(40, fakeDao.getItemById(item.id)!!.quantityOnHand)
    }

    @Test
    fun `dispense fails when insufficient stock`() = runBlocking {
        val item = repo.addStockItem("fac1", "PARA500", "Paracetamol", 5, 20, "tablets", performedBy = "user1")
        assertFalse(repo.dispense(item.id, 10, "user1"))
        assertEquals(5, fakeDao.getItemById(item.id)!!.quantityOnHand) // unchanged
    }

    @Test
    fun `dispense records negative transaction`() = runBlocking {
        val item = repo.addStockItem("fac1", "PARA500", "Paracetamol", 50, 20, "tablets", performedBy = "user1")
        repo.dispense(item.id, 10, "user1", visitId = "visit1")
        val txns = fakeDao.getTransactions(item.id)
        val dispenseTxn = txns.find { it.transactionType == StockTransactionType.DISPENSED.name }
        assertNotNull(dispenseTxn)
        assertEquals(-10, dispenseTxn!!.quantity)
        assertEquals("visit1", dispenseTxn.referenceId)
    }

    @Test
    fun `adjustStock sets new quantity`() = runBlocking {
        val item = repo.addStockItem("fac1", "PARA500", "Paracetamol", 50, 20, "tablets", performedBy = "user1")
        val result = repo.adjustStock(item.id, 45, "user1", "Physical count mismatch")
        assertTrue(result)
        assertEquals(45, fakeDao.getItemById(item.id)!!.quantityOnHand)
    }

    @Test
    fun `adjustStock records correct difference`() = runBlocking {
        val item = repo.addStockItem("fac1", "PARA500", "Paracetamol", 50, 20, "tablets", performedBy = "user1")
        repo.adjustStock(item.id, 45, "user1", "Count mismatch")
        val txns = fakeDao.getTransactions(item.id)
        val adjustTxn = txns.find { it.transactionType == StockTransactionType.ADJUSTED.name }
        assertNotNull(adjustTxn)
        assertEquals(-5, adjustTxn!!.quantity) // 45 - 50 = -5
    }

    @Test
    fun `markExpired sets quantity to zero`() = runBlocking {
        val item = repo.addStockItem("fac1", "PARA500", "Paracetamol", 50, 20, "tablets", performedBy = "user1")
        val result = repo.markExpired(item.id, "user1")
        assertTrue(result)
        assertEquals(0, fakeDao.getItemById(item.id)!!.quantityOnHand)
    }

    @Test
    fun `getLowStock returns items at or below reorder level`() = runBlocking {
        repo.addStockItem("fac1", "PARA500", "Paracetamol", 100, 20, "tablets", performedBy = "user1")
        repo.addStockItem("fac1", "AMOX", "Amoxicillin", 15, 20, "capsules", performedBy = "user1") // low
        repo.addStockItem("fac1", "IBU400", "Ibuprofen", 0, 10, "tablets", performedBy = "user1") // out
        val lowStock = repo.getLowStock("fac1")
        assertEquals(2, lowStock.size)
    }

    @Test
    fun `getLowStockCount returns correct count`() = runBlocking {
        repo.addStockItem("fac1", "PARA500", "Paracetamol", 100, 20, "tablets", performedBy = "user1")
        repo.addStockItem("fac1", "AMOX", "Amoxicillin", 15, 20, "capsules", performedBy = "user1")
        assertEquals(1, repo.getLowStockCount("fac1"))
    }

    @Test
    fun `getByDrugCode finds correct item`() = runBlocking {
        repo.addStockItem("fac1", "PARA500", "Paracetamol", 100, 20, "tablets", performedBy = "user1")
        val item = repo.getByDrugCode("fac1", "PARA500")
        assertNotNull(item)
        assertEquals("Paracetamol", item!!.drugName)
    }

    private class FakeStockDao : StockDao() {
        private val items = mutableMapOf<String, StockItemEntity>()
        private val transactions = mutableListOf<StockTransactionEntity>()

        override suspend fun insertItem(item: StockItemEntity) { items[item.id] = item }
        override suspend fun updateItem(item: StockItemEntity) { items[item.id] = item }
        override suspend fun getItemById(id: String) = items[id]
        override suspend fun getByFacility(facilityId: String) = items.values.filter { it.facilityId == facilityId }
        override suspend fun getByDrugCode(facilityId: String, drugCode: String) = items.values.find { it.facilityId == facilityId && it.drugCode == drugCode }
        override suspend fun getLowStock(facilityId: String) = items.values.filter { it.facilityId == facilityId && it.quantityOnHand <= it.reorderLevel }
        override suspend fun getExpiringSoon(facilityId: String, beforeDate: Long) = items.values.filter { it.facilityId == facilityId && it.expiryDate != null && it.expiryDate <= beforeDate }
        override suspend fun getLowStockCount(facilityId: String) = getLowStock(facilityId).size
        override fun observeLowStock(facilityId: String): Flow<List<StockItemEntity>> = flowOf(emptyList())
        override suspend fun atomicDispense(id: String, qty: Int, userId: String, now: Long): Int {
            val item = items[id] ?: return 0
            if (item.quantityOnHand < qty) return 0
            items[id] = item.copy(quantityOnHand = item.quantityOnHand - qty, lastUpdatedBy = userId, lastUpdatedAt = now)
            return 1
        }
        override suspend fun atomicReceive(id: String, qty: Int, userId: String, now: Long): Int {
            val item = items[id] ?: return 0
            items[id] = item.copy(quantityOnHand = item.quantityOnHand + qty, lastUpdatedBy = userId, lastUpdatedAt = now)
            return 1
        }
        override suspend fun atomicAdjust(id: String, newQty: Int, userId: String, now: Long): Int {
            val item = items[id] ?: return 0
            items[id] = item.copy(quantityOnHand = newQty, lastUpdatedBy = userId, lastUpdatedAt = now)
            return 1
        }
        override suspend fun getQuantity(id: String): Int? = items[id]?.quantityOnHand
        override suspend fun insertTransaction(transaction: StockTransactionEntity) { transactions.add(transaction) }
        override suspend fun getTransactions(stockItemId: String) = transactions.filter { it.stockItemId == stockItemId }
        override suspend fun getRecentTransactions(stockItemId: String, limit: Int) = getTransactions(stockItemId).take(limit)
    }
}
