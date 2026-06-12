package com.chartlite.app

import com.chartlite.app.database.dao.LabOrderDao
import com.chartlite.app.database.entity.LabOrderEntity
import com.chartlite.app.database.repository.LabOrderRepository
import com.chartlite.app.model.LabOrderStatus
import kotlinx.coroutines.flow.Flow
import kotlinx.coroutines.flow.flowOf
import kotlinx.coroutines.runBlocking
import org.junit.Assert.*
import org.junit.Before
import org.junit.Test

class LabOrderRepositoryTest {

    private lateinit var repo: LabOrderRepository
    private lateinit var fakeDao: FakeLabOrderDao

    @Before
    fun setup() {
        fakeDao = FakeLabOrderDao()
        repo = LabOrderRepository(fakeDao)
    }

    @Test
    fun `createOrder sets initial status to ORDERED`() = runBlocking {
        val order = repo.createOrder("visit1", "patient1", "CBC", "Complete Blood Count", "user1")
        assertEquals(LabOrderStatus.ORDERED.name, order.status)
        assertEquals("CBC", order.testCode)
        assertEquals("ROUTINE", order.priority)
        assertNotNull(order.id)
        assertTrue(order.orderedAt > 0)
    }

    @Test
    fun `createOrder with custom priority`() = runBlocking {
        val order = repo.createOrder("visit1", "patient1", "CBC", "CBC", "user1", priority = "STAT")
        assertEquals("STAT", order.priority)
    }

    @Test
    fun `createOrder with notes`() = runBlocking {
        val order = repo.createOrder("visit1", "patient1", "CBC", "CBC", "user1", notes = "Fasting required")
        assertEquals("Fasting required", order.notes)
    }

    @Test
    fun `markCollected transitions ORDERED to COLLECTED`() = runBlocking {
        val order = repo.createOrder("visit1", "patient1", "CBC", "CBC", "user1")
        val result = repo.markCollected(order.id)
        assertTrue(result)
        val updated = fakeDao.getById(order.id)!!
        assertEquals(LabOrderStatus.COLLECTED.name, updated.status)
        assertNotNull(updated.collectedAt)
    }

    @Test
    fun `markCollected fails for non-ORDERED status`() = runBlocking {
        val order = repo.createOrder("visit1", "patient1", "CBC", "CBC", "user1")
        repo.markCollected(order.id)
        // Try to mark collected again (now COLLECTED status)
        val result = repo.markCollected(order.id)
        assertFalse(result)
    }

    @Test
    fun `markCollected fails for non-existent order`() = runBlocking {
        val result = repo.markCollected("non-existent")
        assertFalse(result)
    }

    @Test
    fun `enterResult transitions to RESULTED`() = runBlocking {
        val order = repo.createOrder("visit1", "patient1", "CBC", "CBC", "user1")
        val result = repo.enterResult(order.id, "12.5", "g/dL", "12-17", false, "lab_user")
        assertTrue(result)
        val updated = fakeDao.getById(order.id)!!
        assertEquals(LabOrderStatus.RESULTED.name, updated.status)
        assertEquals("12.5", updated.resultValue)
        assertEquals("g/dL", updated.resultUnit)
        assertEquals("12-17", updated.referenceRange)
        assertEquals(false, updated.isAbnormal)
        assertNotNull(updated.resultedAt)
        assertEquals("lab_user", updated.resultedBy)
    }

    @Test
    fun `enterResult fails for already RESULTED order`() = runBlocking {
        val order = repo.createOrder("visit1", "patient1", "CBC", "CBC", "user1")
        repo.enterResult(order.id, "12.5", null, null, null, "lab_user")
        val result = repo.enterResult(order.id, "13.0", null, null, null, "lab_user")
        assertFalse(result)
    }

    @Test
    fun `enterResult fails for CANCELLED order`() = runBlocking {
        val order = repo.createOrder("visit1", "patient1", "CBC", "CBC", "user1")
        repo.cancelOrder(order.id)
        val result = repo.enterResult(order.id, "12.5", null, null, null, "lab_user")
        assertFalse(result)
    }

    @Test
    fun `cancelOrder transitions to CANCELLED`() = runBlocking {
        val order = repo.createOrder("visit1", "patient1", "CBC", "CBC", "user1")
        val result = repo.cancelOrder(order.id)
        assertTrue(result)
        assertEquals(LabOrderStatus.CANCELLED.name, fakeDao.getById(order.id)!!.status)
    }

    @Test
    fun `cancelOrder fails for RESULTED order`() = runBlocking {
        val order = repo.createOrder("visit1", "patient1", "CBC", "CBC", "user1")
        repo.enterResult(order.id, "12.5", null, null, null, "lab_user")
        val result = repo.cancelOrder(order.id)
        assertFalse(result)
    }

    @Test
    fun `getByVisitId returns correct orders`() = runBlocking {
        repo.createOrder("visit1", "patient1", "CBC", "CBC", "user1")
        repo.createOrder("visit1", "patient1", "RDT_MALARIA", "Malaria RDT", "user1")
        repo.createOrder("visit2", "patient2", "HIV_RAPID", "HIV Rapid", "user1")
        val orders = repo.getByVisitId("visit1")
        assertEquals(2, orders.size)
    }

    @Test
    fun `getByPatientId returns correct orders`() = runBlocking {
        repo.createOrder("visit1", "patient1", "CBC", "CBC", "user1")
        repo.createOrder("visit2", "patient1", "LFT", "Liver Function", "user1")
        repo.createOrder("visit3", "patient2", "HIV_RAPID", "HIV", "user1")
        val orders = repo.getByPatientId("patient1")
        assertEquals(2, orders.size)
    }

    @Test
    fun `getPending returns only ORDERED and COLLECTED`() = runBlocking {
        val order1 = repo.createOrder("visit1", "patient1", "CBC", "CBC", "user1")
        val order2 = repo.createOrder("visit1", "patient1", "LFT", "LFT", "user1")
        repo.createOrder("visit1", "patient1", "HIV", "HIV", "user1")
        repo.enterResult(order1.id, "ok", null, null, null, "lab_user")
        repo.markCollected(order2.id)
        val pending = repo.getPending()
        assertEquals(2, pending.size) // COLLECTED + ORDERED
    }

    @Test
    fun `getPendingCount returns correct count`() = runBlocking {
        repo.createOrder("v1", "p1", "CBC", "CBC", "u1")
        repo.createOrder("v1", "p1", "LFT", "LFT", "u1")
        assertEquals(2, repo.getPendingCount())
    }

    // Fake DAO
    private class FakeLabOrderDao : LabOrderDao() {
        private val orders = mutableMapOf<String, LabOrderEntity>()

        override suspend fun insert(order: LabOrderEntity) { orders[order.id] = order }
        override suspend fun update(order: LabOrderEntity) { orders[order.id] = order }
        override suspend fun getById(id: String) = orders[id]
        override suspend fun getByVisitId(visitId: String) = orders.values.filter { it.visitId == visitId }
        override suspend fun getByPatientId(patientId: String) = orders.values.filter { it.patientId == patientId }
        override suspend fun getPending() = orders.values.filter {
            it.status == LabOrderStatus.ORDERED.name || it.status == LabOrderStatus.COLLECTED.name
        }
        override suspend fun getPendingCount() = getPending().size
        override fun observeByPatientId(patientId: String): Flow<List<LabOrderEntity>> = flowOf(emptyList())
        override fun observePending(): Flow<List<LabOrderEntity>> = flowOf(emptyList())
        override suspend fun getResultedByPatient(patientId: String) = orders.values.filter {
            it.patientId == patientId && it.status == LabOrderStatus.RESULTED.name
        }
    }
}
