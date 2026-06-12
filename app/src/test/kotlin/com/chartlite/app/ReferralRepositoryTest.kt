package com.chartlite.app

import com.chartlite.app.database.dao.ReferralDao
import com.chartlite.app.database.entity.ReferralEntity
import com.chartlite.app.database.repository.ReferralRepository
import com.chartlite.app.model.ReferralStatus
import kotlinx.coroutines.flow.Flow
import kotlinx.coroutines.flow.flowOf
import kotlinx.coroutines.runBlocking
import org.junit.Assert.*
import org.junit.Before
import org.junit.Test

class ReferralRepositoryTest {

    private lateinit var repo: ReferralRepository
    private lateinit var fakeDao: FakeReferralDao

    @Before
    fun setup() {
        fakeDao = FakeReferralDao()
        repo = ReferralRepository(fakeDao)
    }

    @Test
    fun `createReferral sets initial status to PENDING`() = runBlocking {
        val referral = repo.createReferral("v1", "p1", "prov1", "fac1", "City Hospital", "URGENT", "Suspected fracture")
        assertEquals(ReferralStatus.PENDING.name, referral.status)
        assertEquals("City Hospital", referral.toFacility)
        assertEquals("URGENT", referral.urgency)
        assertEquals("Suspected fracture", referral.reason)
    }

    @Test
    fun `createReferral with optional fields`() = runBlocking {
        val referral = repo.createReferral("v1", "p1", "prov1", "fac1", "Hospital", "ROUTINE", "Follow-up",
            toDepartment = "Orthopedics", clinicalNotes = "X-ray shows possible fracture")
        assertEquals("Orthopedics", referral.toDepartment)
        assertEquals("X-ray shows possible fracture", referral.clinicalNotes)
    }

    @Test
    fun `updateStatus changes referral status`() = runBlocking {
        val referral = repo.createReferral("v1", "p1", "prov1", "fac1", "Hospital", "ROUTINE", "Check-up")
        val result = repo.updateStatus(referral.id, ReferralStatus.ACCEPTED.name)
        assertTrue(result)
        assertEquals(ReferralStatus.ACCEPTED.name, fakeDao.getById(referral.id)!!.status)
    }

    @Test
    fun `updateStatus fails for non-existent referral`() = runBlocking {
        val result = repo.updateStatus("nonexistent", ReferralStatus.ACCEPTED.name)
        assertFalse(result)
    }

    @Test
    fun `getPending returns only PENDING referrals`() = runBlocking {
        val r1 = repo.createReferral("v1", "p1", "prov1", "fac1", "Hospital A", "URGENT", "Emergency")
        val r2 = repo.createReferral("v2", "p2", "prov1", "fac1", "Hospital B", "ROUTINE", "Follow-up")
        repo.updateStatus(r1.id, ReferralStatus.ACCEPTED.name)
        val pending = repo.getPending("fac1")
        assertEquals(1, pending.size)
        assertEquals(r2.id, pending[0].id)
    }

    @Test
    fun `getByPatient returns patient referrals`() = runBlocking {
        repo.createReferral("v1", "p1", "prov1", "fac1", "Hospital", "URGENT", "Reason1")
        repo.createReferral("v2", "p1", "prov1", "fac1", "Hospital", "ROUTINE", "Reason2")
        repo.createReferral("v3", "p2", "prov1", "fac1", "Hospital", "ROUTINE", "Reason3")
        assertEquals(2, repo.getByPatient("p1").size)
    }

    @Test
    fun `getByFacility returns facility referrals`() = runBlocking {
        repo.createReferral("v1", "p1", "prov1", "fac1", "Hospital", "URGENT", "Reason1")
        repo.createReferral("v2", "p2", "prov1", "fac2", "Hospital", "ROUTINE", "Reason2")
        assertEquals(1, repo.getByFacility("fac1").size)
    }

    @Test
    fun `getPendingCount returns correct count`() = runBlocking {
        repo.createReferral("v1", "p1", "prov1", "fac1", "Hospital", "URGENT", "Reason")
        repo.createReferral("v2", "p2", "prov1", "fac1", "Hospital", "ROUTINE", "Reason")
        assertEquals(2, repo.getPendingCount("fac1"))
    }

    @Test
    fun `getByFacility filters invalid placeholder destination referrals`() = runBlocking {
        repo.createReferral("v1", "p1", "prov1", "fac1", "Hospital", "URGENT", "Reason")
        fakeDao.insert(
            ReferralEntity(
                id = "invalid",
                visitId = "v2",
                patientId = "p2",
                fromProviderId = "prov1",
                fromFacilityId = "fac1",
                toFacility = "null",
                toDepartment = "null",
                urgency = "ROUTINE",
                reason = "Clinical referral",
                clinicalNotes = null,
                status = ReferralStatus.PENDING.name,
                referredAt = System.currentTimeMillis(),
                updatedAt = System.currentTimeMillis()
            )
        )

        val referrals = repo.getByFacility("fac1")
        assertEquals(1, referrals.size)
        assertEquals("Hospital", referrals[0].toFacility)
    }

    @Test
    fun `full referral lifecycle`() = runBlocking {
        val ref = repo.createReferral("v1", "p1", "prov1", "fac1", "Hospital", "URGENT", "Fracture")
        assertEquals(ReferralStatus.PENDING.name, fakeDao.getById(ref.id)!!.status)
        repo.updateStatus(ref.id, ReferralStatus.ACCEPTED.name)
        assertEquals(ReferralStatus.ACCEPTED.name, fakeDao.getById(ref.id)!!.status)
        repo.updateStatus(ref.id, ReferralStatus.COMPLETED.name)
        assertEquals(ReferralStatus.COMPLETED.name, fakeDao.getById(ref.id)!!.status)
    }

    private class FakeReferralDao : ReferralDao {
        private val referrals = mutableMapOf<String, ReferralEntity>()

        override suspend fun insert(referral: ReferralEntity) { referrals[referral.id] = referral }
        override suspend fun update(referral: ReferralEntity) { referrals[referral.id] = referral }
        override suspend fun getById(id: String) = referrals[id]
        override suspend fun getByPatient(patientId: String) = referrals.values.filter { it.patientId == patientId }
        override suspend fun getPending(facilityId: String) = referrals.values.filter { it.status == ReferralStatus.PENDING.name && it.fromFacilityId == facilityId }
        override suspend fun getByFacility(facilityId: String, limit: Int) = referrals.values.filter { it.fromFacilityId == facilityId }.take(limit)
        override suspend fun getByVisitId(visitId: String) = referrals.values.filter { it.visitId == visitId }
        override suspend fun getPendingCount(facilityId: String) = getPending(facilityId).size
        override fun observePending(facilityId: String): Flow<List<ReferralEntity>> = flowOf(emptyList())
    }
}
