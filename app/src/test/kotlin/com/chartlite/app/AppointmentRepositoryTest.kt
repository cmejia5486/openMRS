package com.chartlite.app

import com.chartlite.app.database.dao.AppointmentDao
import com.chartlite.app.database.entity.AppointmentEntity
import com.chartlite.app.database.repository.AppointmentRepository
import com.chartlite.app.model.AppointmentStatus
import kotlinx.coroutines.flow.Flow
import kotlinx.coroutines.flow.flowOf
import kotlinx.coroutines.runBlocking
import org.junit.Assert.*
import org.junit.Before
import org.junit.Test

class AppointmentRepositoryTest {

    private lateinit var repo: AppointmentRepository
    private lateinit var fakeDao: FakeAppointmentDao

    @Before
    fun setup() {
        fakeDao = FakeAppointmentDao()
        repo = AppointmentRepository(fakeDao)
    }

    @Test
    fun `schedule creates appointment with SCHEDULED status`() = runBlocking {
        val appt = repo.schedule("p1", "f1", 1000L, "NEW_VISIT", "user1")
        assertEquals(AppointmentStatus.SCHEDULED.name, appt.status)
        assertEquals("p1", appt.patientId)
        assertEquals("f1", appt.facilityId)
        assertEquals(30, appt.durationMinutes) // default
    }

    @Test
    fun `schedule with custom parameters`() = runBlocking {
        val appt = repo.schedule("p1", "f1", 1000L, "FOLLOW_UP", "user1",
            scheduledTime = "09:30", durationMinutes = 45, notes = "Post-op check")
        assertEquals("09:30", appt.scheduledTime)
        assertEquals(45, appt.durationMinutes)
        assertEquals("Post-op check", appt.notes)
    }

    @Test
    fun `checkIn transitions SCHEDULED to CHECKED_IN`() = runBlocking {
        val appt = repo.schedule("p1", "f1", 1000L, "NEW_VISIT", "user1")
        val result = repo.checkIn(appt.id)
        assertTrue(result)
        assertEquals(AppointmentStatus.CHECKED_IN.name, fakeDao.getById(appt.id)!!.status)
    }

    @Test
    fun `checkIn fails for non-SCHEDULED appointment`() = runBlocking {
        val appt = repo.schedule("p1", "f1", 1000L, "NEW_VISIT", "user1")
        repo.checkIn(appt.id)
        val result = repo.checkIn(appt.id) // Already CHECKED_IN
        assertFalse(result)
    }

    @Test
    fun `startVisit transitions to IN_PROGRESS`() = runBlocking {
        val appt = repo.schedule("p1", "f1", 1000L, "NEW_VISIT", "user1")
        repo.checkIn(appt.id)
        val result = repo.startVisit(appt.id)
        assertTrue(result)
        assertEquals(AppointmentStatus.IN_PROGRESS.name, fakeDao.getById(appt.id)!!.status)
    }

    @Test
    fun `complete transitions to COMPLETED`() = runBlocking {
        val appt = repo.schedule("p1", "f1", 1000L, "NEW_VISIT", "user1")
        repo.checkIn(appt.id)
        repo.startVisit(appt.id)
        val result = repo.complete(appt.id)
        assertTrue(result)
        assertEquals(AppointmentStatus.COMPLETED.name, fakeDao.getById(appt.id)!!.status)
    }

    @Test
    fun `markNoShow transitions to NO_SHOW`() = runBlocking {
        val appt = repo.schedule("p1", "f1", 1000L, "NEW_VISIT", "user1")
        val result = repo.markNoShow(appt.id)
        assertTrue(result)
        assertEquals(AppointmentStatus.NO_SHOW.name, fakeDao.getById(appt.id)!!.status)
    }

    @Test
    fun `cancel transitions to CANCELLED`() = runBlocking {
        val appt = repo.schedule("p1", "f1", 1000L, "NEW_VISIT", "user1")
        val result = repo.cancel(appt.id)
        assertTrue(result)
        assertEquals(AppointmentStatus.CANCELLED.name, fakeDao.getById(appt.id)!!.status)
    }

    @Test
    fun `getByDate returns correct appointments`() = runBlocking {
        repo.schedule("p1", "f1", 1000L, "NEW_VISIT", "user1")
        repo.schedule("p2", "f1", 1000L, "FOLLOW_UP", "user1")
        repo.schedule("p3", "f1", 2000L, "NEW_VISIT", "user1")
        val appts = repo.getByDate("f1", 1000L)
        assertEquals(2, appts.size)
    }

    @Test
    fun `getByPatient returns all patient appointments`() = runBlocking {
        repo.schedule("p1", "f1", 1000L, "NEW_VISIT", "user1")
        repo.schedule("p1", "f1", 2000L, "FOLLOW_UP", "user1")
        repo.schedule("p2", "f1", 1000L, "NEW_VISIT", "user1")
        val appts = repo.getByPatient("p1")
        assertEquals(2, appts.size)
    }

    @Test
    fun `non-existent appointment operations return false`() = runBlocking {
        assertFalse(repo.checkIn("nonexistent"))
        assertFalse(repo.startVisit("nonexistent"))
        assertFalse(repo.complete("nonexistent"))
        assertFalse(repo.markNoShow("nonexistent"))
        assertFalse(repo.cancel("nonexistent"))
    }

    @Test
    fun `full appointment lifecycle`() = runBlocking {
        val appt = repo.schedule("p1", "f1", 1000L, "NEW_VISIT", "user1")
        assertEquals(AppointmentStatus.SCHEDULED.name, fakeDao.getById(appt.id)!!.status)
        repo.checkIn(appt.id)
        assertEquals(AppointmentStatus.CHECKED_IN.name, fakeDao.getById(appt.id)!!.status)
        repo.startVisit(appt.id)
        assertEquals(AppointmentStatus.IN_PROGRESS.name, fakeDao.getById(appt.id)!!.status)
        repo.complete(appt.id)
        assertEquals(AppointmentStatus.COMPLETED.name, fakeDao.getById(appt.id)!!.status)
    }

    private class FakeAppointmentDao : AppointmentDao {
        private val appts = mutableMapOf<String, AppointmentEntity>()

        override suspend fun insert(appointment: AppointmentEntity) { appts[appointment.id] = appointment }
        override suspend fun update(appointment: AppointmentEntity) { appts[appointment.id] = appointment }
        override suspend fun getById(id: String) = appts[id]
        override suspend fun getByDate(facilityId: String, date: Long) = appts.values.filter { it.facilityId == facilityId && it.scheduledDate == date }
        override suspend fun getByPatient(patientId: String) = appts.values.filter { it.patientId == patientId }
        override suspend fun getUpcoming(facilityId: String, fromDate: Long) =
            appts.values.filter {
                it.facilityId == facilityId &&
                    it.scheduledDate >= fromDate &&
                    it.status == AppointmentStatus.SCHEDULED.name
            }
        override suspend fun getCountForDate(facilityId: String, date: Long) = getByDate(facilityId, date).size
        override suspend fun getNextForDate(facilityId: String, date: Long) = getByDate(facilityId, date).firstOrNull()
        override fun observeByDate(facilityId: String, date: Long): Flow<List<AppointmentEntity>> = flowOf(emptyList())
    }
}
