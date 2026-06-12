package com.chartlite.app

import com.chartlite.app.auth.AuditLogger
import com.chartlite.app.auth.AuthConfig
import com.chartlite.app.auth.SessionManager
import com.chartlite.app.auth.UserRole
import com.chartlite.app.auth.UserSession
import com.chartlite.app.auth.PinHasher
import com.chartlite.app.database.dao.AuditLogDao
import com.chartlite.app.database.dao.UserDao
import com.chartlite.app.database.entity.AuditLogEntity
import com.chartlite.app.database.entity.UserEntity
import kotlinx.coroutines.flow.Flow
import kotlinx.coroutines.flow.flowOf
import kotlinx.coroutines.runBlocking
import org.junit.Assert.*
import org.junit.Before
import org.junit.Test

/**
 * Tests for AuditLogger.
 * Verifies log entries are created with correct fields, user ID resolution, and system fallback.
 */
class AuditLoggerTest {

    private lateinit var auditLogger: AuditLogger
    private lateinit var fakeAuditLogDao: FakeAuditLogDao
    private lateinit var sessionManager: SessionManager

    private val testSalt = PinHasher.generateSalt()
    private val testHash = PinHasher.hash("1234", testSalt)

    @Before
    fun setUp() {
        fakeAuditLogDao = FakeAuditLogDao()

        val testUser = UserEntity(
            id = "user-001", username = "dr.smith", displayName = "Dr. Smith",
            pinHash = testHash, pinSalt = testSalt, role = "DOCTOR",
            facilityId = "ZA-FAC001", isActive = true, createdBy = "setup",
            createdAt = System.currentTimeMillis(), updatedAt = System.currentTimeMillis()
        )
        val fakeUserDao = FakeUserDao(listOf(testUser))
        val fakeConfig = FakeAuthConfig()

        sessionManager = SessionManager(fakeConfig, fakeUserDao)
        auditLogger = AuditLogger(fakeAuditLogDao, sessionManager)
    }

    // ── Basic Logging ────────────────────────────────────────────────

    @Test
    fun `log creates entry with correct action`() = runBlocking {
        auditLogger.log("LOGIN")
        assertEquals(1, fakeAuditLogDao.logs.size)
        assertEquals("LOGIN", fakeAuditLogDao.logs[0].action)
    }

    @Test
    fun `log creates entry with target type and id`() = runBlocking {
        auditLogger.log("CREATE_PATIENT", targetType = "PATIENT", targetId = "P-12345")
        val log = fakeAuditLogDao.logs[0]
        assertEquals("CREATE_PATIENT", log.action)
        assertEquals("PATIENT", log.targetType)
        assertEquals("P-12345", log.targetId)
    }

    @Test
    fun `log creates entry with details`() = runBlocking {
        auditLogger.log("SETTINGS_CHANGE", details = """{"field":"language","value":"zu"}""")
        val log = fakeAuditLogDao.logs[0]
        assertEquals("""{"field":"language","value":"zu"}""", log.details)
    }

    @Test
    fun `log generates unique IDs for each entry`() = runBlocking {
        auditLogger.log("ACTION_1")
        auditLogger.log("ACTION_2")
        assertNotEquals(
            "Log entries should have different IDs",
            fakeAuditLogDao.logs[0].id,
            fakeAuditLogDao.logs[1].id
        )
    }

    @Test
    fun `log timestamp is recent`() = runBlocking {
        val before = System.currentTimeMillis()
        auditLogger.log("TEST")
        val after = System.currentTimeMillis()
        val timestamp = fakeAuditLogDao.logs[0].timestamp
        assertTrue("Timestamp should be >= before", timestamp >= before)
        assertTrue("Timestamp should be <= after", timestamp <= after)
    }

    // ── User ID Resolution ───────────────────────────────────────────

    @Test
    fun `log uses system userId when no session`() = runBlocking {
        auditLogger.log("SYSTEM_EVENT")
        assertEquals("system", fakeAuditLogDao.logs[0].userId)
    }

    @Test
    fun `log uses session userId when logged in`() = runBlocking {
        sessionManager.login("dr.smith", "1234", "ZA-FAC001")
        auditLogger.log("CREATE_ENCOUNTER")
        assertEquals("user-001", fakeAuditLogDao.logs[0].userId)
    }

    @Test
    fun `log uses explicit userId override`() = runBlocking {
        sessionManager.login("dr.smith", "1234", "ZA-FAC001")
        auditLogger.log("FAILED_AUTH", userId = "user-999")
        assertEquals("user-999", fakeAuditLogDao.logs[0].userId)
    }

    // ── Multiple Logs ────────────────────────────────────────────────

    @Test
    fun `multiple logs are all recorded`() = runBlocking {
        auditLogger.log("LOGIN")
        auditLogger.log("CREATE_PATIENT", targetType = "PATIENT", targetId = "P1")
        auditLogger.log("CREATE_ENCOUNTER", targetType = "ENCOUNTER", targetId = "E1")
        auditLogger.log("LOGOUT")
        assertEquals(4, fakeAuditLogDao.logs.size)
    }

    // ── Null Optional Fields ─────────────────────────────────────────

    @Test
    fun `log with null optional fields`() = runBlocking {
        auditLogger.log("LOGIN")
        val log = fakeAuditLogDao.logs[0]
        assertNull("targetType should be null", log.targetType)
        assertNull("targetId should be null", log.targetId)
        assertNull("details should be null", log.details)
    }

    // ── Fake Implementations ─────────────────────────────────────────

    private class FakeAuditLogDao : AuditLogDao {
        val logs = mutableListOf<AuditLogEntity>()
        override suspend fun insert(log: AuditLogEntity) { logs.add(log) }
        override suspend fun getByUserId(userId: String, limit: Int) = logs.filter { it.userId == userId }.take(limit)
        override suspend fun getByAction(action: String, limit: Int) = logs.filter { it.action == action }.take(limit)
        override suspend fun getByDateRange(startTime: Long, endTime: Long, limit: Int) =
            logs.filter { it.timestamp in startTime..endTime }.take(limit)
        override suspend fun getByTarget(targetType: String, targetId: String) =
            logs.filter { it.targetType == targetType && it.targetId == targetId }
        override suspend fun getRecentFailedAuthCount(userId: String, since: Long) =
            logs.count { it.userId == userId && it.action == "FAILED_AUTH" && it.timestamp > since }
        override suspend fun getRecent(limit: Int) = logs.takeLast(limit)
        override suspend fun deleteOlderThan(before: Long) = logs.count { it.timestamp < before }.also {
            logs.removeAll { l -> l.timestamp < before }
        }
    }

    private class FakeUserDao(private val users: List<UserEntity>) : UserDao {
        override suspend fun insert(user: UserEntity) {}
        override suspend fun update(user: UserEntity) {}
        override suspend fun getById(id: String) = users.find { it.id == id }
        override suspend fun getByUsername(username: String, facilityId: String) =
            users.find { it.username == username && it.facilityId == facilityId }
        override suspend fun getByFacilityId(facilityId: String) = users.filter { it.facilityId == facilityId }
        override suspend fun getActiveByFacilityId(facilityId: String) =
            users.filter { it.facilityId == facilityId && it.isActive }
        override fun observeByFacilityId(facilityId: String): Flow<List<UserEntity>> =
            flowOf(users.filter { it.facilityId == facilityId })
        override suspend fun getByRole(role: String, facilityId: String) =
            users.filter { it.role == role && it.facilityId == facilityId }
        override suspend fun getCount(facilityId: String) = users.count { it.facilityId == facilityId }
        override suspend fun getActiveAdminCount(facilityId: String) =
            users.count { it.facilityId == facilityId && it.role == "ADMIN" && it.isActive }
    }

    private class FakeAuthConfig : AuthConfig {
        override var currentUserId: String = ""
        override var sessionStartedAt: Long = 0L
        override var autoLockEnabled: Boolean = true
        override var autoLockMinutes: Int = 5
        override var pinLength: Int = 4
        override var failedAttempts: Int = 0
        override var lockoutUntil: Long = 0L
        override var lockoutStatesJson: String = "{}"
        override var lastActiveAt: Long = System.currentTimeMillis()
    }
}
