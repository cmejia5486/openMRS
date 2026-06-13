package com.chartlite.app

import com.chartlite.app.auth.AuthConfig
import com.chartlite.app.auth.AuthResult
import com.chartlite.app.auth.PinHasher
import com.chartlite.app.auth.SessionManager
import com.chartlite.app.auth.UserRole
import com.chartlite.app.database.dao.UserDao
import com.chartlite.app.database.entity.UserEntity
import kotlinx.coroutines.flow.Flow
import kotlinx.coroutines.flow.flowOf
import kotlinx.coroutines.runBlocking
import org.junit.Assert.*
import org.junit.Before
import org.junit.Test

/**
 * Tests for SessionManager.
 * Uses a fake UserDao and AuthConfig to test login, logout, lockout, and session management.
 */
class SessionManagerTest {

    private lateinit var sessionManager: SessionManager
    private lateinit var fakeUserDao: FakeUserDao
    private lateinit var fakeConfig: FakeAuthConfig

    private val testSalt = PinHasher.generateSalt()
    private val testHash = PinHasher.hash("1234", testSalt)

    private val testUser = UserEntity(
        id = "user-001",
        username = "dr.smith",
        displayName = "Dr. Smith",
        pinHash = testHash,
        pinSalt = testSalt,
        role = "DOCTOR",
        facilityId = "ZA-FAC001",
        isActive = true,
        createdBy = "setup",
        createdAt = System.currentTimeMillis(),
        updatedAt = System.currentTimeMillis()
    )

    private val disabledUser = testUser.copy(
        id = "user-002",
        username = "disabled.user",
        isActive = false
    )

    @Before
    fun setUp() {
        fakeUserDao = FakeUserDao(listOf(testUser, disabledUser))
        fakeConfig = FakeAuthConfig()
        sessionManager = SessionManager(fakeConfig, fakeUserDao)
    }

    // ── Login Success ────────────────────────────────────────────────

    @Test
    fun `login with correct credentials succeeds`() = runBlocking {
        val result = sessionManager.login("dr.smith", "1234", "ZA-FAC001")
        assertTrue("Should succeed", result is AuthResult.Success)
        val session = (result as AuthResult.Success).session
        assertEquals("user-001", session.userId)
        assertEquals("dr.smith", session.username)
        assertEquals("Dr. Smith", session.displayName)
        assertEquals(UserRole.DOCTOR, session.role)
        assertEquals("ZA-FAC001", session.facilityId)
    }

    @Test
    fun `login sets current session`() = runBlocking {
        assertNull("Session should be null before login", sessionManager.currentSession)
        sessionManager.login("dr.smith", "1234", "ZA-FAC001")
        assertNotNull("Session should be set after login", sessionManager.currentSession)
        assertEquals("user-001", sessionManager.currentSession!!.userId)
    }

    @Test
    fun `login persists userId to config`() = runBlocking {
        sessionManager.login("dr.smith", "1234", "ZA-FAC001")
        assertEquals("user-001", fakeConfig.currentUserId)
        assertTrue("Session start time should be set", fakeConfig.sessionStartedAt > 0)
    }

    // ── Login Failure ────────────────────────────────────────────────

    @Test
    fun `login with wrong PIN fails`() = runBlocking {
        val result = sessionManager.login("dr.smith", "9999", "ZA-FAC001")
        assertTrue("Should fail", result is AuthResult.Failed)
        assertEquals("Invalid credentials", (result as AuthResult.Failed).reason)
        assertNull("Session should remain null", sessionManager.currentSession)
    }

    @Test
    fun `login with unknown user fails`() = runBlocking {
        val result = sessionManager.login("nobody", "1234", "ZA-FAC001")
        assertTrue("Should fail", result is AuthResult.Failed)
        assertEquals("Invalid credentials", (result as AuthResult.Failed).reason)
    }

    @Test
    fun `login with disabled account returns AccountDisabled`() = runBlocking {
        val result = sessionManager.login("disabled.user", "1234", "ZA-FAC001")
        assertTrue("Should return AccountDisabled", result is AuthResult.AccountDisabled)
    }

    // ── Lockout After Failed Attempts ────────────────────────────────

    @Test
    fun `lockout after 5 failed attempts`() = runBlocking {
        repeat(5) {
            sessionManager.login("dr.smith", "wrong", "ZA-FAC001")
        }
        val result = sessionManager.login("dr.smith", "1234", "ZA-FAC001")
        assertTrue("Should be locked out after 5 failures", result is AuthResult.TooManyAttempts)
        assertTrue("isLockedOut should return true", sessionManager.isLockedOut())
    }

    @Test
    fun `lockout remaining seconds is positive when locked`() = runBlocking {
        repeat(5) {
            sessionManager.login("dr.smith", "wrong", "ZA-FAC001")
        }
        assertTrue(
            "Lockout remaining should be > 0",
            sessionManager.lockoutRemainingSeconds() > 0
        )
    }

    @Test
    fun `successful login resets failure counter`() = runBlocking {
        // 4 failures (not enough to lock out)
        repeat(4) {
            sessionManager.login("dr.smith", "wrong", "ZA-FAC001")
        }
        // Success resets the counter
        sessionManager.login("dr.smith", "1234", "ZA-FAC001")

        // 4 more failures should not lock out (counter was reset)
        repeat(4) {
            sessionManager.login("dr.smith", "wrong", "ZA-FAC001")
        }
        assertFalse("Should not be locked out after reset + 4 failures", sessionManager.isLockedOut())
    }

    // ── Logout ───────────────────────────────────────────────────────

    @Test
    fun `logout clears session`() = runBlocking {
        sessionManager.login("dr.smith", "1234", "ZA-FAC001")
        assertNotNull(sessionManager.currentSession)

        sessionManager.logout()
        assertNull("Session should be null after logout", sessionManager.currentSession)
        assertEquals("Config userId should be cleared", "", fakeConfig.currentUserId)
        assertEquals("Config sessionStartedAt should be 0", 0L, fakeConfig.sessionStartedAt)
    }

    // ── Session Restore ──────────────────────────────────────────────

    @Test
    fun `restoreSession succeeds with valid stored userId`() = runBlocking {
        fakeConfig.currentUserId = "user-001"
        fakeConfig.sessionStartedAt = 1000L

        val restored = sessionManager.restoreSession()
        assertTrue("Should restore successfully", restored)
        assertNotNull(sessionManager.currentSession)
        assertEquals("user-001", sessionManager.currentSession!!.userId)
        assertEquals(1000L, sessionManager.currentSession!!.sessionStartedAt)
    }

    @Test
    fun `restoreSession fails with empty userId`() = runBlocking {
        fakeConfig.currentUserId = ""
        val restored = sessionManager.restoreSession()
        assertFalse("Should not restore with empty userId", restored)
    }

    @Test
    fun `restoreSession fails with unknown userId`() = runBlocking {
        fakeConfig.currentUserId = "nonexistent"
        val restored = sessionManager.restoreSession()
        assertFalse("Should not restore with unknown userId", restored)
    }

    @Test
    fun `restoreSession fails for disabled user and logs out`() = runBlocking {
        fakeConfig.currentUserId = "user-002" // disabled user
        val restored = sessionManager.restoreSession()
        assertFalse("Should not restore disabled user", restored)
        assertEquals("Config should be cleared", "", fakeConfig.currentUserId)
    }

    // ── Reauthentication ─────────────────────────────────────────────

    @Test
    fun `reauthenticate succeeds with correct PIN`() = runBlocking {
        sessionManager.login("dr.smith", "1234", "ZA-FAC001")
        val result = sessionManager.reauthenticate("1234")
        assertTrue("Reauthentication should succeed", result)
    }

    @Test
    fun `reauthenticate fails with wrong PIN`() = runBlocking {
        sessionManager.login("dr.smith", "1234", "ZA-FAC001")
        val result = sessionManager.reauthenticate("9999")
        assertFalse("Reauthentication should fail with wrong PIN", result)
    }

    @Test
    fun `reauthenticate fails with no session`() = runBlocking {
        val result = sessionManager.reauthenticate("1234")
        assertFalse("Reauthentication should fail without session", result)
    }

    // ── Auto-Lock ────────────────────────────────────────────────────

    @Test
    fun `shouldLock returns false when no session`() {
        assertFalse("Should not lock when no session", sessionManager.shouldLock())
    }

    @Test
    fun `shouldLock returns false when autoLock is disabled`() = runBlocking {
        sessionManager.login("dr.smith", "1234", "ZA-FAC001")
        fakeConfig.autoLockEnabled = false
        assertFalse("Should not lock when autoLock disabled", sessionManager.shouldLock())
    }

    @Test
    fun `shouldLock returns false immediately after activity`() = runBlocking {
        sessionManager.login("dr.smith", "1234", "ZA-FAC001")
        fakeConfig.autoLockEnabled = true
        fakeConfig.autoLockMinutes = 5
        sessionManager.touch() // Reset timer
        assertFalse("Should not lock right after touch", sessionManager.shouldLock())
    }

    // ── Lockout Timer ────────────────────────────────────────────────

    @Test
    fun `lockoutRemainingSeconds returns 0 when not locked`() {
        assertEquals(0, sessionManager.lockoutRemainingSeconds())
    }

    @Test
    fun `isLockedOut returns false initially`() {
        assertFalse(sessionManager.isLockedOut())
    }

    // ── Role Parsing ─────────────────────────────────────────────────

    @Test
    fun `login parses user role correctly`() = runBlocking {
        val result = sessionManager.login("dr.smith", "1234", "ZA-FAC001")
        assertTrue(result is AuthResult.Success)
        assertEquals(UserRole.DOCTOR, (result as AuthResult.Success).session.role)
    }

    @Test
    fun `login with unknown role falls back to REGISTRATION_CLERK`() = runBlocking {
        val userWithBadRole = testUser.copy(
            id = "user-003",
            username = "bad.role",
            role = "INVALID_ROLE"
        )
        fakeUserDao = FakeUserDao(listOf(userWithBadRole))
        sessionManager = SessionManager(fakeConfig, fakeUserDao)

        val result = sessionManager.login("bad.role", "1234", "ZA-FAC001")
        assertTrue(result is AuthResult.Success)
        assertEquals(
            "Unknown role should fallback to REGISTRATION_CLERK",
            UserRole.REGISTRATION_CLERK,
            (result as AuthResult.Success).session.role
        )
    }

    // ── Fake Implementations ─────────────────────────────────────────

    /**
     * In-memory UserDao for testing without Room.
     */
    private class FakeUserDao(private val users: List<UserEntity>) : UserDao {
        override suspend fun insert(user: UserEntity) {}
        override suspend fun update(user: UserEntity) {}
        override suspend fun getById(id: String): UserEntity? = users.find { it.id == id }
        override suspend fun getByUsername(username: String, facilityId: String): UserEntity? =
            users.find { it.username == username && it.facilityId == facilityId }
        override suspend fun getByFacilityId(facilityId: String): List<UserEntity> =
            users.filter { it.facilityId == facilityId }
        override suspend fun getActiveByFacilityId(facilityId: String): List<UserEntity> =
            users.filter { it.facilityId == facilityId && it.isActive }
        override fun observeByFacilityId(facilityId: String): Flow<List<UserEntity>> =
            flowOf(users.filter { it.facilityId == facilityId })
        override suspend fun getByRole(role: String, facilityId: String): List<UserEntity> =
            users.filter { it.role == role && it.facilityId == facilityId }
        override suspend fun getCount(facilityId: String): Int =
            users.count { it.facilityId == facilityId }
        override suspend fun getActiveAdminCount(facilityId: String): Int =
            users.count { it.facilityId == facilityId && it.role == "ADMIN" && it.isActive }
    }

    /**
     * Simple in-memory AuthConfig for testing without EncryptedSharedPreferences.
     */
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
