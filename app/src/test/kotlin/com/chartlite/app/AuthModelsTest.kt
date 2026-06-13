package com.chartlite.app

import com.chartlite.app.auth.AuthResult
import com.chartlite.app.auth.UserRole
import com.chartlite.app.auth.UserSession
import org.junit.Assert.*
import org.junit.Test

/**
 * Tests for UserRole permissions, UserSession, and AuthResult.
 * Covers: role permission matrix, display names, session construction, result types.
 */
class AuthModelsTest {

    // ── UserRole Display Names ───────────────────────────────────────

    @Test
    fun `all roles have display names`() {
        UserRole.entries.forEach { role ->
            assertTrue(
                "Role ${role.name} should have a non-blank display name",
                role.displayName.isNotBlank()
            )
        }
    }

    @Test
    fun `ADMIN display name is Administrator`() {
        assertEquals("Administrator", UserRole.ADMIN.displayName)
    }

    @Test
    fun `CHW display name is Community Health Worker`() {
        assertEquals("Community Health Worker", UserRole.CHW.displayName)
    }

    @Test
    fun `REGISTRATION_CLERK display name is Registration Clerk`() {
        assertEquals("Registration Clerk", UserRole.REGISTRATION_CLERK.displayName)
    }

    // ── Role Permission Matrix ───────────────────────────────────────

    @Test
    fun `ADMIN can do everything`() {
        val admin = UserRole.ADMIN
        assertTrue("ADMIN canConsult", admin.canConsult)
        assertTrue("ADMIN canDispense", admin.canDispense)
        assertTrue("ADMIN canRegister", admin.canRegister)
        assertTrue("ADMIN canTriage", admin.canTriage)
        assertTrue("ADMIN canManageUsers", admin.canManageUsers)
        assertTrue("ADMIN canViewDashboard", admin.canViewDashboard)
        assertTrue("ADMIN canSync", admin.canSync)
        assertTrue("ADMIN canEditSettings", admin.canEditSettings)
    }

    @Test
    fun `DOCTOR can consult triage register and view dashboard`() {
        val doctor = UserRole.DOCTOR
        assertTrue("DOCTOR canConsult", doctor.canConsult)
        assertFalse("DOCTOR cannot dispense", doctor.canDispense)
        assertTrue("DOCTOR canRegister", doctor.canRegister)
        assertTrue("DOCTOR canTriage", doctor.canTriage)
        assertFalse("DOCTOR cannot manage users", doctor.canManageUsers)
        assertTrue("DOCTOR canViewDashboard", doctor.canViewDashboard)
        assertFalse("DOCTOR cannot sync", doctor.canSync)
        assertFalse("DOCTOR cannot edit settings", doctor.canEditSettings)
    }

    @Test
    fun `NURSE can triage register and view dashboard`() {
        val nurse = UserRole.NURSE
        assertFalse("NURSE cannot consult", nurse.canConsult)
        assertFalse("NURSE cannot dispense", nurse.canDispense)
        assertTrue("NURSE canRegister", nurse.canRegister)
        assertTrue("NURSE canTriage", nurse.canTriage)
        assertFalse("NURSE cannot manage users", nurse.canManageUsers)
        assertTrue("NURSE canViewDashboard", nurse.canViewDashboard)
        assertFalse("NURSE cannot sync", nurse.canSync)
        assertFalse("NURSE cannot edit settings", nurse.canEditSettings)
    }

    @Test
    fun `PHARMACIST can only dispense and view dashboard`() {
        val pharmacist = UserRole.PHARMACIST
        assertFalse("PHARMACIST cannot consult", pharmacist.canConsult)
        assertTrue("PHARMACIST canDispense", pharmacist.canDispense)
        assertFalse("PHARMACIST cannot register", pharmacist.canRegister)
        assertFalse("PHARMACIST cannot triage", pharmacist.canTriage)
        assertFalse("PHARMACIST cannot manage users", pharmacist.canManageUsers)
        assertTrue("PHARMACIST canViewDashboard", pharmacist.canViewDashboard)
        assertFalse("PHARMACIST cannot sync", pharmacist.canSync)
        assertFalse("PHARMACIST cannot edit settings", pharmacist.canEditSettings)
    }

    @Test
    fun `CHW can triage and register but not consult or dispense`() {
        val chw = UserRole.CHW
        assertFalse("CHW cannot consult", chw.canConsult)
        assertFalse("CHW cannot dispense", chw.canDispense)
        assertTrue("CHW canRegister", chw.canRegister)
        assertTrue("CHW canTriage", chw.canTriage)
        assertFalse("CHW cannot manage users", chw.canManageUsers)
        assertFalse("CHW cannot view dashboard", chw.canViewDashboard)
        assertFalse("CHW cannot sync", chw.canSync)
        assertFalse("CHW cannot edit settings", chw.canEditSettings)
    }

    @Test
    fun `REGISTRATION_CLERK can only register`() {
        val clerk = UserRole.REGISTRATION_CLERK
        assertFalse("CLERK cannot consult", clerk.canConsult)
        assertFalse("CLERK cannot dispense", clerk.canDispense)
        assertTrue("CLERK canRegister", clerk.canRegister)
        assertFalse("CLERK cannot triage", clerk.canTriage)
        assertFalse("CLERK cannot manage users", clerk.canManageUsers)
        assertFalse("CLERK cannot view dashboard", clerk.canViewDashboard)
        assertFalse("CLERK cannot sync", clerk.canSync)
        assertFalse("CLERK cannot edit settings", clerk.canEditSettings)
    }

    // ── Only ADMIN can manage users ──────────────────────────────────

    @Test
    fun `only ADMIN can manage users`() {
        UserRole.entries.forEach { role ->
            if (role == UserRole.ADMIN) {
                assertTrue("${role.name} should be able to manage users", role.canManageUsers)
            } else {
                assertFalse("${role.name} should NOT be able to manage users", role.canManageUsers)
            }
        }
    }

    // ── Only ADMIN can sync ──────────────────────────────────────────

    @Test
    fun `only ADMIN can sync`() {
        UserRole.entries.forEach { role ->
            if (role == UserRole.ADMIN) {
                assertTrue("${role.name} should be able to sync", role.canSync)
            } else {
                assertFalse("${role.name} should NOT be able to sync", role.canSync)
            }
        }
    }

    // ── Only ADMIN and DOCTOR can consult ────────────────────────────

    @Test
    fun `only ADMIN and DOCTOR can consult`() {
        val consultRoles = UserRole.entries.filter { it.canConsult }
        assertEquals(
            "Only ADMIN and DOCTOR should be able to consult",
            setOf(UserRole.ADMIN, UserRole.DOCTOR),
            consultRoles.toSet()
        )
    }

    // ── Only ADMIN and PHARMACIST can dispense ───────────────────────

    @Test
    fun `only ADMIN and PHARMACIST can dispense`() {
        val dispenseRoles = UserRole.entries.filter { it.canDispense }
        assertEquals(
            "Only ADMIN and PHARMACIST should be able to dispense",
            setOf(UserRole.ADMIN, UserRole.PHARMACIST),
            dispenseRoles.toSet()
        )
    }

    // ── UserSession ──────────────────────────────────────────────────

    @Test
    fun `UserSession stores all fields correctly`() {
        val session = UserSession(
            userId = "user-123",
            username = "dr.smith",
            displayName = "Dr. Smith",
            role = UserRole.DOCTOR,
            facilityId = "ZA-ABC123"
        )
        assertEquals("user-123", session.userId)
        assertEquals("dr.smith", session.username)
        assertEquals("Dr. Smith", session.displayName)
        assertEquals(UserRole.DOCTOR, session.role)
        assertEquals("ZA-ABC123", session.facilityId)
        assertTrue("Session start time should be recent", session.sessionStartedAt > 0)
    }

    @Test
    fun `UserSession with custom start time`() {
        val session = UserSession(
            userId = "u1",
            username = "admin",
            displayName = "Admin",
            role = UserRole.ADMIN,
            facilityId = "F1",
            sessionStartedAt = 1000L
        )
        assertEquals(1000L, session.sessionStartedAt)
    }

    // ── AuthResult ───────────────────────────────────────────────────

    @Test
    fun `AuthResult Success contains session`() {
        val session = UserSession("u1", "admin", "Admin", UserRole.ADMIN, "F1")
        val result = AuthResult.Success(session)
        assertEquals(session, result.session)
        assertTrue(result is AuthResult.Success)
    }

    @Test
    fun `AuthResult Failed contains reason`() {
        val result = AuthResult.Failed("Incorrect PIN")
        assertEquals("Incorrect PIN", result.reason)
        assertTrue(result is AuthResult.Failed)
    }

    @Test
    fun `AuthResult AccountDisabled is singleton`() {
        val result = AuthResult.AccountDisabled
        assertTrue(result is AuthResult.AccountDisabled)
    }

    @Test
    fun `AuthResult TooManyAttempts is singleton`() {
        val result = AuthResult.TooManyAttempts
        assertTrue(result is AuthResult.TooManyAttempts)
    }

    // ── Role Enum Coverage ───────────────────────────────────────────

    @Test
    fun `all six roles exist`() {
        assertEquals(6, UserRole.entries.size)
        assertNotNull(UserRole.valueOf("ADMIN"))
        assertNotNull(UserRole.valueOf("DOCTOR"))
        assertNotNull(UserRole.valueOf("NURSE"))
        assertNotNull(UserRole.valueOf("PHARMACIST"))
        assertNotNull(UserRole.valueOf("CHW"))
        assertNotNull(UserRole.valueOf("REGISTRATION_CLERK"))
    }

    @Test(expected = IllegalArgumentException::class)
    fun `invalid role name throws`() {
        UserRole.valueOf("INVALID_ROLE")
    }
}
