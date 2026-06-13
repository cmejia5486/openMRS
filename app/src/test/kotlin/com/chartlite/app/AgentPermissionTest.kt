package com.chartlite.app

import com.chartlite.app.agent.AgentContext
import com.chartlite.app.agent.AgentPermission
import com.chartlite.app.agent.AgentPermissionDeniedException
import org.junit.Assert.*
import org.junit.Test

class AgentPermissionTest {

    // ── Permission sets by role ─────────────────────────────────────────

    @Test
    fun `ADMIN role has all permissions`() {
        val perms = AgentPermission.forRole("ADMIN")
        assertEquals(AgentPermission.entries.toSet(), perms)
    }

    @Test
    fun `DOCTOR role has clinical permissions but not AUDIT_READ`() {
        val perms = AgentPermission.forRole("DOCTOR")
        assertTrue(AgentPermission.PATIENT_READ in perms)
        assertTrue(AgentPermission.ENCOUNTER_CREATE in perms)
        assertTrue(AgentPermission.LAB_ORDER_CREATE in perms)
        assertTrue(AgentPermission.REFERRAL_CREATE in perms)
        assertTrue(AgentPermission.IMMUNIZATION_CREATE in perms)
        assertFalse(AgentPermission.AUDIT_READ in perms)
        assertFalse(AgentPermission.STOCK_DISPENSE in perms)
    }

    @Test
    fun `NURSE role can triage but not consult`() {
        val perms = AgentPermission.forRole("NURSE")
        assertTrue(AgentPermission.PATIENT_CREATE in perms)
        assertTrue(AgentPermission.ENCOUNTER_CREATE in perms)
        assertTrue(AgentPermission.LAB_ORDER_CREATE in perms)
        assertFalse(AgentPermission.ENCOUNTER_UPDATE in perms)
        assertFalse(AgentPermission.STOCK_DISPENSE in perms)
    }

    @Test
    fun `PHARMACIST role has stock permissions but not encounters`() {
        val perms = AgentPermission.forRole("PHARMACIST")
        assertTrue(AgentPermission.STOCK_READ in perms)
        assertTrue(AgentPermission.STOCK_UPDATE in perms)
        assertTrue(AgentPermission.STOCK_DISPENSE in perms)
        assertFalse(AgentPermission.ENCOUNTER_CREATE in perms)
        assertFalse(AgentPermission.REFERRAL_CREATE in perms)
    }

    @Test
    fun `CHW role has community health permissions`() {
        val perms = AgentPermission.forRole("CHW")
        assertTrue(AgentPermission.PATIENT_CREATE in perms)
        assertTrue(AgentPermission.ENCOUNTER_CREATE in perms)
        assertTrue(AgentPermission.IMMUNIZATION_CREATE in perms)
        assertTrue(AgentPermission.CDSS_QUERY in perms)
        assertFalse(AgentPermission.LAB_ORDER_CREATE in perms)
        assertFalse(AgentPermission.STOCK_DISPENSE in perms)
    }

    @Test
    fun `REGISTRATION_CLERK has limited permissions`() {
        val perms = AgentPermission.forRole("REGISTRATION_CLERK")
        assertTrue(AgentPermission.PATIENT_CREATE in perms)
        assertTrue(AgentPermission.APPOINTMENT_CREATE in perms)
        assertFalse(AgentPermission.ENCOUNTER_CREATE in perms)
        assertFalse(AgentPermission.LAB_ORDER_CREATE in perms)
    }

    @Test
    fun `unknown role gets minimal read-only permissions`() {
        val perms = AgentPermission.forRole("UNKNOWN_ROLE")
        assertEquals(setOf(AgentPermission.PATIENT_READ, AgentPermission.CDSS_QUERY), perms)
    }

    @Test
    fun `role matching is case insensitive`() {
        val perms1 = AgentPermission.forRole("doctor")
        val perms2 = AgentPermission.forRole("DOCTOR")
        assertEquals(perms1, perms2)
    }

    // ── AgentContext permission checks ──────────────────────────────────

    @Test
    fun `hasPermission returns true for granted permission`() {
        val ctx = AgentContext(userId = "u1", userRole = "DOCTOR", agentId = "test")
        assertTrue(ctx.hasPermission(AgentPermission.PATIENT_READ))
    }

    @Test
    fun `hasPermission returns false for denied permission`() {
        val ctx = AgentContext(userId = "u1", userRole = "PHARMACIST", agentId = "test")
        assertFalse(ctx.hasPermission(AgentPermission.ENCOUNTER_CREATE))
    }

    @Test
    fun `requirePermission throws for denied permission`() {
        val ctx = AgentContext(userId = "u1", userRole = "PHARMACIST", agentId = "test_agent")
        try {
            ctx.requirePermission(AgentPermission.ENCOUNTER_CREATE)
            fail("Expected AgentPermissionDeniedException")
        } catch (e: AgentPermissionDeniedException) {
            assertEquals("test_agent", e.agentId)
            assertEquals("u1", e.userId)
            assertEquals(AgentPermission.ENCOUNTER_CREATE, e.permission)
            assertTrue(e.message!!.contains("encounter:create"))
        }
    }

    @Test
    fun `requirePermission succeeds for granted permission`() {
        val ctx = AgentContext(userId = "u1", userRole = "DOCTOR", agentId = "test")
        ctx.requirePermission(AgentPermission.PATIENT_READ) // Should not throw
    }

    @Test
    fun `AgentContext with custom permissions overrides role defaults`() {
        val customPerms = setOf(AgentPermission.PATIENT_READ)
        val ctx = AgentContext(userId = "u1", userRole = "ADMIN", agentId = "test", permissions = customPerms)
        assertTrue(ctx.hasPermission(AgentPermission.PATIENT_READ))
        assertFalse(ctx.hasPermission(AgentPermission.AUDIT_READ)) // Even though admin normally has this
    }

    @Test
    fun `AgentContext carries session and intent metadata`() {
        val ctx = AgentContext(
            userId = "u1", userRole = "DOCTOR", agentId = "voice_assistant",
            sessionId = "session-123", intent = "Order CBC for patient"
        )
        assertEquals("session-123", ctx.sessionId)
        assertEquals("Order CBC for patient", ctx.intent)
    }

    // ── Permission enum structure ───────────────────────────────────────

    @Test
    fun `all permissions have resource and action`() {
        AgentPermission.entries.forEach { perm ->
            assertTrue("${perm.name} missing resource", perm.resource.isNotBlank())
            assertTrue("${perm.name} missing action", perm.action.isNotBlank())
        }
    }

    @Test
    fun `permission count is correct`() {
        // 25 permissions defined
        assertEquals(25, AgentPermission.entries.size)
    }
}
