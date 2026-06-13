package com.chartlite.app

import com.chartlite.app.model.*
import org.junit.Assert.*
import org.junit.Test

/**
 * Tests for all Phase 2-4 domain model enums.
 */
class DomainModelsTest {

    // ── Lab Order enums ─────────────────────────────────────────────────

    @Test
    fun `LabOrderStatus has 4 states`() {
        assertEquals(4, LabOrderStatus.entries.size)
        assertNotNull(LabOrderStatus.valueOf("ORDERED"))
        assertNotNull(LabOrderStatus.valueOf("COLLECTED"))
        assertNotNull(LabOrderStatus.valueOf("RESULTED"))
        assertNotNull(LabOrderStatus.valueOf("CANCELLED"))
    }

    @Test
    fun `LabPriority has 3 levels`() {
        assertEquals(3, LabPriority.entries.size)
        assertNotNull(LabPriority.valueOf("ROUTINE"))
        assertNotNull(LabPriority.valueOf("URGENT"))
        assertNotNull(LabPriority.valueOf("STAT"))
    }

    @Test
    fun `LabTestCatalogEntry holds test metadata`() {
        val entry = LabTestCatalogEntry(
            code = "CBC", name = "Complete Blood Count",
            category = "Hematology", defaultUnit = "cells/uL",
            referenceRange = "WBC: 4.5-11.0", criticalRange = "WBC <2.0"
        )
        assertEquals("CBC", entry.code)
        assertEquals("Hematology", entry.category)
    }

    // ── Appointment enums ───────────────────────────────────────────────

    @Test
    fun `AppointmentType has 6 types`() {
        assertEquals(6, AppointmentType.entries.size)
        assertNotNull(AppointmentType.valueOf("FOLLOW_UP"))
        assertNotNull(AppointmentType.valueOf("NEW_VISIT"))
        assertNotNull(AppointmentType.valueOf("LAB_REVIEW"))
        assertNotNull(AppointmentType.valueOf("CHRONIC_CARE"))
        assertNotNull(AppointmentType.valueOf("ANTENATAL"))
        assertNotNull(AppointmentType.valueOf("IMMUNIZATION"))
    }

    @Test
    fun `AppointmentStatus has 6 states`() {
        assertEquals(6, AppointmentStatus.entries.size)
        assertNotNull(AppointmentStatus.valueOf("SCHEDULED"))
        assertNotNull(AppointmentStatus.valueOf("CHECKED_IN"))
        assertNotNull(AppointmentStatus.valueOf("IN_PROGRESS"))
        assertNotNull(AppointmentStatus.valueOf("COMPLETED"))
        assertNotNull(AppointmentStatus.valueOf("NO_SHOW"))
        assertNotNull(AppointmentStatus.valueOf("CANCELLED"))
    }

    // ── Referral enums ──────────────────────────────────────────────────

    @Test
    fun `ReferralUrgency has 3 levels`() {
        assertEquals(3, ReferralUrgency.entries.size)
        assertNotNull(ReferralUrgency.valueOf("ROUTINE"))
        assertNotNull(ReferralUrgency.valueOf("URGENT"))
        assertNotNull(ReferralUrgency.valueOf("EMERGENCY"))
    }

    @Test
    fun `ReferralStatus has 4 states`() {
        assertEquals(4, ReferralStatus.entries.size)
        assertNotNull(ReferralStatus.valueOf("PENDING"))
        assertNotNull(ReferralStatus.valueOf("ACCEPTED"))
        assertNotNull(ReferralStatus.valueOf("COMPLETED"))
        assertNotNull(ReferralStatus.valueOf("CANCELLED"))
    }

    // ── Stock enums ─────────────────────────────────────────────────────

    @Test
    fun `StockTransactionType has 5 types`() {
        assertEquals(5, StockTransactionType.entries.size)
        assertNotNull(StockTransactionType.valueOf("RECEIVED"))
        assertNotNull(StockTransactionType.valueOf("DISPENSED"))
        assertNotNull(StockTransactionType.valueOf("ADJUSTED"))
        assertNotNull(StockTransactionType.valueOf("EXPIRED"))
        assertNotNull(StockTransactionType.valueOf("RETURNED"))
    }
}
