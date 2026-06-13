package com.chartlite.app

import com.chartlite.app.cdss.DosageChecker
import com.chartlite.app.model.AlertSeverity
import com.chartlite.app.model.Medication
import org.junit.Assert.*
import org.junit.Before
import org.junit.Test

class DosageCheckerTest {

    private lateinit var checker: DosageChecker

    @Before
    fun setup() {
        checker = DosageChecker()
    }

    // -- Normal doses --

    @Test
    fun `no alerts for normal amoxicillin dose`() {
        val meds = listOf(
            Medication("0001", "Amoxicillin", 500f, "mg", "TDS", 7, "PO", 0.9f)
        )
        val alerts = checker.check(meds)
        assertTrue("Amox 500mg TDS = 1500mg/day, max 3000mg, should be fine", alerts.isEmpty())
    }

    @Test
    fun `no alerts for normal paracetamol dose`() {
        val meds = listOf(
            Medication("0010", "Paracetamol", 1000f, "mg", "QDS", 3, "PO", 0.9f)
        )
        val alerts = checker.check(meds)
        assertTrue("Paracetamol 1000mg QDS = 4000mg/day = max, should be fine", alerts.isEmpty())
    }

    // -- Warning doses (over max but under 2x max) --

    @Test
    fun `warning for paracetamol slightly over max`() {
        val meds = listOf(
            Medication("0010", "Paracetamol", 1500f, "mg", "TDS", 3, "PO", 0.9f)
        )
        val alerts = checker.check(meds)
        // 1500mg TDS = 4500mg/day > 4000mg max
        assertTrue("Should warn about excessive paracetamol", alerts.isNotEmpty())
        assertEquals(AlertSeverity.WARNING, alerts[0].severity)
        assertEquals("Dosage", alerts[0].category)
    }

    @Test
    fun `warning for ibuprofen over max`() {
        val meds = listOf(
            Medication("0011", "Ibuprofen", 800f, "mg", "QDS", 5, "PO", 0.85f)
        )
        val alerts = checker.check(meds)
        // 800mg QDS = 3200mg/day > 2400mg max, but < 4800mg (2x max)
        assertTrue(alerts.isNotEmpty())
        assertEquals(AlertSeverity.WARNING, alerts[0].severity)
    }

    // -- Critical doses (over 2x max) --

    @Test
    fun `critical for paracetamol way over max`() {
        val meds = listOf(
            Medication("0010", "Paracetamol", 3000f, "mg", "QDS", 3, "PO", 0.5f)
        )
        val alerts = checker.check(meds)
        // 3000mg QDS = 12000mg/day > 8000mg (2x max of 4000)
        assertTrue(alerts.isNotEmpty())
        assertEquals(AlertSeverity.CRITICAL, alerts[0].severity)
    }

    @Test
    fun `critical for amoxicillin extreme dose`() {
        val meds = listOf(
            Medication("0001", "Amoxicillin", 2000f, "mg", "QDS", 7, "PO", 0.5f)
        )
        val alerts = checker.check(meds)
        // 2000mg QDS = 8000mg/day > 6000mg (2x max of 3000)
        assertTrue(alerts.isNotEmpty())
        assertEquals(AlertSeverity.CRITICAL, alerts[0].severity)
    }

    // -- Edge cases --

    @Test
    fun `no alert for unknown drug`() {
        val meds = listOf(
            Medication("9999", "UnknownDrug", 5000f, "mg", "TDS", 7, "PO", 0.5f)
        )
        val alerts = checker.check(meds)
        assertTrue("Unknown drugs should not trigger dosage alerts", alerts.isEmpty())
    }

    @Test
    fun `no alert for null dose`() {
        val meds = listOf(
            Medication("0001", "Amoxicillin", null, null, "TDS", 7, "PO", 0.5f)
        )
        val alerts = checker.check(meds)
        assertTrue("Null dose should skip checking", alerts.isEmpty())
    }

    @Test
    fun `no alert for mismatched units`() {
        val meds = listOf(
            Medication("0001", "Amoxicillin", 5000f, "ml", "TDS", 7, "PO", 0.5f)
        )
        val alerts = checker.check(meds)
        assertTrue("ml vs mg mismatch should skip checking", alerts.isEmpty())
    }

    @Test
    fun `empty medication list produces no alerts`() {
        val alerts = checker.check(emptyList())
        assertTrue(alerts.isEmpty())
    }

    @Test
    fun `OD frequency uses multiplier of 1`() {
        val meds = listOf(
            Medication("0005", "Amlodipine", 15f, "mg", "OD", 30, "PO", 0.9f)
        )
        val alerts = checker.check(meds)
        // 15mg OD = 15mg/day > 10mg max
        assertTrue(alerts.isNotEmpty())
        assertEquals(AlertSeverity.WARNING, alerts[0].severity)
    }

    @Test
    fun `BD frequency uses multiplier of 2`() {
        val meds = listOf(
            Medication("0010", "Paracetamol", 1500f, "mg", "BD", 3, "PO", 0.9f)
        )
        val alerts = checker.check(meds)
        // 1500mg BD = 3000mg/day < 4000mg max -> OK
        assertTrue("3000mg/day < 4000mg max should be fine", alerts.isEmpty())
    }

    // -- Multiple medications --

    @Test
    fun `checks each medication independently`() {
        val meds = listOf(
            Medication("0001", "Amoxicillin", 500f, "mg", "TDS", 7, "PO", 0.9f), // OK
            Medication("0010", "Paracetamol", 2000f, "mg", "TDS", 3, "PO", 0.9f)  // Over
        )
        val alerts = checker.check(meds)
        // Only paracetamol should trigger (6000mg > 4000mg)
        assertTrue(alerts.isNotEmpty())
        assertTrue(alerts[0].message.contains("Paracetamol"))
    }

    @Test
    fun `alert message contains drug name and dose`() {
        val meds = listOf(
            Medication("0010", "Paracetamol", 1500f, "mg", "TDS", 3, "PO", 0.9f)
        )
        val alerts = checker.check(meds)
        assertTrue(alerts.isNotEmpty())
        assertTrue("Alert should mention drug name", alerts[0].message.contains("Paracetamol"))
        assertTrue("Alert should mention dose", alerts[0].message.contains("4500"))
    }

    @Test
    fun `alert related field is medications`() {
        val meds = listOf(
            Medication("0010", "Paracetamol", 2000f, "mg", "QDS", 3, "PO", 0.5f)
        )
        val alerts = checker.check(meds)
        assertTrue(alerts.all { it.relatedField == "medications" })
    }

    // -- Frequency handling --

    @Test
    fun `PRN frequency skips dosage check`() {
        val meds = listOf(
            Medication("0010", "Paracetamol", 2000f, "mg", "PRN", 3, "PO", 0.9f)
        )
        val alerts = checker.check(meds)
        assertTrue("PRN frequency should skip dosage check — cannot compute daily dose", alerts.isEmpty())
    }

    @Test
    fun `WEEKLY frequency skips dosage check`() {
        val meds = listOf(
            Medication("0004", "Metformin", 2550f, "mg", "WEEKLY", 30, "PO", 0.9f)
        )
        val alerts = checker.check(meds)
        assertTrue("WEEKLY frequency should skip dosage check", alerts.isEmpty())
    }

    @Test
    fun `STAT frequency skips dosage check`() {
        val meds = listOf(
            Medication("0010", "Paracetamol", 4000f, "mg", "STAT", null, "PO", 0.9f)
        )
        val alerts = checker.check(meds)
        assertTrue("STAT frequency should skip dosage check", alerts.isEmpty())
    }

    @Test
    fun `null frequency uses default multiplier of 1`() {
        val meds = listOf(
            Medication("0005", "Amlodipine", 15f, "mg", null, 30, "PO", 0.9f)
        )
        val alerts = checker.check(meds)
        // 15mg * 1 = 15mg/day > 10mg max
        assertTrue("Null frequency should default to OD", alerts.isNotEmpty())
    }
}
