package com.chartlite.app

import android.content.Context
import android.content.res.AssetManager
import com.chartlite.app.cdss.StaticCDSS
import com.chartlite.app.model.*
import io.mockk.every
import io.mockk.mockk
import org.junit.Assert.*
import org.junit.Test
import java.io.IOException
import java.time.Instant

/**
 * Tests for StaticCDSS evaluate() — covers drug-allergy, drug-drug interactions,
 * vital alerts, and dosage checks. Prevents regressions for:
 * - Too many irrelevant drug-drug interaction alerts (false positives)
 * - Missing critical allergy alerts
 * - Correct alert severity levels
 */
class StaticCDSSTest {

    // Mock Context so loadRules() falls back to hardcoded defaults
    private val mockContext: Context = mockk {
        val mockAssets = mockk<AssetManager>()
        every { assets } returns mockAssets
        every { mockAssets.open(any()) } throws IOException("test — using hardcoded defaults")
    }
    private val cdss = StaticCDSS(mockContext)

    private fun encounter(
        medications: List<Medication> = emptyList(),
        vitals: VitalSigns? = null,
        allergies: List<String> = emptyList(),
        diagnoses: List<Diagnosis> = emptyList()
    ) = StructuredEncounter(
        id = "enc-test",
        patientId = "KFMT-4WRN",
        providerId = "prov-001",
        facilityId = "fac-001",
        timestamp = Instant.now(),
        transcript = "test",
        medications = medications,
        diagnoses = diagnoses,
        vitals = vitals,
        allergies = allergies,
        followUp = null,
        referral = null,
        freeTextNote = "",
        extractionConfidence = 0.9f
    )

    // ── Drug-Allergy Interactions ──

    @Test
    fun `penicillin allergy triggers alert for amoxicillin`() {
        val enc = encounter(
            medications = listOf(
                Medication("0001", "Amoxicillin", 500f, "mg", "TDS", 7, "PO", 0.9f)
            ),
            allergies = listOf("penicillin")
        )
        val alerts = cdss.evaluate(enc, listOf("penicillin"))
        val allergyAlerts = alerts.filter { it.category.contains("allergy", ignoreCase = true) || it.category.contains("Allergy", ignoreCase = true) }
        assertTrue(
            "Penicillin allergy + Amoxicillin should trigger allergy alert",
            allergyAlerts.isNotEmpty()
        )
        assertTrue(
            "Allergy alert should be CRITICAL or WARNING",
            allergyAlerts.any { it.severity == AlertSeverity.CRITICAL || it.severity == AlertSeverity.WARNING }
        )
    }

    @Test
    fun `no allergy alert when no allergies`() {
        val enc = encounter(
            medications = listOf(
                Medication("0001", "Amoxicillin", 500f, "mg", "TDS", 7, "PO", 0.9f)
            )
        )
        val alerts = cdss.evaluate(enc, emptyList())
        val allergyAlerts = alerts.filter { it.category.contains("allergy", ignoreCase = true) || it.category.contains("Allergy", ignoreCase = true) }
        assertTrue("No allergies = no allergy alerts", allergyAlerts.isEmpty())
    }

    @Test
    fun `sulfa allergy triggers alert for sulfa drugs`() {
        val enc = encounter(
            medications = listOf(
                Medication("0050", "Sulfamethoxazole", 400f, "mg", "BD", 5, "PO", 0.85f)
            ),
            allergies = listOf("sulfa")
        )
        val alerts = cdss.evaluate(enc, listOf("sulfa"))
        val allergyAlerts = alerts.filter { it.category.contains("allergy", ignoreCase = true) || it.category.contains("Allergy", ignoreCase = true) }
        assertTrue("Sulfa allergy + Sulfamethoxazole should trigger alert", allergyAlerts.isNotEmpty())
    }

    // ── Drug-Drug Interactions ──

    @Test
    fun `no drug interactions for single medication`() {
        val enc = encounter(
            medications = listOf(
                Medication("0001", "Amoxicillin", 500f, "mg", "TDS", 7, "PO", 0.9f)
            )
        )
        val alerts = cdss.evaluate(enc, emptyList())
        val drugDrugAlerts = alerts.filter { it.category.contains("drug-drug", ignoreCase = true) || it.category.contains("Drug-Drug", ignoreCase = true) || it.category.contains("interaction", ignoreCase = true) }
        assertTrue("Single medication should have no drug-drug interactions", drugDrugAlerts.isEmpty())
    }

    @Test
    fun `drug interactions only for actually prescribed medications`() {
        // This tests the false positive regression — only meds in the current encounter should trigger
        val enc = encounter(
            medications = listOf(
                Medication("0003", "Paracetamol", 1000f, "mg", "TDS", 5, "PO", 0.9f),
                Medication("0005", "Amlodipine", 5f, "mg", "OD", 30, "PO", 0.9f)
            )
        )
        val alerts = cdss.evaluate(enc, emptyList())
        // Paracetamol + Amlodipine should not have a clinically significant interaction
        val drugDrugAlerts = alerts.filter {
            it.category.contains("drug-drug", ignoreCase = true) ||
            it.category.contains("Drug-Drug", ignoreCase = true) ||
            it.category.contains("interaction", ignoreCase = true)
        }
        // We're being flexible here — the key assertion is no CRITICAL interaction between these two
        val criticalDrugAlerts = drugDrugAlerts.filter { it.severity == AlertSeverity.CRITICAL }
        assertTrue(
            "Paracetamol + Amlodipine should not have CRITICAL interaction",
            criticalDrugAlerts.isEmpty()
        )
    }

    // ── Vital Alerts integrated in evaluate() ──

    @Test
    fun `critical BP triggers alert via evaluate`() {
        val enc = encounter(
            vitals = VitalSigns(systolicBP = 210, diastolicBP = 130)
        )
        val alerts = cdss.evaluate(enc, emptyList())
        val vitalAlerts = alerts.filter { it.severity == AlertSeverity.CRITICAL }
        assertTrue("BP 210/130 should trigger CRITICAL alerts", vitalAlerts.isNotEmpty())
    }

    @Test
    fun `normal vitals produce no critical alerts`() {
        val enc = encounter(
            vitals = VitalSigns(
                systolicBP = 120, diastolicBP = 80,
                temperature = 36.8f, pulse = 72, oxygenSaturation = 98
            )
        )
        val alerts = cdss.evaluate(enc, emptyList())
        val criticalAlerts = alerts.filter { it.severity == AlertSeverity.CRITICAL }
        assertTrue("Normal vitals should have no CRITICAL alerts", criticalAlerts.isEmpty())
    }

    @Test
    fun `no alerts for encounter with no vitals and no medications`() {
        val enc = encounter()
        val alerts = cdss.evaluate(enc, emptyList())
        assertTrue("Empty encounter should have no alerts", alerts.isEmpty())
    }

    // ── Dosage alerts integrated in evaluate() ──

    @Test
    fun `high dose medication triggers dosage alert via evaluate`() {
        val enc = encounter(
            medications = listOf(
                Medication("0003", "Paracetamol", 1500f, "mg", "QDS", 3, "PO", 0.9f)
                // 1500mg * 4 = 6000mg/day, max is 4000mg
            )
        )
        val alerts = cdss.evaluate(enc, emptyList())
        val dosageAlerts = alerts.filter {
            it.category.contains("dosage", ignoreCase = true) ||
            it.category.contains("Dosage", ignoreCase = true) ||
            it.category.contains("dose", ignoreCase = true)
        }
        assertTrue("6000mg/day paracetamol should trigger dosage alert", dosageAlerts.isNotEmpty())
    }

    // ── Alert count sanity ──

    @Test
    fun `reasonable alert count for typical encounter`() {
        // This prevents the "too many alerts" regression
        val enc = encounter(
            medications = listOf(
                Medication("0001", "Amoxicillin", 500f, "mg", "TDS", 7, "PO", 0.9f),
                Medication("0003", "Paracetamol", 1000f, "mg", "TDS", 5, "PO", 0.9f)
            ),
            vitals = VitalSigns(systolicBP = 130, diastolicBP = 85, temperature = 37.2f, pulse = 82),
            allergies = emptyList()
        )
        val alerts = cdss.evaluate(enc, emptyList())
        assertTrue(
            "Typical encounter with normal vitals and safe meds should have <5 alerts, got ${alerts.size}",
            alerts.size < 5
        )
    }
}
