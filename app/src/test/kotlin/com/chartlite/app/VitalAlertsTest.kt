package com.chartlite.app

import com.chartlite.app.cdss.VitalAlerts
import com.chartlite.app.model.AlertSeverity
import com.chartlite.app.model.VitalSigns
import org.junit.Assert.*
import org.junit.Before
import org.junit.Test

class VitalAlertsTest {

    private lateinit var vitalAlerts: VitalAlerts

    @Before
    fun setup() {
        vitalAlerts = VitalAlerts()
    }

    // -- Normal vitals --

    @Test
    fun `no alerts for normal vitals`() {
        val vitals = VitalSigns(
            systolicBP = 120, diastolicBP = 80,
            temperature = 37.0f, pulse = 72,
            oxygenSaturation = 98, respiratoryRate = 16
        )
        val alerts = vitalAlerts.check(vitals)
        assertTrue("Normal vitals should produce no alerts", alerts.isEmpty())
    }

    @Test
    fun `no alerts for null vitals`() {
        val vitals = VitalSigns()
        val alerts = vitalAlerts.check(vitals)
        assertTrue("All-null vitals should produce no alerts", alerts.isEmpty())
    }

    // -- Systolic BP --

    @Test
    fun `critical alert for systolic BP above 200`() {
        val vitals = VitalSigns(systolicBP = 210)
        val alerts = vitalAlerts.check(vitals)
        assertTrue(alerts.isNotEmpty())
        assertEquals(AlertSeverity.CRITICAL, alerts[0].severity)
        assertTrue(alerts[0].message.contains("210"))
    }

    @Test
    fun `critical alert for systolic BP below 70`() {
        val vitals = VitalSigns(systolicBP = 60)
        val alerts = vitalAlerts.check(vitals)
        assertTrue(alerts.isNotEmpty())
        assertEquals(AlertSeverity.CRITICAL, alerts[0].severity)
    }

    @Test
    fun `warning alert for systolic BP 161-200`() {
        val vitals = VitalSigns(systolicBP = 170)
        val alerts = vitalAlerts.check(vitals)
        assertTrue(alerts.isNotEmpty())
        assertEquals(AlertSeverity.WARNING, alerts[0].severity)
    }

    @Test
    fun `warning alert for low systolic BP 70-89`() {
        val vitals = VitalSigns(systolicBP = 80)
        val alerts = vitalAlerts.check(vitals)
        assertTrue(alerts.isNotEmpty())
        assertEquals(AlertSeverity.WARNING, alerts[0].severity)
    }

    // -- Diastolic BP --

    @Test
    fun `critical alert for diastolic BP above 120`() {
        val vitals = VitalSigns(diastolicBP = 130)
        val alerts = vitalAlerts.check(vitals)
        assertTrue(alerts.isNotEmpty())
        assertEquals(AlertSeverity.CRITICAL, alerts[0].severity)
    }

    @Test
    fun `warning alert for diastolic BP 101-120`() {
        val vitals = VitalSigns(diastolicBP = 110)
        val alerts = vitalAlerts.check(vitals)
        assertTrue(alerts.isNotEmpty())
        assertEquals(AlertSeverity.WARNING, alerts[0].severity)
    }

    // -- Temperature --

    @Test
    fun `critical alert for high fever above 40`() {
        val vitals = VitalSigns(temperature = 41.0f)
        val alerts = vitalAlerts.check(vitals)
        assertTrue(alerts.isNotEmpty())
        assertEquals(AlertSeverity.CRITICAL, alerts[0].severity)
    }

    @Test
    fun `critical alert for hypothermia below 35`() {
        val vitals = VitalSigns(temperature = 34.0f)
        val alerts = vitalAlerts.check(vitals)
        assertTrue(alerts.isNotEmpty())
        assertEquals(AlertSeverity.CRITICAL, alerts[0].severity)
    }

    @Test
    fun `warning alert for fever 38_5 to 40`() {
        val vitals = VitalSigns(temperature = 39.5f)
        val alerts = vitalAlerts.check(vitals)
        assertTrue(alerts.isNotEmpty())
        assertEquals(AlertSeverity.WARNING, alerts[0].severity)
    }

    // -- Pulse --

    @Test
    fun `critical alert for tachycardia above 150`() {
        val vitals = VitalSigns(pulse = 160)
        val alerts = vitalAlerts.check(vitals)
        assertTrue(alerts.isNotEmpty())
        assertEquals(AlertSeverity.CRITICAL, alerts[0].severity)
    }

    @Test
    fun `critical alert for severe bradycardia below 40`() {
        val vitals = VitalSigns(pulse = 35)
        val alerts = vitalAlerts.check(vitals)
        assertTrue(alerts.isNotEmpty())
        assertEquals(AlertSeverity.CRITICAL, alerts[0].severity)
    }

    @Test
    fun `warning alert for mild tachycardia 121-150`() {
        val vitals = VitalSigns(pulse = 130)
        val alerts = vitalAlerts.check(vitals)
        assertTrue(alerts.isNotEmpty())
        assertEquals(AlertSeverity.WARNING, alerts[0].severity)
    }

    // -- SpO2 --

    @Test
    fun `critical alert for spo2 below 90`() {
        val vitals = VitalSigns(oxygenSaturation = 85)
        val alerts = vitalAlerts.check(vitals)
        assertTrue(alerts.isNotEmpty())
        assertEquals(AlertSeverity.CRITICAL, alerts[0].severity)
        assertTrue(alerts[0].message.contains("85"))
    }

    @Test
    fun `warning alert for spo2 90-93`() {
        val vitals = VitalSigns(oxygenSaturation = 92)
        val alerts = vitalAlerts.check(vitals)
        assertTrue(alerts.isNotEmpty())
        assertEquals(AlertSeverity.WARNING, alerts[0].severity)
    }

    @Test
    fun `no alert for normal spo2`() {
        val vitals = VitalSigns(oxygenSaturation = 98)
        val alerts = vitalAlerts.check(vitals)
        assertTrue(alerts.isEmpty())
    }

    // -- Respiratory Rate --

    @Test
    fun `critical alert for high respiratory rate above 30`() {
        val vitals = VitalSigns(respiratoryRate = 35)
        val alerts = vitalAlerts.check(vitals)
        assertTrue(alerts.isNotEmpty())
        assertEquals(AlertSeverity.CRITICAL, alerts[0].severity)
    }

    @Test
    fun `critical alert for very low respiratory rate below 8`() {
        val vitals = VitalSigns(respiratoryRate = 6)
        val alerts = vitalAlerts.check(vitals)
        assertTrue(alerts.isNotEmpty())
        assertEquals(AlertSeverity.CRITICAL, alerts[0].severity)
    }

    @Test
    fun `warning alert for mild tachypnea 21-30`() {
        val vitals = VitalSigns(respiratoryRate = 25)
        val alerts = vitalAlerts.check(vitals)
        assertTrue(alerts.isNotEmpty())
        assertEquals(AlertSeverity.WARNING, alerts[0].severity)
    }

    // -- Combined --

    @Test
    fun `multiple alerts for multiple abnormal vitals`() {
        val vitals = VitalSigns(
            systolicBP = 210, // critical
            temperature = 39.0f, // warning
            oxygenSaturation = 88 // critical
        )
        val alerts = vitalAlerts.check(vitals)
        assertEquals("Should produce exactly 3 alerts (BP critical, temp warning, SpO2 critical)", 3, alerts.size)
    }

    @Test
    fun `alerts have correct category`() {
        val vitals = VitalSigns(systolicBP = 210)
        val alerts = vitalAlerts.check(vitals)
        assertTrue(alerts.all { it.category == "Vitals" })
    }

    @Test
    fun `alerts have correct related field`() {
        val vitals = VitalSigns(pulse = 160)
        val alerts = vitalAlerts.check(vitals)
        assertTrue(alerts.all { it.relatedField == "vitals" })
    }
}
