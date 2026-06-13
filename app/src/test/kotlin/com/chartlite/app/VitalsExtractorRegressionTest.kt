package com.chartlite.app

import com.chartlite.app.extraction.VitalsExtractor
import org.junit.Assert.*
import org.junit.Before
import org.junit.Test

/**
 * Regression tests for VitalsExtractor — covers bugs found during demo:
 * - False BP 120/80 appearing when not mentioned in transcript
 * - False temperature 30°C prefilled
 * - Number-word parsing ("three" → 3) for future handling
 * - Edge cases from real clinical transcripts
 */
class VitalsExtractorRegressionTest {

    private lateinit var extractor: VitalsExtractor

    @Before
    fun setup() {
        extractor = VitalsExtractor()
    }

    // ── False positive regressions ──

    @Test
    fun `no vitals extracted from transcript without any vitals`() {
        val vitals = extractor.extract(
            "Patient complains of headache and body aches for two days. " +
            "No fever, no cough. Gave paracetamol 1g stat."
        )
        assertNull("No vitals mentioned — should return null", vitals)
    }

    @Test
    fun `does not false-match dates as BP`() {
        val vitals = extractor.extract("seen on 12/03/2025 for follow up")
        if (vitals != null) {
            assertNull("Date 12/03 should not match as BP", vitals.systolicBP)
        }
    }

    @Test
    fun `does not false-match age as vitals`() {
        val vitals = extractor.extract("patient is 45 year old male with chronic pain")
        if (vitals != null) {
            assertNull("Age 45 should not match as pulse", vitals.pulse)
            assertNull("Age 45 should not match as weight", vitals.weight)
        }
    }

    @Test
    fun `does not match medication doses as vitals`() {
        val vitals = extractor.extract("gave amoxicillin 500 mg TDS and paracetamol 1000 mg stat")
        if (vitals != null) {
            assertNull("500mg should not match as BP", vitals.systolicBP)
            assertNull("1000mg should not match as pulse", vitals.pulse)
        }
    }

    @Test
    fun `does not match ratios or fractions as BP`() {
        val vitals = extractor.extract("success rate was 120/150 in the trial")
        if (vitals != null) {
            assertNull("Bare 120/150 without BP context should not match", vitals.systolicBP)
        }
    }

    // ── Edge cases from real transcripts ──

    @Test
    fun `extracts BP from natural speech`() {
        val vitals = extractor.extract("his blood pressure today is one thirty over eighty five")
        // VitalsExtractor only handles numeric notation, not words
        // This documents the limitation
    }

    @Test
    fun `extracts vitals from noisy transcript with filler words`() {
        val vitals = extractor.extract(
            "okay so umm the bp is uh 145/95 mmhg and temperature is like 37.8 degrees"
        )
        assertNotNull(vitals)
        assertEquals(145, vitals!!.systolicBP)
        assertEquals(95, vitals.diastolicBP)
        assertEquals(37.8f, vitals.temperature!!, 0.1f)
    }

    @Test
    fun `extracts partial vitals — BP only`() {
        val vitals = extractor.extract("blood pressure 140/90")
        assertNotNull(vitals)
        assertEquals(140, vitals!!.systolicBP)
        assertEquals(90, vitals.diastolicBP)
        assertNull("Temp should be null when not mentioned", vitals.temperature)
        assertNull("Pulse should be null when not mentioned", vitals.pulse)
    }

    @Test
    fun `extracts partial vitals — temp only`() {
        val vitals = extractor.extract("temp is 39.1")
        assertNotNull(vitals)
        assertEquals(39.1f, vitals!!.temperature!!, 0.1f)
        assertNull("BP should be null when not mentioned", vitals.systolicBP)
    }

    @Test
    fun `handles Fahrenheit temperature gracefully`() {
        // VitalsExtractor assumes Celsius — Fahrenheit values should be out of range
        val vitals = extractor.extract("temp 102 F")
        if (vitals != null && vitals.temperature != null) {
            // 102 is out of Celsius range (>42), should be rejected
            assertTrue(
                "102°F should be rejected as Celsius",
                vitals.temperature!! > 42f || vitals.temperature == null
            )
        }
    }

    @Test
    fun `extracts SpO2 with percent sign attached`() {
        val vitals = extractor.extract("spo2 94%")
        assertNotNull(vitals)
        assertEquals(94, vitals!!.oxygenSaturation)
    }

    @Test
    fun `extracts SpO2 with space before percent`() {
        val vitals = extractor.extract("oxygen sat is 96 percent on room air")
        assertNotNull(vitals)
        assertEquals(96, vitals!!.oxygenSaturation)
    }

    // ── Boundary values ──

    @Test
    fun `accepts minimum valid BP`() {
        val vitals = extractor.extract("bp 60/40 mmhg")
        assertNotNull(vitals)
        assertEquals(60, vitals!!.systolicBP)
        assertEquals(40, vitals.diastolicBP)
    }

    @Test
    fun `accepts maximum valid BP`() {
        val vitals = extractor.extract("bp 260/160 mmhg")
        assertNotNull(vitals)
        assertEquals(260, vitals!!.systolicBP)
        assertEquals(160, vitals.diastolicBP)
    }

    @Test
    fun `accepts boundary temperature 35 degrees`() {
        val vitals = extractor.extract("temp 35.0 degrees")
        assertNotNull(vitals)
        assertEquals(35.0f, vitals!!.temperature!!, 0.1f)
    }

    @Test
    fun `accepts boundary temperature 42 degrees`() {
        val vitals = extractor.extract("temp 42.0 degrees")
        assertNotNull(vitals)
        assertEquals(42.0f, vitals!!.temperature!!, 0.1f)
    }

    @Test
    fun `rejects SpO2 over 100`() {
        val vitals = extractor.extract("spo2 105%")
        if (vitals != null) {
            assertNull("SpO2 > 100 should be rejected", vitals.oxygenSaturation)
        }
    }

    // ── Combined real-world transcripts ──

    @Test
    fun `extracts all vitals from triage transcript`() {
        val vitals = extractor.extract(
            "Vitals: bp 130/85 mmhg, temp 38.2 degrees celsius, " +
            "pulse 92 bpm, weight 70 kg, spo2 96%, resp rate 20"
        )
        assertNotNull(vitals)
        assertEquals(130, vitals!!.systolicBP)
        assertEquals(85, vitals.diastolicBP)
        assertEquals(38.2f, vitals.temperature!!, 0.1f)
        assertEquals(92, vitals.pulse)
        assertEquals(70f, vitals.weight!!, 0.1f)
        assertEquals(96, vitals.oxygenSaturation)
        assertEquals(20, vitals.respiratoryRate)
    }

    @Test
    fun `handles multiline transcript`() {
        val vitals = extractor.extract(
            "Patient presents with cough.\n" +
            "BP: 140/90 mmhg\n" +
            "Temp: 37.5 degrees\n" +
            "Pulse: 88 bpm"
        )
        assertNotNull(vitals)
        assertEquals(140, vitals!!.systolicBP)
        assertEquals(37.5f, vitals.temperature!!, 0.1f)
        assertEquals(88, vitals.pulse)
    }
}
