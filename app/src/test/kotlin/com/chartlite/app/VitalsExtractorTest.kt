package com.chartlite.app

import com.chartlite.app.extraction.VitalsExtractor
import org.junit.Assert.*
import org.junit.Before
import org.junit.Test

class VitalsExtractorTest {

    private lateinit var extractor: VitalsExtractor

    @Before
    fun setup() {
        extractor = VitalsExtractor()
    }

    // -- Blood Pressure --

    @Test
    fun `extracts BP with slash notation`() {
        val vitals = extractor.extract("blood pressure 130/85 mmHg")
        assertNotNull(vitals)
        assertEquals(130, vitals!!.systolicBP)
        assertEquals(85, vitals.diastolicBP)
    }

    @Test
    fun `extracts BP with over notation`() {
        val vitals = extractor.extract("bp is 140 over 90")
        assertNotNull(vitals)
        assertEquals(140, vitals!!.systolicBP)
        assertEquals(90, vitals.diastolicBP)
    }

    @Test
    fun `extracts BP shorthand`() {
        val vitals = extractor.extract("bp 120/80")
        assertNotNull(vitals)
        assertEquals(120, vitals!!.systolicBP)
        assertEquals(80, vitals.diastolicBP)
    }

    @Test
    fun `rejects out of range BP`() {
        val vitals = extractor.extract("bp 300/200")
        // Raw BP values are parsed (non-null), so VitalSigns object is returned.
        // But out-of-range values are filtered by takeIf, so the fields are null.
        assertNotNull(vitals)
        assertNull("Systolic 300 > 260 should be rejected", vitals!!.systolicBP)
        assertNull("Diastolic 200 > 160 should be rejected", vitals.diastolicBP)
    }

    // -- Temperature --

    @Test
    fun `extracts temperature with degrees`() {
        val vitals = extractor.extract("temperature is 38.5 degrees celsius")
        assertNotNull(vitals)
        assertEquals(38.5f, vitals!!.temperature!!, 0.1f)
    }

    @Test
    fun `extracts temp shorthand`() {
        val vitals = extractor.extract("temp 37.2 c")
        assertNotNull(vitals)
        assertEquals(37.2f, vitals!!.temperature!!, 0.1f)
    }

    @Test
    fun `rejects out of range temperature`() {
        val vitals = extractor.extract("temp 50 degrees")
        // 50 > 42 range, but VitalSigns object still created (raw value was parsed)
        if (vitals != null) {
            assertNull("Temperature 50 > 42 should be rejected", vitals.temperature)
        }
    }

    // -- Pulse --

    @Test
    fun `extracts pulse bpm`() {
        val vitals = extractor.extract("pulse 88 bpm")
        assertNotNull(vitals)
        assertEquals(88, vitals!!.pulse)
    }

    @Test
    fun `extracts heart rate`() {
        val vitals = extractor.extract("heart rate is 72 beats per minute")
        assertNotNull(vitals)
        assertEquals(72, vitals!!.pulse)
    }

    // -- Weight --

    @Test
    fun `extracts weight in kg`() {
        val vitals = extractor.extract("weight is 75.5 kg")
        assertNotNull(vitals)
        assertEquals(75.5f, vitals!!.weight!!, 0.1f)
    }

    @Test
    fun `extracts weight shorthand`() {
        val vitals = extractor.extract("weighs 68 kilos")
        assertNotNull(vitals)
        assertEquals(68f, vitals!!.weight!!, 0.1f)
    }

    // -- Height --

    @Test
    fun `extracts height in cm`() {
        val vitals = extractor.extract("height is 172 cm")
        assertNotNull(vitals)
        assertEquals(172f, vitals!!.height!!, 0.1f)
    }

    // -- Respiratory Rate --

    @Test
    fun `extracts respiratory rate`() {
        val vitals = extractor.extract("resp rate 18")
        assertNotNull(vitals)
        assertEquals(18, vitals!!.respiratoryRate)
    }

    @Test
    fun `extracts rr shorthand`() {
        val vitals = extractor.extract("rr 22")
        assertNotNull(vitals)
        assertEquals(22, vitals!!.respiratoryRate)
    }

    // -- SpO2 --

    @Test
    fun `extracts spo2 percentage`() {
        val vitals = extractor.extract("spo2 97%")
        assertNotNull(vitals)
        assertEquals(97, vitals!!.oxygenSaturation)
    }

    @Test
    fun `extracts oxygen saturation`() {
        val vitals = extractor.extract("oxygen saturation is 95 percent")
        assertNotNull(vitals)
        assertEquals(95, vitals!!.oxygenSaturation)
    }

    @Test
    fun `extracts sats on room air`() {
        val vitals = extractor.extract("92% on room air")
        assertNotNull(vitals)
        assertEquals(92, vitals!!.oxygenSaturation)
    }

    // -- Combined --

    @Test
    fun `extracts multiple vitals from transcript`() {
        val transcript = "Vitals: bp 130/85, temp 38.2 degrees, pulse 92 bpm, weight 70 kg, spo2 96%"
        val vitals = extractor.extract(transcript)
        assertNotNull(vitals)
        assertEquals(130, vitals!!.systolicBP)
        assertEquals(85, vitals.diastolicBP)
        assertEquals(38.2f, vitals.temperature!!, 0.1f)
        assertEquals(92, vitals.pulse)
        assertEquals(70f, vitals.weight!!, 0.1f)
        assertEquals(96, vitals.oxygenSaturation)
    }

    @Test
    fun `returns null when no vitals present`() {
        val vitals = extractor.extract("patient complains of headache and nausea")
        assertNull(vitals)
    }

    @Test
    fun `returns null for empty input`() {
        val vitals = extractor.extract("")
        assertNull(vitals)
    }

    @Test
    fun `bare slash notation without BP keyword or mmHg does not match`() {
        // Prevents false positives from dates, fractions, etc.
        val vitals = extractor.extract("the ratio is 120/80 in the report")
        // Should not match bare XX/YY without "bp"/"blood pressure" prefix or "mmhg" suffix
        if (vitals != null) {
            assertNull("Bare 120/80 without context should not match as BP", vitals.systolicBP)
        }
    }

    @Test
    fun `slash notation with mmHg suffix matches without keyword`() {
        val vitals = extractor.extract("reading was 120/80 mmhg")
        assertNotNull(vitals)
        assertEquals(120, vitals!!.systolicBP)
        assertEquals(80, vitals.diastolicBP)
    }

    @Test
    fun `height-only transcript returns non-null`() {
        val vitals = extractor.extract("height is 165 cm")
        assertNotNull("Height-only should return non-null VitalSigns", vitals)
        assertEquals(165f, vitals!!.height!!, 0.1f)
    }

    @Test
    fun `respiratory rate only transcript returns non-null`() {
        val vitals = extractor.extract("resp rate 20")
        assertNotNull("RR-only should return non-null VitalSigns", vitals)
        assertEquals(20, vitals!!.respiratoryRate)
    }
}
