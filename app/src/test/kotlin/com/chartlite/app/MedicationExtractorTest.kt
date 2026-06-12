package com.chartlite.app

import com.chartlite.app.extraction.MedicationExtractor
import com.chartlite.app.model.Formulary
import com.chartlite.app.model.FormularyDrug
import org.junit.Assert.*
import org.junit.Before
import org.junit.Test

class MedicationExtractorTest {

    private lateinit var extractor: MedicationExtractor

    private val testFormulary = Formulary(
        version = "test",
        country = "ZA",
        drugs = listOf(
            FormularyDrug("0001", "Amoxicillin", listOf("amoxil", "amoxicillin", "amoxycillin", "amox"),
                listOf("250mg", "500mg"), "PO", "antibiotic", "S4"),
            FormularyDrug("0002", "Metformin", listOf("metformin", "glucophage", "metfin"),
                listOf("500mg", "850mg", "1000mg"), "PO", "antidiabetic", "S3"),
            FormularyDrug("0003", "Paracetamol", listOf("paracetamol", "panado", "acetaminophen", "tylenol"),
                listOf("500mg", "1000mg"), "PO", "analgesic", "S0"),
            FormularyDrug("0004", "Ibuprofen", listOf("ibuprofen", "brufen", "nurofen"),
                listOf("200mg", "400mg"), "PO", "nsaid", "S1"),
            FormularyDrug("0005", "Amlodipine", listOf("amlodipine", "norvasc"),
                listOf("5mg", "10mg"), "PO", "antihypertensive", "S3"),
            FormularyDrug("0006", "Salbutamol", listOf("salbutamol", "ventolin", "albuterol"),
                listOf("100mcg", "200mcg"), "INH", "bronchodilator", "S2"),
            FormularyDrug("0007", "Hydrochlorothiazide", listOf("hydrochlorothiazide", "hctz", "riazide"),
                listOf("12.5mg", "25mg"), "PO", "diuretic", "S3"),
        )
    )

    @Before
    fun setup() {
        extractor = MedicationExtractor(testFormulary)
    }

    // ── Drug Name Matching ──

    @Test
    fun `extracts drug by exact name`() {
        val meds = extractor.extract("prescribe amoxicillin 500mg twice daily for 7 days")
        assertEquals(1, meds.size)
        assertEquals("Amoxicillin", meds[0].name)
        assertEquals("0001", meds[0].formularyCode)
    }

    @Test
    fun `extracts drug by brand name`() {
        val meds = extractor.extract("give panado 1000mg as needed")
        assertEquals(1, meds.size)
        assertEquals("Paracetamol", meds[0].name)
    }

    @Test
    fun `extracts drug by alias`() {
        val meds = extractor.extract("start glucophage 500mg once daily")
        assertEquals(1, meds.size)
        assertEquals("Metformin", meds[0].name)
    }

    @Test
    fun `handles fuzzy spelling`() {
        val meds = extractor.extract("prescribe amoxicilin 500mg") // missing one l
        assertEquals(1, meds.size)
        assertEquals("Amoxicillin", meds[0].name)
    }

    // ── Dose Extraction ──

    @Test
    fun `extracts dose in mg`() {
        val meds = extractor.extract("amoxicillin 500mg twice daily")
        assertEquals(1, meds.size)
        assertEquals(500f, meds[0].dose!!, 0.1f)
        assertEquals("mg", meds[0].unit)
    }

    @Test
    fun `extracts dose in mcg`() {
        val meds = extractor.extract("salbutamol 200mcg inhaled twice daily")
        assertEquals(1, meds.size)
        assertEquals(200f, meds[0].dose!!, 0.1f)
        assertEquals("mcg", meds[0].unit)
    }

    // ── Frequency Extraction ──

    @Test
    fun `extracts once daily frequency`() {
        val meds = extractor.extract("amlodipine 5mg once daily")
        assertEquals(1, meds.size)
        assertEquals("OD", meds[0].frequency)
    }

    @Test
    fun `extracts twice daily frequency`() {
        val meds = extractor.extract("metformin 500mg twice daily")
        assertEquals(1, meds.size)
        assertEquals("BD", meds[0].frequency)
    }

    @Test
    fun `extracts three times daily`() {
        val meds = extractor.extract("amoxicillin 250mg three times a day")
        assertEquals(1, meds.size)
        assertEquals("TDS", meds[0].frequency)
    }

    @Test
    fun `extracts PRN frequency`() {
        val meds = extractor.extract("paracetamol 1000mg as needed")
        assertEquals(1, meds.size)
        assertEquals("PRN", meds[0].frequency)
    }

    @Test
    fun `extracts STAT frequency`() {
        val meds = extractor.extract("give amoxicillin 500mg stat")
        assertEquals(1, meds.size)
        assertEquals("STAT", meds[0].frequency)
    }

    // ── Route Extraction ──

    @Test
    fun `extracts oral route`() {
        val meds = extractor.extract("amoxicillin 500mg orally twice daily")
        assertEquals(1, meds.size)
        assertEquals("PO", meds[0].route)
    }

    @Test
    fun `extracts inhaled route`() {
        val meds = extractor.extract("salbutamol 100mcg inhaled as needed")
        assertEquals(1, meds.size)
        assertEquals("inhaled", meds[0].route)
    }

    @Test
    fun `uses default route when not specified`() {
        val meds = extractor.extract("start amoxicillin 500mg daily")
        assertEquals(1, meds.size)
        assertEquals("PO", meds[0].route) // default for amoxicillin
    }

    // ── Duration Extraction ──

    @Test
    fun `extracts duration in days`() {
        val meds = extractor.extract("amoxicillin 500mg three times daily for 7 days")
        assertEquals(1, meds.size)
        assertEquals(7, meds[0].duration)
    }

    @Test
    fun `extracts duration with slash notation`() {
        val meds = extractor.extract("amoxicillin 500mg tds 5/7")
        assertEquals(1, meds.size)
        assertEquals(5, meds[0].duration)
    }

    @Test
    fun `extracts duration in weeks`() {
        val meds = extractor.extract("metformin 500mg daily for 2 weeks")
        assertEquals(1, meds.size)
        assertEquals(14, meds[0].duration)
    }

    // ── Multiple Medications ──

    @Test
    fun `extracts multiple medications`() {
        val transcript = "prescribe amoxicillin 500mg three times daily for 7 days " +
                "and paracetamol 1000mg as needed and amlodipine 5mg once daily"
        val meds = extractor.extract(transcript)
        assertTrue("Expected at least 2 medications, got ${meds.size}", meds.size >= 2)
        val names = meds.map { it.name }.toSet()
        assertTrue("Should contain Amoxicillin", "Amoxicillin" in names)
        assertTrue("Should contain Paracetamol", "Paracetamol" in names)
    }

    // ── Confidence ──

    @Test
    fun `confidence is higher with dose and frequency`() {
        val fullMeds = extractor.extract("amoxicillin 500mg twice daily")
        val partialMeds = extractor.extract("amoxicillin something something")
        assertTrue("Full spec should have higher confidence",
            fullMeds[0].confidence > partialMeds[0].confidence)
    }

    @Test
    fun `confidence is between 0 and 1`() {
        val meds = extractor.extract("amoxicillin 500mg twice daily")
        for (med in meds) {
            assertTrue(med.confidence in 0f..1f)
        }
    }

    // ── Edge Cases ──

    @Test
    fun `returns empty for no medications`() {
        val meds = extractor.extract("patient presents with headache and fever")
        assertTrue(meds.isEmpty())
    }

    @Test
    fun `handles empty transcript`() {
        val meds = extractor.extract("")
        assertTrue(meds.isEmpty())
    }
}
