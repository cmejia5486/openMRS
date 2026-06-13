package com.chartlite.app

import com.chartlite.app.extraction.DiagnosisExtractor
import com.chartlite.app.model.ICD10Entry
import com.chartlite.app.model.ICD10Index
import org.junit.Assert.*
import org.junit.Before
import org.junit.Test

class DiagnosisExtractorTest {

    private lateinit var extractor: DiagnosisExtractor

    private val testIcd10 = ICD10Index(
        version = "test",
        codes = listOf(
            ICD10Entry("J06.9", "Acute upper respiratory infection, unspecified",
                listOf("upper respiratory", "URTI", "cold", "flu", "cough fever", "sore throat"),
                mapOf("zu" to listOf("umkhuhlane", "isifuba"))),
            ICD10Entry("J18.9", "Pneumonia, unspecified organism",
                listOf("pneumonia", "chest infection", "lower respiratory", "LRTI"),
                mapOf("zu" to listOf("inyumoniya"))),
            ICD10Entry("E11", "Type 2 diabetes mellitus",
                listOf("type 2 diabetes", "diabetes mellitus", "sugar diabetes", "T2DM", "diabetes type 2"),
                mapOf("zu" to listOf("ushukela"))),
            ICD10Entry("I10", "Essential hypertension",
                listOf("hypertension", "high blood pressure", "HTN", "elevated blood pressure"),
                mapOf()),
            ICD10Entry("J45", "Asthma",
                listOf("asthma", "wheeze", "wheezing", "bronchospasm", "reactive airway"),
                mapOf("zu" to listOf("isifuba somoya"))),
            ICD10Entry("N39.0", "Urinary tract infection",
                listOf("urinary tract infection", "UTI", "cystitis", "bladder infection"),
                mapOf()),
            ICD10Entry("R11", "Nausea and vomiting",
                listOf("vomiting", "vomit", "nausea"),
                mapOf()),
        )
    )

    @Before
    fun setup() {
        extractor = DiagnosisExtractor(testIcd10)
    }

    @Test
    fun `extracts diagnosis by keyword`() {
        val dx = extractor.extract("patient presents with pneumonia")
        assertTrue(dx.isNotEmpty())
        assertEquals("J18.9", dx[0].icd10Code)
    }

    @Test
    fun `extracts diagnosis by abbreviation`() {
        val dx = extractor.extract("diagnosis is URTI")
        assertTrue(dx.isNotEmpty())
        assertTrue(dx.any { it.icd10Code == "J06.9" })
    }

    @Test
    fun `extracts diabetes from common terms`() {
        val dx = extractor.extract("patient has sugar diabetes")
        assertTrue(dx.isNotEmpty())
        assertTrue(dx.any { it.icd10Code == "E11" })
    }

    @Test
    fun `extracts hypertension from descriptive terms`() {
        val dx = extractor.extract("assessment is high blood pressure")
        assertTrue(dx.isNotEmpty())
        assertTrue(dx.any { it.icd10Code == "I10" })
    }

    @Test
    fun `extracts diagnosis from local language terms`() {
        val dx = extractor.extract("patient has inyumoniya")
        assertTrue(dx.isNotEmpty())
        assertTrue(dx.any { it.icd10Code == "J18.9" })
    }

    @Test
    fun `extracts Zulu term for URTI`() {
        val dx = extractor.extract("umkhuhlane severe case")
        assertTrue(dx.isNotEmpty())
        assertTrue(dx.any { it.icd10Code == "J06.9" })
    }

    @Test
    fun `first diagnosis is marked as primary`() {
        val dx = extractor.extract("diagnosis pneumonia")
        assertTrue(dx.isNotEmpty())
        assertTrue(dx[0].isPrimary)
        if (dx.size > 1) {
            assertFalse(dx[1].isPrimary)
        }
    }

    @Test
    fun `returns max 3 diagnoses`() {
        val dx = extractor.extract(
            "patient has pneumonia and hypertension and diabetes and asthma and UTI"
        )
        assertTrue(dx.size <= 3)
    }

    @Test
    fun `higher score near diagnosis marker`() {
        val dxWithMarker = extractor.extract("diagnosis is pneumonia")
        val dxWithoutMarker = extractor.extract("pneumonia mentioned something")
        // Both should find pneumonia
        assertTrue(dxWithMarker.isNotEmpty())
        assertTrue(dxWithoutMarker.isNotEmpty())
        // With-marker should have higher or equal confidence due to marker bonus
        val withMarkerConf = dxWithMarker.first { it.icd10Code == "J18.9" }.confidence
        val withoutMarkerConf = dxWithoutMarker.first { it.icd10Code == "J18.9" }.confidence
        assertTrue(
            "Diagnosis near marker ($withMarkerConf) should have >= confidence than without ($withoutMarkerConf)",
            withMarkerConf >= withoutMarkerConf
        )
    }

    @Test
    fun `confidence is between 0 and 1`() {
        val dx = extractor.extract("patient has pneumonia and hypertension")
        for (d in dx) {
            assertTrue("Confidence should be 0-1: ${d.confidence}",
                d.confidence in 0f..1f)
        }
    }

    @Test
    fun `returns empty for no diagnoses`() {
        val dx = extractor.extract("patient wants a follow up appointment next week")
        assertTrue(dx.isEmpty())
    }

    @Test
    fun `handles empty transcript`() {
        val dx = extractor.extract("")
        assertTrue(dx.isEmpty())
    }

    @Test
    fun `no false positive from substring matches`() {
        // "start" should NOT match "ART" (HIV keyword)
        // "cold" as a standalone word should still match J06.9
        val dx = extractor.extract("okay yes so now let's start the counseling how are you")
        // Should NOT produce any diagnosis — no clinical terms present
        assertTrue("Greeting transcript should not produce diagnoses, got: $dx", dx.isEmpty())
    }

    @Test
    fun `short abbreviation requires exact uppercase token`() {
        // "UTI" as exact token should match
        val dxMatch = extractor.extract("patient has UTI symptoms")
        assertTrue(dxMatch.any { it.icd10Code == "N39.0" })

        // "utility" should NOT match UTI
        val dxNoMatch = extractor.extract("this utility is great")
        assertFalse(dxNoMatch.any { it.icd10Code == "N39.0" })
    }

    @Test
    fun `local language term has high confidence`() {
        val dx = extractor.extract("patient has inyumoniya")
        assertTrue(dx.isNotEmpty())
        val pneumonia = dx.first { it.icd10Code == "J18.9" }
        assertTrue("Local term should have high confidence >= 0.8: ${pneumonia.confidence}",
            pneumonia.confidence >= 0.8f)
    }

    @Test
    fun `negated symptom keyword does not become diagnosis`() {
        val dx = extractor.extract("child has fever and cough for three days. no vomiting.")
        assertFalse(dx.any { it.icd10Code == "R11" })
    }
}
