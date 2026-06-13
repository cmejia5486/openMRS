package com.chartlite.app

import com.chartlite.app.extraction.LlmResponseParser
import com.chartlite.app.model.Formulary
import com.chartlite.app.model.FormularyDrug
import com.chartlite.app.model.ICD10Entry
import com.chartlite.app.model.ICD10Index
import org.junit.Assert.assertEquals
import org.junit.Assert.assertFalse
import org.junit.Assert.assertNotNull
import org.junit.Assert.assertNull
import org.junit.Assert.assertTrue
import org.junit.Before
import org.junit.Test

class LlmResponseParserTest {

    private lateinit var parser: LlmResponseParser

    @Before
    fun setup() {
        parser = LlmResponseParser(
            ICD10Index(
                version = "test",
                codes = listOf(
                    ICD10Entry("J06.9", "Acute upper respiratory infection", listOf("URTI", "upper respiratory infection")),
                    ICD10Entry("J18.9", "Pneumonia", listOf("pneumonia")),
                    ICD10Entry("I10", "Essential hypertension", listOf("hypertension"))
                )
            ),
            Formulary(
                version = "test",
                country = "za",
                drugs = listOf(
                    FormularyDrug("AMX001", "Amoxicillin", listOf("amoxil"), listOf("250mg", "500mg"), "oral", "antibiotic", "S4"),
                    FormularyDrug("PCM001", "Paracetamol", listOf("panado"), listOf("500mg"), "oral", "analgesic", "S0")
                )
            )
        )
    }

    @Test
    fun `parses benchmark json response`() {
        val transcript = """
            The child has had fever and cough for three days.
            Assessment acute upper respiratory infection.
            Let us start amoxicillin 500 mg three times daily for five days and paracetamol as needed.
            Please come back in three days if not improving.
        """.trimIndent()
        val json = """
        {
          "demographics": {"age": "3", "sex": null, "name": null},
          "chief_complaint": "fever and cough for three days",
          "vitals": [
            {"name": "temperature", "value": "38.5", "unit": "C"},
            {"name": "pulse", "value": "88", "unit": "bpm"}
          ],
          "exam_findings": ["fever", "cough"],
          "investigations": [],
          "diagnoses": ["Acute upper respiratory infection"],
          "medications": [
            {"name": "Amoxicillin", "dose": "500 mg three times daily for five days", "context": "new"},
            {"name": "Paracetamol", "dose": "as needed", "context": "new"}
          ],
          "allergies": ["NKDA"],
          "social_history": [],
          "plan": ["come back in three days if not improving"]
        }
        """.trimIndent()

        val result = parser.parse(json, transcript, "P001", "DR001", "FAC001")

        assertNotNull(result)
        assertEquals(1, result!!.suggestedDiagnoses.size)
        assertEquals("J06.9", result.suggestedDiagnoses.first().icd10Code)
        assertEquals(2, result.medications.size)
        assertTrue(result.medications.any { it.formularyCode == "AMX001" })
        assertTrue(result.medications.any { it.formularyCode == "PCM001" })
        assertNotNull(result.vitals)
        assertEquals(38.5f, result.vitals!!.temperature!!, 0.01f)
        assertEquals(88, result.vitals!!.pulse)
        assertNotNull(result.followUp)
        assertEquals(3, result.followUp!!.days)
        assertTrue(result.freeTextNote.contains("fever and cough", ignoreCase = true))
    }

    @Test
    fun `derives blood pressure from benchmark vitals array`() {
        val result = parser.parse(
            """
            {
              "demographics": {"age": null, "sex": null, "name": null},
              "chief_complaint": "headache",
              "vitals": [{"name": "blood pressure", "value": "120/80", "unit": "mmHg"}],
              "exam_findings": [],
              "investigations": [],
              "diagnoses": [],
              "medications": [],
              "allergies": [],
              "social_history": [],
              "plan": []
            }
            """.trimIndent(),
            "Blood pressure 120/80.",
            "P001",
            "DR001",
            "FAC001"
        )

        assertNotNull(result)
        assertEquals(120, result!!.vitals!!.systolicBP)
        assertEquals(80, result.vitals!!.diastolicBP)
    }

    @Test
    fun `drops unresolved diagnoses and medications`() {
        val result = parser.parse(
            """
            {
              "demographics": {"age": null, "sex": null, "name": null},
              "chief_complaint": "cough",
              "vitals": [],
              "exam_findings": [],
              "investigations": [],
              "diagnoses": ["Made up disease"],
              "medications": [{"name": "Invented syrup", "dose": "5 ml", "context": "new"}],
              "allergies": [],
              "social_history": [],
              "plan": []
            }
            """.trimIndent(),
            "cough",
            "P001",
            "DR001",
            "FAC001"
        )

        assertNotNull(result)
        assertTrue(result!!.suggestedDiagnoses.isEmpty())
        assertTrue(result.medications.isEmpty())
        assertEquals("cough", result.freeTextNote)
    }

    @Test
    fun `ignores placeholder strings and unknown vitals in valid json`() {
        val result = parser.parse(
            """
            {
              "demographics": {"age": "unknown", "sex": "M/F", "name": "unknown"},
              "chief_complaint": "brief summary",
              "vitals": [
                {"name": "temperature", "value": "unknown", "unit": "C"},
                {"name": "respiratory rate", "value": "unknown", "unit": "breaths/min"}
              ],
              "exam_findings": ["finding 1", "fever", "fever"],
              "investigations": [
                {"test": "test", "result": "result"},
                {"test": "Chest X-ray", "result": "normal"}
              ],
              "diagnoses": ["diagnosis 1", "Pneumonia"],
              "medications": [
                {"name": "Amoxicillin", "dose": "500 mg", "context": "new"},
                {"name": "unknown", "dose": "unknown", "context": "current"}
              ],
              "allergies": ["allergy or NKDA", "NKDA", "NKDA"],
              "social_history": ["factor 1", "non-smoker", "non-smoker"],
              "plan": ["action 1", "review in three days", "review in three days"]
            }
            """.trimIndent(),
            "The child has fever and cough for three days. Start amoxicillin 500 mg. Review in three days.",
            "P001",
            "DR001",
            "FAC001"
        )

        assertNotNull(result)
        assertNull(result!!.vitals)
        assertEquals(listOf("fever"), result.examFindings)
        assertTrue(result.investigations.isEmpty())
        assertTrue(result.suggestedDiagnoses.isEmpty())
        assertEquals(1, result.medications.size)
        assertEquals("AMX001", result.medications.first().formularyCode)
        assertTrue(result.allergies.isEmpty())
        assertTrue(result.socialHistory.isEmpty())
        assertEquals(listOf("review in three days"), result.plan)
        assertNotNull(result.followUp)
        assertEquals(3, result.followUp!!.days)
        assertEquals("", result.freeTextNote)
    }

    @Test
    fun `drops resolved but ungrounded diagnoses and medications`() {
        val result = parser.parse(
            """
            {
              "demographics": {"age": null, "sex": null, "name": null},
              "chief_complaint": "fever and cough for three days",
              "vitals": [],
              "exam_findings": ["fever", "crackles"],
              "investigations": [],
              "diagnoses": ["diagnosis 1", "Pneumonia", "Essential hypertension"],
              "medications": [
                {"name": "Amoxicillin", "dose": "500 mg three times daily for five days", "context": "new"},
                {"name": "Paracetamol", "dose": "500 mg", "context": "new"}
              ],
              "allergies": ["NKDA"],
              "social_history": ["smoker"],
              "plan": ["review in three days", "start antihypertensive therapy"]
            }
            """.trimIndent(),
            "The child has had fever and cough for three days. Start amoxicillin 500 mg three times daily for five days. Please come back in three days if not improving.",
            "P001",
            "DR001",
            "FAC001"
        )

        assertNotNull(result)
        assertTrue(result!!.suggestedDiagnoses.isEmpty())
        assertEquals(1, result.medications.size)
        assertEquals("AMX001", result.medications.first().formularyCode)
        assertEquals(listOf("fever"), result.examFindings)
        assertEquals(listOf("review in three days"), result.plan)
        assertTrue(result.socialHistory.isEmpty())
        assertTrue(result.allergies.isEmpty())
        assertNotNull(result.followUp)
        assertEquals(3, result.followUp!!.days)
    }

    @Test
    fun `returns null for plain text with no json`() {
        val result = parser.parse("plain natural language answer", "transcript", "P001", "DR001", "FAC001")
        assertNull(result)
    }

    @Test
    fun `parseDetailed reports missing json for plain text`() {
        val report = parser.parseDetailed(
            responseText = "plain natural language answer",
            transcript = "child has fever",
            patientId = "P001",
            providerId = "DR001",
            facilityId = "FAC001"
        )

        assertNull(report.encounter)
        assertNull(report.format)
        assertEquals("no JSON object found in model output", report.failureReason)
    }

    @Test
    fun `parseDetailed reports json eof for truncated array item`() {
        val report = parser.parseDetailed(
            responseText = """{"demographics":{"age":"3","sex":null,"name":null},"chief_complaint":"fever","vitals":[],"exam_findings":[],"investigations":[],"diagnoses":["Pneumonia"],"medications":[{"name":"Amoxicillin","dose":"500 mg","context":"new"}],"allergies":[],"social_history":[],"plan":["review"]""",
            transcript = "child has fever",
            patientId = "P001",
            providerId = "DR001",
            facilityId = "FAC001"
        )

        assertNull(report.encounter)
        assertNull(report.format)
        assertTrue(report.failureReason!!.startsWith("invalid JSON structure"))
        assertFalse(report.failureReason!!.contains("TOON"))
    }

    @Test
    fun `parseDetailed rejects json with no usable clinical fields`() {
        val report = parser.parseDetailed(
            responseText = """
            {
              "demographics": {"age": null, "sex": null, "name": null},
              "chief_complaint": null,
              "vitals": [],
              "exam_findings": [],
              "investigations": [],
              "diagnoses": [],
              "medications": [],
              "allergies": [],
              "social_history": [],
              "plan": []
            }
            """.trimIndent(),
            transcript = "child has fever",
            patientId = "P001",
            providerId = "DR001",
            facilityId = "FAC001"
        )

        assertNull(report.encounter)
        assertTrue(report.failureReason!!.contains("parsed but yielded no usable clinical fields"))
    }

    @Test
    fun `parseDetailed treats placeholder-only json as no usable clinical fields`() {
        val report = parser.parseDetailed(
            responseText = """
            {
              "demographics": {"age": "unknown", "sex": "M/F", "name": "unknown"},
              "chief_complaint": "brief summary",
              "vitals": [{"name": "temperature", "value": "unknown", "unit": "C"}],
              "exam_findings": ["finding 1"],
              "investigations": [{"test": "test", "result": "result"}],
              "diagnoses": ["diagnosis 1"],
              "medications": [{"name": "unknown", "dose": "unknown", "context": "current"}],
              "allergies": ["allergy or NKDA"],
              "social_history": ["factor 1"],
              "plan": ["action 1"]
            }
            """.trimIndent(),
            transcript = "good morning doctor",
            patientId = "P001",
            providerId = "DR001",
            facilityId = "FAC001"
        )

        assertNull(report.encounter)
        assertTrue(report.failureReason!!.contains("parsed but yielded no usable clinical fields"))
    }

    @Test
    fun `extracts json from markdown code block`() {
        val result = parser.parse(
            """
            ```json
            {
              "demographics": {"age": null, "sex": null, "name": null},
              "chief_complaint": "hypertension",
              "vitals": [],
              "exam_findings": [],
              "investigations": [],
              "diagnoses": ["Essential hypertension"],
              "medications": [],
              "allergies": [],
              "social_history": [],
              "plan": []
            }
            ```
            """.trimIndent(),
            "Diagnosis hypertension.",
            "P001",
            "DR001",
            "FAC001"
        )

        assertNotNull(result)
        assertEquals("I10", result!!.suggestedDiagnoses.first().icd10Code)
    }

    @Test
    fun `extractJson handles direct block and embedded json`() {
        assertNotNull(parser.extractJson("""{"diagnoses":[]}"""))
        assertNotNull(parser.extractJson("```json\n{\"diagnoses\":[]}\n```"))
        assertNotNull(parser.extractJson("Here is the result: {\"diagnoses\":[]} done"))
        assertNull(parser.extractJson("no json here"))
    }
}
