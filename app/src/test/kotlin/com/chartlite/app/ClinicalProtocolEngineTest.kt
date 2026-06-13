package com.chartlite.app

import com.chartlite.app.protocols.ClinicalProtocolEngine
import io.mockk.mockk
import org.junit.Assert.*
import org.junit.Before
import org.junit.Test

class ClinicalProtocolEngineTest {

    private lateinit var engine: ClinicalProtocolEngine

    private val testJson = """
    {
        "version": "1.0",
        "source": "Test",
        "protocols": [
            {
                "id": "MALARIA_UNCOMPLICATED",
                "name": "Uncomplicated Malaria",
                "category": "Infectious Disease",
                "icd10Codes": ["B50", "B51", "B52", "B53", "B54"],
                "applicableTo": "ALL",
                "steps": [
                    {
                        "id": "confirm",
                        "title": "Confirm Diagnosis",
                        "instructions": "Perform malaria rapid diagnostic test.",
                        "requiredActions": ["RDT or blood smear"],
                        "redFlags": ["Prostration", "Impaired consciousness"],
                        "followUpDays": 3
                    },
                    {
                        "id": "treat",
                        "title": "Treatment",
                        "instructions": "First-line: Artemether-Lumefantrine for 3 days.",
                        "medications": [
                            {
                                "name": "Artemether-Lumefantrine",
                                "dose": "Weight-based",
                                "frequency": "Twice daily",
                                "duration": "3 days"
                            }
                        ],
                        "referralCriteria": ["No improvement after 48 hours"]
                    }
                ]
            },
            {
                "id": "MALARIA_SEVERE",
                "name": "Severe Malaria",
                "category": "Infectious Disease",
                "icd10Codes": ["B50.0", "B50.8"],
                "applicableTo": "ALL",
                "urgency": "EMERGENCY",
                "steps": [
                    {
                        "id": "stabilize",
                        "title": "Emergency Stabilization",
                        "instructions": "Establish IV access immediately.",
                        "requiredActions": ["IV access", "Blood glucose check"]
                    }
                ]
            },
            {
                "id": "HYPERTENSION",
                "name": "Hypertension Management",
                "category": "Non-Communicable Disease",
                "icd10Codes": ["I10", "I11", "I12"],
                "applicableTo": "ADULT",
                "steps": [
                    {
                        "id": "diagnose",
                        "title": "Confirm Diagnosis",
                        "instructions": "Measure BP on 2 separate occasions.",
                        "criteria": {"Stage 1": "SBP 140-159", "Stage 2": "SBP 160-179"}
                    },
                    {
                        "id": "treat",
                        "title": "Treatment",
                        "instructions": "Start medication based on stage.",
                        "medications": [
                            {
                                "name": "Amlodipine",
                                "dose": "5-10 mg daily",
                                "contraindications": ["Severe aortic stenosis"]
                            }
                        ],
                        "followUpDays": 28
                    }
                ]
            },
            {
                "id": "IMCI_FEVER",
                "name": "IMCI Fever in Children Under 5",
                "category": "Pediatric",
                "icd10Codes": ["R50"],
                "applicableTo": "PEDIATRIC",
                "steps": [
                    {
                        "id": "assess",
                        "title": "Check Danger Signs",
                        "instructions": "Check for general danger signs in child.",
                        "redFlags": ["Unable to drink", "Vomiting everything", "Convulsions"]
                    }
                ]
            },
            {
                "id": "ANC",
                "name": "Antenatal Care",
                "category": "Maternal Health",
                "icd10Codes": ["Z34"],
                "applicableTo": "ADULT_FEMALE",
                "steps": [
                    {
                        "id": "first_visit",
                        "title": "First ANC Visit",
                        "instructions": "Confirm pregnancy and calculate EDD."
                    }
                ]
            }
        ]
    }
    """.trimIndent()

    @Before
    fun setUp() {
        engine = ClinicalProtocolEngine(mockk(relaxed = true))
        engine.loadFromJson(testJson)
    }

    @Test
    fun `getAllProtocols returns all loaded protocols`() {
        val protocols = engine.getAllProtocols()
        assertEquals(5, protocols.size)
    }

    @Test
    fun `getCategories returns unique sorted categories`() {
        val categories = engine.getCategories()
        assertEquals(4, categories.size)
        assertEquals("Infectious Disease", categories[0])
        assertEquals("Maternal Health", categories[1])
        assertEquals("Non-Communicable Disease", categories[2])
        assertEquals("Pediatric", categories[3])
    }

    @Test
    fun `getByCategory filters correctly`() {
        val infectious = engine.getByCategory("Infectious Disease")
        assertEquals(2, infectious.size)
        assertTrue(infectious.all { it.category == "Infectious Disease" })
    }

    @Test
    fun `getByCategory is case-insensitive`() {
        val infectious = engine.getByCategory("infectious disease")
        assertEquals(2, infectious.size)
    }

    @Test
    fun `findByICD10 matches exact code`() {
        val protocols = engine.findByICD10("I10")
        assertEquals(1, protocols.size)
        assertEquals("HYPERTENSION", protocols[0].id)
    }

    @Test
    fun `findByICD10 matches parent code`() {
        // B50 should match both uncomplicated (B50) and severe (B50.0, B50.8)
        val protocols = engine.findByICD10("B50")
        assertEquals(2, protocols.size)
    }

    @Test
    fun `findByICD10 matches sub-code to parent`() {
        // B50.0 should match both protocols that have B50 or B50.0
        val protocols = engine.findByICD10("B50.0")
        assertEquals(2, protocols.size)
    }

    @Test
    fun `findByICD10 returns empty for unmatched code`() {
        val protocols = engine.findByICD10("Z99")
        assertTrue(protocols.isEmpty())
    }

    @Test
    fun `findByICD10 handles whitespace and case`() {
        val protocols = engine.findByICD10("  b50  ")
        assertEquals(2, protocols.size)
    }

    @Test
    fun `findForEncounter maps multiple codes`() {
        val result = engine.findForEncounter(listOf("B50", "I10", "Z99"))
        assertEquals(2, result.size) // B50 and I10 match, Z99 doesn't
        assertTrue(result.containsKey("B50"))
        assertTrue(result.containsKey("I10"))
        assertFalse(result.containsKey("Z99"))
    }

    @Test
    fun `getEmergencyProtocols returns only emergency protocols`() {
        val emergencies = engine.getEmergencyProtocols()
        assertEquals(1, emergencies.size)
        assertEquals("MALARIA_SEVERE", emergencies[0].id)
        assertEquals("EMERGENCY", emergencies[0].urgency)
    }

    @Test
    fun `getRedFlags returns all red flags for protocol`() {
        val flags = engine.getRedFlags("MALARIA_UNCOMPLICATED")
        assertEquals(2, flags.size)
        assertTrue(flags.contains("Prostration"))
        assertTrue(flags.contains("Impaired consciousness"))
    }

    @Test
    fun `getRedFlags returns empty for nonexistent protocol`() {
        val flags = engine.getRedFlags("NONEXISTENT")
        assertTrue(flags.isEmpty())
    }

    @Test
    fun `getMedications returns all medications across steps`() {
        val meds = engine.getMedications("MALARIA_UNCOMPLICATED")
        assertEquals(1, meds.size)
        assertEquals("Artemether-Lumefantrine", meds[0].name)
    }

    @Test
    fun `getReferralCriteria collects from all steps`() {
        val criteria = engine.getReferralCriteria("MALARIA_UNCOMPLICATED")
        assertEquals(1, criteria.size)
        assertTrue(criteria[0].contains("No improvement"))
    }

    @Test
    fun `getFollowUpDays returns earliest follow-up`() {
        val days = engine.getFollowUpDays("MALARIA_UNCOMPLICATED")
        assertEquals(3, days)
    }

    @Test
    fun `getFollowUpDays returns null when no follow-up defined`() {
        val days = engine.getFollowUpDays("MALARIA_SEVERE")
        assertNull(days)
    }

    @Test
    fun `search matches protocol name`() {
        val results = engine.search("malaria")
        assertEquals(2, results.size)
    }

    @Test
    fun `search matches category`() {
        val results = engine.search("pediatric")
        assertEquals(1, results.size)
        assertEquals("IMCI_FEVER", results[0].id)
    }

    @Test
    fun `search matches step instructions`() {
        val results = engine.search("artemether")
        assertEquals(1, results.size)
        assertEquals("MALARIA_UNCOMPLICATED", results[0].id)
    }

    @Test
    fun `search returns empty for blank query`() {
        assertTrue(engine.search("").isEmpty())
        assertTrue(engine.search("   ").isEmpty())
    }

    @Test
    fun `filterByPatient ALL includes everything`() {
        val allProtocols = engine.getAllProtocols().filter { it.applicableTo == "ALL" }
        assertEquals(2, allProtocols.size) // Malaria uncomplicated + severe
    }

    @Test
    fun `filterByPatient adult male excludes pediatric and female-only`() {
        val filtered = engine.filterByPatient(isAdult = true, isFemale = false)
        // Should include: ALL (2 malaria) + ADULT (hypertension) = 3
        // Should exclude: PEDIATRIC (IMCI_FEVER) + ADULT_FEMALE (ANC)
        assertEquals(3, filtered.size)
        assertFalse(filtered.any { it.id == "IMCI_FEVER" })
        assertFalse(filtered.any { it.id == "ANC" })
    }

    @Test
    fun `filterByPatient adult female includes ADULT_FEMALE`() {
        val filtered = engine.filterByPatient(isAdult = true, isFemale = true)
        // Should include: ALL (2) + ADULT (1) + ADULT_FEMALE (1) = 4
        assertEquals(4, filtered.size)
        assertTrue(filtered.any { it.id == "ANC" })
    }

    @Test
    fun `filterByPatient child includes PEDIATRIC excludes ADULT`() {
        val filtered = engine.filterByPatient(isAdult = false, isFemale = false)
        // Should include: ALL (2) + PEDIATRIC (1) = 3
        // Should exclude: ADULT (hypertension) + ADULT_FEMALE (ANC)
        assertEquals(3, filtered.size)
        assertTrue(filtered.any { it.id == "IMCI_FEVER" })
        assertFalse(filtered.any { it.id == "HYPERTENSION" })
    }

    @Test
    fun `protocol step medications include contraindications`() {
        val meds = engine.getMedications("HYPERTENSION")
        assertEquals(1, meds.size)
        assertTrue(!meds[0].contraindications.isNullOrEmpty())
        assertEquals("Severe aortic stenosis", meds[0].contraindications!![0])
    }

    @Test
    fun `protocol step criteria are preserved`() {
        val protocol = engine.getAllProtocols().find { it.id == "HYPERTENSION" }!!
        val diagnoseStep = protocol.steps.find { it.id == "diagnose" }!!
        assertNotNull(diagnoseStep.criteria)
        assertEquals(2, diagnoseStep.criteria!!.size)
        assertTrue(diagnoseStep.criteria!!.containsKey("Stage 1"))
    }
}

