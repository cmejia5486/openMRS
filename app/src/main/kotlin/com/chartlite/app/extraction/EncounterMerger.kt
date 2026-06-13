package com.chartlite.app.extraction

import com.chartlite.app.model.Investigation
import com.chartlite.app.model.Medication
import com.chartlite.app.model.StructuredEncounter
import com.chartlite.app.model.VitalSigns

/**
 * Merges multiple snippet-based extractions into a single accumulated encounter.
 *
 * Used in snippet recording mode: clinician dictates short clinical phrases
 * ("BP 168/98, pulse 92"), each snippet is extracted independently, then
 * merged here into a running encounter that accumulates all clinical facts.
 *
 * Merge rules:
 * - Medications: union by formularyCode, keep highest confidence per drug
 * - Diagnoses: union by icd10Code, keep highest confidence per code
 * - Vitals: later values override earlier (null = not mentioned, doesn't override)
 * - Allergies: union (distinct)
 * - Follow-up / Referral: last non-null wins
 * - Transcript: concatenated with newline
 * - Confidence: weighted average (base weighted by its snippet count)
 */
object EncounterMerger {

    /**
     * Merge a new snippet extraction into the accumulated encounter.
     *
     * @param base The accumulated encounter so far (from previous snippets)
     * @param snippet The newly extracted snippet
     * @return A new StructuredEncounter combining both
     */
    fun merge(base: StructuredEncounter, snippet: StructuredEncounter): StructuredEncounter {
        return StructuredEncounter(
            id = base.id,
            patientId = base.patientId,
            providerId = base.providerId,
            facilityId = base.facilityId,
            timestamp = base.timestamp,
            transcript = listOf(base.transcript, snippet.transcript)
                .filter { it.isNotBlank() }
                .joinToString("\n"),
            medications = mergeMedications(base.medications, snippet.medications),
            diagnoses = mergeDiagnoses(base.diagnoses, snippet.diagnoses),
            vitals = mergeVitals(base.vitals, snippet.vitals),
            allergies = (base.allergies + snippet.allergies).distinct(),
            followUp = snippet.followUp ?: base.followUp,
            referral = snippet.referral ?: base.referral,
            freeTextNote = listOf(base.freeTextNote, snippet.freeTextNote)
                .filter { it.isNotBlank() }
                .joinToString("\n"),
            extractionConfidence = (base.extractionConfidence + snippet.extractionConfidence) / 2f,
            // Benchmark-driven categories: accumulate across snippets
            examFindings = (base.examFindings + snippet.examFindings).distinct(),
            investigations = mergeInvestigations(base.investigations, snippet.investigations),
            plan = (base.plan + snippet.plan).distinct(),
            socialHistory = (base.socialHistory + snippet.socialHistory).distinct(),
            suggestedDiagnoses = mergeDiagnoses(base.suggestedDiagnoses, snippet.suggestedDiagnoses)
        )
    }

    /**
     * Merge medications: union by formularyCode, keeping higher confidence when duplicate.
     */
    private fun mergeMedications(
        base: List<com.chartlite.app.model.Medication>,
        snippet: List<com.chartlite.app.model.Medication>
    ): List<com.chartlite.app.model.Medication> {
        val byCode = LinkedHashMap<String, com.chartlite.app.model.Medication>()

        // Base medications first
        for (med in base) {
            byCode[med.formularyCode] = med
        }

        // Snippet medications: override if higher confidence or new
        for (med in snippet) {
            val existing = byCode[med.formularyCode]
            if (existing == null || med.confidence > existing.confidence) {
                byCode[med.formularyCode] = med
            }
        }

        return byCode.values.toList()
    }

    /**
     * Merge diagnoses: union by ICD-10 code, keeping higher confidence when duplicate.
     * Preserves isPrimary from whichever entry has higher confidence.
     */
    private fun mergeDiagnoses(
        base: List<com.chartlite.app.model.Diagnosis>,
        snippet: List<com.chartlite.app.model.Diagnosis>
    ): List<com.chartlite.app.model.Diagnosis> {
        val byCode = LinkedHashMap<String, com.chartlite.app.model.Diagnosis>()

        for (dx in base) {
            byCode[dx.icd10Code] = dx
        }

        for (dx in snippet) {
            val existing = byCode[dx.icd10Code]
            if (existing == null || dx.confidence > existing.confidence) {
                byCode[dx.icd10Code] = dx
            }
        }

        return byCode.values.toList()
    }

    /**
     * Merge investigations: union by test name, snippet result overrides if both have same test.
     */
    private fun mergeInvestigations(
        base: List<Investigation>,
        snippet: List<Investigation>
    ): List<Investigation> {
        val byTest = LinkedHashMap<String, Investigation>()
        for (inv in base) { byTest[inv.test.lowercase()] = inv }
        for (inv in snippet) { byTest[inv.test.lowercase()] = inv }
        return byTest.values.toList()
    }

    /**
     * Merge vision extraction results into an existing encounter.
     * Vision values fill null fields but don't overwrite voice-dictated values.
     * Investigations and medications are appended and deduplicated.
     */
    fun mergeVisionResult(
        existing: StructuredEncounter,
        vision: VisionExtractor.VisionResult
    ): StructuredEncounter {
        // Convert vision vitals to VitalSigns
        val visionVitals = visionVitalsToModel(vision.vitals)

        // Convert vision investigations (labs + RDT)
        val visionInvestigations = vision.investigations.map {
            Investigation(test = it.test, result = it.result)
        }.toMutableList()
        // Add RDT as an investigation if present
        vision.rdt?.let { rdt ->
            visionInvestigations.add(
                Investigation(
                    test = "${rdt.testType.replaceFirstChar { c -> c.uppercase() }} RDT",
                    result = rdt.result.replaceFirstChar { c -> c.uppercase() }
                )
            )
        }

        // Convert vision medications
        val visionMeds = vision.medications.map {
            Medication(
                formularyCode = "",
                name = it.name,
                dose = it.dose?.toFloatOrNull(),
                unit = it.form
            )
        }

        return existing.copy(
            vitals = mergeVitals(existing.vitals, visionVitals),
            investigations = mergeInvestigations(existing.investigations, visionInvestigations),
            medications = mergeMedications(existing.medications, visionMeds)
        )
    }

    private fun visionVitalsToModel(readings: List<VisionExtractor.VitalReading>): VitalSigns? {
        if (readings.isEmpty()) return null
        var bp_sys: Int? = null; var bp_dia: Int? = null
        var temp: Float? = null; var pulse: Int? = null
        var spo2: Int? = null; var rr: Int? = null
        var weight: Float? = null; var height: Float? = null

        for (r in readings) {
            val name = r.name.lowercase()
            when {
                "systolic" in name || ("bp" in name && "dia" !in name) -> bp_sys = r.value.toIntOrNull()
                "diastolic" in name || "dia" in name -> bp_dia = r.value.toIntOrNull()
                "temp" in name -> temp = r.value.toFloatOrNull()
                "pulse" in name || "heart" in name || "hr" in name -> pulse = r.value.toIntOrNull()
                "spo2" in name || "oxygen" in name || "sat" in name -> spo2 = r.value.toIntOrNull()
                "respiratory" in name || "rr" in name -> rr = r.value.toIntOrNull()
                "weight" in name -> weight = r.value.toFloatOrNull()
                "height" in name -> height = r.value.toFloatOrNull()
            }
        }
        return VitalSigns(
            systolicBP = bp_sys, diastolicBP = bp_dia,
            temperature = temp, pulse = pulse,
            weight = weight, height = height,
            respiratoryRate = rr, oxygenSaturation = spo2
        )
    }

    /**
     * Merge vitals: newer snippet values override base values.
     * Null fields in snippet mean "not mentioned" and don't override.
     */
    fun mergeVitals(base: VitalSigns?, snippet: VitalSigns?): VitalSigns? {
        if (base == null) return snippet
        if (snippet == null) return base

        return VitalSigns(
            systolicBP = snippet.systolicBP ?: base.systolicBP,
            diastolicBP = snippet.diastolicBP ?: base.diastolicBP,
            temperature = snippet.temperature ?: base.temperature,
            pulse = snippet.pulse ?: base.pulse,
            weight = snippet.weight ?: base.weight,
            height = snippet.height ?: base.height,
            respiratoryRate = snippet.respiratoryRate ?: base.respiratoryRate,
            oxygenSaturation = snippet.oxygenSaturation ?: base.oxygenSaturation
        )
    }
}
