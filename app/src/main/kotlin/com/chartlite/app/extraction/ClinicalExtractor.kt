package com.chartlite.app.extraction

import com.chartlite.app.model.*
import java.time.Instant
import java.util.UUID

class ClinicalExtractor(
    private val formulary: Formulary,
    private val icd10: ICD10Index,
    private val vectorStore: ClinicalVectorStore? = null
) {
    private val medicationExtractor = MedicationExtractor(formulary)
    private val diagnosisExtractor = DiagnosisExtractor(icd10)
    private val vitalsExtractor = VitalsExtractor()

    fun extract(
        transcript: String,
        patientId: String,
        providerId: String,
        facilityId: String
    ): StructuredEncounter {
        val wordCount = transcript.split(Regex("\\s+")).count { it.isNotBlank() }

        // Only run clinical extraction if the transcript has enough content
        // Short transcripts (< 5 words) are likely greetings or noise
        val medications = if (wordCount >= 5) medicationExtractor.extract(transcript) else emptyList()
        val vitals = vitalsExtractor.extract(transcript) // Vitals have strict numeric patterns, safe at any length
        val allergies = if (wordCount >= 3) extractAllergies(transcript) else emptyList()
        val followUp = extractFollowUp(transcript)
        val referral = extractReferral(transcript)
        val immunizations = if (wordCount >= 3) extractImmunizations(transcript) else emptyList()

        val confidences = mutableListOf<Float>()
        medications.forEach { confidences.add(it.confidence) }
        val overallConfidence = if (confidences.isEmpty()) 0.5f
        else confidences.average().toFloat()

        // Regex fallback suggestions stay keyword-grounded only.
        val suggestedDiagnoses = if (wordCount >= 5) buildSuggestedDiagnoses(transcript) else emptyList()
        val freeText = buildFreeText(
            transcript = transcript,
            suggestedDiagnoses = suggestedDiagnoses,
            medications = medications,
            vitals = vitals,
            allergies = allergies,
            followUp = followUp,
            referral = referral
        )

        return StructuredEncounter(
            id = UUID.randomUUID().toString(),
            patientId = patientId,
            providerId = providerId,
            facilityId = facilityId,
            timestamp = Instant.now(),
            transcript = transcript,
            medications = medications,
            diagnoses = emptyList(), // Diagnoses are clinician-selected only
            vitals = vitals,
            allergies = allergies,
            followUp = followUp,
            referral = referral,
            freeTextNote = freeText,
            extractionConfidence = overallConfidence,
            suggestedDiagnoses = suggestedDiagnoses,
            immunizations = immunizations
        )
    }

    /**
     * Build conservative ICD-10 suggestions for the regex fallback path.
     * Semantic vector retrieval is intentionally excluded here so fallback mode
     * does not guess diagnoses from loose symptom similarity.
     */
    private fun buildSuggestedDiagnoses(transcript: String): List<Diagnosis> {
        return diagnosisExtractor.extract(transcript).take(7)
    }

    private fun extractAllergies(text: String): List<String> {
        val allergies = mutableListOf<String>()
        val lower = text.lowercase()

        val patterns = listOf(
            Regex("""allerg(?:ic|y)\s+to\s+([\w\s]+?)(?:\.|,|$)"""),
            Regex("""([\w]+)\s+allergy"""),
            Regex("""known\s+allerg(?:ic|y)\s+(?:to\s+)?([\w\s]+?)(?:\.|,|$)""")
        )

        for (pattern in patterns) {
            pattern.findAll(lower).forEach { match ->
                val allergen = match.groupValues[1].trim()
                if (allergen.isNotBlank() && allergen.length < 30) {
                    allergies.add(allergen)
                }
            }
        }
        return allergies.distinct()
    }

    private fun extractFollowUp(text: String): FollowUp? {
        val lower = text.lowercase()

        val patterns = listOf(
            Regex("""(?:come back|follow[- ]?up|return|review)\s+(?:in\s+)?(\d+)\s+(day|week|month)s?"""),
            Regex("""(\d+)\s+(day|week|month)s?\s+(?:follow[- ]?up|review)"""),
            Regex("""see\s+(?:me\s+)?(?:again\s+)?(?:in\s+)?(\d+)\s+(day|week|month)s?""")
        )

        for (pattern in patterns) {
            val match = pattern.find(lower) ?: continue
            val number = match.groupValues[1].toIntOrNull() ?: continue
            val unit = match.groupValues[2]
            val days = when (unit) {
                "week" -> number * 7
                "month" -> number * 30
                else -> number
            }
            return FollowUp(days = days)
        }
        return null
    }

    private fun extractReferral(text: String): Referral? {
        val lower = text.lowercase()

        if (!lower.contains("refer")) return null

        val type = when {
            lower.contains("hospital") -> "hospital"
            lower.contains("specialist") -> "specialist"
            lower.contains("lab") || lower.contains("laboratory") -> "lab"
            else -> "hospital"
        }

        val urgency = when {
            lower.contains("emergency") || lower.contains("emergent") -> "emergency"
            lower.contains("urgent") -> "urgent"
            else -> "routine"
        }

        // Try to extract specialty
        val specialtyPattern = Regex("""refer\w*\s+(?:to\s+)?(?:the\s+)?(\w+(?:olog\w+|iatri\w+|geon|ist))""")
        val specialty = specialtyPattern.find(lower)?.groupValues?.get(1)

        val reasonPattern = Regex("""refer\w*\s+(?:to\s+\w+\s+)?(?:for\s+)([\w\s]+?)(?:\.|,|$)""")
        val reason = reasonPattern.find(lower)?.groupValues?.get(1)?.trim()

        return Referral(type, specialty, urgency, reason)
    }

    private fun buildFreeText(
        transcript: String,
        suggestedDiagnoses: List<Diagnosis>,
        medications: List<Medication>,
        vitals: VitalSigns?,
        allergies: List<String>,
        followUp: FollowUp?,
        referral: Referral?
    ): String {
        val normalizedTranscript = transcript.replace(Regex("\\s+"), " ").trim()
        if (normalizedTranscript.isBlank()) return ""

        val summaryParts = mutableListOf<String>()

        val chiefComplaint = extractChiefConcern(normalizedTranscript)
        chiefComplaint?.let { summaryParts += "Chief concern: $it." }

        if (suggestedDiagnoses.isNotEmpty()) {
            val dx = suggestedDiagnoses.take(3).joinToString(", ") { "${it.icd10Code} ${it.description}" }
            summaryParts += "Suggested diagnoses: $dx."
        }

        if (medications.isNotEmpty()) {
            val rx = medications.take(3).joinToString(", ") { med ->
                buildString {
                    append(med.name)
                    med.dose?.let { append(" ${if (it % 1f == 0f) it.toInt().toString() else it.toString()}") }
                    med.unit?.let { append(it) }
                    med.frequency?.let { append(" $it") }
                    med.duration?.let { append(" x${it}d") }
                }.trim()
            }
            summaryParts += "Treatment discussed: $rx."
        }

        vitals?.let {
            val vitalParts = listOfNotNull(
                it.systolicBP?.let { sys -> "BP $sys/${it.diastolicBP ?: "?"}" },
                it.temperature?.let { temp -> "Temp ${"%.1f".format(temp)}C" },
                it.pulse?.let { pulse -> "Pulse $pulse" },
                it.oxygenSaturation?.let { spo2 -> "SpO2 $spo2%" }
            )
            if (vitalParts.isNotEmpty()) {
                summaryParts += "Recorded vitals: ${vitalParts.joinToString(", ")}."
            }
        }

        if (allergies.isNotEmpty()) {
            summaryParts += "Allergies noted: ${allergies.joinToString(", ")}."
        }

        followUp?.let {
            summaryParts += "Follow-up planned in ${it.days} days" +
                (it.reason?.let { reason -> " ($reason)." } ?: ".")
        }

        referral?.let {
            summaryParts += "Referral: ${it.type}" +
                (it.specialty?.let { specialty -> " ($specialty)" } ?: "") +
                " urgency ${it.urgency}."
        }

        if (summaryParts.isEmpty()) {
            return normalizedTranscript.take(500)
        }
        return summaryParts.joinToString(" ").take(1000)
    }

    private fun extractChiefConcern(transcript: String): String? {
        val candidates = transcript
            .split(Regex("(?<=[.!?])\\s+"))
            .mapNotNull(::sanitizeChiefConcernSentence)

        val preferred = candidates.firstOrNull(::containsClinicalSignal)
            ?: candidates.firstOrNull()

        return preferred
            ?.take(220)
            ?.trimEnd('.', '!', '?')
            ?.takeIf { it.isNotBlank() }
    }

    private fun sanitizeChiefConcernSentence(sentence: String): String? {
        var cleaned = sentence.trim()
        if (cleaned.isBlank()) return null

        val prefixes = listOf(
            Regex(
                """^(?:good\s+(?:morning|afternoon|evening)|hello|hi|hey)\b[\s,!.:-]*(?:doctor|doc|nurse|sir|madam)?[\s,!.:-]*""",
                RegexOption.IGNORE_CASE
            ),
            Regex("""^(?:doctor|doc|nurse)\b[\s,!.:-]*""", RegexOption.IGNORE_CASE),
            Regex("""^(?:okay|ok|alright|please|so)\b[\s,!.:-]*""", RegexOption.IGNORE_CASE)
        )

        var changed: Boolean
        do {
            changed = false
            for (pattern in prefixes) {
                val updated = cleaned.replaceFirst(pattern, "").trim()
                if (updated != cleaned) {
                    cleaned = updated
                    changed = true
                }
            }
        } while (changed)

        return cleaned.takeIf { it.isNotBlank() }
    }

    private fun containsClinicalSignal(text: String): Boolean {
        val lower = text.lowercase()
        val words = Regex("[\\p{L}\\p{N}]+").findAll(lower).map { it.value }.toSet()
        return lower.any { it.isDigit() } || CHIEF_CONCERN_KEYWORDS.any { it in words }
    }

    /**
     * Extract immunizations mentioned in the transcript via regex.
     * Looks for patterns like "gave BCG vaccine", "administered measles dose 2".
     */
    private fun extractImmunizations(text: String): List<ExtractedImmunization> {
        val lower = text.lowercase()
        val results = mutableListOf<ExtractedImmunization>()

        for ((code, keywords) in VACCINE_KEYWORDS) {
            for (keyword in keywords) {
                if (lower.contains(keyword)) {
                    // Try to extract dose number from nearby context
                    val doseNumber = extractDoseNumber(lower, keyword)
                    results.add(
                        ExtractedImmunization(
                            vaccineCode = code,
                            vaccineName = VACCINE_DISPLAY_NAMES[code] ?: code,
                            doseNumber = doseNumber
                        )
                    )
                    break // Don't double-match same vaccine
                }
            }
        }

        return results.distinctBy { it.vaccineCode }
    }

    /** Extract dose number from text near a vaccine keyword. */
    private fun extractDoseNumber(text: String, keyword: String): Int {
        val keywordIndex = text.indexOf(keyword)
        if (keywordIndex < 0) return 1
        // Look in a 60-char window around the keyword
        val start = maxOf(0, keywordIndex - 30)
        val end = minOf(text.length, keywordIndex + keyword.length + 30)
        val context = text.substring(start, end)

        // "dose 2", "dose number 3"
        Regex("""dose\s*(?:number\s*)?(\d)""").find(context)?.let {
            return it.groupValues[1].toInt()
        }
        // "first dose", "second dose", "third dose"
        when {
            context.contains("first") -> return 1
            context.contains("second") -> return 2
            context.contains("third") -> return 3
        }
        // "opv0", "opv1", "opv2", "opv3", "penta1", "penta2"
        Regex("""(?:$keyword)\s*(\d)""").find(context)?.let {
            return it.groupValues[1].toInt()
        }
        return 1
    }

    companion object {
        private val CHIEF_CONCERN_KEYWORDS = setOf(
            "ache", "allergy", "bleeding", "breathing", "cough", "diarrhea", "dizzy",
            "fever", "headache", "pain", "pregnant", "rash", "shortness", "swelling",
            "vomiting", "weakness", "wheeze"
        )

        /** Vaccine code → list of transcript keywords (lowercase). */
        private val VACCINE_KEYWORDS = mapOf(
            "BCG" to listOf("bcg", "bacillus calmette"),
            "OPV" to listOf("opv", "oral polio"),
            "PENTA" to listOf("penta", "pentavalent", "dpt"),
            "PCV" to listOf("pcv", "pneumococcal"),
            "ROTA" to listOf("rota", "rotavirus"),
            "MEASLES" to listOf("measles", "mmr"),
            "HPV" to listOf("hpv", "human papilloma"),
            "TT" to listOf("tetanus"),
            "HEP_B" to listOf("hepatitis b", "hep b"),
            "YELLOW_FEVER" to listOf("yellow fever"),
            "COVID" to listOf("covid vaccine", "covid jab"),
            "RUBELLA" to listOf("rubella"),
            "INFLUENZA" to listOf("flu vaccine", "influenza vaccine")
        )

        private val VACCINE_DISPLAY_NAMES = mapOf(
            "BCG" to "BCG", "OPV" to "Oral Polio", "PENTA" to "Pentavalent",
            "PCV" to "Pneumococcal", "ROTA" to "Rotavirus", "MEASLES" to "Measles",
            "HPV" to "HPV", "TT" to "Tetanus", "HEP_B" to "Hepatitis B",
            "YELLOW_FEVER" to "Yellow Fever", "COVID" to "COVID-19",
            "RUBELLA" to "Rubella", "INFLUENZA" to "Influenza"
        )
    }
}
