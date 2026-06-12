package com.chartlite.app.extraction

import com.chartlite.app.model.*
import com.google.gson.JsonObject
import com.google.gson.JsonParser
import java.time.Instant
import java.util.UUID

/**
 * Parses LLM output into a StructuredEncounter.
 *
 * Hallucination guard: free-text diagnoses and medications are grounded against the
 * loaded ICD-10 index and formulary. Unresolved entries are dropped.
 *
 * Shared extraction contract (2026-03):
 * - JSON only
 * - Diagnoses are free-text strings resolved against the local ICD-10 index
 * - Medications are free-text entries resolved against the local formulary
 */
class LlmResponseParser(
    private val icd10: ICD10Index,
    private val formulary: Formulary
) {
    internal data class ParseReport(
        val encounter: StructuredEncounter?,
        val format: String? = null,
        val failureReason: String? = null
    )

    private data class ParseAttempt(
        val encounter: StructuredEncounter? = null,
        val failureReason: String? = null
    )

    private val validIcd10Codes: Set<String> by lazy { icd10.codes.map { it.code }.toSet() }
    private val icd10EntriesByCode: Map<String, ICD10Entry> by lazy {
        icd10.codes.associateBy { it.code }
    }
    private val icd10Descriptions: Map<String, String> by lazy {
        icd10.codes.associate { it.code to it.description }
    }
    private val icd10ByNormalizedDescription: Map<String, String> by lazy {
        icd10.codes.associate { normalizeText(it.description) to it.code }
    }
    private val formularyByCode: Map<String, FormularyDrug> by lazy {
        formulary.drugs.associateBy { it.code }
    }
    private val formularyNames: Map<String, String> by lazy {
        formulary.drugs.associate { it.code to it.name }
    }
    private val formularyCodeByNormalizedLabel: Map<String, String> by lazy {
        buildMap {
            formulary.drugs.forEach { drug ->
                put(normalizeText(drug.name), drug.code)
                drug.aliases.forEach { alias ->
                    put(normalizeText(alias), drug.code)
                }
            }
        }
    }
    private val medicationExtractor by lazy { MedicationExtractor(formulary) }
    private val vitalsExtractor by lazy { VitalsExtractor() }
    /** Parse JSON model output into a StructuredEncounter. */
    fun parse(
        responseText: String,
        transcript: String,
        patientId: String,
        providerId: String,
        facilityId: String
    ): StructuredEncounter? =
        parseDetailed(responseText, transcript, patientId, providerId, facilityId).encounter

    internal fun parseDetailed(
        responseText: String,
        transcript: String,
        patientId: String,
        providerId: String,
        facilityId: String
    ): ParseReport {
        val jsonAttempt = parseJsonDetailed(responseText, transcript, patientId, providerId, facilityId)
        if (jsonAttempt.encounter != null) {
            return ParseReport(encounter = jsonAttempt.encounter, format = "JSON")
        }

        return ParseReport(
            encounter = null,
            failureReason = jsonAttempt.failureReason ?: "JSON parse failed"
        )
    }

    private fun resolveFormularyCode(rawName: String): String? {
        val normalized = normalizeText(rawName)
        if (normalized.isBlank()) return null
        formularyCodeByNormalizedLabel[normalized]?.let { return it }

        val fuzzy = formularyCodeByNormalizedLabel.entries
            .firstOrNull { keyValue ->
                val key = keyValue.key
                key.length >= 4 && (normalized.contains(key) || key.contains(normalized))
            }
        return fuzzy?.value
    }

    private fun resolveIcd10Code(rawCode: String?, rawDescription: String?): String? {
        val code = rawCode?.trim().orEmpty()
        if (code in validIcd10Codes) return code

        // Accept "I10 - Hypertension" style values.
        val extractedCode = Regex("""\b([A-Z][0-9]{2}(?:\.[0-9A-Z]{1,2})?)\b""")
            .find(code)?.groupValues?.get(1)
        if (extractedCode != null && extractedCode in validIcd10Codes) return extractedCode

        val normalizedDescription = normalizeText(rawDescription.orEmpty())
        if (normalizedDescription.isBlank()) return null

        icd10ByNormalizedDescription[normalizedDescription]?.let { return it }

        val fuzzy = icd10ByNormalizedDescription.entries
            .firstOrNull { entry ->
                val key = entry.key
                key.length >= 6 && (normalizedDescription.contains(key) || key.contains(normalizedDescription))
            }
        return fuzzy?.value
    }

    private fun parseLooseInt(raw: String?): Int? {
        val text = raw?.trim().orEmpty()
        if (text.isBlank()) return null
        val token = Regex("""-?\d+""").find(text)?.value ?: return null
        return token.toIntOrNull()
    }

    private fun parseLooseFloat(raw: String?): Float? {
        val text = raw?.trim().orEmpty()
        if (text.isBlank()) return null
        val token = Regex("""-?\d+(?:\.\d+)?""").find(text)?.value ?: return null
        return token.toFloatOrNull()
    }

    private fun normalizeText(raw: String): String =
        raw.lowercase()
            .replace(Regex("""[^a-z0-9]+"""), " ")
            .trim()

    private fun parseJsonDetailed(
        responseText: String,
        transcript: String,
        patientId: String,
        providerId: String,
        facilityId: String
    ): ParseAttempt {
        val json = extractJson(responseText)
            ?: return ParseAttempt(failureReason = "no JSON object found in model output")

        return try {
            val root = JsonParser.parseString(json).asJsonObject
            val context = buildTranscriptContext(transcript)

            val chiefComplaint = parseChiefComplaint(root)
                ?.takeIf { isNarrativeGrounded(it, context) }
            val suggestedDiagnoses = groundDiagnoses(parseDiagnosesFromJson(root), context)
                .mapIndexed { index, diagnosis -> diagnosis.copy(isPrimary = index == 0) }
            val medications = groundMedications(parseMedications(root), context)
            val vitals = parseVitals(root)
            val allergies = groundAllergies(parseAllergies(root), context)
            val plan = groundNarrativeItems(parseStringArray(root, "plan"), context)
            val followUp = groundFollowUp(
                deriveFollowUpFromTexts(plan + listOfNotNull(chiefComplaint)),
                context
            )
            val freeTextCandidate = firstSanitizedNarrative(listOfNotNull(chiefComplaint))

            val examFindings = groundNarrativeItems(parseStringArray(root, "exam_findings"), context)
            val investigations = groundInvestigations(parseInvestigations(root), context)
            val socialHistory = groundNarrativeItems(parseStringArray(root, "social_history"), context)
            val immunizations = parseImmunizations(root)
            val smsSummary = jsonString(root.get("sms_summary"))
                ?.take(19)
                ?.takeIf { it.isNotBlank() }

            if (suggestedDiagnoses.isEmpty() && medications.isEmpty() && vitals == null &&
                allergies.isEmpty() && followUp == null &&
                freeTextCandidate == null && examFindings.isEmpty() &&
                investigations.isEmpty() && plan.isEmpty() && socialHistory.isEmpty() &&
                immunizations.isEmpty()) {
                return ParseAttempt(
                    failureReason = emptyContentReason(
                        suggestedDiagnoses = suggestedDiagnoses.size,
                        medications = medications.size,
                        vitals = 0,
                        allergies = allergies.size,
                        followUp = 0,
                        note = 0,
                        examFindings = examFindings.size,
                        investigations = investigations.size,
                        plan = plan.size,
                        socialHistory = socialHistory.size,
                        immunizations = immunizations.size
                    )
                )
            }

            val confidences = medications.map { it.confidence } + suggestedDiagnoses.map { it.confidence }
            val overallConfidence = if (confidences.isEmpty()) 0.5f else confidences.average().toFloat()

            // Rescue: LLMs sometimes put vaccines in "medications" instead of "immunizations".
            // Scan medications for vaccine-like names and move them to immunizations.
            val rescuedImmunizations = mutableListOf<ExtractedImmunization>()
            val filteredMedications = medications.filter { med ->
                val grounded = groundVaccine(med.name)
                if (grounded != null) {
                    rescuedImmunizations.add(ExtractedImmunization(
                        vaccineCode = grounded.first,
                        vaccineName = grounded.second,
                        doseNumber = 1
                    ))
                    false // Remove from medications
                } else true
            }
            val allImmunizations = (immunizations + rescuedImmunizations).distinctBy { it.vaccineCode }

            ParseAttempt(
                encounter = StructuredEncounter(
                    id = UUID.randomUUID().toString(),
                    patientId = patientId,
                    providerId = providerId,
                    facilityId = facilityId,
                    timestamp = Instant.now(),
                    transcript = transcript,
                    medications = filteredMedications,
                    diagnoses = emptyList(), // Clinician-selected only
                    vitals = vitals,
                    allergies = allergies,
                    followUp = followUp,
                    referral = null,
                    freeTextNote = freeTextCandidate ?: "",
                    extractionConfidence = overallConfidence,
                    examFindings = examFindings,
                    investigations = investigations,
                    plan = plan,
                    socialHistory = socialHistory,
                    suggestedDiagnoses = suggestedDiagnoses,
                    immunizations = allImmunizations,
                    smsSummary = smsSummary
                )
            )
        } catch (e: Exception) {
            val detail = e.message
                ?.replace(Regex("""\s+"""), " ")
                ?.trim()
                ?.take(180)
            ParseAttempt(
                failureReason = buildString {
                    append("invalid JSON structure (${e::class.simpleName ?: "parse error"})")
                    if (!detail.isNullOrBlank()) {
                        append(": ")
                        append(detail)
                    }
                }
            )
        }
    }

    private fun emptyContentReason(
        suggestedDiagnoses: Int,
        medications: Int,
        vitals: Int,
        allergies: Int,
        followUp: Int,
        note: Int,
        examFindings: Int,
        investigations: Int,
        plan: Int,
        socialHistory: Int,
        immunizations: Int = 0
    ): String =
        "parsed but yielded no usable clinical fields " +
            "(dx=$suggestedDiagnoses, meds=$medications, vitals=$vitals, " +
            "allergies=$allergies, followUp=$followUp, note=$note, " +
            "exam=$examFindings, investigations=$investigations, plan=$plan, " +
            "social=$socialHistory, immunizations=$immunizations)"

    internal fun extractJson(text: String): String? {
        val trimmed = text.trim()
        val codeBlockPattern = Regex("""```(?:json)?\s*\n?(.*?)\n?\s*```""", RegexOption.DOT_MATCHES_ALL)
        val match = codeBlockPattern.find(trimmed)
        if (match != null) return match.groupValues[1].trim()

        val start = trimmed.indexOf('{')
        val end = trimmed.lastIndexOf('}')
        if (start >= 0 && end > start) return trimmed.substring(start, end + 1)
        return null
    }

    /** Parse benchmark diagnosis strings. All LLM diagnoses are marked source="llm". */
    private fun parseDiagnosesFromJson(root: JsonObject): List<Diagnosis> {
        val elem = root.get("diagnoses") ?: return emptyList()
        if (elem.isJsonNull || !elem.isJsonArray) return emptyList()
        return elem.asJsonArray.mapIndexedNotNull { index, item ->
            try {
                val description = jsonString(item) ?: return@mapIndexedNotNull null
                val code = resolveIcd10Code(null, description) ?: return@mapIndexedNotNull null
                Diagnosis(
                    icd10Code = code,
                    description = icd10Descriptions[code] ?: description,
                    isPrimary = index == 0,
                    confidence = 0.8f,
                    source = "llm"
                )
            } catch (_: Exception) { null }
        }
    }

    private fun parseMedications(root: JsonObject): List<Medication> {
        val elem = root.get("medications") ?: return emptyList()
        if (elem.isJsonNull || !elem.isJsonArray) return emptyList()
        return elem.asJsonArray.mapNotNull { item ->
            try {
                val obj = item.asJsonObject
                val name = jsonString(obj.get("name")) ?: return@mapNotNull null
                val code = resolveFormularyCode(name) ?: return@mapNotNull null

                val doseText = jsonString(obj.get("dose"))
                val context = jsonString(obj.get("context"))
                val benchmarkMedicationText = listOfNotNull(name, doseText, context).joinToString(" ")
                val extractedMedication = benchmarkMedicationText
                    .takeIf { it.isNotBlank() }
                    ?.let(medicationExtractor::extract)
                    ?.firstOrNull { it.formularyCode == code }

                Medication(
                    formularyCode = code,
                    name = formularyNames[code] ?: name,
                    dose = extractedMedication?.dose ?: parseLooseFloat(doseText),
                    unit = extractedMedication?.unit,
                    frequency = extractedMedication?.frequency,
                    duration = extractedMedication?.duration ?: parseDurationToken(doseText),
                    route = extractedMedication?.route,
                    confidence = extractedMedication?.confidence ?: 0.8f
                )
            } catch (_: Exception) { null }
        }
    }

    private fun parseVitals(root: JsonObject): VitalSigns? {
        val elem = root.get("vitals") ?: return null
        if (elem.isJsonNull || !elem.isJsonArray) return null
        val vitals = parseVitalsArray(elem.asJsonArray)
        return if (vitals == VitalSigns()) null else vitals
    }

    private fun parseAllergies(root: JsonObject): List<String> {
        val elem = root.get("allergies") ?: return emptyList()
        if (elem.isJsonNull || !elem.isJsonArray) return emptyList()
        return elem.asJsonArray.mapNotNull { item ->
            jsonString(item)
        }
    }

    /** Parse a JSON string array like "exam_findings": ["finding1", "finding2"] */
    private fun parseStringArray(root: JsonObject, key: String): List<String> {
        val elem = root.get(key) ?: return emptyList()
        if (elem.isJsonNull || !elem.isJsonArray) return emptyList()
        return elem.asJsonArray.mapNotNull { item ->
            jsonString(item)
        }
    }

    /** Parse investigations: [{"test": "...", "result": "..."}] */
    private fun parseInvestigations(root: JsonObject): List<Investigation> {
        val elem = root.get("investigations") ?: return emptyList()
        if (elem.isJsonNull || !elem.isJsonArray) return emptyList()
        return elem.asJsonArray.mapNotNull { item ->
            try {
                val obj = item.asJsonObject
                val test = jsonString(obj.get("test")) ?: return@mapNotNull null
                Investigation(
                    test = test,
                    result = jsonString(obj.get("result"))
                )
            } catch (_: Exception) { null }
        }
    }

    /** Parse immunizations: [{"vaccine": "measles", "dose_number": 1}] */
    private fun parseImmunizations(root: JsonObject): List<ExtractedImmunization> {
        val elem = root.get("immunizations") ?: return emptyList()
        if (elem.isJsonNull || !elem.isJsonArray) return emptyList()
        return elem.asJsonArray.mapNotNull { item ->
            try {
                val obj = item.asJsonObject
                val rawVaccine = jsonString(obj.get("vaccine")) ?: return@mapNotNull null
                val doseNumber = obj.get("dose_number")?.let {
                    if (it.isJsonPrimitive) it.asInt else 1
                } ?: 1
                groundVaccine(rawVaccine)?.let { (code, name) ->
                    ExtractedImmunization(
                        vaccineCode = code,
                        vaccineName = name,
                        doseNumber = doseNumber.coerceIn(1, 10)
                    )
                }
            } catch (_: Exception) { null }
        }
    }

    /**
     * Ground a free-text vaccine name against standard EPI vaccine codes.
     * Returns (code, displayName) or null if not recognized.
     */
    private fun groundVaccine(raw: String): Pair<String, String>? {
        val lower = raw.lowercase().trim()
        for ((code, names) in EPI_VACCINE_TABLE) {
            if (names.any { lower.contains(it) }) {
                return code to EPI_VACCINE_DISPLAY[code]!!
            }
        }
        return null
    }

    private fun sanitizeInvestigations(investigations: List<Investigation>): List<Investigation> =
        investigations.mapNotNull { investigation ->
            val test = sanitizeNarrative(investigation.test) ?: return@mapNotNull null
            val result = investigation.result?.let(::sanitizeNarrative)
            if (looksLikeHeaderValue(test) || (result != null && looksLikeHeaderValue(result))) {
                return@mapNotNull null
            }

            Investigation(
                test = test,
                result = result,
                confidence = investigation.confidence
            )
        }.distinctBy { normalizeGroundingText("${it.test} ${it.result.orEmpty()}") }

    private fun parseChiefComplaint(root: JsonObject): String? =
        jsonString(root.get("chief_complaint")) ?: jsonString(root.get("chiefComplaint"))

    private fun deriveFollowUpFromTexts(texts: List<String>): FollowUp? {
        val combined = texts.joinToString(". ").trim()
        if (combined.isBlank()) return null
        return extractFollowUpFromTranscript(buildTranscriptContext(combined))
    }

    private fun jsonString(element: com.google.gson.JsonElement?): String? {
        if (element == null || element.isJsonNull || !element.isJsonPrimitive) return null
        return try { sanitizeNarrative(element.asString) } catch (_: Exception) { null }
    }

    private fun parseDurationToken(text: String?): Int? {
        val raw = text?.trim().orEmpty()
        if (raw.isBlank()) return null
        val match = DURATION_PATTERN.find(raw.lowercase()) ?: return null
        val number = parseNumberToken(match.groupValues[1]) ?: return null
        return when {
            match.groupValues[2].startsWith("week") -> number * 7
            match.groupValues[2].startsWith("month") -> number * 30
            else -> number
        }
    }

    private fun parseVitalsArray(array: com.google.gson.JsonArray): VitalSigns {
        var systolicBP: Int? = null
        var diastolicBP: Int? = null
        var temperature: Float? = null
        var pulse: Int? = null
        var weight: Float? = null
        var height: Float? = null
        var respiratoryRate: Int? = null
        var oxygenSaturation: Int? = null

        array.forEach { item ->
            if (!item.isJsonObject) return@forEach
            val obj = item.asJsonObject
            val name = jsonString(obj.get("name"))?.lowercase() ?: return@forEach
            val value = jsonString(obj.get("value")) ?: return@forEach

            when {
                name.contains("blood pressure") || name == "bp" -> {
                    val normalized = value.lowercase().replace("over", "/")
                    val match = Regex("""(\d+)\s*/\s*(\d+)""").find(normalized) ?: return@forEach
                    systolicBP = match.groupValues[1].toIntOrNull() ?: systolicBP
                    diastolicBP = match.groupValues[2].toIntOrNull() ?: diastolicBP
                }
                name.contains("temperature") || name == "temp" -> {
                    temperature = parseLooseFloat(value) ?: temperature
                }
                name.contains("pulse") || name.contains("heart rate") -> {
                    pulse = parseLooseInt(value) ?: pulse
                }
                name.contains("weight") -> {
                    weight = parseLooseFloat(value) ?: weight
                }
                name.contains("height") -> {
                    height = parseLooseFloat(value) ?: height
                }
                name.contains("respiratory") -> {
                    respiratoryRate = parseLooseInt(value) ?: respiratoryRate
                }
                name.contains("oxygen") || name.contains("spo2") -> {
                    oxygenSaturation = parseLooseInt(value) ?: oxygenSaturation
                }
            }
        }

        return VitalSigns(
            systolicBP = systolicBP,
            diastolicBP = diastolicBP,
            temperature = temperature,
            pulse = pulse,
            weight = weight,
            height = height,
            respiratoryRate = respiratoryRate,
            oxygenSaturation = oxygenSaturation
        )
    }

    private fun groundDiagnoses(diagnoses: List<Diagnosis>, context: TranscriptContext): List<Diagnosis> =
        diagnoses.filter { diagnosis ->
            val entry = icd10EntriesByCode[diagnosis.icd10Code]
            when {
                entry != null -> transcriptSupportsDiagnosis(entry, context)
                else -> isNarrativeGrounded(diagnosis.description, context)
            }
        }.distinctBy { it.icd10Code }

    private fun groundMedications(medications: List<Medication>, context: TranscriptContext): List<Medication> {
        val transcriptMeds = medicationExtractor.extract(context.transcript).associateBy { it.formularyCode }

        return medications.mapNotNull { medication ->
            val entry = formularyByCode[medication.formularyCode] ?: return@mapNotNull null
            val transcriptMedication = transcriptMeds[medication.formularyCode]
            val medContext = medicationContext(entry, context.transcript)

            if (transcriptMedication == null && medContext == null) return@mapNotNull null

            val dose = transcriptMedication?.dose
                ?: medication.dose?.takeIf { transcriptSupportsDose(medContext, it, medication.unit) }
            val unit = when {
                dose == null -> null
                transcriptMedication?.dose != null -> transcriptMedication.unit
                else -> medication.unit?.takeIf { transcriptSupportsDose(medContext, medication.dose, it) }
            }
            val frequency = transcriptMedication?.frequency
                ?: medication.frequency?.takeIf { transcriptSupportsFrequency(medContext, it) }
            val duration = transcriptMedication?.duration
                ?: medication.duration?.takeIf { transcriptSupportsDuration(medContext, it) }
            val route = sequenceOf(transcriptMedication?.route, medication.route)
                .filterNotNull()
                .firstOrNull { transcriptSupportsRoute(medContext, it) }

            Medication(
                formularyCode = medication.formularyCode,
                name = entry.name,
                dose = dose,
                unit = unit,
                frequency = frequency,
                duration = duration,
                route = route,
                confidence = maxOf(medication.confidence, transcriptMedication?.confidence ?: 0f)
            )
        }.distinctBy { it.formularyCode }
    }

    private fun groundVitals(vitals: VitalSigns?, context: TranscriptContext): VitalSigns? {
        val regexVitals = vitalsExtractor.extract(context.transcript)
        if (regexVitals != null) return regexVitals
        if (vitals == null) return null
        return null
    }

    private fun groundAllergies(allergies: List<String>, context: TranscriptContext): List<String> =
        allergies.mapNotNull(::sanitizeNarrative)
            .filter { allergy ->
                if (isNoKnownAllergyMarker(allergy)) {
                    NO_KNOWN_ALLERGY_PATTERNS.any { it.containsMatchIn(context.lowerTranscript) }
                } else {
                    isNarrativeGrounded(allergy, context)
                }
            }
            .distinctBy(::normalizeGroundingText)

    private fun groundFollowUp(followUp: FollowUp?, context: TranscriptContext): FollowUp? {
        val groundedFromTranscript = extractFollowUpFromTranscript(context)
        val reason = followUp?.reason
            ?.let(::sanitizeNarrative)
            ?.takeIf { isNarrativeGrounded(it, context) }

        return when {
            groundedFromTranscript != null -> groundedFromTranscript.copy(reason = reason ?: groundedFromTranscript.reason)
            followUp != null && transcriptSupportsFollowUpDays(context, followUp.days) -> {
                FollowUp(days = followUp.days, reason = reason)
            }
            else -> null
        }
    }

    private fun groundReferral(referral: Referral?, context: TranscriptContext): Referral? {
        val normalizedReferral = referral.normalizedOrNull() ?: return null
        if (!REFERRAL_PATTERN.containsMatchIn(context.lowerTranscript)) return null

        val specialty = normalizedReferral.specialty
            ?.let(::sanitizeNarrative)
            ?.takeIf { isNarrativeGrounded(it, context) }
        val reason = normalizedReferral.reason
            ?.let(::sanitizeNarrative)
            ?.takeIf { isNarrativeGrounded(it, context) }
        val urgency = when {
            context.lowerTranscript.contains("emergency") || context.lowerTranscript.contains("emergent") -> "emergency"
            context.lowerTranscript.contains("urgent") -> "urgent"
            else -> "routine"
        }
        val type = when {
            context.lowerTranscript.contains("specialist") -> "specialist"
            context.lowerTranscript.contains("lab") || context.lowerTranscript.contains("laboratory") -> "lab"
            context.lowerTranscript.contains("hospital") -> "hospital"
            else -> normalizedReferral.type
        }

        return Referral(type = type, specialty = specialty, urgency = urgency, reason = reason).normalizedOrNull()
    }

    private fun groundInvestigations(
        investigations: List<Investigation>,
        context: TranscriptContext
    ): List<Investigation> = investigations.mapNotNull { investigation ->
        val test = sanitizeNarrative(investigation.test) ?: return@mapNotNull null
        val result = investigation.result?.let(::sanitizeNarrative)
        if (looksLikeHeaderValue(test) || (result != null && looksLikeHeaderValue(result))) return@mapNotNull null
        if (!isNarrativeGrounded(test, context) && (result == null || !isNarrativeGrounded(result, context))) {
            return@mapNotNull null
        }

        Investigation(
            test = test,
            result = result?.takeIf { isNarrativeGrounded(it, context) },
            confidence = investigation.confidence
        )
    }.distinctBy { normalizeGroundingText("${it.test} ${it.result.orEmpty()}") }

    private fun sanitizeNarrativeItems(items: List<String>): List<String> =
        items.mapNotNull(::sanitizeNarrative)
            .distinctBy(::normalizeGroundingText)

    private fun groundNarrativeItems(items: List<String>, context: TranscriptContext): List<String> =
        sanitizeNarrativeItems(items)
            .filter { isNarrativeGrounded(it, context) }
            .distinctBy(::normalizeGroundingText)

    private fun firstSanitizedNarrative(candidates: List<String>): String? =
        candidates.asSequence()
            .mapNotNull(::sanitizeNarrative)
            .firstOrNull()

    private fun transcriptSupportsDiagnosis(entry: ICD10Entry, context: TranscriptContext): Boolean {
        val normalizedDescription = normalizeGroundingText(entry.description)
        if (normalizedDescription.isNotBlank() && context.normalizedTranscript.contains(normalizedDescription)) {
            return true
        }

        for (keyword in entry.keywords) {
            if (transcriptContainsMedicalKeyword(keyword, context)) return true
        }

        return entry.localTerms.values.flatten().any { term ->
            val normalized = normalizeGroundingText(term)
            normalized.isNotBlank() && context.normalizedTranscript.contains(normalized)
        }
    }

    private fun transcriptContainsMedicalKeyword(keyword: String, context: TranscriptContext): Boolean {
        val normalized = normalizeGroundingText(keyword)
        if (normalized.isBlank()) return false

        val isShortAbbreviation = keyword.length <= SHORT_ABBREVIATION_THRESHOLD &&
            keyword.all { it.isLetter() } &&
            (keyword.uppercase() == keyword || keyword.length <= 3)

        if (isShortAbbreviation) {
            return context.originalTokens.any { token ->
                token.equals(keyword.uppercase(), ignoreCase = false) ||
                    token.trimEnd('.', ',', ';', ':', '!', '?').equals(keyword.uppercase(), ignoreCase = false)
            }
        }

        return context.normalizedTranscript.contains(normalized)
    }

    private fun medicationContext(drug: FormularyDrug, transcript: String): String? {
        val lowerTranscript = transcript.lowercase()
        val names = listOf(drug.name) + drug.aliases

        val firstMatch = names.asSequence()
            .map { name ->
                Regex("""\b${Regex.escape(name.lowercase())}\b""").find(lowerTranscript)
            }
            .filterNotNull()
            .minByOrNull { it.range.first }
            ?: return null

        val start = maxOf(0, firstMatch.range.first - 20)
        val end = minOf(lowerTranscript.length, firstMatch.range.first + MEDICATION_CONTEXT_WINDOW_CHARS)
        return lowerTranscript.substring(start, end)
    }

    private fun transcriptSupportsDose(context: String?, dose: Float?, unit: String?): Boolean {
        val value = dose ?: return false
        val doseUnit = unit?.trim()?.lowercase() ?: return false
        val text = context ?: return false
        val numeric = if (value % 1f == 0f) value.toInt().toString() else value.toString()
        val compact = numeric.replace(".0", "")
        return Regex("""\b${Regex.escape(compact)}\s*${Regex.escape(doseUnit)}\b""").containsMatchIn(text)
    }

    private fun transcriptSupportsFrequency(context: String?, frequency: String): Boolean {
        val normalizedFrequency = frequency.trim().uppercase()
        val text = context ?: return false
        val patterns = FREQUENCY_EVIDENCE[normalizedFrequency] ?: listOf(frequency.lowercase())
        return patterns.any { pattern -> normalizeGroundingText(text).contains(normalizeGroundingText(pattern)) }
    }

    private fun transcriptSupportsDuration(context: String?, days: Int): Boolean {
        val text = context ?: return false
        return extractDurationCandidates(text).contains(days)
    }

    private fun transcriptSupportsRoute(context: String?, route: String): Boolean {
        val text = context ?: return false
        val patterns = ROUTE_EVIDENCE[route.trim().uppercase()] ?: listOf(route.lowercase())
        return patterns.any { pattern -> normalizeGroundingText(text).contains(normalizeGroundingText(pattern)) }
    }

    private fun transcriptSupportsFollowUpDays(context: TranscriptContext, days: Int): Boolean =
        FOLLOW_UP_TRIGGER_PATTERN.containsMatchIn(context.lowerTranscript) &&
            extractDurationCandidates(context.transcript).contains(days)

    private fun extractFollowUpFromTranscript(context: TranscriptContext): FollowUp? {
        for (pattern in FOLLOW_UP_PATTERNS) {
            val match = pattern.find(context.lowerTranscript) ?: continue
            val number = parseNumberToken(match.groupValues[1]) ?: continue
            val unit = match.groupValues[2]
            val days = when {
                unit.startsWith("week") -> number * 7
                unit.startsWith("month") -> number * 30
                else -> number
            }
            val reason = match.groupValues.getOrNull(3)
                ?.takeIf { it.isNotBlank() }
                ?.let(::sanitizeNarrative)
            return FollowUp(days = days, reason = reason)
        }
        return null
    }

    private fun extractDurationCandidates(text: String): Set<Int> =
        DURATION_PATTERN.findAll(text.lowercase()).mapNotNull { match ->
            val number = parseNumberToken(match.groupValues[1]) ?: return@mapNotNull null
            when {
                match.groupValues[2].startsWith("week") -> number * 7
                match.groupValues[2].startsWith("month") -> number * 30
                else -> number
            }
        }.toSet()

    private fun parseNumberToken(token: String): Int? {
        val normalized = token.trim().lowercase()
        return normalized.toIntOrNull() ?: NUMBER_WORDS[normalized]
    }

    private fun sanitizeNarrative(raw: String?): String? {
        var value = raw?.trim()
            ?.trimStart('-', '*', '•')
            ?.trim()
            ?.replace(Regex("""\s+"""), " ")
            ?: return null
        if (value.isBlank()) return null

        val labelMatch = Regex("""^([A-Za-z_ ]{2,32}):\s*(.+)$""").matchEntire(value)
        if (labelMatch != null && normalizeGroundingText(labelMatch.groupValues[1]) in ECHO_LABELS) {
            value = labelMatch.groupValues[2].trim()
        }

        if (value.isBlank() || looksLikePlaceholder(value)) return null
        return value
    }

    private fun isNarrativeGrounded(value: String, context: TranscriptContext): Boolean {
        val normalized = normalizeGroundingText(value)
        if (normalized.isBlank()) return false
        if (context.normalizedTranscript.contains(normalized) && normalized.length >= 6) return true

        val tokens = groundingTokens(value)
        if (tokens.isEmpty()) return false
        val matched = tokens.count { it in context.tokenSet }
        val required = when {
            tokens.size == 1 -> 1
            tokens.size == 2 -> 2
            else -> 2
        }
        return matched >= required
    }

    private fun looksLikePlaceholder(value: String): Boolean {
        val normalized = normalizeGroundingText(value)
        if (normalized.isBlank()) return true
        if (value.contains('<') && value.contains('>')) return true
        return normalized in PLACEHOLDER_VALUES
    }

    private fun looksLikeHeaderValue(value: String): Boolean =
        normalizeGroundingText(value) in HEADER_VALUES

    private fun isNoKnownAllergyMarker(value: String): Boolean =
        normalizeGroundingText(value) in NO_KNOWN_ALLERGY_VALUES

    private fun normalizeGroundingText(raw: String): String =
        raw.lowercase()
            .replace(Regex("""[^a-z0-9]+"""), " ")
            .trim()
            .split(Regex("""\s+"""))
            .filter { it.isNotBlank() }
            .joinToString(" ") { token -> NUMBER_WORDS[token]?.toString() ?: token }

    private fun groundingTokens(raw: String): List<String> =
        normalizeGroundingText(raw)
            .split(" ")
            .filter { it.isNotBlank() && it !in GROUNDING_STOPWORDS }

    private fun buildTranscriptContext(transcript: String): TranscriptContext = TranscriptContext(
        transcript = transcript,
        lowerTranscript = transcript.lowercase(),
        normalizedTranscript = normalizeGroundingText(transcript),
        tokenSet = groundingTokens(transcript).toSet(),
        originalTokens = transcript.split(Regex("""\s+"""))
            .map { it.trim() }
            .filter { it.isNotBlank() }
    )

    private data class TranscriptContext(
        val transcript: String,
        val lowerTranscript: String,
        val normalizedTranscript: String,
        val tokenSet: Set<String>,
        val originalTokens: List<String>
    )

    companion object {
        private const val SHORT_ABBREVIATION_THRESHOLD = 4
        private const val MEDICATION_CONTEXT_WINDOW_CHARS = 140

        private val NUMBER_WORDS = mapOf(
            "one" to 1,
            "two" to 2,
            "three" to 3,
            "four" to 4,
            "five" to 5,
            "six" to 6,
            "seven" to 7,
            "eight" to 8,
            "nine" to 9,
            "ten" to 10,
            "eleven" to 11,
            "twelve" to 12,
            "thirteen" to 13,
            "fourteen" to 14,
            "fifteen" to 15,
            "sixteen" to 16,
            "seventeen" to 17,
            "eighteen" to 18,
            "nineteen" to 19,
            "twenty" to 20,
            "twenty one" to 21,
            "twenty two" to 22,
            "twenty three" to 23,
            "twenty four" to 24,
            "twenty five" to 25,
            "twenty six" to 26,
            "twenty seven" to 27,
            "twenty eight" to 28,
            "twenty nine" to 29,
            "thirty" to 30
        )

        private val GROUNDING_STOPWORDS = setOf(
            "a", "an", "and", "are", "as", "at", "be", "by", "for", "from", "has", "have",
            "if", "in", "into", "is", "it", "let", "of", "on", "or", "please", "start",
            "take", "the", "their", "there", "to", "was", "were", "with", "follow", "up",
            "plan", "exam", "finding", "findings", "result", "results", "test", "tests",
            "review", "return", "come", "back", "patient", "doctor", "clinical", "summary"
        )

        private val ECHO_LABELS = setOf(
            "exam findings",
            "exam_findings",
            "investigations",
            "plan",
            "social history",
            "social_history",
            "allergies",
            "free text note",
            "free_text_note"
        )

        private val PLACEHOLDER_VALUES = setOf(
            "null",
            "brief summary",
            "concise clinical summary",
            "brief clinical summary",
            "free text note",
            "unknown",
            "not stated",
            "not mentioned",
            "n a",
            "finding 1",
            "finding 2",
            "diagnosis 1",
            "allergy or nkda",
            "factor 1",
            "action 1",
            "action 2"
        )

        private val HEADER_VALUES = setOf(
            "test",
            "result",
            "test result",
            "name",
            "value",
            "unit"
        )

        private val NO_KNOWN_ALLERGY_VALUES = setOf(
            "nkda",
            "no allergy",
            "no allergies",
            "no known allergy",
            "no known allergies",
            "no known drug allergy",
            "no known drug allergies"
        )

        private val NO_KNOWN_ALLERGY_PATTERNS = listOf(
            Regex("""\bnkda\b"""),
            Regex("""\bno known drug allergies\b"""),
            Regex("""\bno known allergies\b"""),
            Regex("""\bno allergies\b""")
        )

        private val DURATION_PATTERN = Regex(
            """\b(\d+|one|two|three|four|five|six|seven|eight|nine|ten|eleven|twelve|thirteen|fourteen|fifteen|sixteen|seventeen|eighteen|nineteen|twenty|thirty)\s+(day|days|week|weeks|month|months)\b"""
        )

        private val FOLLOW_UP_TRIGGER_PATTERN = Regex("""\b(come back|follow ?up|return|review|see (?:me )?again)\b""")
        private val REFERRAL_PATTERN = Regex("""\b(refer|referral|transfer)\b""")

        private val FOLLOW_UP_PATTERNS = listOf(
            Regex("""(?:come back|follow[- ]?up|return|review|see(?: me)? again)\s+(?:in\s+)?(\d+|one|two|three|four|five|six|seven|eight|nine|ten|eleven|twelve|thirteen|fourteen|fifteen|sixteen|seventeen|eighteen|nineteen|twenty|thirty)\s+(day|days|week|weeks|month|months)(?:\s+(?:if|for)\s+([^.,]+))?"""),
            Regex("""(\d+|one|two|three|four|five|six|seven|eight|nine|ten|eleven|twelve|thirteen|fourteen|fifteen|sixteen|seventeen|eighteen|nineteen|twenty|thirty)\s+(day|days|week|weeks|month|months)\s+(?:follow[- ]?up|review)(?:\s+(?:for|if)\s+([^.,]+))?""")
        )

        private val FREQUENCY_EVIDENCE = mapOf(
            "OD" to listOf("once daily", "once a day", "daily", "od"),
            "BD" to listOf("twice daily", "twice a day", "bd", "bid"),
            "TDS" to listOf("three times daily", "three times a day", "three times", "tds", "tid"),
            "QDS" to listOf("four times daily", "four times a day", "four times", "qds", "qid"),
            "PRN" to listOf("as needed", "if needed", "when needed", "prn"),
            "STAT" to listOf("stat", "immediately", "now"),
            "WEEKLY" to listOf("weekly", "once a week")
        )

        /** EPI vaccine code → list of matching keywords (lowercase). */
        private val EPI_VACCINE_TABLE = mapOf(
            "BCG" to listOf("bcg", "bacillus calmette"),
            "OPV" to listOf("opv", "oral polio"),
            "PENTA" to listOf("penta", "pentavalent", "dpt", "diphtheria"),
            "PCV" to listOf("pcv", "pneumococcal"),
            "ROTA" to listOf("rota", "rotavirus"),
            "MEASLES" to listOf("measles", "mmr"),
            "HPV" to listOf("hpv", "human papilloma", "papillomavirus"),
            "TT" to listOf("tetanus", "tt"),
            "HEP_B" to listOf("hepatitis b", "hep b", "hepb"),
            "YELLOW_FEVER" to listOf("yellow fever"),
            "TYPHOID" to listOf("typhoid"),
            "INFLUENZA" to listOf("influenza", "flu vaccine"),
            "COVID" to listOf("covid", "coronavirus"),
            "RUBELLA" to listOf("rubella"),
            "MUMPS" to listOf("mumps"),
            "VARICELLA" to listOf("varicella", "chickenpox")
        )

        /** Display names for EPI vaccine codes. */
        private val EPI_VACCINE_DISPLAY = mapOf(
            "BCG" to "BCG",
            "OPV" to "Oral Polio",
            "PENTA" to "Pentavalent",
            "PCV" to "Pneumococcal",
            "ROTA" to "Rotavirus",
            "MEASLES" to "Measles",
            "HPV" to "HPV",
            "TT" to "Tetanus",
            "HEP_B" to "Hepatitis B",
            "YELLOW_FEVER" to "Yellow Fever",
            "TYPHOID" to "Typhoid",
            "INFLUENZA" to "Influenza",
            "COVID" to "COVID-19",
            "RUBELLA" to "Rubella",
            "MUMPS" to "Mumps",
            "VARICELLA" to "Varicella"
        )

        private val ROUTE_EVIDENCE = mapOf(
            "PO" to listOf("oral", "orally", "by mouth", "po"),
            "IV" to listOf("intravenous", "iv"),
            "IM" to listOf("intramuscular", "im"),
            "SC" to listOf("subcutaneous", "subcut", "sc"),
            "SL" to listOf("sublingual", "under the tongue"),
            "PR" to listOf("rectal"),
            "TOPICAL" to listOf("topical", "topically", "apply"),
            "INHALED" to listOf("inhale", "inhaled", "nebulize")
        )
    }
}
