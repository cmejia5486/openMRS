package com.chartlite.app.sms

import com.chartlite.app.model.Medication
import com.chartlite.app.model.StructuredEncounter
import com.chartlite.app.model.VitalSigns
import java.time.LocalDate
import java.time.ZoneOffset

/**
 * Aggregates health history across all encounters for a patient,
 * producing a compact summary suitable for inclusion in v2 SMS payloads.
 *
 * The goal: each SMS becomes a "portable health record" so the patient
 * can store only the latest SMS and have all significant clinical details.
 */
data class PatientHealthSummary(
    val totalVisits: Int,
    val chronicConditions: List<ChronicCondition>,
    val abnormalVitals: List<AbnormalVital>,
    val cumulativeAllergyFlags: Int,
    // v4 additions
    val latestWeight: Int = 0,            // kg
    val latestHeight: Int = 0,            // cm
    val weightZScore: Float = 0f,         // WHO z-score
    val heightZScore: Float = 0f,         // WHO z-score
    val hasGrowth: Boolean = false,
    val recentImmunizations: List<ImmunizationRecord> = emptyList(),
    val clinicalStatusFlags1: Int = 0,    // infectious/reproductive
    val clinicalStatusFlags2: Int = 0     // lab/risk
)

/** Immunization record for SMS encoding (from immunizations table). */
data class ImmunizationRecord(
    val vaccineCode: String,
    val doseNumber: Int
)

/** A diagnosis (ICD-10 code) that appeared in ≥2 encounters. */
data class ChronicCondition(
    val icd10Code: String,
    val occurrenceCount: Int
)

/** A single abnormal vital reading with the date it was recorded. */
data class AbnormalVital(
    val date: LocalDate,
    val type: VitalType,
    val rawValue: Int
)

enum class VitalType(val label: String) {
    SYSTOLIC_BP("Systolic BP"),
    DIASTOLIC_BP("Diastolic BP"),
    TEMPERATURE("Temperature"),
    PULSE("Pulse"),
    WEIGHT("Weight")
}

object PatientHealthSummaryBuilder {

    private const val MAX_CHRONIC_CONDITIONS = 5
    private const val MAX_ABNORMAL_VITALS = 3
    private const val MAX_IMMUNIZATIONS = 3

    // Allergy flag mapping — same as BinaryEncoder.ALLERGY_FLAGS
    private val ALLERGY_FLAGS = mapOf(
        "penicillin" to 7, "sulfa" to 6, "nsaid" to 5, "latex" to 4,
        "contrast" to 3, "opioid" to 2, "ace inhibitor" to 1
    )

    /**
     * Build a health summary from all encounters for a patient.
     *
     * @param allEncounters All encounters for this patient (including current), sorted newest-first
     * @param patientAllergies Patient-level allergies (authoritative source from PatientEntity)
     * @param growthData Optional latest growth measurements (weight, height, z-scores)
     * @param immunizationRecords Optional immunization history (most recent first)
     */
    fun buildSummary(
        allEncounters: List<StructuredEncounter>,
        patientAllergies: List<String> = emptyList(),
        growthData: GrowthData? = null,
        immunizationRecords: List<ImmunizationRecord> = emptyList()
    ): PatientHealthSummary {
        val statusFlags = computeClinicalStatusFlags(allEncounters)

        // Use provided immunization records, or fall back to extracting from encounters
        val effectiveImmunizations = immunizationRecords.ifEmpty {
            extractImmunizationsFromEncounters(allEncounters)
        }

        return PatientHealthSummary(
            totalVisits = allEncounters.size,
            chronicConditions = extractChronicConditions(allEncounters),
            abnormalVitals = extractAbnormalVitals(allEncounters),
            cumulativeAllergyFlags = computeCumulativeAllergyFlags(allEncounters, patientAllergies),
            latestWeight = growthData?.weightKg ?: 0,
            latestHeight = growthData?.heightCm ?: 0,
            weightZScore = growthData?.weightZScore ?: 0f,
            heightZScore = growthData?.heightZScore ?: 0f,
            hasGrowth = growthData != null,
            recentImmunizations = effectiveImmunizations.take(MAX_IMMUNIZATIONS),
            clinicalStatusFlags1 = statusFlags.first,
            clinicalStatusFlags2 = statusFlags.second
        )
    }

    /**
     * Extract immunization records from encounter-level immunization data.
     * Fallback when dedicated immunization table records aren't available.
     * Deduplicates by vaccine code, keeping the highest dose number.
     */
    private fun extractImmunizationsFromEncounters(
        allEncounters: List<StructuredEncounter>
    ): List<ImmunizationRecord> {
        return allEncounters
            .flatMap { it.immunizations }
            .groupBy { it.vaccineCode.uppercase() }
            .map { (code, records) ->
                ImmunizationRecord(
                    vaccineCode = code,
                    doseNumber = records.maxOf { it.doseNumber }
                )
            }
            .sortedByDescending { it.doseNumber }
    }

    /** Lightweight growth data holder for SMS summary building. */
    data class GrowthData(
        val weightKg: Int,
        val heightCm: Int,
        val weightZScore: Float,
        val heightZScore: Float
    )

    /**
     * Find diagnoses that appear in ≥2 encounters (chronic/recurring conditions).
     * Returns up to [MAX_CHRONIC_CONDITIONS], sorted by frequency descending.
     */
    private fun extractChronicConditions(encounters: List<StructuredEncounter>): List<ChronicCondition> {
        val codeFrequency = mutableMapOf<String, Int>()

        for (encounter in encounters) {
            // Count each unique code once per encounter (not per mention)
            val uniqueCodes = encounter.diagnoses.map { it.icd10Code }.distinct()
            for (code in uniqueCodes) {
                codeFrequency[code] = (codeFrequency[code] ?: 0) + 1
            }
        }

        return codeFrequency
            .filter { it.value >= 2 }
            .entries
            .sortedByDescending { it.value }
            .take(MAX_CHRONIC_CONDITIONS)
            .map { ChronicCondition(it.key, it.value) }
    }

    /**
     * Extract abnormal vital readings across all encounters.
     * Keeps the most recent abnormal reading per vital type.
     */
    private fun extractAbnormalVitals(encounters: List<StructuredEncounter>): List<AbnormalVital> {
        val mostRecentByType = mutableMapOf<VitalType, AbnormalVital>()

        // Process encounters newest-first so we keep the most recent
        val sorted = encounters.sortedByDescending { it.timestamp }

        for (encounter in sorted) {
            val vitals = encounter.vitals ?: continue
            val date = encounter.timestamp.atZone(ZoneOffset.UTC).toLocalDate()

            // Systolic BP: abnormal if ≥140 or ≤90
            // Encoded as (value - 60) to match BinaryEncoder wire format
            vitals.systolicBP?.let { sbp ->
                if ((sbp >= 140 || sbp <= 90) && VitalType.SYSTOLIC_BP !in mostRecentByType) {
                    mostRecentByType[VitalType.SYSTOLIC_BP] = AbnormalVital(
                        date, VitalType.SYSTOLIC_BP, (sbp - 60).coerceIn(0, 255)
                    )
                }
            }

            // Diastolic BP: abnormal if ≥90 or ≤60
            // Encoded as (value - 30) to match BinaryEncoder wire format
            vitals.diastolicBP?.let { dbp ->
                if ((dbp >= 90 || dbp <= 60) && VitalType.DIASTOLIC_BP !in mostRecentByType) {
                    mostRecentByType[VitalType.DIASTOLIC_BP] = AbnormalVital(
                        date, VitalType.DIASTOLIC_BP, (dbp - 30).coerceIn(0, 255)
                    )
                }
            }

            // Temperature: abnormal if ≥38.0 or ≤35.5
            vitals.temperature?.let { temp ->
                if ((temp >= 38.0f || temp <= 35.5f) && VitalType.TEMPERATURE !in mostRecentByType) {
                    mostRecentByType[VitalType.TEMPERATURE] = AbnormalVital(
                        date, VitalType.TEMPERATURE,
                        ((temp - 35.0f) * 10).toInt() // Same encoding as BinaryEncoder
                    )
                }
            }

            // Pulse: abnormal if >100 or <60
            vitals.pulse?.let { pulse ->
                if ((pulse > 100 || pulse < 60) && VitalType.PULSE !in mostRecentByType) {
                    mostRecentByType[VitalType.PULSE] = AbnormalVital(date, VitalType.PULSE, pulse)
                }
            }
        }

        return mostRecentByType.values
            .sortedBy { it.type.ordinal }
            .take(MAX_ABNORMAL_VITALS)
    }

    /**
     * Compute cumulative allergy flags by unioning allergy data
     * from ALL encounters plus patient-level allergies.
     */
    private fun computeCumulativeAllergyFlags(
        encounters: List<StructuredEncounter>,
        patientAllergies: List<String>
    ): Int {
        var flags = 0

        // Union all encounter-level allergies
        val allAllergies = encounters.flatMap { it.allergies } + patientAllergies

        for (allergy in allAllergies) {
            val lower = allergy.lowercase()
            for ((name, bit) in ALLERGY_FLAGS) {
                if (lower.contains(name)) {
                    flags = flags or (1 shl bit)
                }
            }
            // "other" flag at bit 0 for unrecognized allergies
            if (ALLERGY_FLAGS.none { (name, _) -> lower.contains(name) }) {
                flags = flags or 1
            }
        }

        return flags
    }

    /**
     * Derive clinical status flags from encounter diagnoses and investigations.
     * Returns Pair(flags1: infectious/reproductive, flags2: lab/risk).
     *
     * Flags1 bits: 7=HIV+, 6=HIV on ART, 5=TB active, 4=TB completed, 3=Pregnant,
     *              2=Syphilis+, 1=HepB+, 0=Malaria recent+
     * Flags2 bits: 7=Anemia(Hb<10), 6=Severe anemia(Hb<7), 5=Blood group known,
     *              4=Rh negative, 3=High glucose, 2=Proteinuria, 1=Sickle cell, 0=Malnutrition
     */
    private fun computeClinicalStatusFlags(encounters: List<StructuredEncounter>): Pair<Int, Int> {
        var flags1 = 0
        var flags2 = 0

        // Scan all diagnoses across encounters for ICD-10 codes that map to status flags
        val allDxCodes = encounters.flatMap { enc ->
            enc.diagnoses.map { it.icd10Code } + enc.suggestedDiagnoses.map { it.icd10Code }
        }.toSet()

        // HIV: B20-B24
        if (allDxCodes.any { it.startsWith("B2") && it.length >= 3 && it[2] in '0'..'4' }) {
            flags1 = flags1 or (1 shl 7) // HIV+
        }
        // TB: A15-A19
        if (allDxCodes.any { it.startsWith("A1") && it.length >= 3 && it[2] in '5'..'9' }) {
            flags1 = flags1 or (1 shl 5) // TB active
        }
        // Pregnancy: Z34, O00-O99
        if (allDxCodes.any { it.startsWith("Z34") || (it.startsWith("O") && it.length >= 3) }) {
            flags1 = flags1 or (1 shl 3) // Pregnant
        }
        // Syphilis: A50-A53
        if (allDxCodes.any { it.startsWith("A5") && it.length >= 3 && it[2] in '0'..'3' }) {
            flags1 = flags1 or (1 shl 2) // Syphilis+
        }
        // Hepatitis B: B16, B18.1
        if (allDxCodes.any { it.startsWith("B16") || it == "B18.1" }) {
            flags1 = flags1 or (1 shl 1) // HepB+
        }
        // Malaria: B50-B54
        if (allDxCodes.any { it.startsWith("B5") && it.length >= 3 && it[2] in '0'..'4' }) {
            flags1 = flags1 or (1 shl 0) // Malaria+
        }
        // Sickle cell: D57
        if (allDxCodes.any { it.startsWith("D57") }) {
            flags2 = flags2 or (1 shl 1) // Sickle cell
        }

        // Scan investigations for lab values
        for (encounter in encounters) {
            for (investigation in encounter.investigations) {
                val test = investigation.test.lowercase()
                val result = investigation.result?.lowercase() ?: continue

                // Hemoglobin / anemia
                if (test.contains("hb") || test.contains("haemoglobin") || test.contains("hemoglobin")) {
                    val hb = Regex("""\d+(?:\.\d+)?""").find(result)?.value?.toFloatOrNull()
                    if (hb != null && hb < 10f) flags2 = flags2 or (1 shl 7) // Anemia
                    if (hb != null && hb < 7f) flags2 = flags2 or (1 shl 6)  // Severe anemia
                }
                // Blood glucose
                if (test.contains("glucose") || test.contains("sugar") || test.contains("hba1c")) {
                    val glucose = Regex("""\d+(?:\.\d+)?""").find(result)?.value?.toFloatOrNull()
                    if (glucose != null && glucose > 11f) flags2 = flags2 or (1 shl 3) // High glucose
                }
                // Proteinuria
                if (test.contains("protein") && test.contains("urin")) {
                    if (result.contains("positive") || result.contains("+")) {
                        flags2 = flags2 or (1 shl 2) // Proteinuria
                    }
                }
            }
        }

        return Pair(flags1, flags2)
    }
}
