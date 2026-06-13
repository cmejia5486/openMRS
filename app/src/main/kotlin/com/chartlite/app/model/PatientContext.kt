package com.chartlite.app.model

import android.util.Log
import com.chartlite.app.database.entity.PatientEntity
import com.google.gson.Gson
import com.google.gson.reflect.TypeToken

/**
 * Aggregated patient history loaded from prior encounters and patient record.
 * Displayed as a context banner when starting a new encounter, so the clinician
 * sees known allergies, active medications, and chronic conditions immediately.
 */
data class PatientContext(
    val knownAllergies: List<String>,
    val activeMedications: List<ActiveMedication>,
    val chronicConditions: List<ChronicDiagnosis>,
    val visitCount: Int
) {
    val hasHistory: Boolean get() = visitCount > 0 ||
            knownAllergies.isNotEmpty() ||
            activeMedications.isNotEmpty() ||
            chronicConditions.isNotEmpty()
}

/** A medication seen in recent encounters (name + last dose info). */
data class ActiveMedication(
    val name: String,
    val dose: String?,
    val frequency: String?,
    val encounterCount: Int
)

/** A diagnosis (ICD-10) that appeared in ≥2 encounters (chronic/recurring). */
data class ChronicDiagnosis(
    val icd10Code: String,
    val description: String,
    val occurrenceCount: Int
)

object PatientContextBuilder {

    private const val TAG = "PatientContext"

    /**
     * Build patient context from local DB data.
     * Reuses the same aggregation logic as PatientSummaryScreen helpers.
     */
    fun build(
        patient: PatientEntity?,
        encounters: List<StructuredEncounter>
    ): PatientContext {
        return PatientContext(
            knownAllergies = collectAllergies(patient, encounters),
            activeMedications = collectActiveMedications(encounters),
            chronicConditions = collectChronicConditions(encounters),
            visitCount = encounters.size
        )
    }

    /** Union of patient-level + encounter-level allergies across all encounters. */
    private fun collectAllergies(
        patient: PatientEntity?,
        encounters: List<StructuredEncounter>
    ): List<String> {
        val allergies = mutableSetOf<String>()

        // Patient-level allergies (authoritative source)
        patient?.let { p ->
            if (p.allergies.isNotBlank() && p.allergies != "[]") {
                try {
                    val type = object : TypeToken<List<String>>() {}.type
                    val list: List<String> = Gson().fromJson(p.allergies, type)
                    allergies.addAll(list.filter { it.isNotBlank() })
                } catch (e: Exception) {
                    Log.w(TAG, "Failed to parse patient allergies", e)
                }
            }
        }

        // Encounter-level allergies
        encounters.forEach { enc ->
            allergies.addAll(enc.allergies.filter { it.isNotBlank() })
        }

        return allergies.toList().sorted()
    }

    /** Medications from the most recent encounter (likely "active" / current regimen). */
    private fun collectActiveMedications(
        encounters: List<StructuredEncounter>
    ): List<ActiveMedication> {
        if (encounters.isEmpty()) return emptyList()

        // Count how many encounters each medication appears in
        val medCounts = mutableMapOf<String, Int>()
        encounters.forEach { enc ->
            enc.medications.map { it.name.lowercase() }.distinct().forEach { name ->
                medCounts[name] = (medCounts[name] ?: 0) + 1
            }
        }

        // Use the most recent encounter's medications as the "active" set
        val mostRecent = encounters.maxByOrNull { it.timestamp } ?: return emptyList()
        return mostRecent.medications.map { med ->
            ActiveMedication(
                name = med.name,
                dose = med.dose?.let { "${it}${med.unit ?: "mg"}" },
                frequency = med.frequency,
                encounterCount = medCounts[med.name.lowercase()] ?: 1
            )
        }
    }

    /** Diagnoses appearing in ≥2 encounters (chronic/recurring conditions). */
    private fun collectChronicConditions(
        encounters: List<StructuredEncounter>
    ): List<ChronicDiagnosis> {
        val codeFreq = mutableMapOf<String, Pair<String, Int>>() // code -> (description, count)

        encounters.forEach { enc ->
            // Only count clinician-confirmed diagnoses (not LLM suggestions)
            val uniqueCodes = enc.diagnoses.map { it.icd10Code }.distinct()
            for (code in uniqueCodes) {
                if (code.isBlank()) continue
                val desc = enc.diagnoses.firstOrNull { it.icd10Code == code }?.description ?: code
                val (_, count) = codeFreq[code] ?: (desc to 0)
                codeFreq[code] = desc to (count + 1)
            }
        }

        return codeFreq
            .filter { it.value.second >= 2 }
            .entries
            .sortedByDescending { it.value.second }
            .take(5)
            .map { (code, pair) -> ChronicDiagnosis(code, pair.first, pair.second) }
    }
}
