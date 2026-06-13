package com.chartlite.app.protocols

import android.content.Context
import android.util.Log
import com.google.gson.Gson
import com.google.gson.reflect.TypeToken

/**
 * Clinical Protocol Engine — loads WHO/national treatment guidelines
 * and matches them to patient encounters based on ICD-10 codes.
 *
 * Designed for PHC clinicians in resource-limited settings:
 * - Step-by-step treatment guidance
 * - Red flags / danger sign alerts
 * - Pre-referral treatment recommendations
 * - Medication dosing with weight-based calculations
 * - Follow-up scheduling
 */
class ClinicalProtocolEngine(private val context: Context) {


    @Volatile private var protocols: List<ClinicalProtocol> = emptyList()
    private val gson = Gson()
    @Volatile private var protocolsLoaded = false

    companion object {
        private const val TAG = "ClinicalProtocolEngine"

    }

    /** Load protocols from bundled asset file. */
    @Synchronized
    fun loadProtocols(forceReload: Boolean = false) {
        if (protocolsLoaded && !forceReload) return
        try {
            val json = context.assets.open("protocols/clinical_protocols.json")
                .bufferedReader().use { it.readText() }
            val wrapper = gson.fromJson(json, ProtocolsWrapper::class.java)
            protocols = wrapper?.protocols ?: emptyList()
        } catch (e: Exception) {
            Log.w(TAG, "Failed to load protocols", e)
            protocols = emptyList()
        }
        protocolsLoaded = true
    }

    private fun ensureProtocolsLoaded() {
        if (!protocolsLoaded) loadProtocols()
    }

    fun preload() {
        ensureProtocolsLoaded()
    }

    /** Load from raw JSON string (useful for testing). */
    @Synchronized
    fun loadFromJson(json: String) {
        val wrapper = gson.fromJson(json, ProtocolsWrapper::class.java)
        protocols = wrapper?.protocols ?: emptyList()
        protocolsLoaded = true
    }

    /** Get all loaded protocols. */
    fun getAllProtocols(): List<ClinicalProtocol> {
        ensureProtocolsLoaded()
        return protocols
    }

    /** Get protocols by category. */
    fun getByCategory(category: String): List<ClinicalProtocol> {
        ensureProtocolsLoaded()
        return protocols.filter { it.category.equals(category, ignoreCase = true) }
    }

    /** Get all unique categories. */
    fun getCategories(): List<String> {
        ensureProtocolsLoaded()
        return protocols.map { it.category }.distinct().sorted()
    }

    /** Find protocols matching a specific ICD-10 code. */
    fun findByICD10(code: String): List<ClinicalProtocol> {
        ensureProtocolsLoaded()
        val normalizedCode = code.uppercase().trim()
        return protocols.filter { protocol ->
            protocol.icd10Codes.any { protocolCode ->
                // Match exact code or parent code (e.g., "B50" matches "B50.0")
                normalizedCode.startsWith(protocolCode) || protocolCode.startsWith(normalizedCode)
            }
        }
    }

    /**
     * Find all matching protocols for a list of ICD-10 codes from an encounter.
     * Returns a map of ICD-10 code → matching protocols.
     */
    fun findForEncounter(icd10Codes: List<String>): Map<String, List<ClinicalProtocol>> {
        val result = mutableMapOf<String, List<ClinicalProtocol>>()
        for (code in icd10Codes) {
            val matches = findByICD10(code)
            if (matches.isNotEmpty()) {
                result[code] = matches
            }
        }
        return result
    }

    /**
     * Get emergency protocols — those with urgency = EMERGENCY.
     * These are shown with highest priority.
     */
    fun getEmergencyProtocols(): List<ClinicalProtocol> =
        getAllProtocols().filter { it.urgency == "EMERGENCY" }

    /**
     * Get all red flags across all steps for a given protocol.
     * Useful for displaying a summary danger sign checklist.
     */
    fun getRedFlags(protocolId: String): List<String> =
        getAllProtocols().find { it.id == protocolId }
            ?.steps
            ?.flatMap { it.redFlags ?: emptyList() }
            ?: emptyList()

    /**
     * Get all medications recommended across all steps of a protocol.
     */
    fun getMedications(protocolId: String): List<ProtocolMedication> =
        getAllProtocols().find { it.id == protocolId }
            ?.steps
            ?.flatMap { it.medications ?: emptyList() }
            ?: emptyList()

    /**
     * Get referral criteria for a protocol.
     */
    fun getReferralCriteria(protocolId: String): List<String> =
        getAllProtocols().find { it.id == protocolId }
            ?.steps
            ?.flatMap { it.referralCriteria ?: emptyList() }
            ?: emptyList()

    /**
     * Get the follow-up schedule (earliest recommended follow-up in days).
     */
    fun getFollowUpDays(protocolId: String): Int? =
        getAllProtocols().find { it.id == protocolId }
            ?.steps
            ?.mapNotNull { it.followUpDays }
            ?.minOrNull()

    /**
     * Search protocols by keyword in name, category, or step content.
     */
    fun search(query: String): List<ClinicalProtocol> {
        ensureProtocolsLoaded()
        val q = query.lowercase().trim()
        if (q.isBlank()) return emptyList()
        return protocols.filter { protocol ->
            protocol.name.lowercase().contains(q) ||
            protocol.category.lowercase().contains(q) ||
            protocol.steps.any { step ->
                step.title.lowercase().contains(q) ||
                step.instructions.lowercase().contains(q)
            }
        }
    }

    /**
     * Filter protocols by patient applicability.
     * @param isAdult true if patient is ≥5 years
     * @param isFemale true if patient is female
     */
    fun filterByPatient(isAdult: Boolean, isFemale: Boolean): List<ClinicalProtocol> =
        getAllProtocols().filter { protocol ->
            when (protocol.applicableTo) {
                "ALL" -> true
                "ADULT" -> isAdult
                "PEDIATRIC" -> !isAdult
                "ADULT_FEMALE" -> isAdult && isFemale
                else -> true
            }
        }

}

// ── Data Models ──

data class ProtocolsWrapper(
    val version: String,
    val source: String,
    val protocols: List<ClinicalProtocol>
)

data class ClinicalProtocol(
    val id: String,
    val name: String,
    val category: String,
    val icd10Codes: List<String>,
    val applicableTo: String = "ALL",
    val urgency: String? = null,
    val steps: List<ProtocolStep>
)

data class ProtocolStep(
    val id: String,
    val title: String,
    val instructions: String,
    val requiredActions: List<String>? = null,
    val redFlags: List<String>? = null,
    val escalation: String? = null,
    val urgency: String? = null,
    val medications: List<ProtocolMedication>? = null,
    val alternatives: List<ProtocolAlternative>? = null,
    val criteria: Map<String, String>? = null,
    val followUpDays: Int? = null,
    val referralCriteria: List<String>? = null,
    val referTo: String? = null
)

data class ProtocolMedication(
    val name: String,
    val dose: String,
    val frequency: String? = null,
    val duration: String? = null,
    val indication: String? = null,
    val contraindications: List<String>? = null
)

data class ProtocolAlternative(
    val name: String,
    val indication: String? = null
)
