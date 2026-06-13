package com.chartlite.app.cdss

import android.content.Context
import android.util.Log
import com.chartlite.app.model.*
import com.google.gson.Gson
import com.google.gson.reflect.TypeToken

/**
 * Static Clinical Decision Support System.
 * Evaluates clinical rules on-device without connectivity.
 */
class StaticCDSS(private val context: Context) {

    private var allergyInteractions: Map<String, AllergyInteraction> = emptyMap()
    private var drugInteractions: List<DrugInteraction> = emptyList()
    private var vitalAlerts = VitalAlerts()
    private var dosageChecker = DosageChecker()
    @Volatile private var rulesLoaded = false

    private val gson = Gson()

    @Synchronized
    fun loadRules(forceReload: Boolean = false) {
        if (rulesLoaded && !forceReload) return
        loadAllergyRules()
        loadDrugInteractions()
        rulesLoaded = true
    }

    private fun ensureRulesLoaded() {
        if (!rulesLoaded) loadRules()
    }

    fun preload() {
        ensureRulesLoaded()
    }

    private fun loadAllergyRules() {
        try {
            val json = context.assets.open("cdss/allergy_interactions.json")
                .bufferedReader().use { it.readText() }
            val type = object : TypeToken<Map<String, AllergyInteraction>>() {}.type
            allergyInteractions = gson.fromJson(json, type) ?: emptyMap()
        } catch (e: Exception) {
            Log.w(TAG, "Failed to load allergy rules from assets, using hardcoded defaults", e)
            allergyInteractions = defaultAllergyInteractions()
        }
    }

    private fun loadDrugInteractions() {
        try {
            val json = context.assets.open("cdss/drug_interactions.json")
                .bufferedReader().use { it.readText() }
            val wrapper = gson.fromJson(json, DrugInteractionWrapper::class.java)
            drugInteractions = wrapper?.interactions ?: emptyList()
        } catch (e: Exception) {
            Log.w(TAG, "Failed to load drug interactions from assets, using hardcoded defaults", e)
            drugInteractions = defaultDrugInteractions()
        }
    }

    /**
     * Evaluate all CDSS rules for an encounter.
     * Returns list of alerts sorted by severity (critical first).
     */
    fun evaluate(encounter: StructuredEncounter, patientAllergies: List<String>): List<CDSSAlert> {
        ensureRulesLoaded()
        val alerts = mutableListOf<CDSSAlert>()

        // 1. Drug-allergy interactions (CRITICAL)
        alerts.addAll(checkAllergyInteractions(encounter.medications, patientAllergies))

        // 2. Drug-drug interactions
        alerts.addAll(checkDrugInteractions(encounter.medications))

        // 3. Dosage range checks
        alerts.addAll(dosageChecker.check(encounter.medications))

        // 4. Vital sign alerts
        encounter.vitals?.let { alerts.addAll(vitalAlerts.check(it)) }

        return alerts.sortedBy { alert ->
            when (alert.severity) {
                AlertSeverity.CRITICAL -> 0
                AlertSeverity.WARNING -> 1
                AlertSeverity.INFO -> 2
            }
        }
    }

    private fun checkAllergyInteractions(
        medications: List<Medication>,
        patientAllergies: List<String>
    ): List<CDSSAlert> {
        val alerts = mutableListOf<CDSSAlert>()

        for (allergy in patientAllergies) {
            val allergyLower = allergy.lowercase()
            val interaction = allergyInteractions[allergyLower] ?: continue

            for (med in medications) {
                val medNameLower = med.name.lowercase()
                // Match by formulary code OR drug name
                val isContraindicated = med.formularyCode in interaction.contraindicated ||
                    interaction.contraindicatedNames.any { medNameLower.contains(it.lowercase()) }

                if (isContraindicated) {
                    alerts.add(
                        CDSSAlert(
                            severity = AlertSeverity.CRITICAL,
                            category = "Drug-Allergy",
                            message = interaction.message.replace("{drug}", med.name),
                            relatedField = "medications"
                        )
                    )
                }
                // Check cross-reactivity: e.g. penicillin allergy → cephalosporin warning
                val isCrossReactive = (interaction.crossReactivity.isNotEmpty() &&
                    med.formularyCode in interaction.crossReactivity) ||
                    interaction.crossReactivityNames.any { medNameLower.contains(it.lowercase()) }

                if (isCrossReactive) {
                    alerts.add(
                        CDSSAlert(
                            severity = AlertSeverity.WARNING,
                            category = "Drug-Allergy Cross-Reactivity",
                            message = "Patient has ${interaction.allergen} allergy. ${med.name} may cross-react (~5-10% risk). Consider alternative.",
                            relatedField = "medications"
                        )
                    )
                }
            }
        }
        return alerts
    }

    private fun checkDrugInteractions(medications: List<Medication>): List<CDSSAlert> {
        val alerts = mutableListOf<CDSSAlert>()
        // Exclude empty codes — EncounterMerger can produce "" for ungrounded meds,
        // and many interaction rules also have empty drug codes. "" in codes would
        // match EVERY such rule, producing dozens of false positive alerts.
        val codes = medications.mapNotNull { it.formularyCode.ifBlank { null } }.toSet()
        val names = medications.map { it.name.lowercase() }.toSet()

        for (interaction in drugInteractions) {
            // Match by formulary code (if non-empty) OR drug name
            val match1 = (interaction.drug1.isNotBlank() && interaction.drug1 in codes) ||
                interaction.drugName1?.let { dn -> dn.isNotBlank() && names.any { it.contains(dn.lowercase()) } } == true
            val match2 = (interaction.drug2.isNotBlank() && interaction.drug2 in codes) ||
                interaction.drugName2?.let { dn -> dn.isNotBlank() && names.any { it.contains(dn.lowercase()) } } == true

            if (match1 && match2) {
                val severity = when (interaction.severity) {
                    "high" -> AlertSeverity.CRITICAL
                    "medium" -> AlertSeverity.WARNING
                    else -> AlertSeverity.INFO
                }
                alerts.add(
                    CDSSAlert(
                        severity = severity,
                        category = "Drug-Drug",
                        message = interaction.message,
                        relatedField = "medications"
                    )
                )
            }
        }
        return alerts
    }

    // Hardcoded defaults in case asset files aren't loaded
    private fun defaultAllergyInteractions(): Map<String, AllergyInteraction> = mapOf(
        "penicillin" to AllergyInteraction(
            allergen = "penicillin",
            contraindicated = listOf("0001", "0003", "0004", "0005"),
            crossReactivity = listOf("cephalosporins_1st_gen"),
            severity = "high",
            message = "Patient has penicillin allergy. {drug} is a penicillin-type antibiotic."
        ),
        "sulfa" to AllergyInteraction(
            allergen = "sulfa",
            contraindicated = listOf("0050", "0051"),
            crossReactivity = emptyList(),
            severity = "high",
            message = "Patient has sulfa allergy. {drug} contains sulfonamide."
        )
    )

    private fun defaultDrugInteractions(): List<DrugInteraction> = listOf(
        DrugInteraction(drug1 = "0100", drug2 = "0101", drugName1 = "warfarin", drugName2 = "aspirin", severity = "high", message = "Warfarin + Aspirin: increased bleeding risk."),
        DrugInteraction(drug1 = "0002", drug2 = "0200", drugName1 = "metformin", drugName2 = "contrast", severity = "high", message = "Hold Metformin 48hrs before/after contrast.")
    )

    private data class DrugInteractionWrapper(val interactions: List<DrugInteraction>)

    companion object {
        private const val TAG = "StaticCDSS"
    }
}
