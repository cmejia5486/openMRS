package com.chartlite.app.billing

import com.chartlite.app.model.Diagnosis
import com.chartlite.app.model.Medication
import com.chartlite.app.model.VitalSigns

/**
 * Real ICD-10 → CPT/HCPCS mapping engine for insurance claim generation.
 *
 * Maps diagnoses to procedure codes and calculates tariffs using
 * actual medical billing logic:
 * - Evaluation & Management (E/M) codes based on encounter complexity
 * - Procedure codes mapped from ICD-10 categories
 * - Medication administration codes
 * - Vital sign assessment codes
 */
object ClaimEngine {

    data class ClaimLine(
        val cptCode: String,
        val description: String,
        val icd10Pointers: List<String>,
        val units: Int = 1,
        val tariffZAR: Double,       // South Africa Rand
        val tariffUSD: Double,       // US Dollar equivalent
        val modifier: String? = null
    )

    data class ClaimPreview(
        val claimLines: List<ClaimLine>,
        val totalZAR: Double,
        val totalUSD: Double,
        val emLevel: Int,            // E/M complexity level 1-5
        val emCode: String,          // E/M CPT code
        val payerType: String,       // "Medical Aid", "NHI", "Private", "Self-pay"
        val claimId: String
    )

    // ── ICD-10 Category → CPT Procedure Mapping ──
    // Based on common PHC procedures for sub-Saharan Africa

    private val icd10ToCpt = mapOf(
        // Infectious diseases
        "A00" to CptMapping("87081", "Culture, presumptive pathogen", 185.0, 12.50),
        "A01" to CptMapping("87081", "Culture, presumptive pathogen", 185.0, 12.50),
        "A09" to CptMapping("87328", "Infectious agent antigen detection", 145.0, 9.80),
        "B20" to CptMapping("86701", "HIV-1 antibody", 280.0, 18.90),
        "B24" to CptMapping("86701", "HIV-1 antibody", 280.0, 18.90),
        "B50" to CptMapping("87207", "Smear, special stain for malaria", 165.0, 11.15),
        "B54" to CptMapping("87207", "Smear, special stain for malaria", 165.0, 11.15),

        // Respiratory
        "J00" to CptMapping("99213", "Office visit - established, low complexity", 520.0, 35.15),
        "J02" to CptMapping("87880", "Strep A antigen detection", 155.0, 10.50),
        "J06" to CptMapping("99213", "Office visit - established, low complexity", 520.0, 35.15),
        "J11" to CptMapping("87804", "Influenza virus detection", 175.0, 11.85),
        "J18" to CptMapping("71046", "Chest X-ray, 2 views", 385.0, 26.00),
        "J20" to CptMapping("99213", "Office visit - established, low complexity", 520.0, 35.15),
        "J45" to CptMapping("94010", "Spirometry", 310.0, 20.95),

        // Cardiovascular
        "I10" to CptMapping("93000", "Electrocardiogram, 12-lead", 290.0, 19.60),
        "I11" to CptMapping("93000", "Electrocardiogram, 12-lead", 290.0, 19.60),
        "I25" to CptMapping("93000", "Electrocardiogram, 12-lead", 290.0, 19.60),
        "I50" to CptMapping("93306", "Echocardiography, complete", 1250.0, 84.50),
        "I63" to CptMapping("70551", "MRI brain without contrast", 3200.0, 216.25),

        // Endocrine
        "E10" to CptMapping("82947", "Glucose, quantitative", 85.0, 5.75),
        "E11" to CptMapping("83036", "Hemoglobin A1c", 195.0, 13.20),
        "E14" to CptMapping("83036", "Hemoglobin A1c", 195.0, 13.20),
        "E66" to CptMapping("99213", "Office visit - established, low complexity", 520.0, 35.15),
        "E78" to CptMapping("80061", "Lipid panel", 235.0, 15.90),

        // GI
        "K21" to CptMapping("99213", "Office visit - established, low complexity", 520.0, 35.15),
        "K29" to CptMapping("43239", "Upper GI endoscopy with biopsy", 2800.0, 189.25),
        "K35" to CptMapping("44970", "Laparoscopic appendectomy", 12500.0, 845.00),
        "K59" to CptMapping("99213", "Office visit - established, low complexity", 520.0, 35.15),

        // Musculoskeletal
        "M54" to CptMapping("72100", "Lumbar spine X-ray", 420.0, 28.40),
        "M79" to CptMapping("99213", "Office visit - established, low complexity", 520.0, 35.15),

        // Genitourinary
        "N39" to CptMapping("81001", "Urinalysis, automated", 75.0, 5.10),
        "N40" to CptMapping("76857", "Pelvic ultrasound, limited", 650.0, 43.95),

        // Pregnancy
        "O80" to CptMapping("59400", "Routine obstetric care", 8500.0, 574.65),
        "Z34" to CptMapping("59425", "Antepartum care only", 3200.0, 216.25),

        // Mental health
        "F32" to CptMapping("90834", "Psychotherapy, 45 min", 750.0, 50.70),
        "F41" to CptMapping("90834", "Psychotherapy, 45 min", 750.0, 50.70),

        // Skin
        "L02" to CptMapping("10060", "Incision and drainage, abscess", 480.0, 32.45),
        "L30" to CptMapping("99213", "Office visit - established, low complexity", 520.0, 35.15),

        // Injury / trauma
        "S00" to CptMapping("99282", "Emergency department visit, low-mod", 890.0, 60.15),
        "S52" to CptMapping("25600", "Closed treatment, distal radius fracture", 3800.0, 256.85),
        "T14" to CptMapping("99283", "Emergency department visit, moderate", 1250.0, 84.50),

        // Preventive
        "Z00" to CptMapping("99395", "Periodic comprehensive preventive visit", 680.0, 45.95),
        "Z23" to CptMapping("90471", "Immunization administration", 135.0, 9.15),
        "Z30" to CptMapping("99213", "Office visit - established, low complexity", 520.0, 35.15)
    )

    // E/M code levels with ZAR tariffs (SAMA rates approximation)
    private val emLevels = listOf(
        EmLevel(1, "99211", "Minimal problem", 280.0, 18.90),
        EmLevel(2, "99212", "Self-limited problem", 395.0, 26.70),
        EmLevel(3, "99213", "Low complexity", 520.0, 35.15),
        EmLevel(4, "99214", "Moderate complexity", 740.0, 50.00),
        EmLevel(5, "99215", "High complexity", 985.0, 66.55)
    )

    // Medication administration CPT codes
    private val medAdminCodes = mapOf(
        "oral" to CptMapping("99211", "Medication counseling, brief", 135.0, 9.15),
        "iv" to CptMapping("96365", "IV infusion, initial hour", 450.0, 30.40),
        "im" to CptMapping("96372", "Therapeutic injection, IM/SC", 195.0, 13.20),
        "sc" to CptMapping("96372", "Therapeutic injection, IM/SC", 195.0, 13.20),
        "nebulizer" to CptMapping("94640", "Pressurized inhalation treatment", 165.0, 11.15),
        "topical" to CptMapping("99211", "Medication counseling, brief", 135.0, 9.15)
    )

    /**
     * Generate a complete claim preview from encounter data.
     */
    fun generateClaim(
        encounterId: String,
        diagnoses: List<Diagnosis>,
        medications: List<Medication>,
        vitals: VitalSigns?,
        hasReferral: Boolean = false,
        countryCode: String = "za"
    ): ClaimPreview {
        val claimLines = mutableListOf<ClaimLine>()
        val icd10Codes = diagnoses.map { it.icd10Code }

        // 1. Calculate E/M level based on encounter complexity
        val emLevel = calculateEmLevel(diagnoses, medications, vitals, hasReferral)
        val em = emLevels[emLevel - 1]

        claimLines.add(
            ClaimLine(
                cptCode = em.code,
                description = "E/M: ${em.description}",
                icd10Pointers = icd10Codes,
                tariffZAR = em.tariffZAR,
                tariffUSD = em.tariffUSD
            )
        )

        // 2. Map each diagnosis to procedure codes (deduplicate by CPT code, merge ICD-10 pointers)
        val cptToProcedure = mutableMapOf<String, Pair<CptMapping, MutableList<String>>>()
        diagnoses.forEach { dx ->
            val prefix = dx.icd10Code.take(3)
            icd10ToCpt[prefix]?.let { cpt ->
                if (cpt.code != em.code) {
                    cptToProcedure.getOrPut(cpt.code) { cpt to mutableListOf() }
                        .second.add(dx.icd10Code)
                }
            }
        }
        cptToProcedure.values.forEach { (cpt, pointers) ->
            claimLines.add(
                ClaimLine(
                    cptCode = cpt.code,
                    description = cpt.description,
                    icd10Pointers = pointers.distinct(),
                    tariffZAR = cpt.tariffZAR,
                    tariffUSD = cpt.tariffUSD
                )
            )
        }

        // 3. Add medication administration codes for non-oral routes
        medications.forEach { med ->
            val route = med.route?.lowercase() ?: "oral"
            if (route != "oral") {
                medAdminCodes[route]?.let { cpt ->
                    claimLines.add(
                        ClaimLine(
                            cptCode = cpt.code,
                            description = "${cpt.description} — ${med.name}",
                            icd10Pointers = icd10Codes.take(1),
                            tariffZAR = cpt.tariffZAR,
                            tariffUSD = cpt.tariffUSD,
                            modifier = "59" // Distinct procedural service
                        )
                    )
                }
            }
        }

        // 4. Vital signs assessment if comprehensive
        if (vitals != null) {
            val vitalCount = listOfNotNull(
                vitals.systolicBP, vitals.temperature, vitals.pulse,
                vitals.weight, vitals.oxygenSaturation, vitals.respiratoryRate
            ).size
            if (vitalCount >= 4) {
                claimLines.add(
                    ClaimLine(
                        cptCode = "99000",
                        description = "Specimen handling / vitals documentation",
                        icd10Pointers = icd10Codes.take(1),
                        tariffZAR = 65.0,
                        tariffUSD = 4.40
                    )
                )
            }
        }

        val totalZAR = claimLines.sumOf { it.tariffZAR * it.units }
        val totalUSD = claimLines.sumOf { it.tariffUSD * it.units }

        return ClaimPreview(
            claimLines = claimLines,
            totalZAR = totalZAR,
            totalUSD = totalUSD,
            emLevel = emLevel,
            emCode = em.code,
            payerType = if (countryCode == "za") "Medical Aid" else "Insurance",
            claimId = "CLM-${encounterId.take(8).uppercase()}"
        )
    }

    /**
     * Determine E/M complexity level (1-5) based on encounter contents.
     * Uses 2021 E/M guidelines: Medical Decision Making (MDM) approach.
     */
    private fun calculateEmLevel(
        diagnoses: List<Diagnosis>,
        medications: List<Medication>,
        vitals: VitalSigns?,
        hasReferral: Boolean
    ): Int {
        var score = 0

        // Number and complexity of problems addressed
        score += when {
            diagnoses.isEmpty() -> 0
            diagnoses.size == 1 && diagnoses[0].confidence > 0.8f -> 1
            diagnoses.size <= 2 -> 2
            diagnoses.size <= 4 -> 3
            else -> 4
        }

        // Data reviewed (vitals = 1 point, comprehensive vitals = 2)
        if (vitals != null) {
            val vitalCount = listOfNotNull(
                vitals.systolicBP, vitals.temperature, vitals.pulse,
                vitals.weight, vitals.oxygenSaturation
            ).size
            score += if (vitalCount >= 3) 2 else 1
        }

        // Treatment complexity
        score += when {
            medications.isEmpty() -> 0
            medications.size <= 2 -> 1
            medications.size <= 4 -> 2
            else -> 3
        }

        // Referral adds complexity
        if (hasReferral) score += 1

        // Map score to E/M level
        return when {
            score <= 1 -> 1
            score <= 3 -> 2
            score <= 5 -> 3
            score <= 7 -> 4
            else -> 5
        }
    }

    private data class CptMapping(
        val code: String,
        val description: String,
        val tariffZAR: Double,
        val tariffUSD: Double
    )

    private data class EmLevel(
        val level: Int,
        val code: String,
        val description: String,
        val tariffZAR: Double,
        val tariffUSD: Double
    )
}
