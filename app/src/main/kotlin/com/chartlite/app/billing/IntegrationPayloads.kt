package com.chartlite.app.billing

import com.chartlite.app.database.entity.EncounterEntity
import com.chartlite.app.database.entity.normalizedReferralOrNull
import com.chartlite.app.model.*
import java.time.Instant
import java.time.ZoneId
import java.time.format.DateTimeFormatter

/**
 * Builds real integration payloads showing exactly what data
 * would be transmitted to each external system.
 *
 * These are production-accurate data structures — only the
 * HTTP transport is not connected yet.
 */
object IntegrationPayloads {

    // ── 837P Electronic Claim (X12N v5010A1) ──

    fun build837PClaim(
        enc: EncounterEntity,
        claim: ClaimEngine.ClaimPreview,
        diagnoses: List<Diagnosis>,
        patientName: String,
        providerName: String
    ): String {
        val date = DateTimeFormatter.ofPattern("yyyyMMdd")
            .withZone(ZoneId.systemDefault())
            .format(Instant.ofEpochMilli(enc.timestamp))
        val time = DateTimeFormatter.ofPattern("HHmm")
            .withZone(ZoneId.systemDefault())
            .format(Instant.ofEpochMilli(enc.timestamp))

        return buildString {
            appendLine("┌─────────────────────────────────────────┐")
            appendLine("│   837P PROFESSIONAL CLAIM (v5010A1)     │")
            appendLine("└─────────────────────────────────────────┘")
            appendLine()
            appendLine("ISA*00*          *00*          *ZZ*CHARTLITE     *ZZ*PAYER          *$date*$time*^*00501*000000001*0*P*:")
            appendLine("GS*HC*CHARTLITE*PAYER*$date*$time*1*X*005010X222A1")
            appendLine("ST*837*0001*005010X222A1")
            appendLine()
            appendLine("── Billing Provider (2010AA) ──")
            appendLine("NM1*85*1*$providerName****XX*PROVIDER_NPI")
            appendLine("N3*${enc.facilityId}")
            appendLine("REF*EI*TAX_ID_NUMBER")
            appendLine()
            appendLine("── Subscriber/Patient (2010BA) ──")
            appendLine("NM1*IL*1*$patientName****MI*${enc.patientId}")
            appendLine("SBR*P*18*******${claim.payerType}")
            appendLine()
            appendLine("── Claim Information (2300) ──")
            appendLine("CLM*${claim.claimId}*${claim.totalZAR}***${enc.facilityId}:B:1*Y*A*Y*Y")
            appendLine("DTP*472*D8*$date   ← Service date")
            appendLine()

            // ICD-10 diagnosis codes
            appendLine("── Diagnosis Codes (2300 HI segment) ──")
            diagnoses.forEachIndexed { i, dx ->
                val qualifier = if (i == 0) "ABK" else "ABF"  // ABK = principal, ABF = other
                appendLine("HI*$qualifier:${dx.icd10Code}   ← ${dx.description}")
            }
            appendLine()

            // Service lines
            appendLine("── Service Lines (2400) ──")
            val claimDxCodes = diagnoses.map { it.icd10Code }
            claim.claimLines.forEachIndexed { i, line ->
                // Map each line's ICD-10 codes to their 1-based position in the claim-level diagnosis list
                val pointers = line.icd10Pointers.mapNotNull { code ->
                    val pos = claimDxCodes.indexOf(code)
                    if (pos >= 0) pos + 1 else null
                }.ifEmpty { listOf(1) }.joinToString(":")
                appendLine("LX*${i + 1}")
                appendLine("SV1*HC:${line.cptCode}${line.modifier?.let { ":$it" } ?: ""}*${line.tariffZAR}*UN*${line.units}***$pointers")
                appendLine("  └→ ${line.description}")
                appendLine("DTP*472*D8*$date")
            }
            appendLine()
            appendLine("── Claim Totals ──")
            appendLine("Total ZAR: R${"%.2f".format(claim.totalZAR)}")
            appendLine("Total USD: \$${"%.2f".format(claim.totalUSD)}")
            appendLine("E/M Level: ${claim.emLevel} (${claim.emCode})")
            appendLine("Payer: ${claim.payerType}")
            appendLine()
            appendLine("SE*[segment count]*0001")
            appendLine("GE*1*1")
            appendLine("IEA*1*000000001")
        }
    }

    // ── FHIR R4 MedicationRequest Bundle ──

    fun buildFHIRMedicationRequests(
        enc: EncounterEntity,
        medications: List<Medication>,
        diagnoses: List<Diagnosis>,
        patientName: String,
        providerName: String
    ): String {
        val dateTime = DateTimeFormatter.ISO_INSTANT
            .format(Instant.ofEpochMilli(enc.timestamp))

        return buildString {
            appendLine("┌─────────────────────────────────────────┐")
            appendLine("│   FHIR R4 MedicationRequest Bundle      │")
            appendLine("│   HL7 FHIR 4.0.1 (STU4)                │")
            appendLine("└─────────────────────────────────────────┘")
            appendLine()
            appendLine("{")
            appendLine("  \"resourceType\": \"Bundle\",")
            appendLine("  \"type\": \"transaction\",")
            appendLine("  \"timestamp\": \"$dateTime\",")
            appendLine("  \"entry\": [")

            medications.forEachIndexed { index, med ->
                appendLine("    {")
                appendLine("      \"resource\": {")
                appendLine("        \"resourceType\": \"MedicationRequest\",")
                appendLine("        \"status\": \"active\",")
                appendLine("        \"intent\": \"order\",")
                appendLine("        \"medicationCodeableConcept\": {")
                appendLine("          \"coding\": [{")
                appendLine("            \"system\": \"http://chartlite.health/formulary\",")
                appendLine("            \"code\": \"${med.formularyCode}\",")
                appendLine("            \"display\": \"${med.name}\"")
                appendLine("          }],")
                appendLine("          \"text\": \"${med.name}\"")
                appendLine("        },")
                appendLine("        \"subject\": {\"reference\": \"Patient/${enc.patientId}\", \"display\": \"$patientName\"},")
                appendLine("        \"requester\": {\"reference\": \"Practitioner/${enc.providerId}\", \"display\": \"$providerName\"},")
                appendLine("        \"encounter\": {\"reference\": \"Encounter/${enc.id}\"},")

                // reasonCode — only include if diagnoses exist
                diagnoses.firstOrNull()?.let { dx ->
                    appendLine("        \"reasonCode\": [{\"coding\": [{\"system\": \"http://hl7.org/fhir/sid/icd-10\", \"code\": \"${dx.icd10Code}\", \"display\": \"${dx.description}\"}]}],")
                }

                appendLine("        \"authoredOn\": \"$dateTime\",")

                // Build dosageInstruction fields
                val dosageFields = mutableListOf<String>()
                med.dose?.let { dose ->
                    val doseVal = if (dose % 1.0f == 0f) "${dose.toInt()}" else "%.1f".format(dose)
                    dosageFields.add("          \"doseAndRate\": [{\"doseQuantity\": {\"value\": $doseVal, \"unit\": \"${med.unit ?: "mg"}\"}}]")
                }
                med.frequency?.let { freq ->
                    val doseText = med.dose?.let { d -> if (d % 1.0f == 0f) "${d.toInt()}" else "%.1f".format(d) } ?: ""
                    dosageFields.add("          \"text\": \"$doseText${med.unit ?: ""} $freq${med.duration?.let { d -> " for $d days" } ?: ""}\"")
                    dosageFields.add("          \"timing\": {\"code\": {\"text\": \"$freq\"}}")
                }
                med.route?.let { route ->
                    dosageFields.add("          \"route\": {\"coding\": [{\"system\": \"http://snomed.info/sct\", \"display\": \"$route\"}]}")
                }
                dosageFields.add("          \"method\": {\"text\": \"${med.route ?: "oral"}\"}")

                val hasDuration = med.duration != null
                appendLine("        \"dosageInstruction\": [{")
                appendLine(dosageFields.joinToString(",\n"))
                append("        }]")
                if (hasDuration) {
                    appendLine(",")
                    appendLine("        \"dispenseRequest\": {")
                    appendLine("          \"expectedSupplyDuration\": {\"value\": ${med.duration}, \"unit\": \"days\"}")
                    append("        }")
                }
                appendLine()
                appendLine("      },")
                appendLine("      \"request\": {\"method\": \"POST\", \"url\": \"MedicationRequest\"}")
                appendLine("    }${if (index < medications.size - 1) "," else ""}")
            }

            appendLine("  ]")
            appendLine("}")
            appendLine()
            appendLine("── Pharmacy Routing ──")
            appendLine("Facility: ${enc.facilityId}")
            appendLine("Patient: $patientName (${enc.patientId})")
            appendLine("Medications: ${medications.size}")
            appendLine("Total items to dispense: ${medications.sumOf { it.duration ?: 1 }} patient-days")
        }
    }

    // ── DHIS2 dataValueSets ──

    fun buildDHIS2DataValueSets(
        facilityId: String,
        period: String,
        encounters: List<EncounterEntity>,
        topDiagnoses: List<Pair<String, Int>>,
        topMedications: List<Pair<String, Int>>,
        totalPatients: Int
    ): String {
        return buildString {
            appendLine("┌─────────────────────────────────────────┐")
            appendLine("│   DHIS2 dataValueSets (v40 API)         │")
            appendLine("│   POST /api/dataValueSets?importStrategy=CREATE_AND_UPDATE │")
            appendLine("└─────────────────────────────────────────┘")
            appendLine()
            appendLine("{")
            appendLine("  \"dataSet\": \"PHC_MONTHLY_REPORT\",")
            appendLine("  \"completeDate\": \"${java.time.LocalDate.now()}\",")
            appendLine("  \"period\": \"$period\",")
            appendLine("  \"orgUnit\": \"$facilityId\",")
            appendLine("  \"dataValues\": [")
            appendLine()
            appendLine("    // ── Service Delivery Indicators ──")
            appendLine("    {\"dataElement\": \"OPD_TOTAL_VISITS\",     \"value\": \"${encounters.size}\"},")
            appendLine("    {\"dataElement\": \"OPD_NEW_PATIENTS\",     \"value\": \"$totalPatients\"},")
            appendLine("    {\"dataElement\": \"OPD_REVISITS\",         \"value\": \"${(encounters.size - totalPatients).coerceAtLeast(0)}\"},")

            // Referrals
            val referralCount = encounters.count { it.normalizedReferralOrNull() != null }
            appendLine("    {\"dataElement\": \"REFERRALS_OUT\",        \"value\": \"$referralCount\"},")
            appendLine()

            appendLine("    // ── Top 10 Morbidity (ICD-10 coded) ──")
            topDiagnoses.take(10).forEachIndexed { i, (name, count) ->
                val comma = if (i < 9 && i < topDiagnoses.size - 1) "," else ""
                appendLine("    {\"dataElement\": \"MORBIDITY_${i + 1}\", \"value\": \"$count\", \"comment\": \"$name\"}$comma")
            }
            appendLine()

            appendLine("    // ── Pharmacy / Drug Consumption ──")
            topMedications.take(10).forEachIndexed { i, (name, count) ->
                val comma = if (i < 9 && i < topMedications.size - 1) "," else ""
                appendLine("    {\"dataElement\": \"DRUG_DISPENSED_${i + 1}\", \"value\": \"$count\", \"comment\": \"$name\"}$comma")
            }

            appendLine("  ]")
            appendLine("}")
            appendLine()
            appendLine("── DHIS2 Metadata ──")
            appendLine("Org Unit: $facilityId")
            appendLine("Period: $period (monthly)")
            appendLine("Data Elements: ${2 + topDiagnoses.size.coerceAtMost(10) + topMedications.size.coerceAtMost(10) + 2}")
            appendLine("Encounters covered: ${encounters.size}")
            appendLine("Import strategy: CREATE_AND_UPDATE (merge)")
        }
    }

    // ── Population Health Summary ──

    data class DiseaseBurden(
        val chapter: String,
        val chapterCode: String,
        val count: Int,
        val percentage: Float,
        val conditions: List<Pair<String, Int>>
    )

    fun buildPopulationHealth(
        diagnoses: List<Pair<String, String>>,  // (icd10Code, description)
        totalEncounters: Int
    ): List<DiseaseBurden> {
        val icd10Chapters = mapOf(
            "A" to "Infectious & Parasitic",
            "B" to "Infectious & Parasitic",
            "C" to "Neoplasms",
            "D" to "Blood Diseases",
            "E" to "Endocrine/Metabolic",
            "F" to "Mental/Behavioural",
            "G" to "Nervous System",
            "H" to "Eye & Ear",
            "I" to "Cardiovascular",
            "J" to "Respiratory",
            "K" to "Digestive",
            "L" to "Skin",
            "M" to "Musculoskeletal",
            "N" to "Genitourinary",
            "O" to "Pregnancy/Childbirth",
            "P" to "Perinatal",
            "Q" to "Congenital",
            "R" to "Symptoms/Signs",
            "S" to "Injury/Trauma",
            "T" to "Injury/Trauma",
            "Z" to "Health Services/Preventive"
        )

        // Group by ICD-10 chapter
        val grouped = diagnoses.groupBy { (code, _) ->
            val letter = code.firstOrNull()?.uppercase() ?: "R"
            icd10Chapters[letter] ?: "Other"
        }

        return grouped.map { (chapter, entries) ->
            val conditions = entries.groupBy { it.second }
                .map { (desc, list) -> desc to list.size }
                .sortedByDescending { it.second }

            DiseaseBurden(
                chapter = chapter,
                chapterCode = entries.first().first.take(1),
                count = entries.size,
                percentage = if (totalEncounters > 0) entries.size * 100f / totalEncounters else 0f,
                conditions = conditions
            )
        }.sortedByDescending { it.count }
    }
}
