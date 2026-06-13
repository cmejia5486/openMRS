package com.chartlite.app.extraction

import com.chartlite.app.model.Diagnosis
import com.chartlite.app.model.Medication
import com.chartlite.app.model.StructuredEncounter
import com.chartlite.app.model.VitalSigns

/**
 * Deterministically renders a clinician-facing draft note from structured fields.
 *
 * This is used on low-RAM devices where the small on-device model is stronger at
 * structured extraction than free-form note writing.
 */
object StructuredDraftNoteRenderer {

    fun render(encounter: StructuredEncounter): String? {
        val sections = buildList {
            section("Chief Complaint", chiefComplaintLines(encounter))?.let(::add)
            section("Examination Findings", encounter.examFindings.asBullets())?.let(::add)
            section("Vitals", vitalsLines(encounter.vitals))?.let(::add)
            section("Investigations", encounter.investigations.mapNotNull { inv ->
                inv.test.trim().takeIf { it.isNotBlank() }?.let { test ->
                    inv.result?.trim()?.takeIf { it.isNotBlank() }?.let { "$test: $it" } ?: test
                }
            })?.let(::add)
            section("Assessment", assessmentLines(encounter))?.let(::add)
            section("Plan", planLines(encounter))?.let(::add)
            section("Follow-up", followUpLines(encounter))?.let(::add)
            section("Allergies", encounter.allergies.asBullets())?.let(::add)
            section("Social History", encounter.socialHistory.asBullets())?.let(::add)
        }

        if (sections.isEmpty()) return null

        return buildString {
            sections.forEachIndexed { index, (title, lines) ->
                appendLine("## $title")
                lines.forEach { appendLine("- $it") }
                if (index != sections.lastIndex) {
                    appendLine()
                }
            }
        }.trim()
    }

    private fun chiefComplaintLines(encounter: StructuredEncounter): List<String> {
        val chiefComplaint = encounter.freeTextNote.trim()
            .takeIf { it.isNotBlank() }
            ?: encounter.smsSummary?.trim()?.takeIf { it.isNotBlank() }
        return listOfNotNull(chiefComplaint)
    }

    private fun vitalsLines(vitals: VitalSigns?): List<String> {
        if (vitals == null) return emptyList()
        return buildList {
            if (vitals.systolicBP != null || vitals.diastolicBP != null) {
                val sys = vitals.systolicBP?.toString() ?: "--"
                val dia = vitals.diastolicBP?.toString() ?: "--"
                add("Blood pressure: $sys/$dia mmHg")
            }
            vitals.temperature?.let { add("Temperature: ${"%.1f".format(it)} C") }
            vitals.pulse?.let { add("Pulse: $it bpm") }
            vitals.respiratoryRate?.let { add("Respiratory rate: $it breaths/min") }
            vitals.oxygenSaturation?.let { add("SpO2: $it%") }
            vitals.weight?.let { add("Weight: ${"%.1f".format(it)} kg") }
            vitals.height?.let { add("Height: ${"%.0f".format(it)} cm") }
        }
    }

    private fun assessmentLines(encounter: StructuredEncounter): List<String> = buildList {
        encounter.diagnoses
            .mapNotNull { diagnosisLabel(it) }
            .distinct()
            .forEach(::add)

        encounter.suggestedDiagnoses
            .mapNotNull { diagnosisLabel(it) }
            .distinct()
            .filterNot { it in this }
            .forEach { add("Suggested diagnosis: $it") }
    }

    private fun planLines(encounter: StructuredEncounter): List<String> = buildList {
        encounter.plan.asBullets().forEach(::add)
        encounter.medications
            .mapNotNull(::medicationLine)
            .forEach { add("Medication: $it") }
        encounter.immunizations
            .mapNotNull { imm ->
                imm.vaccineName.trim().takeIf { it.isNotBlank() }?.let { name ->
                    "Immunization: $name dose ${imm.doseNumber}"
                }
            }
            .forEach(::add)
        encounter.referral?.let { referral ->
            val reason = referral.reason?.trim()?.takeIf { it.isNotBlank() }
            val specialty = referral.specialty?.trim()?.takeIf { it.isNotBlank() }
            add(
                buildString {
                    append("Referral: ")
                    append(specialty ?: referral.type)
                    reason?.let {
                        append(" — ")
                        append(it)
                    }
                }
            )
        }
    }

    private fun followUpLines(encounter: StructuredEncounter): List<String> {
        val followUp = encounter.followUp ?: return emptyList()
        val reason = followUp.reason?.trim()?.takeIf { it.isNotBlank() }
        return listOf(
            buildString {
                append("Review in ${followUp.days} day")
                if (followUp.days != 1) append('s')
                reason?.let {
                    append(" — ")
                    append(it)
                }
            }
        )
    }

    private fun medicationLine(medication: Medication): String? {
        val name = medication.name.trim().takeIf { it.isNotBlank() } ?: return null
        val dose = buildString {
            medication.dose?.let {
                append(
                    if (it % 1f == 0f) {
                        it.toInt().toString()
                    } else {
                        "%.1f".format(it)
                    }
                )
            }
            medication.unit?.trim()?.takeIf { it.isNotBlank() }?.let {
                if (isNotEmpty()) append(' ')
                append(it)
            }
        }.trim()
        val extra = listOfNotNull(
            medication.route?.trim()?.takeIf { it.isNotBlank() },
            medication.frequency?.trim()?.takeIf { it.isNotBlank() },
            medication.duration?.let { "$it day" + if (it == 1) "" else "s" }
        )
        return buildString {
            append(name)
            if (dose.isNotBlank()) {
                append(' ')
                append(dose)
            }
            if (extra.isNotEmpty()) {
                append(" — ")
                append(extra.joinToString(", "))
            }
        }
    }

    private fun diagnosisLabel(diagnosis: Diagnosis): String? =
        diagnosis.description.trim().takeIf { it.isNotBlank() }
            ?: diagnosis.icd10Code.trim().takeIf { it.isNotBlank() }

    private fun section(title: String, lines: List<String>): Pair<String, List<String>>? {
        val cleaned = lines.map { it.trim() }.filter { it.isNotBlank() }
        return cleaned.takeIf { it.isNotEmpty() }?.let { title to it }
    }

    private fun List<String>.asBullets(): List<String> =
        map { it.trim() }.filter { it.isNotBlank() }
}
