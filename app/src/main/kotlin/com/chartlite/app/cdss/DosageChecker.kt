package com.chartlite.app.cdss

import com.chartlite.app.model.AlertSeverity
import com.chartlite.app.model.CDSSAlert
import com.chartlite.app.model.Medication

class DosageChecker {

    // Common max daily doses for frequently prescribed drugs (keys are lowercase for case-insensitive lookup)
    private val maxDailyDoses = mapOf(
        "amoxicillin" to MaxDose(3000f, "mg"),
        "paracetamol" to MaxDose(4000f, "mg"),
        "ibuprofen" to MaxDose(2400f, "mg"),
        "metformin" to MaxDose(2550f, "mg"),
        "amlodipine" to MaxDose(10f, "mg"),
        "enalapril" to MaxDose(40f, "mg"),
        "hydrochlorothiazide" to MaxDose(50f, "mg"),
        "metoprolol" to MaxDose(400f, "mg"),
        "omeprazole" to MaxDose(40f, "mg"),
        "prednisolone" to MaxDose(60f, "mg"),
        "ciprofloxacin" to MaxDose(1500f, "mg"),
        "azithromycin" to MaxDose(500f, "mg"),
        "doxycycline" to MaxDose(200f, "mg"),
        "fluconazole" to MaxDose(400f, "mg"),
        "morphine" to MaxDose(200f, "mg"),
        "tramadol" to MaxDose(400f, "mg"),
        "diclofenac" to MaxDose(150f, "mg")
    )

    fun check(medications: List<Medication>): List<CDSSAlert> {
        val alerts = mutableListOf<CDSSAlert>()

        for (med in medications) {
            val dose = med.dose ?: continue
            val unit = med.unit ?: continue
            val maxDose = maxDailyDoses[med.name.lowercase()] ?: continue

            if (!unit.equals(maxDose.unit, ignoreCase = true)) continue

            // Map frequency to daily multiplier. PRN/STAT/WEEKLY can't be reliably
            // converted to a daily dose — skip dosage check for those frequencies.
            val freqMultiplier = when (med.frequency?.uppercase()) {
                "OD", "DAILY", "NOCTE", "MANE" -> 1
                "BD", "BID" -> 2
                "TDS", "TID" -> 3
                "QDS", "QID" -> 4
                "WEEKLY", "PRN", "STAT", "SOS" -> null  // Cannot compute daily dose
                else -> 1  // Unknown frequency — assume OD as safe default
            }

            val dailyDose = if (freqMultiplier != null) dose * freqMultiplier else continue

            when {
                dailyDose > maxDose.value * 2 -> {
                    alerts.add(
                        CDSSAlert(
                            severity = AlertSeverity.CRITICAL,
                            category = "Dosage",
                            message = "${med.name}: daily dose ${dailyDose}${unit} exceeds safe maximum (${maxDose.value}${maxDose.unit}/day) by >2x",
                            relatedField = "medications"
                        )
                    )
                }
                dailyDose > maxDose.value -> {
                    alerts.add(
                        CDSSAlert(
                            severity = AlertSeverity.WARNING,
                            category = "Dosage",
                            message = "${med.name}: daily dose ${dailyDose}${unit} exceeds recommended maximum (${maxDose.value}${maxDose.unit}/day)",
                            relatedField = "medications"
                        )
                    )
                }
            }
        }

        return alerts
    }

    private data class MaxDose(val value: Float, val unit: String)
}
