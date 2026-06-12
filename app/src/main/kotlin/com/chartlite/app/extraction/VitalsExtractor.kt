package com.chartlite.app.extraction

import com.chartlite.app.model.VitalSigns

class VitalsExtractor {

    fun extract(transcript: String): VitalSigns? {
        val lower = transcript.lowercase()

        val systolic = extractBPSystolic(lower)
        val diastolic = extractBPDiastolic(lower)
        val temperature = extractTemperature(lower)
        val pulse = extractPulse(lower)
        val weight = extractWeight(lower)
        val height = extractHeight(lower)
        val respRate = extractRespiratoryRate(lower)
        val spo2 = extractSpO2(lower)

        // Return null if no vitals found
        if (systolic == null && diastolic == null && temperature == null && pulse == null &&
            weight == null && height == null && respRate == null && spo2 == null) {
            return null
        }

        return VitalSigns(
            systolicBP = systolic?.takeIf { it in 60..260 },
            diastolicBP = diastolic?.takeIf { it in 30..160 },
            temperature = temperature?.takeIf { it in 34.0f..42.0f },
            pulse = pulse?.takeIf { it in 30..220 },
            weight = weight?.takeIf { it in 1f..300f },
            height = height?.takeIf { it in 30f..250f },
            respiratoryRate = respRate?.takeIf { it in 5..60 },
            oxygenSaturation = spo2?.takeIf { it in 50..100 }
        )
    }

    private fun extractBPSystolic(text: String): Int? {
        val patterns = listOf(
            // With BP keyword prefix — mmHg suffix optional
            Regex("""(?:bp|blood pressure)\s*(?:is\s+)?(\d{2,3})\s*(?:over|on|/)\s*(\d{2,3})"""),
            // Without keyword — require mmHg suffix to avoid matching dates/fractions
            Regex("""(\d{2,3})\s*/\s*(\d{2,3})\s*(?:mm\s*hg|mmhg)""")
        )
        for (p in patterns) {
            val match = p.find(text) ?: continue
            return match.groupValues[1].toIntOrNull()
        }
        return null
    }

    private fun extractBPDiastolic(text: String): Int? {
        val patterns = listOf(
            Regex("""(?:bp|blood pressure)\s*(?:is\s+)?(\d{2,3})\s*(?:over|on|/)\s*(\d{2,3})"""),
            // Without keyword — require mmHg suffix to avoid matching dates/fractions
            Regex("""(\d{2,3})\s*/\s*(\d{2,3})\s*(?:mm\s*hg|mmhg)""")
        )
        for (p in patterns) {
            val match = p.find(text) ?: continue
            return match.groupValues[2].toIntOrNull()
        }
        return null
    }

    private fun extractTemperature(text: String): Float? {
        val patterns = listOf(
            Regex("""(?:temp|temperature)\s*(?:is\s+)?(\d{2}(?:\.\d)?)\s*(?:degrees?|°?\s*c(?:elsius)?)?"""),
            Regex("""(\d{2}\.\d)\s*(?:degrees?|°\s*c)""")
        )
        for (p in patterns) {
            val match = p.find(text) ?: continue
            return match.groupValues[1].toFloatOrNull()
        }
        return null
    }

    private fun extractPulse(text: String): Int? {
        val patterns = listOf(
            Regex("""(?:pulse|heart rate|hr)\s*(?:is\s+)?(\d{2,3})\s*(?:bpm|beats)?"""),
            Regex("""(\d{2,3})\s*(?:beats per minute|bpm)""")
        )
        for (p in patterns) {
            val match = p.find(text) ?: continue
            return match.groupValues[1].toIntOrNull()
        }
        return null
    }

    private fun extractWeight(text: String): Float? {
        val patterns = listOf(
            Regex("""(?:weight|weighs?)\s*(?:is\s+)?(\d{1,3}(?:\.\d)?)\s*(?:kg|kilo(?:gram)?s?)"""),
            Regex("""(\d{1,3}(?:\.\d)?)\s*(?:kg|kilos?)""")
        )
        for (p in patterns) {
            val match = p.find(text) ?: continue
            return match.groupValues[1].toFloatOrNull()
        }
        return null
    }

    private fun extractHeight(text: String): Float? {
        val patterns = listOf(
            Regex("""(?:height)\s*(?:is\s+)?(\d{2,3}(?:\.\d)?)\s*(?:cm|centimeter)"""),
            Regex("""(\d{2,3})\s*cm\s*(?:tall)?""")
        )
        for (p in patterns) {
            val match = p.find(text) ?: continue
            return match.groupValues[1].toFloatOrNull()
        }
        return null
    }

    private fun extractRespiratoryRate(text: String): Int? {
        val patterns = listOf(
            Regex("""(?:resp(?:iratory)?\s*rate|rr)\s*(?:is\s+)?(\d{1,2})"""),
            Regex("""(\d{1,2})\s*breaths?\s*(?:per\s*min)""")
        )
        for (p in patterns) {
            val match = p.find(text) ?: continue
            return match.groupValues[1].toIntOrNull()
        }
        return null
    }

    private fun extractSpO2(text: String): Int? {
        val patterns = listOf(
            Regex("""(?:spo2|sats?|oxygen\s*sat(?:uration)?)\s*(?:is\s+)?(\d{2,3})\s*%?"""),
            Regex("""(\d{2,3})\s*%\s*(?:on\s+(?:room\s+air|ra))""")
        )
        for (p in patterns) {
            val match = p.find(text) ?: continue
            return match.groupValues[1].toIntOrNull()
        }
        return null
    }
}
