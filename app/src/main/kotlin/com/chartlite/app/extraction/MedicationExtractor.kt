package com.chartlite.app.extraction

import com.chartlite.app.model.Formulary
import com.chartlite.app.model.FormularyDrug
import com.chartlite.app.model.Medication
import me.xdrop.fuzzywuzzy.FuzzySearch

class MedicationExtractor(private val formulary: Formulary) {

    companion object {
        private val DOSE_PATTERN = Regex("""(\d+(?:\.\d+)?)\s*(mg|ml|g|mcg|iu|units?|%)\b""", RegexOption.IGNORE_CASE)
        private val FREQ_MAP = mapOf(
            "once daily" to "OD", "once a day" to "OD", "daily" to "OD", "od" to "OD",
            "twice daily" to "BD", "twice a day" to "BD", "bd" to "BD", "bid" to "BD",
            "three times" to "TDS", "tds" to "TDS", "tid" to "TDS", "three times a day" to "TDS",
            "four times" to "QDS", "qds" to "QDS", "qid" to "QDS", "four times a day" to "QDS",
            "as needed" to "PRN", "prn" to "PRN", "when needed" to "PRN", "when required" to "PRN",
            "immediately" to "STAT", "stat" to "STAT", "now" to "STAT",
            "weekly" to "WEEKLY", "once a week" to "WEEKLY"
        )
        private val ROUTE_MAP = mapOf(
            "oral" to "PO", "orally" to "PO", "by mouth" to "PO", "po" to "PO",
            "intravenous" to "IV", "iv" to "IV",
            "intramuscular" to "IM", "im" to "IM",
            "topical" to "topical", "topically" to "topical", "apply" to "topical",
            "inhale" to "inhaled", "inhaled" to "inhaled", "nebulize" to "inhaled",
            "subcutaneous" to "SC", "subcut" to "SC", "sc" to "SC",
            "rectal" to "PR", "pr" to "PR",
            "sublingual" to "SL", "under the tongue" to "SL"
        )
        private val DURATION_PATTERN = Regex(
            """(?:for\s+)?(\d+|one|two|three|four|five|six|seven|eight|nine|ten|eleven|twelve|thirteen|fourteen|fifteen|sixteen|seventeen|eighteen|nineteen|twenty|thirty)\s*(?:/7|days?|d)\b|(\d+|one|two|three|four|five|six|seven|eight|nine|ten|eleven|twelve|thirteen|fourteen|fifteen|sixteen|seventeen|eighteen|nineteen|twenty|thirty)\s*(?:week|wk)s?""",
            RegexOption.IGNORE_CASE
        )
        private const val FUZZY_THRESHOLD = 85  // raised from 75 to reduce false positives
        private const val SCAN_WINDOW = 30 // tokens to scan forward after drug match
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
            "thirty" to 30
        )
    }

    fun extract(transcript: String): List<Medication> {
        val tokens = tokenize(transcript)
        val medications = mutableListOf<Medication>()
        val usedIndices = mutableSetOf<Int>()

        for (i in tokens.indices) {
            if (i in usedIndices) continue

            val (drug, score, matchedTokens) = findDrugMatch(tokens, i) ?: continue
            // Mark all consumed token indices to prevent duplicate matches
            for (k in i until i + matchedTokens) usedIndices.add(k)

            // Scan forward from drug position for dose, frequency, route, duration
            val window = tokens.subList(i, minOf(i + SCAN_WINDOW, tokens.size)).joinToString(" ")

            val dose = extractDose(window)
            val frequency = extractFrequency(window)
            val route = extractRoute(window) ?: drug.defaultRoute
            val duration = extractDuration(window)

            val confidence = calculateConfidence(score, dose, frequency)

            medications.add(
                Medication(
                    formularyCode = drug.code,
                    name = drug.name,
                    dose = dose?.first,
                    unit = dose?.second,
                    frequency = frequency,
                    duration = duration,
                    route = route,
                    confidence = confidence
                )
            )
        }

        return medications
    }

    /**
     * Returns Triple(drug, matchScore, tokenCount) or null.
     * Prioritises exact matches, then fuzzy. Only single-token fuzzy
     * matching is allowed to prevent "start amoxicillin" style false positives.
     */
    private fun findDrugMatch(tokens: List<String>, startIndex: Int): Triple<FormularyDrug, Int, Int>? {
        // First pass: exact matches on 1-3 token n-grams
        for (n in 3 downTo 1) {
            if (startIndex + n > tokens.size) continue
            val candidate = tokens.subList(startIndex, startIndex + n).joinToString(" ")
            if (candidate.length < 3) continue

            for (drug in formulary.drugs) {
                val allNames = listOf(drug.name.lowercase()) + drug.aliases.map { it.lowercase() }
                for (name in allNames) {
                    if (candidate.equals(name, ignoreCase = true)) {
                        return Triple(drug, 100, n)
                    }
                }
            }
        }

        // Second pass: fuzzy match on single tokens only (avoids multi-token false positives)
        val candidate = tokens[startIndex]
        if (candidate.length > 4) {
            for (drug in formulary.drugs) {
                val allNames = listOf(drug.name.lowercase()) + drug.aliases.map { it.lowercase() }
                for (name in allNames) {
                    if (name.length > 4) {
                        val score = FuzzySearch.ratio(candidate.lowercase(), name)
                        if (score >= FUZZY_THRESHOLD) {
                            return Triple(drug, score, 1)
                        }
                    }
                }
            }
        }

        return null
    }

    private fun extractDose(text: String): Pair<Float, String>? {
        val match = DOSE_PATTERN.find(text) ?: return null
        val value = match.groupValues[1].toFloatOrNull() ?: return null
        val unit = match.groupValues[2].lowercase()
        return value to unit
    }

    private fun extractFrequency(text: String): String? {
        val lower = text.lowercase()
        // Sort by pattern length descending so "twice daily" matches before "daily"
        for ((pattern, code) in FREQ_MAP.entries.sortedByDescending { it.key.length }) {
            if (lower.contains(pattern)) return code
        }
        return null
    }

    private fun extractRoute(text: String): String? {
        val lower = text.lowercase()
        for ((pattern, code) in ROUTE_MAP) {
            if (lower.contains(pattern)) return code
        }
        return null
    }

    private fun extractDuration(text: String): Int? {
        val match = DURATION_PATTERN.find(text) ?: return null
        val days = parseNumberToken(match.groupValues[1])
        val weeks = parseNumberToken(match.groupValues[2])
        return days ?: weeks?.let { it * 7 }
    }

    private fun parseNumberToken(raw: String): Int? {
        val normalized = raw.trim().lowercase()
        return normalized.toIntOrNull() ?: NUMBER_WORDS[normalized]
    }

    private fun calculateConfidence(matchScore: Int, dose: Pair<Float, String>?, frequency: String?): Float {
        var conf = matchScore / 100f * 0.7f // Drug match contributes 70%
        if (dose != null) conf += 0.15f
        if (frequency != null) conf += 0.15f
        return conf.coerceIn(0f, 1f)
    }

    private fun tokenize(text: String): List<String> {
        return text.split(Regex("\\s+")).filter { it.isNotBlank() }
    }
}
