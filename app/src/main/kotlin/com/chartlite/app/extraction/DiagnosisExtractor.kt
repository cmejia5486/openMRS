package com.chartlite.app.extraction

import com.chartlite.app.model.Diagnosis
import com.chartlite.app.model.ICD10Entry
import com.chartlite.app.model.ICD10Index

class DiagnosisExtractor(private val icd10: ICD10Index) {

    companion object {
        // Words that signal a diagnosis is being stated
        private val DIAGNOSIS_MARKERS = setOf(
            "diagnosis", "diagnose", "diagnosed", "impression", "assessment",
            "presenting with", "presents with", "suffers from", "suffering from",
            "confirmed", "suspect", "suspected", "rule out", "consistent with"
        )

        // Minimum confidence to include a diagnosis in results
        private const val MIN_CONFIDENCE = 0.45f

        // Short keywords (<=4 chars) that are medical abbreviations must appear
        // as uppercase standalone tokens in the ORIGINAL (not lowercased) transcript.
        // This prevents "start" matching "ART", "after" matching "AF", etc.
        private const val SHORT_ABBREV_THRESHOLD = 4

        private val NEGATION_PREFIXES = listOf(
            "no", "not", "without", "denies", "deny", "denied", "negative for"
        )
    }

    fun extract(transcript: String): List<Diagnosis> {
        val lower = transcript.lowercase()
        val matches = mutableListOf<ScoredDiagnosis>()

        // Pre-split original transcript into tokens for abbreviation checking
        val originalTokens = transcript.split(Regex("\\s+")).map { it.trim() }.filter { it.isNotBlank() }

        for (entry in icd10.codes) {
            val score = matchScore(lower, originalTokens, entry)
            if (score >= MIN_CONFIDENCE) {
                matches.add(ScoredDiagnosis(entry, score))
            }
        }

        // Sort by score descending, take top matches
        matches.sortByDescending { it.score }

        return matches.take(3).mapIndexed { index, scored ->
            Diagnosis(
                icd10Code = scored.entry.code,
                description = scored.entry.description,
                isPrimary = index == 0,
                confidence = scored.score,
                source = "suggested"
            )
        }
    }

    private fun matchScore(text: String, originalTokens: List<String>, entry: ICD10Entry): Float {
        var bestScore = 0f

        // Match against keywords
        for (keyword in entry.keywords) {
            val kw = keyword.lowercase()

            var isExactAbbrevMatch = false
            val matched = if (keyword.length <= SHORT_ABBREV_THRESHOLD && keyword.all { it.isLetter() }) {
                // Short keywords: require exact standalone token match
                if (keyword.uppercase() == keyword || keyword.length <= 3) {
                    // Medical abbreviation (e.g., "HIV", "ART", "TB", "PE", "AF")
                    // Must appear as an EXACT uppercase token in the original transcript
                    val found = originalTokens.any { token ->
                        token.equals(keyword.uppercase(), ignoreCase = false) ||
                        token.trimEnd('.', ',', ';', ':', '!', '?').equals(keyword.uppercase(), ignoreCase = false)
                    }
                    if (found) isExactAbbrevMatch = true
                    found
                } else {
                    // Short but not all-caps (e.g., "cold", "rash", "fits", "fell")
                    // Use word boundary matching
                    matchesWholeWord(text, kw)
                }
            } else {
                // Longer keywords: word boundary matching
                matchesWholeWord(text, kw)
            }

            if (matched && !isNegated(text, kw)) {
                // Score based on keyword length (longer = more specific = higher score)
                var kwScore = (kw.length.toFloat() / 15f).coerceIn(0.3f, 0.9f)

                // Exact uppercase abbreviation match is highly specific — boost score
                if (isExactAbbrevMatch) kwScore = maxOf(kwScore, 0.5f)

                // Bonus if near a diagnosis marker
                val markerBonus = if (isNearDiagnosisMarker(text, kw)) 0.15f else 0f

                bestScore = maxOf(bestScore, kwScore + markerBonus)
            }
        }

        // Match against local terms (these are longer, specific medical terms — use substring match)
        for ((_, terms) in entry.localTerms) {
            for (term in terms) {
                val termLower = term.lowercase()
                if (termLower.length >= 4 && text.contains(termLower)) {
                    bestScore = maxOf(bestScore, 0.8f)
                }
            }
        }

        return bestScore.coerceIn(0f, 1f)
    }

    /**
     * Match a keyword as a whole word using word boundaries.
     * Prevents "art" matching inside "start", "age" inside "message", etc.
     */
    private fun matchesWholeWord(text: String, keyword: String): Boolean {
        val pattern = Regex("\\b${Regex.escape(keyword)}\\b", RegexOption.IGNORE_CASE)
        return pattern.containsMatchIn(text)
    }

    private fun isNegated(text: String, keyword: String): Boolean {
        val keywordPattern = keyword
            .trim()
            .split(Regex("\\s+"))
            .joinToString("\\s+") { Regex.escape(it) }

        return NEGATION_PREFIXES.any { prefix ->
            Regex(
                """\b${prefix.split(" ").joinToString("\\s+") { Regex.escape(it) }}\b(?:\s+\w+){0,3}\s+$keywordPattern\b""",
                RegexOption.IGNORE_CASE
            ).containsMatchIn(text)
        }
    }

    private fun isNearDiagnosisMarker(text: String, keyword: String): Boolean {
        val keywordPos = text.indexOf(keyword)
        if (keywordPos < 0) return false

        // Check if any marker appears within 60 chars before the keyword
        val windowStart = maxOf(0, keywordPos - 60)
        val window = text.substring(windowStart, keywordPos)

        return DIAGNOSIS_MARKERS.any { marker -> window.contains(marker) }
    }

    private data class ScoredDiagnosis(val entry: ICD10Entry, val score: Float)
}
