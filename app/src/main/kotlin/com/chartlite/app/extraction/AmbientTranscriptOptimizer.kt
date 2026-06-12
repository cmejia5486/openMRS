package com.chartlite.app.extraction

/**
 * Compacts ambient transcripts before on-device extraction.
 *
 * Goal: preserve clinically meaningful content while removing repeated ASR
 * fragments, filler-only utterances, and low-signal conversation that wastes
 * prompt budget on constrained phones.
 */
object AmbientTranscriptOptimizer {

    data class OptimizationResult(
        val optimizedTranscript: String,
        val originalChars: Int,
        val optimizedChars: Int,
        val fillerSegmentsRemoved: Int,
        val duplicateSegmentsRemoved: Int,
        val clippedToBudget: Boolean
    )

    private data class Segment(
        val index: Int,
        val text: String,
        val key: String,
        val score: Int,
        val protected: Boolean
    )

    fun optimize(transcript: String, charBudget: Int): OptimizationResult {
        val normalized = normalizeTranscript(transcript)
        if (normalized.isBlank()) {
            return OptimizationResult(
                optimizedTranscript = "",
                originalChars = transcript.length,
                optimizedChars = 0,
                fillerSegmentsRemoved = 0,
                duplicateSegmentsRemoved = 0,
                clippedToBudget = false
            )
        }

        val rawSegments = splitSegments(normalized)
        val kept = mutableListOf<Segment>()
        val recentKeys = ArrayDeque<String>()
        var fillerRemoved = 0
        var duplicateRemoved = 0

        rawSegments.forEachIndexed { index, rawSegment ->
            val compacted = compactSegment(rawSegment)
            if (compacted.isBlank()) {
                fillerRemoved++
                return@forEachIndexed
            }

            val key = segmentKey(compacted)
            if (key.isNotBlank() && recentKeys.contains(key)) {
                duplicateRemoved++
                return@forEachIndexed
            }

            kept += Segment(
                index = index,
                text = compacted,
                key = key,
                score = scoreSegment(compacted),
                protected = index == 0 || index == rawSegments.lastIndex || isProtectedSegment(compacted)
            )

            if (key.isNotBlank()) {
                recentKeys.addLast(key)
                if (recentKeys.size > DUPLICATE_WINDOW) {
                    recentKeys.removeFirst()
                }
            }
        }

        if (kept.isEmpty()) {
            return OptimizationResult(
                optimizedTranscript = "",
                originalChars = transcript.length,
                optimizedChars = 0,
                fillerSegmentsRemoved = fillerRemoved,
                duplicateSegmentsRemoved = duplicateRemoved,
                clippedToBudget = false
            )
        }

        val (compacted, clippedToBudget) = fitToBudget(kept, charBudget)
        return OptimizationResult(
            optimizedTranscript = compacted,
            originalChars = transcript.length,
            optimizedChars = compacted.length,
            fillerSegmentsRemoved = fillerRemoved,
            duplicateSegmentsRemoved = duplicateRemoved,
            clippedToBudget = clippedToBudget
        )
    }

    private fun normalizeTranscript(transcript: String): String = transcript
        .replace(Regex("[\\r\\n]+"), ". ")
        .replace(Regex("\\s+"), " ")
        .replace(Regex("\\.{2,}"), ".")
        .replace(Regex("\\s+([,.;!?])"), "$1")
        .trim()

    private fun splitSegments(text: String): List<String> =
        SEGMENT_REGEX.findAll(text)
            .map { it.value.trim() }
            .filter { it.isNotBlank() }
            .toList()

    private fun compactSegment(segment: String): String {
        val tokens = segment
            .replace(Regex("\\s+"), " ")
            .trim()
            .split(" ")
            .filter { it.isNotBlank() }
            .toMutableList()

        while (tokens.isNotEmpty() && isBoundaryFiller(tokens.first())) {
            tokens.removeAt(0)
        }
        while (tokens.isNotEmpty() && isBoundaryFiller(tokens.last())) {
            tokens.removeAt(tokens.lastIndex)
        }

        if (tokens.isEmpty()) return ""

        val deduped = mutableListOf<String>()
        tokens.forEach { token ->
            val normalizedToken = normalizeWord(token)
            val previousToken = deduped.lastOrNull()?.let(::normalizeWord)
            if (normalizedToken.isNotBlank() && normalizedToken == previousToken) {
                return@forEach
            }
            deduped += token
        }

        val compacted = deduped.joinToString(" ")
            .replace(Regex("\\s+([,.;!?])"), "$1")
            .trim()

        val meaningfulWords = words(compacted).filterNot { it in fillerWords }
        if (meaningfulWords.isEmpty()) return ""
        if (meaningfulWords.size <= 2 && !containsClinicalSignal(compacted)) return ""

        return compacted
    }

    private fun fitToBudget(segments: List<Segment>, charBudget: Int): Pair<String, Boolean> {
        if (charBudget <= 0) return "" to true

        val selected = segments.toMutableList()
        if (joinedLength(selected) <= charBudget) {
            return selected.joinToString(" ") { it.text } to false
        }

        val hasStrongSignal = selected.count { it.protected || it.score >= 2 } >= 2
        val removable = if (hasStrongSignal) {
            selected
                .filterNot { it.protected }
                .sortedWith(compareBy<Segment> { it.score }.thenByDescending { it.text.length })
        } else {
            emptyList()
        }

        for (segment in removable) {
            if (joinedLength(selected) <= charBudget) break
            selected.remove(segment)
        }

        if (joinedLength(selected) <= charBudget) {
            return selected.sortedBy { it.index }.joinToString(" ") { it.text } to true
        }

        val ordered = selected.sortedBy { it.index }.joinToString(" ") { it.text }
        return trimToBudget(ordered, charBudget) to true
    }

    private fun trimToBudget(text: String, charBudget: Int): String {
        if (text.length <= charBudget) return text
        if (charBudget <= ELLIPSIS.length + 8) return text.take(charBudget).trim()

        val headBudget = (charBudget * 0.6).toInt().coerceAtLeast(1)
        val tailBudget = (charBudget - headBudget - ELLIPSIS.length).coerceAtLeast(1)

        val head = trimTrailingPartialWord(text.take(headBudget))
        val tail = trimLeadingPartialWord(text.takeLast(tailBudget))
        return listOf(head, tail)
            .filter { it.isNotBlank() }
            .joinToString(ELLIPSIS)
            .take(charBudget)
            .trim()
    }

    private fun trimTrailingPartialWord(text: String): String {
        if (text.isBlank()) return ""
        val trimmed = text.trimEnd()
        val cut = trimmed.lastIndexOf(' ')
        return if (cut >= trimmed.length / 2) trimmed.substring(0, cut).trimEnd() else trimmed
    }

    private fun trimLeadingPartialWord(text: String): String {
        if (text.isBlank()) return ""
        val trimmed = text.trimStart()
        val cut = trimmed.indexOf(' ')
        return if (cut in 1 until trimmed.length / 2) trimmed.substring(cut + 1).trimStart() else trimmed
    }

    private fun joinedLength(segments: List<Segment>): Int =
        segments.sumOf { it.text.length } + ((segments.size - 1).coerceAtLeast(0))

    private fun scoreSegment(text: String): Int {
        val lower = text.lowercase()
        val segmentWords = words(text).toSet()
        var score = 0

        if (lower.any { it.isDigit() }) score += 3
        score += clinicalKeywords.count { it in segmentWords }.coerceAtMost(2)
        if (segmentWords.size >= 5) score += 1
        if (looksLikeGreeting(lower)) score -= 1

        return score
    }

    private fun isProtectedSegment(text: String): Boolean {
        val lower = text.lowercase()
        val segmentWords = words(text).toSet()
        return lower.any { it.isDigit() } ||
            strongClinicalKeywords.any { it in segmentWords }
    }

    private fun containsClinicalSignal(text: String): Boolean {
        val lower = text.lowercase()
        val segmentWords = words(text).toSet()
        return lower.any { it.isDigit() } || clinicalKeywords.any { it in segmentWords }
    }

    private fun looksLikeGreeting(text: String): Boolean =
        text.startsWith("hello") || text.startsWith("hi ") || text.startsWith("good morning")

    private fun segmentKey(text: String): String = words(text)
        .filterNot { it in fillerWords }
        .joinToString(" ")

    private fun words(text: String): List<String> =
        WORD_REGEX.findAll(text.lowercase())
            .map { it.value }
            .toList()

    private fun normalizeWord(token: String): String =
        token.lowercase().replace(Regex("^[^\\p{L}\\p{N}]+|[^\\p{L}\\p{N}]+$"), "")

    private fun isBoundaryFiller(token: String): Boolean =
        normalizeWord(token) in fillerWords

    private val fillerWords = setOf(
        "ah", "alright", "hmm", "mm", "okay", "ok",
        "uh", "um", "thanks", "thank"
    )

    private val clinicalKeywords = setOf(
        "abdomen", "allergy", "antibiotic", "assessment", "asthma", "blood", "bp", "breathing",
        "cough", "diabetes", "diagnosis", "diarrhea", "dose", "drug", "fever", "follow", "headache",
        "history", "hypertension", "infection", "investigation", "lab", "malaria", "medication",
        "mg", "pain", "paracetamol", "plan", "positive", "pregnant", "prescribe", "pressure",
        "pulse", "rash", "refer", "result", "review", "start", "stop", "sugar", "temperature",
        "test", "treatment", "vomiting", "weight"
    )

    private val strongClinicalKeywords = setOf(
        "allergy", "diagnosis", "dose", "drug", "follow", "history", "investigation", "lab",
        "medication", "mg", "plan", "prescribe", "refer", "result", "review", "start", "stop",
        "test", "treatment"
    )

    private val SEGMENT_REGEX = Regex("[^.!?;]+[.!?;]?")
    private val WORD_REGEX = Regex("[\\p{L}\\p{N}]+")
    private const val DUPLICATE_WINDOW = 4
    private const val ELLIPSIS = " ... "
}
