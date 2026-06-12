package com.chartlite.app.extraction

/**
 * Validates transcript quality before sending to LLM extraction.
 * Blocks obviously unusable input and flags likely-gibberish transcripts so the
 * caller can decide whether to continue for model evaluation.
 *
 * Script-aware: skips the Latin vowel ratio check for non-Latin scripts
 * (e.g., Amharic/Ge'ez, Devanagari, Arabic) since those have fundamentally
 * different phonological structures.
 */
class TranscriptValidator(
    private val minWords: Int = 3,
    private val minLength: Int = 10,
    private val minVowelWordRatio: Float = 0.4f
) {

    data class ValidationResult(
        val isValid: Boolean,
        val reason: String?,
        val shouldSkipLlm: Boolean
    )

    private val latinVowels = setOf('a', 'e', 'i', 'o', 'u', 'A', 'E', 'I', 'O', 'U')

    fun isValid(transcript: String): ValidationResult {
        val trimmed = transcript.trim()

        if (trimmed.length < minLength) {
            return ValidationResult(
                isValid = false,
                reason = "Transcript too short (${trimmed.length} chars, need $minLength)",
                shouldSkipLlm = true
            )
        }

        val words = trimmed.split(Regex("\\s+")).filter { it.isNotBlank() }
        if (words.size < minWords) {
            return ValidationResult(
                isValid = false,
                reason = "Too few words (${words.size}, need $minWords)",
                shouldSkipLlm = true
            )
        }

        // Detect script: if majority of alphabetic characters are non-Latin,
        // skip the vowel ratio check (it's meaningless for Ge'ez, Devanagari, etc.)
        val alphaChars = trimmed.filter { it.isLetter() }
        if (alphaChars.isNotEmpty()) {
            val nonLatinCount = alphaChars.count { ch ->
                val script = Character.UnicodeScript.of(ch.code)
                script != Character.UnicodeScript.LATIN && script != Character.UnicodeScript.COMMON
            }
            val nonLatinRatio = nonLatinCount.toFloat() / alphaChars.length
            if (nonLatinRatio > 0.5f) {
                // Non-Latin script detected — length and word count checks are sufficient
                return ValidationResult(true, null, shouldSkipLlm = false)
            }
        }

        // Latin text: check vowel ratio to catch gibberish (e.g., "xkcd brrr zzt")
        val wordsWithVowels = words.count { word -> word.any { it in latinVowels } }
        val ratio = wordsWithVowels.toFloat() / words.size
        if (ratio < minVowelWordRatio) {
            return ValidationResult(
                isValid = false,
                reason = "Text appears to be gibberish (${(ratio * 100).toInt()}% words with vowels, need ${(minVowelWordRatio * 100).toInt()}%)",
                shouldSkipLlm = false
            )
        }

        return ValidationResult(true, null, shouldSkipLlm = false)
    }
}
