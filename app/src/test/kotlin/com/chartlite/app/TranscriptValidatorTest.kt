package com.chartlite.app

import com.chartlite.app.extraction.TranscriptValidator
import org.junit.Assert.*
import org.junit.Test

class TranscriptValidatorTest {

    private val validator = TranscriptValidator()

    // --- Valid transcripts ---

    @Test
    fun `accepts normal clinical transcript`() {
        val result = validator.isValid("Patient presents with fever and cough for three days")
        assertTrue(result.isValid)
        assertNull(result.reason)
        assertFalse(result.shouldSkipLlm)
    }

    @Test
    fun `accepts short but valid transcript`() {
        val result = validator.isValid("headache and nausea today")
        assertTrue(result.isValid)
        assertFalse(result.shouldSkipLlm)
    }

    @Test
    fun `accepts transcript with medical terms`() {
        val result = validator.isValid("blood pressure elevated hypertension diagnosis")
        assertTrue(result.isValid)
        assertFalse(result.shouldSkipLlm)
    }

    @Test
    fun `accepts transcript with numbers and units`() {
        val result = validator.isValid("temperature 38.5 degrees blood pressure 140 over 90")
        assertTrue(result.isValid)
        assertFalse(result.shouldSkipLlm)
    }

    // --- Invalid transcripts: gibberish ---

    @Test
    fun `flags consonant-only gibberish but still allows llm evaluation`() {
        val result = validator.isValid("njklhkjhljkhlkhlkjhkjlh brrrrr ttttt")
        assertFalse(result.isValid)
        assertNotNull(result.reason)
        assertTrue(result.reason!!.contains("gibberish"))
        assertFalse(result.shouldSkipLlm)
    }

    @Test
    fun `rejects random key mashing`() {
        val result = validator.isValid("sdfgh jklzx cvbnm qwrty plkjh")
        assertFalse(result.isValid)
        assertFalse(result.shouldSkipLlm)
    }

    // --- Invalid transcripts: too short ---

    @Test
    fun `rejects empty string`() {
        val result = validator.isValid("")
        assertFalse(result.isValid)
        assertTrue(result.reason!!.contains("too short"))
        assertTrue(result.shouldSkipLlm)
    }

    @Test
    fun `rejects whitespace only`() {
        val result = validator.isValid("   ")
        assertFalse(result.isValid)
        assertTrue(result.shouldSkipLlm)
    }

    @Test
    fun `rejects single word`() {
        val result = validator.isValid("hello")
        assertFalse(result.isValid)
        assertTrue(result.shouldSkipLlm)
    }

    @Test
    fun `rejects two words`() {
        val result = validator.isValid("hello world")
        assertFalse(result.isValid)
        assertTrue(result.shouldSkipLlm)
    }

    // --- Edge cases ---

    @Test
    fun `accepts transcript at minimum threshold`() {
        // 3 words, 10+ chars, all have vowels
        val result = validator.isValid("cough and fever")
        assertTrue(result.isValid)
        assertFalse(result.shouldSkipLlm)
    }

    @Test
    fun `handles mixed valid and gibberish words`() {
        // If >40% have vowels, it passes
        val result = validator.isValid("patient has fever and nnnnn")
        assertTrue(result.isValid) // 4/5 = 80% have vowels
        assertFalse(result.shouldSkipLlm)
    }

    @Test
    fun `flags mostly gibberish with few real words but keeps llm path available`() {
        // Only 1/5 words has vowels (20%) - below 40% threshold
        val result = validator.isValid("cough brrr tttss nnnmm kkkll")
        assertFalse(result.isValid)
        assertFalse(result.shouldSkipLlm)
    }

    // --- Custom thresholds ---

    @Test
    fun `respects custom minimum words`() {
        val strict = TranscriptValidator(minWords = 5)
        val result = strict.isValid("three words only")
        assertFalse(result.isValid)
        assertTrue(result.shouldSkipLlm)
    }

    @Test
    fun `respects custom vowel ratio`() {
        val lenient = TranscriptValidator(minVowelWordRatio = 0.2f)
        // 1/3 words have vowels (33%) - would fail at 40% but pass at 20%
        val result = lenient.isValid("one brrrr ttttss")
        assertTrue(result.isValid)
        assertFalse(result.shouldSkipLlm)
    }
}
