package com.chartlite.app.extraction

import com.chartlite.app.model.StructuredEncounter

/**
 * Strategy for extracting structured clinical data from a transcript.
 *
 * Implementations:
 * - RegexExtractionStrategy: Current regex/keyword pipeline (always available)
 * - ClaudeExtractionStrategy: Cloud-based via Anthropic Messages API
 * - GemmaExtractionStrategy: On-device via MediaPipe/LiteRT (Phase 2)
 */
interface ExtractionStrategy {

    /** Human-readable name for UI display */
    val name: String

    /** Whether this strategy uses an LLM (subject to transcript validation skip). */
    val isLlmBased: Boolean get() = true

    /** Whether this strategy is currently available */
    suspend fun isAvailable(): Boolean

    /**
     * Extract structured clinical data from a transcript.
     * Returns null if extraction failed (triggers fallback to next strategy).
     */
    suspend fun extract(
        transcript: String,
        patientId: String,
        providerId: String,
        facilityId: String
    ): StructuredEncounter?

    /**
     * Generate a draft clinical note from a transcript (draft-note-first architecture).
     * Returns null if not supported (e.g., regex strategies) or if generation failed.
     * Only LLM-based strategies can generate notes.
     */
    suspend fun generateNote(transcript: String): String? = null
}
