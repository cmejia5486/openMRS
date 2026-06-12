package com.chartlite.app.extraction

import android.util.Log
import com.chartlite.app.model.StructuredEncounter
import kotlinx.coroutines.CancellationException
import kotlinx.coroutines.TimeoutCancellationException
import kotlinx.coroutines.withTimeout

/**
 * Orchestrates clinical extraction across multiple strategies with automatic fallback.
 *
 * Hybrid extraction architecture (benchmark-driven, 2026-03):
 * - Vitals: LLM may extract them when explicit; regex merge is optional
 * - Diagnoses: LLM produces suggestedDiagnoses that clinician must confirm
 * - Exam findings, plan, investigations, medications: primarily LLM-driven
 * - Social history, allergies: primarily LLM-driven with Regex fallback available
 *
 * Default chain depends on AI mode:
 * - cloud:     Claude → Regex
 * - on_device: Qwen → Regex
 * - auto:      Claude → Qwen → Regex
 *
 * By default, successful LLM output is returned with minimal modification so the
 * app can reflect actual model performance. Optional regex vitals merge remains
 * available for stricter hybrid extraction flows.
 *
 * Each strategy gets up to [timeoutMs] to complete. If it fails, returns null,
 * or times out, the next strategy is tried. Regex always succeeds as the last resort.
 *
 * If a [transcriptValidator] is provided, only blocking validation failures skip
 * LLM strategies entirely. Warning-level failures are logged but still allowed
 * through so abbreviation-heavy transcripts can be evaluated by the model.
 *
 * Default timeout is 90s to allow for first-run model loading (~30s) plus inference (~60s)
 * on low-end devices like Galaxy A03.
 */
class ExtractionOrchestrator(
    private val strategies: List<ExtractionStrategy>,
    private val timeoutMs: Long = 90_000L,
    private val transcriptValidator: TranscriptValidator? = null,
    private val vitalsExtractor: VitalsExtractor? = null,
    private val mergeRegexVitalsIntoLlmResults: Boolean = false
) {

    data class ExtractionResult(
        val encounter: StructuredEncounter,
        val strategyUsed: String,
        val fallbacksAttempted: List<String>
    )

    /**
     * Extract clinical data from a transcript using the best available strategy.
     * Always returns a result — RegexExtractionStrategy is the guaranteed fallback.
     *
     * For LLM strategies, raw model output is returned unless
     * [mergeRegexVitalsIntoLlmResults] is enabled.
     */
    suspend fun extract(
        transcript: String,
        patientId: String,
        providerId: String,
        facilityId: String
    ): ExtractionResult {
        val fallbacksAttempted = mutableListOf<String>()

        Log.d(TAG, "Extracting from transcript (${transcript.length} chars), ${strategies.size} strategies available")

        // Validate transcript quality. Only blocking failures skip the LLM entirely.
        val validation = transcriptValidator?.isValid(transcript)
        val useRegexOnly = validation?.shouldSkipLlm == true
        when {
            useRegexOnly -> {
                Log.w(TAG, "Transcript failed validation: ${validation?.reason} — using Regex only")
            }
            validation != null && !validation.isValid -> {
                Log.w(TAG, "Transcript failed soft validation: ${validation.reason} — continuing with LLM strategies")
            }
        }

        for (strategy in strategies) {
            // Skip LLM strategies for invalid transcripts (non-LLM strategies like Regex still run)
            if (useRegexOnly && strategy.isLlmBased) {
                Log.d(TAG, "Skipping ${strategy.name}: transcript failed validation")
                fallbacksAttempted.add("${strategy.name} (skipped: invalid transcript)")
                continue
            }
            if (!strategy.isAvailable()) {
                Log.d(TAG, "Skipping ${strategy.name}: not available")
                continue
            }

            try {
                Log.d(TAG, "Trying ${strategy.name}...")
                val encounter = withTimeout(timeoutMs) {
                    strategy.extract(transcript, patientId, providerId, facilityId)
                }

                if (encounter != null) {
                    val finalEncounter = if (
                        strategy.isLlmBased &&
                        mergeRegexVitalsIntoLlmResults &&
                        vitalsExtractor != null
                    ) {
                        val regexVitals = vitalsExtractor.extract(transcript)
                        if (regexVitals != null) {
                            val mergedVitals = EncounterMerger.mergeVitals(encounter.vitals, regexVitals)
                            encounter.copy(vitals = mergedVitals)
                        } else {
                            encounter
                        }
                    } else {
                        encounter
                    }

                    val vitalsMode = when {
                        !strategy.isLlmBased -> "included"
                        mergeRegexVitalsIntoLlmResults -> "regex-merged"
                        else -> "model-only"
                    }
                    Log.d(TAG, "Extraction succeeded via ${strategy.name} " +
                        "(vitals=$vitalsMode, " +
                        "fallbacks: $fallbacksAttempted)")
                    return ExtractionResult(
                        encounter = finalEncounter,
                        strategyUsed = strategy.name,
                        fallbacksAttempted = fallbacksAttempted
                    )
                }

                Log.w(TAG, "${strategy.name} returned no usable result, trying next")
                fallbacksAttempted.add("${strategy.name} (returned no usable result)")

            } catch (_: TimeoutCancellationException) {
                Log.w(TAG, "${strategy.name} timed out after ${timeoutMs}ms")
                fallbacksAttempted.add("${strategy.name} (timed out after ${timeoutMs / 1000}s)")
            } catch (e: CancellationException) {
                // External cancellation (user left screen) — propagate, don't swallow
                throw e
            } catch (e: Exception) {
                Log.w(TAG, "${strategy.name} failed: ${e.message}")
                val detail = e.message?.take(180) ?: "failed"
                fallbacksAttempted.add("${strategy.name} ($detail)")
            }
        }

        // All strategies exhausted — return an empty encounter rather than crashing.
        // This should only happen if RegexExtractionStrategy is missing from the list.
        Log.e(TAG, "All ${strategies.size} extraction strategies failed — returning empty encounter")
        return ExtractionResult(
            encounter = StructuredEncounter(
                id = java.util.UUID.randomUUID().toString(),
                patientId = patientId,
                providerId = providerId,
                facilityId = facilityId,
                timestamp = java.time.Instant.now(),
                transcript = "",
                medications = emptyList(),
                diagnoses = emptyList(),
                vitals = null,
                allergies = emptyList(),
                followUp = null,
                referral = null,
                freeTextNote = "",
                extractionConfidence = 0f
            ),
            strategyUsed = "none (all failed)",
            fallbacksAttempted = fallbacksAttempted
        )
    }

    /**
     * Result of draft note generation (draft-note-first architecture).
     */
    data class NoteGenerationResult(
        val note: String,
        val strategyUsed: String,
        val fallbacksAttempted: List<String>
    )

    /**
     * Generate a draft clinical note from a transcript using the best available LLM strategy.
     * Returns null if no LLM strategy is available or all fail (caller should fall back to
     * the old direct-extraction flow).
     *
     * Only LLM strategies can generate notes — regex strategies return null and are skipped.
     */
    suspend fun generateNote(transcript: String): NoteGenerationResult? {
        val fallbacksAttempted = mutableListOf<String>()

        Log.d(TAG, "Generating draft note from transcript (${transcript.length} chars)")

        // Validate transcript quality — skip LLM note generation for garbage input
        val validation = transcriptValidator?.isValid(transcript)
        if (validation?.shouldSkipLlm == true) {
            Log.w(TAG, "Transcript failed validation for note generation: ${validation.reason}")
            return null
        }

        for (strategy in strategies) {
            // Only LLM strategies can generate notes
            if (!strategy.isLlmBased) continue
            if (!strategy.isAvailable()) {
                Log.d(TAG, "Skipping ${strategy.name} for note generation: not available")
                continue
            }

            try {
                Log.d(TAG, "Trying ${strategy.name} for note generation...")
                val note = withTimeout(timeoutMs) {
                    strategy.generateNote(transcript)
                }

                if (!note.isNullOrBlank()) {
                    Log.d(TAG, "Note generated via ${strategy.name} (${note.length} chars)")
                    return NoteGenerationResult(
                        note = note,
                        strategyUsed = strategy.name,
                        fallbacksAttempted = fallbacksAttempted
                    )
                }

                Log.w(TAG, "${strategy.name} returned empty note, trying next")
                fallbacksAttempted.add("${strategy.name} (returned empty)")

            } catch (_: TimeoutCancellationException) {
                Log.w(TAG, "${strategy.name} note generation timed out after ${timeoutMs}ms")
                fallbacksAttempted.add("${strategy.name} (timed out)")
            } catch (e: CancellationException) {
                throw e
            } catch (e: Exception) {
                Log.w(TAG, "${strategy.name} note generation failed: ${e.message}")
                fallbacksAttempted.add("${strategy.name} (${e.message?.take(120) ?: "failed"})")
            }
        }

        Log.d(TAG, "No LLM strategy could generate a note — caller should use direct extraction")
        return null
    }

    companion object {
        private const val TAG = "ExtractionOrch"
    }
}
