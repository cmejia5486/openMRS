package com.chartlite.app.extraction

import android.util.Log
import com.chartlite.app.model.StructuredEncounter
import kotlinx.coroutines.Dispatchers
import kotlinx.coroutines.withContext

/**
 * Extraction strategy using Qwen 3.5 (0.8B or 2B) via MNN-LLM on-device.
 *
 * Uses the shared benchmark JSON prompt used by the cloud extractor.
 *
 * Output format: shared JSON schema used across cloud and local extraction.
 */
class QwenExtractionStrategy(
    private val modelManagerProvider: () -> LlmModelManager,
    private val promptBuilder: ExtractionPromptBuilder,
    private val responseParser: LlmResponseParser,
    private val prepareForLowRamInference: (suspend () -> Boolean)? = null
) : ExtractionStrategy {

    private val modelManager: LlmModelManager
        get() = modelManagerProvider()

    private class QwenParseRejectedException(message: String) : IllegalStateException(message)

    internal data class PreparedTranscript(
        val text: String,
        val preparedChars: Int,
        val fillerSegmentsRemoved: Int,
        val duplicateSegmentsRemoved: Int,
        val clippedToBudget: Boolean,
        val compacted: Boolean
    )

    override val name: String
        get() {
            val tier = modelManager.activeTier()
            return "Qwen 3.5 ${if (tier == LlmModelManager.ModelTier.LARGE) "2B" else "0.8B"} (on-device)"
        }

    override suspend fun isAvailable(): Boolean {
        val ready = modelManager.isReady()
        val headroom = ready && modelManager.hasRuntimeHeadroom()
        if (!ready || !headroom) {
            Log.d(TAG, "isAvailable=false: ready=$ready, headroom=$headroom")
        }
        return ready && headroom
    }

    override suspend fun extract(
        transcript: String,
        patientId: String,
        providerId: String,
        facilityId: String
    ): StructuredEncounter? = withContext(Dispatchers.Default) { // CPU-bound inference — Default, not IO
        try {
            if (prepareForLowRamInference?.invoke() == false) {
                Log.w(TAG, "Skipping Qwen extraction: ASR is active or still preparing")
                return@withContext null
            }
            if (!modelManager.hasRuntimeHeadroom()) {
                Log.w(TAG, "Skipping Qwen: not enough free memory for safe inference")
                return@withContext null
            }
            val preparedTranscript = prepareTranscriptForInference(
                transcript = transcript,
                charBudget = modelManager.maxTranscriptChars()
            )
            if (preparedTranscript.text.isBlank()) {
                Log.w(TAG, "Skipping Qwen: transcript is empty after preparation")
                return@withContext null
            }
            if (modelManager.shouldSkipLongTranscript(preparedTranscript.preparedChars)) {
                Log.w(TAG, "Skipping Qwen: transcript too long for stable on-device inference")
                return@withContext null
            }

            // Use structured system/user pair — MNN applies native chat template
            // with proper special token IDs (not raw text <|im_start|> tags)
            val (systemPrompt, userMessage) = promptBuilder.extractionSystemAndUser(preparedTranscript.text)

            val maxOutputTokens = modelManager.recommendedExtractionOutputTokens()
            Log.d(
                TAG,
                "Running Qwen inference (system: ${systemPrompt.length} chars, user: ${userMessage.length} chars, " +
                    "transcript=${transcript.length}->${preparedTranscript.preparedChars}, " +
                    "compacted=${preparedTranscript.compacted}, " +
                    "filler_removed=${preparedTranscript.fillerSegmentsRemoved}, " +
                    "duplicates_removed=${preparedTranscript.duplicateSegmentsRemoved}, " +
                    "clipped=${preparedTranscript.clippedToBudget}, max_output_tokens=$maxOutputTokens)"
            )

            val responseText = runWithEmptyResponseRetry(
                systemPrompt = systemPrompt,
                userMessage = userMessage,
                maxOutputTokens = maxOutputTokens
            )

            if (responseText.isNullOrBlank()) {
                Log.w(TAG, "Qwen returned empty response")
                return@withContext null
            }

            val normalizedResponseText = normalizeModelResponse(responseText)
            Log.d(TAG, "Qwen response received (${normalizedResponseText.length} chars)")
            val parseReport = responseParser.parseDetailed(
                responseText = normalizedResponseText,
                transcript = transcript,
                patientId = patientId,
                providerId = providerId,
                facilityId = facilityId
            )

            if (parseReport.encounter == null) {
                val failureReason = parseReport.failureReason ?: "parser rejected output"
                Log.w(TAG, "Qwen parser rejected output: $failureReason")
                logRawOutputPreview(normalizedResponseText)
                throw QwenParseRejectedException(failureReason)
            }

            Log.d(TAG, "Qwen parsed successfully via ${parseReport.format}")
            parseReport.encounter
        } catch (e: QwenParseRejectedException) {
            throw e
        } catch (e: Exception) {
            Log.e(TAG, "Qwen extraction failed", e)
            null
        }
    }

    companion object {
        private const val TAG = "QwenExtraction"
        internal const val JSON_RESPONSE_PREFIX = "{"
        private const val CHAT_ASSISTANT_PREFIX = "<|im_start|>assistant"
        private const val CHAT_END_TOKEN = "<|im_end|>"
        private val PRIMARY_GENERATION_CONFIG = LlmModelManager.GenerationConfig(
            temperature = 0.1f,
            topP = 0.95f,
            topK = 40,
            repeatPenalty = 1.05f
        )
        private val NOTE_GENERATION_CONFIG = LlmModelManager.GenerationConfig(
            temperature = 0.3f,
            topP = 0.95f,
            topK = 40,
            repeatPenalty = 1.3f
        )
        private val COMPACT_NOTE_GENERATION_CONFIG = LlmModelManager.GenerationConfig(
            temperature = 0.2f,
            topP = 0.92f,
            topK = 40,
            repeatPenalty = 1.2f
        )
        private val NOTE_RECOVERY_GENERATION_CONFIG = LlmModelManager.GenerationConfig(
            temperature = 0.2f,
            topP = 0.95f,
            topK = 40,
            repeatPenalty = 1.1f
        )
        private val EMPTY_RESPONSE_RETRY_CONFIG = LlmModelManager.GenerationConfig(
            temperature = 0.2f,
            topP = 0.98f,
            topK = 50,
            repeatPenalty = 1.02f
        )

        internal fun buildPrimedRetryPrompt(prompt: String): String = buildString {
            val trimmed = prompt.trimEnd()
            when {
                trimmed.endsWith(JSON_RESPONSE_PREFIX) -> append(trimmed)
                CHAT_ASSISTANT_PREFIX in trimmed -> {
                    append(trimmed)
                    if (!trimmed.endsWith(JSON_RESPONSE_PREFIX)) {
                        append(JSON_RESPONSE_PREFIX)
                    }
                }
                else -> {
                    append(trimmed)
                    appendLine()
                    appendLine()
                    appendLine("Continue by writing the JSON object immediately after the next line.")
                    append(JSON_RESPONSE_PREFIX)
                }
            }
        }

        internal fun mergePrimedResponse(responseText: String, prefix: String = JSON_RESPONSE_PREFIX): String {
            val trimmed = responseText.trimStart()
            return if (trimmed.trimStart().startsWith(prefix)) {
                trimmed.trimStart()
            } else {
                prefix + trimmed
            }
        }

        /** Regex to match <think>...</think> blocks (including multi-line). */
        private val THINK_TAG_REGEX = Regex("""<think>[\s\S]*?</think>""")
        private val WHITESPACE_REGEX = Regex("""\s+""")

        /**
         * Strip all thinking blocks from model output. Handles both:
         * - Closed blocks: <think>...</think>
         * - Unclosed blocks: <think>... (model ran out of tokens mid-thinking)
         */
        internal fun stripThinkingBlocks(text: String): String {
            // First strip all closed <think>...</think> blocks
            var result = THINK_TAG_REGEX.replace(text, "")
            // Then strip any remaining unclosed <think> block (thinking filled entire output)
            val unclosedIdx = result.indexOf("<think>")
            if (unclosedIdx >= 0) {
                Log.w(TAG, "Stripping unclosed <think> block (model likely ran out of tokens mid-thinking)")
                result = result.substring(0, unclosedIdx)
            }
            return result.trim()
        }

        internal fun normalizeModelResponse(responseText: String): String {
            val trimmed = responseText.trimEnd()
            if (trimmed.isBlank()) return trimmed.trim()

            val unwrapped = trimmed
                .removePrefix(CHAT_ASSISTANT_PREFIX)
                .trimStart('\n', '\r')
                .removeSuffix(CHAT_END_TOKEN)
                .trimEnd()

            // Strip any thinking blocks the model may have emitted
            val withoutThinking = stripThinkingBlocks(unwrapped)

            val normalized = withoutThinking.trimStart()
            val result = when {
                normalized.startsWith("{") || normalized.startsWith("[") -> normalized
                normalized.startsWith("\"") -> mergePrimedResponse(normalized)
                else -> withoutThinking
            }

            // Detect and truncate degenerate repetition loops
            return truncateRepetition(result)
        }

        /**
         * Detect if the model output has degenerate repetition (same 40+ char
         * substring appearing 3+ times). If so, truncate at the 2nd occurrence
         * and attempt to close the JSON cleanly.
         */
        internal fun truncateRepetition(text: String, minPatternLen: Int = 40, maxOccurrences: Int = 3): String {
            if (text.length < minPatternLen * maxOccurrences) return text

            // Check the last portion of the output for repeating patterns
            val checkRegion = text.takeLast((minPatternLen * maxOccurrences * 2).coerceAtMost(text.length))
            for (patternLen in minPatternLen..80) {
                if (patternLen > checkRegion.length / 2) break
                val pattern = checkRegion.takeLast(patternLen)
                var count = 0
                var searchFrom = 0
                while (true) {
                    val idx = text.indexOf(pattern, searchFrom)
                    if (idx < 0) break
                    count++
                    searchFrom = idx + 1
                }
                if (count >= maxOccurrences) {
                    // Find the 2nd occurrence and truncate there
                    val firstIdx = text.indexOf(pattern)
                    val secondIdx = text.indexOf(pattern, firstIdx + 1)
                    if (secondIdx > 0) {
                        Log.w(TAG, "Repetition detected: ${patternLen}-char pattern repeated ${count}x, truncating at position $secondIdx")
                        val truncated = text.substring(0, secondIdx).trimEnd()
                        // Try to close JSON cleanly
                        return closeJsonBrackets(truncated)
                    }
                }
            }
            return text
        }

        /** Best-effort close unclosed JSON braces/brackets after truncation. */
        private fun closeJsonBrackets(text: String): String {
            var openBraces = 0
            var openBrackets = 0
            var inString = false
            var escaped = false
            for (ch in text) {
                if (escaped) { escaped = false; continue }
                if (ch == '\\' && inString) { escaped = true; continue }
                if (ch == '"') { inString = !inString; continue }
                if (inString) continue
                when (ch) {
                    '{' -> openBraces++
                    '}' -> openBraces--
                    '[' -> openBrackets++
                    ']' -> openBrackets--
                }
            }
            val sb = StringBuilder(text)
            // Close any open strings
            if (inString) sb.append('"')
            // Close brackets then braces
            repeat(openBrackets.coerceAtLeast(0)) { sb.append(']') }
            repeat(openBraces.coerceAtLeast(0)) { sb.append('}') }
            return sb.toString()
        }

        internal fun prepareTranscriptForInference(transcript: String, charBudget: Int): PreparedTranscript {
            val trimmedTranscript = transcript.trim()
            if (trimmedTranscript.isBlank()) {
                return PreparedTranscript(
                    text = "",
                    preparedChars = 0,
                    fillerSegmentsRemoved = 0,
                    duplicateSegmentsRemoved = 0,
                    clippedToBudget = false,
                    compacted = false
                )
            }

            if (charBudget <= 0 || trimmedTranscript.length <= charBudget) {
                return PreparedTranscript(
                    text = trimmedTranscript,
                    preparedChars = trimmedTranscript.length,
                    fillerSegmentsRemoved = 0,
                    duplicateSegmentsRemoved = 0,
                    clippedToBudget = false,
                    compacted = false
                )
            }

            val optimizedTranscript = AmbientTranscriptOptimizer.optimize(
                transcript = transcript,
                charBudget = charBudget
            )
            return PreparedTranscript(
                text = optimizedTranscript.optimizedTranscript,
                preparedChars = optimizedTranscript.optimizedChars,
                fillerSegmentsRemoved = optimizedTranscript.fillerSegmentsRemoved,
                duplicateSegmentsRemoved = optimizedTranscript.duplicateSegmentsRemoved,
                clippedToBudget = optimizedTranscript.clippedToBudget,
                compacted = true
            )
        }

        internal fun responsePreview(
            text: String,
            maxChars: Int = 1800
        ): String = text
            .replace(WHITESPACE_REGEX, " ")
            .trim()
            .take(maxChars)

        internal fun responseTailPreview(
            text: String,
            maxChars: Int = 500
        ): String = text
            .takeLast(maxChars)
            .replace(WHITESPACE_REGEX, " ")
            .trim()

        /**
         * Note-specific repetition truncation. Handles two patterns:
         * 1. Identical consecutive lines (bullet points or sentences repeated back-to-back)
         * 2. Longer substring repetition (30+ chars appearing 3+ times)
         *
         * Unlike [truncateRepetition], this does NOT attempt JSON bracket closing —
         * notes are plain text / Markdown.
         */
        internal fun truncateNoteRepetition(text: String): String {
            // Pass 1: Deduplicate identical consecutive lines
            val lines = text.lines()
            val deduped = mutableListOf<String>()
            var prevLine: String? = null
            var dupCount = 0
            for (line in lines) {
                val trimmedLine = line.trim()
                if (trimmedLine == prevLine && trimmedLine.isNotBlank()) {
                    dupCount++
                    if (dupCount >= 2) continue // keep at most 1 duplicate
                } else {
                    dupCount = 0
                }
                deduped.add(line)
                prevLine = trimmedLine
            }
            val afterLineDup = deduped.joinToString("\n")

            // Pass 2: Detect longer repeating substrings (30+ chars, 3+ occurrences)
            val minLen = 30
            val maxOccurrences = 3
            if (afterLineDup.length < minLen * maxOccurrences) return afterLineDup

            val checkRegion = afterLineDup.takeLast((minLen * maxOccurrences * 2).coerceAtMost(afterLineDup.length))
            for (patternLen in minLen..100) {
                if (patternLen > checkRegion.length / 2) break
                val pattern = checkRegion.takeLast(patternLen)
                var count = 0
                var searchFrom = 0
                while (true) {
                    val idx = afterLineDup.indexOf(pattern, searchFrom)
                    if (idx < 0) break
                    count++
                    searchFrom = idx + 1
                }
                if (count >= maxOccurrences) {
                    val firstIdx = afterLineDup.indexOf(pattern)
                    val secondIdx = afterLineDup.indexOf(pattern, firstIdx + 1)
                    if (secondIdx > 0) {
                        Log.w(TAG, "Note repetition: ${patternLen}-char pattern repeated ${count}x, truncating")
                        return afterLineDup.substring(0, secondIdx).trimEnd()
                    }
                }
            }
            return afterLineDup
        }

        internal fun looksLikeUsableNote(text: String): Boolean {
            val lines = text.lines()
                .map { it.trim() }
                .filter { it.isNotBlank() }
            val letterCount = text.count { it.isLetter() }
            val hasBodyContent = lines.any { it.startsWith("-") || it.length >= 32 }
            return letterCount >= 24 && hasBodyContent
        }
    }

    /**
     * Generate a draft clinical note from transcript via on-device Qwen inference.
     * Returns plain text (not JSON) — the clinician reviews/edits this before extraction.
     */
    override suspend fun generateNote(transcript: String): String? = withContext(Dispatchers.Default) { // CPU-bound
        try {
            if (prepareForLowRamInference?.invoke() == false) {
                Log.w(TAG, "Skipping Qwen note generation: ASR is active or still preparing")
                return@withContext null
            }
            if (!modelManager.hasRuntimeHeadroom()) {
                Log.w(TAG, "Skipping Qwen note generation: not enough free memory")
                return@withContext null
            }
            val prepared = prepareTranscriptForInference(
                transcript = transcript,
                charBudget = modelManager.maxTranscriptChars()
            )
            if (prepared.text.isBlank()) {
                Log.w(TAG, "Skipping Qwen note generation: transcript empty after preparation")
                return@withContext null
            }
            // Use structured system/user pair — MNN applies native chat template
            val compact = false
            val (systemPrompt, userMessage) = promptBuilder.noteSystemAndUser(prepared.text, compact = compact)
            val maxOutputTokens = modelManager.recommendedNoteOutputTokens()
            val config = NOTE_GENERATION_CONFIG

            Log.d(TAG, "Running Qwen note generation (system: ${systemPrompt.length} chars, user: ${userMessage.length} chars, compact=$compact)")

            val responseText = modelManager.runChatInference(
                systemPrompt = systemPrompt,
                userMessage = userMessage,
                maxTokens = maxOutputTokens,
                config = config
            )
            val primaryNote = normalizeGeneratedNote(responseText)
            if (primaryNote != null) {
                Log.d(TAG, "Qwen note generated (${primaryNote.length} chars)")
                return@withContext primaryNote
            }

            Log.w(TAG, "Primary Qwen note output was empty or too weak; retrying with stronger note prompt")
            val retryResponse = modelManager.runChatInference(
                systemPrompt = promptBuilder.buildNoteSystemPrompt(compact = true),
                userMessage = buildNoteRecoveryUserMessage(prepared.text),
                maxTokens = maxOutputTokens,
                config = if (modelManager.activeTier() == LlmModelManager.ModelTier.SMALL) {
                    COMPACT_NOTE_GENERATION_CONFIG
                } else {
                    NOTE_RECOVERY_GENERATION_CONFIG
                }
            )
            val recoveredNote = normalizeGeneratedNote(retryResponse)
            if (recoveredNote == null) {
                Log.w(TAG, "Qwen note generation produced no usable note after retry")
                return@withContext null
            }
            Log.d(TAG, "Qwen note generated after retry (${recoveredNote.length} chars)")
            recoveredNote
        } catch (e: Exception) {
            Log.e(TAG, "Qwen note generation failed", e)
            null
        }
    }

    private fun buildNoteRecoveryUserMessage(transcript: String): String = buildString {
        appendLine("Write a clinically useful note from this dictation.")
        appendLine("Return the note only.")
        appendLine("Include any stated diagnosis, medication, immunization, treatment, counseling, and follow-up.")
        appendLine("Use markdown headers (##) and bullet points (-).")
        appendLine("Start directly with a section header such as ## Chief Complaint or ## Assessment.")
        appendLine()
        appendLine("DICTATION:")
        appendLine()
        appendLine(transcript)
    }

    private fun normalizeGeneratedNote(responseText: String?): String? {
        if (responseText.isNullOrBlank()) {
            Log.w(TAG, "Qwen note generation returned empty response")
            return null
        }

        val cleaned = responseText.trimEnd()
            .removePrefix(CHAT_ASSISTANT_PREFIX)
            .trimStart('\n', '\r')
            .removeSuffix(CHAT_END_TOKEN)
            .let { stripThinkingBlocks(it) }

        if (cleaned.isBlank()) {
            Log.w(TAG, "Qwen note was entirely a thinking block — no usable content")
            return null
        }

        val deduped = truncateNoteRepetition(cleaned)
        return deduped.takeIf {
            looksLikeUsableNote(it)
        } ?: run {
            Log.w(TAG, "Qwen note output was too thin to use (${deduped.length} chars)")
            null
        }
    }

    private suspend fun runWithEmptyResponseRetry(
        systemPrompt: String,
        userMessage: String,
        maxOutputTokens: Int
    ): String? {
        val primary = modelManager.runChatInference(
            systemPrompt = systemPrompt,
            userMessage = userMessage,
            maxTokens = maxOutputTokens,
            config = PRIMARY_GENERATION_CONFIG
        )
        if (!primary.isNullOrBlank()) return primary

        Log.w(TAG, "Primary Qwen attempt returned empty; retrying with JSON prefix priming")

        // For retry, append JSON prefix hint to user message
        val primedUserMessage = "$userMessage\n\nRespond with JSON starting with: {"
        val retry = modelManager.runChatInference(
            systemPrompt = systemPrompt,
            userMessage = primedUserMessage,
            maxTokens = maxOutputTokens,
            config = EMPTY_RESPONSE_RETRY_CONFIG
        )
        if (retry.isNullOrBlank()) return null
        return mergePrimedResponse(retry)
    }

    private fun logRawOutputPreview(responseText: String) {
        Log.d(TAG, "Qwen output received (${responseText.length} chars)")
    }

}
