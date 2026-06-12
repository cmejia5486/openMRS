package com.chartlite.app.extraction

import android.util.Log
import com.chartlite.app.model.StructuredEncounter
import kotlinx.coroutines.*
import kotlinx.coroutines.flow.MutableStateFlow
import kotlinx.coroutines.flow.StateFlow
import java.time.Instant

/**
 * Batched inference queue for on-device LLM extraction.
 *
 * Instead of loading the LLM for every patient encounter (expensive: ~2-3W sustained,
 * 5s model load, 800MB-1.4GB RAM), this queue collects transcripts and processes them
 * in a single batch — loading the model once for N patients.
 *
 * Design:
 * - Clinicians record encounters normally; transcripts go into the queue
 * - Regex fallback provides immediate preview (vitals, drug names, obvious diagnoses)
 * - Batch processing triggers on: manual "Process Queue" tap, configurable auto-batch
 *   (every N patients or M minutes idle), or end-of-day
 * - Urgent encounters (referrals, emergencies) bypass the queue for immediate LLM extraction
 *
 * Battery impact: Model loads once for N patients instead of N times.
 * RAM impact: Model only resident during batch window; freed for UI/ASR between batches.
 */
class ExtractionQueue(
    private val orchestrator: ExtractionOrchestrator,
    private val repository: ExtractionQueueRepository,
    private val scope: CoroutineScope = CoroutineScope(SupervisorJob() + Dispatchers.IO),
    private val cancelCurrentProcessing: () -> Unit = {},
    /** Optional callback to unload LLM model after batch cancel or between batch items on constrained devices. */
    var unloadLlm: (suspend () -> Unit)? = null,
    /** Optional: process pending clinical photos during batch. Returns merged encounter. */
    var photoProcessor: (suspend (patientId: String, encounter: StructuredEncounter) -> StructuredEncounter)? = null
) {
    private val workerScope = CoroutineScope(
        scope.coroutineContext + SupervisorJob(scope.coroutineContext[Job])
    )

    // ── Queue state ─────────────────────────────────────────────────────

    enum class QueueState {
        IDLE,           // No batch in progress
        PROCESSING,     // Batch inference running
    }

    data class QueuedTranscript(
        val id: String,                       // Unique queue entry ID
        val transcript: String,
        val patientId: String,
        val providerId: String,
        val facilityId: String,
        val visitId: String?,
        val stationType: String?,
        val queuedAt: Instant,
        val isUrgent: Boolean = false,        // Urgent = needs immediate processing
        val deferredReview: Boolean = false
    )

    data class QueuedResult(
        val queueEntryId: String,
        val result: ExtractionOrchestrator.ExtractionResult,
        val processedAt: Instant,
        val draftNote: String? = null  // Draft note from note-first flow (if available)
    )

    /**
     * Result of draft note generation (note-first architecture).
     */
    data class QueuedNoteResult(
        val queueEntryId: String,
        val note: String,
        val strategyUsed: String,
        val generatedAt: Instant
    )

    /**
     * Granular processing step for UI feedback.
     * On low-end devices each step can take 30-90s, so showing "Loading model..."
     * vs "Extracting clinical data..." tells the user the app isn't frozen.
     */
    enum class ProcessingStep {
        IDLE,
        LOADING_MODEL,
        GENERATING_NOTE,
        EXTRACTING,
        SAVING
    }

    private val _state = MutableStateFlow(QueueState.IDLE)
    val state: StateFlow<QueueState> = _state

    private val _items = MutableStateFlow<List<ExtractionQueueRepository.QueueItem>>(emptyList())
    val items: StateFlow<List<ExtractionQueueRepository.QueueItem>> = _items

    private val _processedCount = MutableStateFlow(0)
    val processedCount: StateFlow<Int> = _processedCount

    private val _processingStep = MutableStateFlow(ProcessingStep.IDLE)
    val processingStep: StateFlow<ProcessingStep> = _processingStep

    private var batchJob: Job? = null

    init {
        workerScope.launch {
            recoverInterruptedItemsIfIdle()
        }
        workerScope.launch {
            repository.observeActiveItems().collect { queueItems ->
                _items.value = queueItems
            }
        }
    }

    // ── Enqueue ─────────────────────────────────────────────────────────

    /**
     * Add a transcript to the extraction queue.
     *
     * @param urgent If true, triggers immediate single-item processing
     *   (bypasses batch queue). Use for referral/emergency encounters where
     *   the clinician needs structured data right now.
     * @return The queue entry ID
     */
    /**
     * @param approvedNote If the clinician already reviewed a draft note, pass it here
     *   to skip redundant note generation during processing. The original transcript
     *   is still stored for audit/reference.
     */
    suspend fun enqueue(
        transcript: String,
        patientId: String,
        providerId: String,
        facilityId: String,
        urgent: Boolean = false,
        visitId: String? = null,
        stationType: String? = null,
        deferredReview: Boolean = false,
        approvedNote: String? = null
    ): String {
        val entryId = repository.enqueue(
            transcript = transcript,
            patientId = patientId,
            providerId = providerId,
            facilityId = facilityId,
            visitId = visitId,
            stationType = stationType,
            urgent = urgent,
            deferredReview = deferredReview
        )

        // If an approved note was passed, store it immediately to skip re-generation
        if (approvedNote != null) {
            repository.markNoteGenerated(entryId, approvedNote, "pre-approved")
        }

        val entry = QueuedTranscript(
            id = entryId,
            transcript = transcript,
            patientId = patientId,
            providerId = providerId,
            facilityId = facilityId,
            visitId = visitId,
            stationType = stationType,
            queuedAt = Instant.now(),
            isUrgent = urgent,
            deferredReview = deferredReview
        )
        Log.d(TAG, "Enqueued transcript for patient ${patientId.take(4)}*** (urgent=$urgent, deferred=$deferredReview, hasNote=${approvedNote != null})")

        // Urgent encounters get immediate processing
        if (urgent) {
            processUrgent(entry)
        }

        return entry.id
    }

    // ── Batch processing ────────────────────────────────────────────────

    /**
     * Process all queued transcripts in a single batch.
     * Loads the LLM once, runs inference for each transcript, then unloads.
     *
     * Call from: "Process Queue" button, auto-batch timer, or end-of-day trigger.
     */
    fun processBatch() {
        if (batchJob?.isActive == true) {
            Log.w(TAG, "Batch already in progress, skipping")
            return
        }

        batchJob = workerScope.launch {
            recoverInterruptedItemsIfIdle()
            _state.value = QueueState.PROCESSING
            try {
                val pending = repository.getQueuedItems().filter { !it.isUrgent }

                if (pending.isEmpty()) {
                    Log.d(TAG, "No pending transcripts to process")
                    return@launch
                }

                Log.d(TAG, "Starting batch processing: ${pending.size} transcripts")

                var processed = 0
                for (entry in pending) {
                    if (!isActive) break

                    try {
                        // Batch mode: skip note generation to halve LLM work per item.
                        // On low-end devices, each LLM round trip (model load + inference)
                        // can take 60-90s — doing it twice per item is the #1 cause of
                        // "stuck at batch extraction running".
                        processEntry(entry, skipNoteGeneration = true)
                        processed++
                        _processedCount.value = processed

                        // On constrained devices (≤6GB), unload LLM every 3 items to
                        // let the system reclaim memory. Prevents gradual OOM from
                        // MNN KV-cache fragmentation across many sequential inferences.
                        if (processed % BATCH_UNLOAD_INTERVAL == 0 && pending.size > processed) {
                            Log.d(TAG, "Batch checkpoint: unloading LLM after $processed items to reclaim memory")
                            unloadLlm?.invoke()
                            System.gc()
                            delay(500) // Brief pause for memory reclamation
                        }
                    } catch (e: CancellationException) {
                        repository.retry(entry.id)
                        throw e
                    } catch (e: Exception) {
                        Log.e(TAG, "Failed to process transcript for patient ${entry.patientId.take(4)}***", e)
                        repository.markFailed(entry.id, e.message)
                    }
                }
                Log.d(TAG, "Batch complete: $processed/${pending.size} processed")
            } finally {
                _state.value = QueueState.IDLE
                _processingStep.value = ProcessingStep.IDLE
                _processedCount.value = 0
                batchJob = null
            }
        }
    }

    /**
     * Cancel the current batch processing.
     * Already-processed results are kept; remaining items stay in queue.
     */
    fun cancelBatch() {
        cancelCurrentProcessing()
        batchJob?.cancel()
        // Unload LLM immediately so subsequent recording doesn't OOM
        // (cancelled batch leaves model loaded, next ASR load competes for RAM)
        workerScope.launch { unloadLlm?.invoke() }
    }

    // ── Urgent (immediate) processing ───────────────────────────────────

    /**
     * Process a single urgent encounter immediately, bypassing the batch queue.
     * Used for referrals and emergencies where the clinician needs structured data now.
     */
    private suspend fun processUrgent(entry: QueuedTranscript) {
        _state.value = QueueState.PROCESSING
        try {
            val result = processEntry(
                repository.getItem(entry.id)
                    ?: return
            )
            Log.d(TAG, "Urgent processing complete: patient ${entry.patientId.take(4)}*** via ${result.result.strategyUsed}")
        } catch (e: CancellationException) {
            repository.retry(entry.id)
            throw e
        } catch (e: Exception) {
            Log.e(TAG, "Urgent processing failed for patient ${entry.patientId.take(4)}***", e)
            repository.markFailed(entry.id, e.message)
        } finally {
            // On ≤4GB devices, releaseLlmForLowMemoryHandoff() unloads the model so
            // ASR can reclaim the memory. On 4GB+ devices the callback is a no-op,
            // letting the auto-unload timer keep the model warm for follow-up work.
            unloadLlm?.invoke()
            _state.value = QueueState.IDLE
            _processingStep.value = ProcessingStep.IDLE
        }
    }

    suspend fun processItem(queueEntryId: String): QueuedResult? {
        if (batchJob?.isActive == true) {
            Log.w(TAG, "Cannot process single queue item while a batch is running")
            return null
        }

        recoverInterruptedItemsIfIdle()
        val item = repository.getItem(queueEntryId) ?: return null
        if (item.status == ExtractionQueueRepository.QueueStatus.READY && item.encounter != null) {
            return getResult(queueEntryId)
        }

        _state.value = QueueState.PROCESSING
        return try {
            processEntry(item)
        } catch (e: CancellationException) {
            repository.retry(queueEntryId)
            throw e
        } catch (e: Exception) {
            Log.e(TAG, "Single-item processing failed for ${item.patientId.take(4)}***", e)
            repository.markFailed(queueEntryId, e.message)
            null
        } finally {
            // See processUrgent — gated by shouldAggressivelySerializeAsrAndLlm() in the callback.
            unloadLlm?.invoke()
            _state.value = QueueState.IDLE
            _processingStep.value = ProcessingStep.IDLE
            _processedCount.value = 0
        }
    }

    // ── Note generation (draft-note-first architecture) ─────────────────

    /** In-memory store for generated draft notes (keyed by queue entry ID). Thread-safe. */
    private val noteResults = java.util.concurrent.ConcurrentHashMap<String, QueuedNoteResult>()

    /**
     * Generate a draft clinical note for a queued transcript.
     * Uses the LLM strategy fallback chain (Claude → Qwen).
     * Returns null if no LLM is available (caller should fall back to direct extraction).
     */
    suspend fun generateNoteForEntry(queueEntryId: String): QueuedNoteResult? {
        val item = repository.getItem(queueEntryId) ?: return null

        val noteResult = generateNoteWithFallbacks(item.transcript, item.patientId) ?: return null

        val result = QueuedNoteResult(
            queueEntryId = queueEntryId,
            note = noteResult.note,
            strategyUsed = noteResult.strategyUsed,
            generatedAt = Instant.now()
        )
        // Evict old entries to prevent unbounded memory growth
        if (noteResults.size > MAX_NOTE_RESULTS) {
            noteResults.clear()
        }
        noteResults[queueEntryId] = result
        return result
    }

    /**
     * Generate a draft note directly from a transcript (not from a queue entry).
     * Used for urgent/immediate processing where the transcript isn't queued first.
     */
    suspend fun generateNoteFromTranscript(transcript: String): ExtractionOrchestrator.NoteGenerationResult? {
        return generateNoteWithFallbacks(transcript, "direct")
    }

    fun getNoteResult(queueEntryId: String): QueuedNoteResult? = noteResults[queueEntryId]

    fun consumeNoteResult(queueEntryId: String) {
        noteResults.remove(queueEntryId)
    }

    // ── Result retrieval ────────────────────────────────────────────────

    /**
     * Get the extraction result for a specific queue entry.
     * Returns null if not yet processed.
     */
    suspend fun getResult(queueEntryId: String): QueuedResult? {
        val item = repository.getItem(queueEntryId) ?: return null
        val encounter = item.encounter ?: return null
        if (item.status != ExtractionQueueRepository.QueueStatus.READY) return null
        return QueuedResult(
            queueEntryId = queueEntryId,
            result = ExtractionOrchestrator.ExtractionResult(
                encounter = encounter,
                strategyUsed = item.strategyUsed ?: "Unknown",
                fallbacksAttempted = item.fallbacksAttempted
            ),
            processedAt = item.updatedAt
        )
    }

    /**
     * Get the extraction result for a specific patient's most recent encounter.
     */
    suspend fun getResultForPatient(patientId: String): QueuedResult? {
        val readyItems = _items.value
            .filter {
                it.patientId == patientId &&
                    it.status == ExtractionQueueRepository.QueueStatus.READY &&
                    it.encounter != null
            }
            .maxByOrNull { it.updatedAt }
            ?: return null
        return QueuedResult(
            queueEntryId = readyItems.id,
            result = ExtractionOrchestrator.ExtractionResult(
                encounter = readyItems.encounter ?: return null,
                strategyUsed = readyItems.strategyUsed ?: "Unknown",
                fallbacksAttempted = readyItems.fallbacksAttempted
            ),
            processedAt = readyItems.updatedAt
        )
    }

    /**
     * Clear processed results (e.g., after they've been saved to the database).
     * Thread-safe: mutations go through dedicated lock to match suspend-path mutex semantics.
     */
    fun clearResults() {
        workerScope.launch {
            _items.value
                .filter { it.status == ExtractionQueueRepository.QueueStatus.READY && !it.deferredReview }
                .forEach {
                    noteResults.remove(it.id)
                    repository.delete(it.id)
                }
        }
    }

    /**
     * Remove a specific result after it's been consumed.
     * Thread-safe: mutations go through dedicated lock to match suspend-path mutex semantics.
     */
    fun consumeResult(queueEntryId: String) {
        noteResults.remove(queueEntryId)
        workerScope.launch {
            val item = repository.getItem(queueEntryId) ?: return@launch
            if (!item.deferredReview) {
                repository.delete(queueEntryId)
            }
        }
    }

    suspend fun getItem(queueEntryId: String): ExtractionQueueRepository.QueueItem? {
        return repository.getItem(queueEntryId)
    }

    suspend fun markSaved(queueEntryId: String, savedEncounterId: String) {
        repository.markSaved(queueEntryId, savedEncounterId)
    }

    fun retry(queueEntryId: String) {
        scope.launch {
            repository.retry(queueEntryId)
        }
    }

    fun delete(queueEntryId: String) {
        noteResults.remove(queueEntryId)
        workerScope.launch {
            repository.delete(queueEntryId)
        }
    }

    fun close() {
        cancelCurrentProcessing()
        batchJob?.cancel()
        workerScope.cancel()
    }

    val pendingCount: Int
        get() = _items.value.count {
            it.status == ExtractionQueueRepository.QueueStatus.QUEUED ||
                it.status == ExtractionQueueRepository.QueueStatus.PROCESSING
        }
    val readyCount: Int get() = _items.value.count { it.status == ExtractionQueueRepository.QueueStatus.READY }
    val failedCount: Int get() = _items.value.count { it.status == ExtractionQueueRepository.QueueStatus.FAILED }
    val isProcessing: Boolean get() = _state.value == QueueState.PROCESSING

    private suspend fun recoverInterruptedItemsIfIdle() {
        if (_state.value != QueueState.IDLE) return
        val recovered = repository.recoverInterruptedProcessing()
        if (recovered > 0) {
            Log.w(TAG, "Recovered $recovered queue item(s) left in PROCESSING after interrupted on-device run")
        }
    }

    /**
     * @param skipNoteGeneration If true, extract directly from the raw transcript without
     *   generating a draft note first. Used in batch mode to halve on-device LLM work
     *   (model load + inference is the bottleneck on low-end devices).
     */
    private suspend fun processEntry(
        item: ExtractionQueueRepository.QueueItem,
        skipNoteGeneration: Boolean = false
    ): QueuedResult {
        val startedAt = System.currentTimeMillis()
        Log.d(TAG, "Processing transcript for patient ${item.patientId.take(4)}*** (skipNote=$skipNoteGeneration)")
        repository.markProcessing(item.id)
        _processingStep.value = ProcessingStep.LOADING_MODEL

        // Note-first flow: generate a draft clinical note first, then extract structured data from it.
        // Skip generation if: (a) pre-approved note exists, (b) batch mode (skipNoteGeneration=true).
        val existingNote = item.draftNote
        val noteResult: ExtractionOrchestrator.NoteGenerationResult?
        val extractionInput: String

        if (existingNote != null) {
            // Note was pre-approved — skip redundant LLM note generation
            Log.d(TAG, "Using pre-approved note for ${item.patientId.take(4)}*** (${existingNote.length} chars)")
            noteResult = ExtractionOrchestrator.NoteGenerationResult(
                note = existingNote,
                strategyUsed = item.noteStrategyUsed ?: "pre-approved",
                fallbacksAttempted = emptyList()
            )
            extractionInput = existingNote
        } else if (skipNoteGeneration) {
            // Batch mode — skip note generation to save an entire LLM round trip
            Log.d(TAG, "Batch mode: skipping note generation for ${item.patientId.take(4)}***")
            noteResult = null
            extractionInput = item.transcript
        } else {
            // Note generation already has per-strategy timeouts in the orchestrator and
            // per-inference bounds in LlmModelManager. Don't wrap the whole item in a
            // second outer timeout or we can abort before later fallbacks run.
            _processingStep.value = ProcessingStep.GENERATING_NOTE
            val generated = generateNoteWithFallbacks(item.transcript, item.patientId)
            if (generated != null) {
                repository.markNoteGenerated(item.id, generated.note, generated.strategyUsed)
                noteResult = generated
                extractionInput = generated.note
                Log.d(TAG, "Draft note generated for ${item.patientId.take(4)}*** via ${generated.strategyUsed}")
            } else {
                // Fallback: if note generation fails (no LLM available), extract directly from transcript
                Log.w(TAG, "Note generation unavailable for ${item.patientId.take(4)}***, extracting from raw transcript")
                noteResult = null
                extractionInput = item.transcript
            }
        }

        _processingStep.value = ProcessingStep.EXTRACTING
        val extractionStartedAt = System.currentTimeMillis()
        val result = orchestrator.extract(
            transcript = extractionInput,
            patientId = item.patientId,
            providerId = item.providerId,
            facilityId = item.facilityId
        )
        Log.d(
            TAG,
            "Structured extraction finished for ${item.patientId.take(4)}*** in " +
                "${System.currentTimeMillis() - extractionStartedAt}ms via ${result.strategyUsed}"
        )

        // Process any pending clinical photos for this patient
        var mergedEncounter = result.encounter
        photoProcessor?.let { processor ->
            try {
                _processingStep.value = ProcessingStep.EXTRACTING
                mergedEncounter = withTimeout(PHOTO_PROCESSING_TIMEOUT_MS) {
                    processor(item.patientId, mergedEncounter)
                }
            } catch (_: TimeoutCancellationException) {
                Log.w(TAG, "Photo processing timed out for ${item.patientId.take(4)}***")
            } catch (e: Exception) {
                Log.w(TAG, "Photo processing failed for ${item.patientId.take(4)}***: ${e.message}")
            }
        }

        _processingStep.value = ProcessingStep.SAVING
        // Set freeTextNote to the draft note (document of record), keep original transcript
        // Generate SMS summary if LLM didn't produce one
        val smsSummary = mergedEncounter.smsSummary
            ?: buildAlgorithmicSmsSummary(mergedEncounter)
        val enrichedResult = ExtractionOrchestrator.ExtractionResult(
            encounter = mergedEncounter.copy(
                freeTextNote = noteResult?.note ?: mergedEncounter.freeTextNote,
                transcript = item.transcript,  // Preserve original transcript
                smsSummary = smsSummary
            ),
            strategyUsed = result.strategyUsed,
            fallbacksAttempted = result.fallbacksAttempted
        )

        repository.markReady(item.id, enrichedResult)
        Log.d(
            TAG,
            "Processed patient ${item.patientId.take(4)}*** via ${enrichedResult.strategyUsed} " +
                "in ${System.currentTimeMillis() - startedAt}ms"
        )
        return QueuedResult(
            queueEntryId = item.id,
            result = enrichedResult,
            processedAt = Instant.now(),
            draftNote = noteResult?.note
        )
    }

    private suspend fun generateNoteWithFallbacks(
        transcript: String,
        patientIdForLog: String
    ): ExtractionOrchestrator.NoteGenerationResult? {
        val startedAt = System.currentTimeMillis()
        val result = orchestrator.generateNote(transcript)
        if (result != null) {
            Log.d(
                TAG,
                "Draft note finished for ${patientIdForLog.take(4)}*** in " +
                    "${System.currentTimeMillis() - startedAt}ms via ${result.strategyUsed}"
            )
        }
        return result
    }

    companion object {
        private const val TAG = "ExtractionQueue"
        /** Maximum number of cached note results before eviction. */
        private const val MAX_NOTE_RESULTS = 20
        /** Unload LLM every N batch items to prevent OOM from KV-cache fragmentation. */
        private const val BATCH_UNLOAD_INTERVAL = 3
        /** Max bytes for SMS free-text in BinaryEncoder V4. */
        private const val SMS_SUMMARY_MAX = 19
        private const val PHOTO_PROCESSING_TIMEOUT_MS = 30_000L

        // Common medical abbreviation map for SMS summary.
        // Multi-word phrases MUST come before their single-word components
        // (e.g. "back pain" before "pain") to match correctly.
        private val COMPLAINT_ABBREV = linkedMapOf(
            "upper respiratory" to "URI", "urinary tract" to "UTI",
            "sore throat" to "SrThr", "back pain" to "BkPn",
            "chest pain" to "ChPn",
            "fever" to "Fvr", "cough" to "Cgh", "headache" to "HA",
            "diarrhea" to "Diarr", "diarrhoea" to "Diarr",
            "vomiting" to "Vom", "nausea" to "Naus",
            "pain" to "Pn", "abdominal" to "Abd",
            "hypertension" to "HTN", "diabetes" to "DM",
            "pneumonia" to "PNA", "malaria" to "Mal",
            "asthma" to "Asth", "infection" to "Inf",
            "pregnant" to "Preg", "anemia" to "Ane", "anaemia" to "Ane",
            "hiv" to "HIV", "tuberculosis" to "TB", "tb" to "TB",
            "ear" to "Ear", "skin" to "Skin", "rash" to "Rash",
            "wound" to "Wnd", "fracture" to "Fx", "injury" to "Inj",
            "joint" to "Jnt"
        )

        /**
         * Build a ≤19-char abbreviated visit summary from extracted encounter data.
         * Format: "[Complaint] [Age][Sex] [Med]" using medical shorthand.
         * E.g. "Fvr Cgh 3yM Amox" or "HTN DM f/u 2wk"
         */
        internal fun buildAlgorithmicSmsSummary(encounter: StructuredEncounter): String? {
            val parts = mutableListOf<String>()

            // 1. Chief complaint / top diagnosis abbreviation
            // Prefer structured diagnoses over freeTextNote (which may be a full clinical note)
            val complaint = encounter.suggestedDiagnoses.firstOrNull()?.description
                ?: encounter.diagnoses.firstOrNull()?.description
                ?: encounter.freeTextNote.split("\n").first().take(60).ifBlank { null }
            if (complaint != null) {
                val lower = complaint.lowercase()
                // Try multi-word abbreviations first
                var abbreviated: String? = null
                for ((phrase, abbrev) in COMPLAINT_ABBREV) {
                    if (lower.contains(phrase)) {
                        abbreviated = abbrev
                        break
                    }
                }
                parts.add(abbreviated ?: complaint.split(" ").first().take(5).replaceFirstChar { it.uppercase() })
            }

            // 2. Second complaint/diagnosis if space
            if (encounter.suggestedDiagnoses.size >= 2) {
                val second = encounter.suggestedDiagnoses[1].description.lowercase()
                for ((phrase, abbrev) in COMPLAINT_ABBREV) {
                    if (second.contains(phrase)) {
                        parts.add(abbrev)
                        break
                    }
                }
            }

            // 3. Follow-up (medications/vitals/immunizations already in binary fields)
            encounter.followUp?.let { fu ->
                val fuStr = when {
                    fu.days % 30 == 0 && fu.days >= 30 -> "f/u ${fu.days / 30}mo"
                    fu.days % 7 == 0 && fu.days >= 7 -> "f/u ${fu.days / 7}wk"
                    else -> "f/u ${fu.days}d"
                }
                parts.add(fuStr)
            }

            if (parts.isEmpty()) return null

            // Build summary, greedily adding parts that fit within 19 chars
            val sb = StringBuilder()
            for (part in parts) {
                val candidate = if (sb.isEmpty()) part else "${sb} $part"
                if (candidate.length <= SMS_SUMMARY_MAX) {
                    sb.clear()
                    sb.append(candidate)
                } else {
                    break
                }
            }

            return sb.toString().takeIf { it.isNotBlank() }
        }
    }
}
