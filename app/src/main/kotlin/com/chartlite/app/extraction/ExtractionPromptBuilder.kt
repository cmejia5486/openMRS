package com.chartlite.app.extraction

import com.chartlite.app.model.Formulary
import com.chartlite.app.model.ICD10Index

/**
 * Builds the shared benchmark JSON prompt used by both local and cloud extraction.
 */
class ExtractionPromptBuilder(
    @Suppress("UNUSED_PARAMETER") icd10: ICD10Index,
    @Suppress("UNUSED_PARAMETER") formulary: Formulary,
    @Suppress("UNUSED_PARAMETER") vectorStore: ClinicalVectorStore? = null
) {

    /** Build the shared extraction prompt for on-device LLM extraction. */
    fun buildRagPrompt(transcript: String): String = buildOnDeviceChatPrompt(transcript)

    fun buildSystemPrompt(@Suppress("UNUSED_PARAMETER") condensed: Boolean = false): String =
        BENCHMARK_SYSTEM_PROMPT

    /**
     * Build the user message containing the transcript.
     */
    fun buildUserPrompt(transcript: String): String = buildBenchmarkUserPrompt(transcript)

    /**
     * Build a single combined prompt (for models that don't support system/user separation).
     */
    fun buildCombinedPrompt(transcript: String, @Suppress("UNUSED_PARAMETER") condensed: Boolean = false): String = buildString {
        append(buildSystemPrompt())
        appendLine()
        appendLine("---")
        appendLine()
        append(buildUserPrompt(transcript))
    }

    /**
     * Build the shared chat-formatted prompt for short dictation snippets.
     */
    fun buildSnippetPrompt(snippet: String): String {
        return buildOnDeviceChatPrompt(snippet)
    }

    // ── Separated system+user for native chat template ──

    /** Return (system, user) pair for extraction — used with LlamaBridge.applyChatTemplate(). */
    fun extractionSystemAndUser(transcript: String): Pair<String, String> =
        Pair(buildOnDeviceSystemPrompt(), buildOnDeviceUserPrompt(transcript))

    /** Return (system, user) pair for note generation — used with LlamaBridge.applyChatTemplate(). */
    fun noteSystemAndUser(transcript: String, compact: Boolean = false): Pair<String, String> =
        Pair(buildNoteSystemPrompt(compact), buildNoteUserPrompt(transcript, compact))

    // ── Note Generation Prompts (draft-note-first architecture) ──

    /** System prompt for generating a clinical note from transcript. */
    fun buildNoteSystemPrompt(compact: Boolean = false): String =
        if (compact) COMPACT_NOTE_SYSTEM_PROMPT else NOTE_SYSTEM_PROMPT

    /** User prompt for note generation (cloud LLM). */
    fun buildNoteUserPrompt(transcript: String, compact: Boolean = false): String = buildString {
        appendLine("Summarize this dictation into a concise clinical note.")
        appendLine("Include ONLY facts from the dictation. Omit empty sections.")
        appendLine()
        if (compact) {
            appendLine("Keep bullets short, but do not omit important clinical facts.")
            appendLine("Always include any stated diagnosis, medication, immunization, treatment, counseling, and follow-up.")
        }
        appendLine("Sections (include only if relevant):")
        appendLine("## Chief Complaint")
        appendLine("## History of Present Illness")
        appendLine("## Examination Findings")
        appendLine("## Vitals")
        appendLine("## Investigations")
        appendLine("## Assessment")
        appendLine("## Plan (include all treatments, medications, immunizations given)")
        appendLine("## Follow-up")
        appendLine("## Allergies")
        appendLine()
        appendLine("DICTATION:")
        appendLine()
        appendLine(transcript)
    }

    /** On-device chat-formatted prompt for note generation (Qwen). */
    fun buildOnDeviceNoteChatPrompt(transcript: String, compact: Boolean = false): String = buildString {
        appendLine("<|im_start|>system")
        appendLine(buildNoteSystemPrompt(compact))
        appendLine("<|im_end|>")
        appendLine("<|im_start|>user")
        appendLine(buildNoteUserPrompt(transcript, compact))
        appendLine("<|im_end|>")
        appendLine("<|im_start|>assistant")
        // Pre-close thinking block so Qwen skips thinking and generates content directly
        appendLine("<think>")
        appendLine("</think>")
    }

    private fun buildOnDeviceChatPrompt(transcript: String): String {
        return buildString {
            appendLine("<|im_start|>system")
            appendLine(buildOnDeviceSystemPrompt())
            appendLine("<|im_end|>")
            appendLine("<|im_start|>user")
            appendLine(buildOnDeviceUserPrompt(transcript))
            appendLine("<|im_end|>")
            appendLine("<|im_start|>assistant")
            // Pre-close thinking block so Qwen skips thinking and generates content directly
            appendLine("<think>")
            appendLine("</think>")
            append(ON_DEVICE_ASSISTANT_PREFIX)
        }
    }

    private fun buildOnDeviceSystemPrompt(): String = buildSystemPrompt()

    private fun buildOnDeviceUserPrompt(transcript: String): String = buildBenchmarkUserPrompt(transcript)

    private fun buildBenchmarkUserPrompt(transcript: String): String {
        // Detect if input is a structured note (from note-first flow) vs raw dictation
        val isStructuredNote = transcript.contains("## ")
        return buildString {
            if (isStructuredNote) {
                appendLine("Extract structured clinical facts from this clinical note as JSON.")
                appendLine("\"Assessment & Plan\" contains diagnoses, medications, immunizations, and plan items — extract each into the correct JSON field.")
            } else {
                appendLine("Extract structured clinical facts from this clinician")
                appendLine("dictation as JSON.")
            }
            appendLine()
            appendLine("Schema:")
            appendLine()
            appendLine(BENCHMARK_JSON_SCHEMA)
            appendLine()
            if (isStructuredNote) {
                appendLine("CLINICAL NOTE:")
            } else {
                appendLine("CLINICIAN DICTATION:")
            }
            appendLine()
            appendLine(transcript)
            appendLine()
            append("JSON:")
        }
    }

    // ── Vision Prompts (camera scan → auto-extract) ──

    /** System prompt for vision-based clinical image extraction. */
    fun visionSystemPrompt(isLargeModel: Boolean = false): String = VISION_SYSTEM_PROMPT

    /** User prompt for vision extraction — the image is passed separately via JNI.
     *  @param isLargeModel true for 2B+ models that can interpret results, false for 0.8B OCR-only
     */
    fun visionUserPrompt(isLargeModel: Boolean = false, additionalContext: String = ""): String = buildString {
        if (additionalContext.isNotBlank()) {
            appendLine(additionalContext)
            appendLine()
        }
        appendLine(if (isLargeModel) VISION_PROMPT_LARGE else VISION_PROMPT_SMALL)
    }

    companion object {
        private const val ON_DEVICE_ASSISTANT_PREFIX = "{"
        private val BENCHMARK_SYSTEM_PROMPT = """
You are a clinical data extractor. Extract structured
facts from clinical text.

Rules:

- Extract ONLY what is explicitly stated. Do NOT infer or
assume.

- Use exact numbers and values as dictated.

- Use null for unmentioned scalar fields.

- Use [] for unmentioned list fields.

- Do NOT output placeholder values like "unknown", "not stated",
or schema labels.

- Do NOT repeat duplicate entries.

- Include vitals only when they are explicitly stated.

- Vaccines and immunizations go in "immunizations", NOT in
"medications". If something is a vaccine (e.g. Pentavalent,
DTP, OPV, BCG, Measles, Hepatitis B, Rotavirus, PCV, HPV,
Td, MMR, IPV), put it in "immunizations" with its vaccine
code and dose number. Only therapeutic drugs go in
"medications".

- Output valid JSON only.

- sms_summary: a ≤19-character abbreviated REASON FOR VISIT only.
  Do NOT include age, sex, vitals, medications, vaccines, or
  immunizations (these are already stored in binary fields).
  Use medical shorthand for the chief complaint / diagnosis only.
  Examples: "Imm f/u prev pneum", "HTN DM f/u 2wk",
  "Fvr cgh 3d", "Pn f/u improving". ASCII-only.
        """.trimIndent()

        private val NOTE_SYSTEM_PROMPT = """
You are a clinical scribe. Summarize a clinician's dictation into
a concise, professional clinical note.

Rules:
- SUMMARIZE in third-person clinical prose. Never copy dialog.
- Include ONLY facts explicitly stated. Do NOT infer or add anything.
- Remove ALL repetition — each fact appears once.
- Omit sections with no content. Do NOT write "None" or "Not mentioned".
- Use exact numbers, values, and medical terms as dictated.
- Format: ## for headers, - for bullets, **bold** for key terms.
- If diagnoses, medications, immunizations, procedures, counseling,
  or follow-up are stated, include them in the note.
- No disclaimers or commentary.
        """.trimIndent()

        private val COMPACT_NOTE_SYSTEM_PROMPT = """
You are a clinical scribe.
Write a clinically useful note from the dictation.
Use only stated facts. No repetition. Omit empty sections.
Use ## headers and short bullets only, but do not drop important treatments,
medications, diagnoses, counseling, or follow-up.
Do not use bold text. Do not write paragraphs.
        """.trimIndent()

        private val BENCHMARK_JSON_SCHEMA = """
{
  "demographics": {"age": "...", "sex": "M/F", "name": "..."},
  "chief_complaint": "brief summary",
  "vitals": [{"name": "...", "value": "...", "unit": "..."}],
  "exam_findings": ["finding 1", "finding 2"],
  "investigations": [{"test": "...", "result": "..."}],
  "diagnoses": ["diagnosis 1"],
  "medications": [{"name": "drug name (NOT vaccines)", "dose": "...", "context": "current/new"}],
  "allergies": ["allergy or NKDA"],
  "immunizations": [{"vaccine": "vaccine code (e.g. PENTA, DTP, OPV, MEASLES)", "dose_number": 1}],
  "social_history": ["factor 1"],
  "plan": ["action 1", "action 2"],
  "sms_summary": "≤19 char abbrev"
}
        """.trimIndent()

        private val VISION_SYSTEM_PROMPT = """
You are a clinical data extractor for medical images.
Auto-detect the content type and extract structured data.

Content types:
- lab_report: CBC, chemistry, urinalysis results
- rdt_cassette: Malaria RDT, HIV RDT, pregnancy test (positive/negative/invalid)
- vital_device: BP monitor, pulse oximeter, thermometer, glucometer readings
- medication_package: Drug name, strength, manufacturer, expiry
- referral_letter: Referring facility, diagnosis, reason, urgency

Rules:
- Extract ONLY what is visible. Do NOT infer.
- Use exact numbers from device displays.
- For RDT cassettes: determine result from colored lines on the cassette ONLY. Ignore text on surrounding papers.
- Set content_type field.
- Output valid JSON only.
        """.trimIndent()

        // Small model (0.8B): schema with "..." placeholders — model fills in real values
        private val VISION_PROMPT_SMALL = """
<schema>
{
  "content_type": "lab_report|rdt_cassette|vital_device|medication_package|referral_letter|unknown",
  "vitals": [{"name": "...", "value": "...", "unit": "..."}],
  "investigations": [{"test": "...", "result": "..."}],
  "medications": [{"name": "...", "dose": "...", "manufacturer": "...", "expiry": "..."}],
  "referral": {"from_facility": "...", "diagnosis": "...", "reason": "...", "urgency": "..."},
  "raw_text": "any visible text not captured above"
}
</schema>

JSON:""".trimIndent()

        // Large model (2B+): classify + OCR + interpret results as structured JSON
        private val VISION_PROMPT_LARGE = """
Read and interpret the clinical image. Output JSON with these fields:
{"content_type":"rdt_result|lab_report|vital_device|medication_package|referral_letter|other","raw_text":"ALL TEXT VISIBLE ON THE ITEM","item_name":"SPECIFIC ITEM NAME","rdt":{"test_type":"HIV|malaria|pregnancy|hepatitis|syphilis|other","result":"positive|negative|invalid","bands":"DESCRIBE WHICH COLORED LINES ARE VISIBLE ON THE CASSETTE - DETERMINE RESULT FROM BANDS ONLY NOT SURROUNDING TEXT"},"vitals":[{"name":"READING NAME","value":"NUMBER","unit":"UNIT"}],"medications":[{"name":"DRUG NAME","dose":"DOSE","expiry":"DATE"}],"investigations":[{"test":"TEST NAME","result":"RESULT","unit":"UNIT"}]}
Include only relevant sections. For RDT: determine result from colored lines on the cassette only, ignore text on surrounding papers.""".trimIndent()
    }
}
