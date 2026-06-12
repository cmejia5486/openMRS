package com.chartlite.app

import com.chartlite.app.extraction.ExtractionPromptBuilder
import com.chartlite.app.model.Formulary
import com.chartlite.app.model.FormularyDrug
import com.chartlite.app.model.ICD10Entry
import com.chartlite.app.model.ICD10Index
import org.junit.Assert.assertEquals
import org.junit.Assert.assertFalse
import org.junit.Assert.assertTrue
import org.junit.Before
import org.junit.Test

class ExtractionPromptBuilderTest {

    private lateinit var builder: ExtractionPromptBuilder

    @Before
    fun setup() {
        builder = ExtractionPromptBuilder(
            ICD10Index(
                version = "test",
                codes = listOf(ICD10Entry("J06.9", "Acute upper respiratory infection", listOf("URTI")))
            ),
            Formulary(
                version = "test",
                country = "za",
                drugs = listOf(FormularyDrug("AMX001", "Amoxicillin", listOf("amoxil"), listOf("500mg"), "oral", "antibiotic", "S4"))
            )
        )
    }

    @Test
    fun `system prompt uses benchmark extractor rules`() {
        val prompt = builder.buildSystemPrompt()

        assertTrue(prompt.contains("You are a clinical data extractor"))
        assertTrue(prompt.contains("Extract ONLY what is explicitly stated"))
        assertTrue(prompt.contains("Use null for unmentioned scalar fields"))
        assertTrue(prompt.contains("Use [] for unmentioned list fields"))
        assertTrue(prompt.contains("Do NOT output placeholder values"))
        assertTrue(prompt.contains("Do NOT repeat duplicate entries"))
        assertTrue(prompt.contains("Include vitals only when they are explicitly stated"))
        assertTrue(prompt.contains("Output valid JSON only"))
        assertFalse(prompt.contains("ICD-10"))
        assertFalse(prompt.contains("formularyCode"))
    }

    @Test
    fun `system prompt ignores condensed flag and stays unified`() {
        assertEquals(
            builder.buildSystemPrompt(condensed = false),
            builder.buildSystemPrompt(condensed = true)
        )
    }

    @Test
    fun `user prompt uses benchmark schema and transcript`() {
        val prompt = builder.buildUserPrompt("The child has fever and cough.")

        assertTrue(prompt.contains("Extract structured clinical facts from this clinician"))
        assertTrue(prompt.contains("\"chief_complaint\": \"brief summary\""))
        assertTrue(prompt.contains("\"diagnoses\": [\"diagnosis 1\"]"))
        assertTrue(prompt.contains("\"medications\": [{\"name\": \"drug name (NOT vaccines)\", \"dose\": \"...\", \"context\": \"current/new\"}]"))
        assertTrue(prompt.contains("CLINICIAN DICTATION:"))
        assertTrue(prompt.contains("The child has fever and cough."))
        assertTrue(prompt.trimEnd().endsWith("JSON:"))
    }

    @Test
    fun `combined prompt includes shared system and user blocks`() {
        val prompt = builder.buildCombinedPrompt("patient has cough", condensed = true)

        assertTrue(prompt.contains("You are a clinical data extractor"))
        assertTrue(prompt.contains("CLINICIAN DICTATION:"))
        assertTrue(prompt.contains("patient has cough"))
    }

    @Test
    fun `qwen prompt wraps shared benchmark prompt in chat template`() {
        val prompt = builder.buildSnippetPrompt("amoxicillin 500mg three times daily for 5 days")

        assertTrue(prompt.contains("<|im_start|>system"))
        assertTrue(prompt.contains("<|im_start|>user"))
        assertTrue(prompt.contains("<|im_start|>assistant"))
        // Pre-closed thinking block suppresses Qwen thinking mode
        assertTrue(prompt.contains("<think>"))
        assertTrue(prompt.contains("</think>"))
        assertTrue(prompt.contains("{"))
        assertTrue(prompt.contains("\"demographics\": {\"age\": \"...\", \"sex\": \"M/F\", \"name\": \"...\"}"))
        assertTrue(prompt.contains("\"plan\": [\"action 1\", \"action 2\"]"))
        assertTrue(prompt.contains("\"sms_summary\":"))
        assertFalse(prompt.contains("suggested_diagnoses"))
        assertFalse(prompt.contains("Formulary reference:"))
    }

    @Test
    fun `compact note prompt still asks for full clinical sections`() {
        val prompt = builder.buildNoteUserPrompt("fever and cough for three days", compact = true)

        assertTrue(prompt.contains("## Chief Complaint"))
        assertTrue(prompt.contains("## History of Present Illness"))
        assertTrue(prompt.contains("## Assessment"))
        assertTrue(prompt.contains("## Plan"))
        assertFalse(prompt.contains("about 60 words total"))
    }
}
