package com.chartlite.app.model

import java.time.Instant

// ── ASR Results ──

data class TranscriptionResult(
    val text: String,
    val words: List<WordResult>,
    val durationMs: Long,
    val error: String? = null,
    /** True when audio was recorded offline and queued for cloud transcription */
    val pendingCloudTranscription: Boolean = false,
    /** Links to CloudASRQueueEntity.id for store-and-forward retrieval */
    val cloudQueueId: String? = null
)

data class WordResult(
    val word: String,
    val confidence: Float,
    val startMs: Long,
    val endMs: Long,
    val alternatives: List<String>
)

// ── Clinical Extraction ──

data class StructuredEncounter(
    val id: String,
    val patientId: String,
    val providerId: String,
    val facilityId: String,
    val timestamp: Instant,
    val transcript: String,
    val medications: List<Medication>,
    val diagnoses: List<Diagnosis>,
    val vitals: VitalSigns?,
    val allergies: List<String>,
    val followUp: FollowUp?,
    val referral: Referral?,
    val freeTextNote: String,
    val extractionConfidence: Float,
    // Benchmark-driven categories (2026-03 architecture update)
    val examFindings: List<String> = emptyList(),
    val investigations: List<Investigation> = emptyList(),
    val plan: List<String> = emptyList(),
    val socialHistory: List<String> = emptyList(),
    // Diagnoses are clinician-selected, not LLM-extracted (63% hallucination rate).
    // LLM-suggested diagnoses go here for the clinician to confirm/reject.
    val suggestedDiagnoses: List<Diagnosis> = emptyList(),
    // Immunizations administered during this encounter (extracted from voice)
    val immunizations: List<ExtractedImmunization> = emptyList(),
    // Concise ≤19-char visit summary for SMS binary encoding (abbreviated medical shorthand)
    val smsSummary: String? = null
)

data class Medication(
    val formularyCode: String,
    val name: String,
    val dose: Float? = null,
    val unit: String? = null,
    val frequency: String? = null,
    val duration: Int? = null,
    val route: String? = null,
    val confidence: Float = 0f
)

data class Diagnosis(
    val icd10Code: String,
    val description: String,
    val isPrimary: Boolean = false,
    val confidence: Float = 0f,
    // Source: "clinician" (confirmed via ICD-10 picker) or "llm" (suggested, needs confirmation)
    val source: String = "llm"
)

data class Investigation(
    val test: String,
    val result: String? = null,
    val confidence: Float = 0.8f
)

data class VitalSigns(
    val systolicBP: Int? = null,
    val diastolicBP: Int? = null,
    val temperature: Float? = null,
    val pulse: Int? = null,
    val weight: Float? = null,
    val height: Float? = null,
    val respiratoryRate: Int? = null,
    val oxygenSaturation: Int? = null
)

data class FollowUp(
    val days: Int,
    val reason: String? = null
)

data class Referral(
    val type: String,
    val specialty: String? = null,
    val urgency: String = "routine",
    val reason: String? = null
)

data class ExtractedImmunization(
    val vaccineCode: String,   // BCG, OPV, PENTA, MEASLES, etc.
    val vaccineName: String,
    val doseNumber: Int = 1
)

// ── Formulary ──

data class FormularyDrug(
    val code: String,
    val name: String,
    val aliases: List<String>,
    val strengths: List<String>,
    val defaultRoute: String,
    val category: String,
    val scheduleClass: String,
    val maxDoseAdult: DoseLimit? = null,
    val maxDosePediatric: DoseLimit? = null
)

data class DoseLimit(
    val value: Int,
    val unit: String,
    val per: String
)

data class Formulary(
    val version: String,
    val country: String,
    val drugs: List<FormularyDrug>
)

// ── ICD-10 ──

data class ICD10Entry(
    val code: String,
    val description: String,
    val keywords: List<String>,
    val localTerms: Map<String, List<String>> = emptyMap()
)

data class ICD10Index(
    val version: String,
    val codes: List<ICD10Entry>
)

// ── Country Config ──

data class CountryConfig(
    val country: String,
    val name: String,
    val languages: List<String>,
    val defaultLanguage: String,
    val formularyFile: String,
    val icd10File: String,
    val cdssRules: String,
    val languageModelDir: String,
    val smsEnabled: Boolean,
    val nationalIdFormat: String,
    val nationalIdLabel: String,
    val phoneFormat: String,
    val dateFormat: String,
    val currencyCode: String,
    val facilityIdPrefix: String
)

// ── CDSS ──

data class CDSSAlert(
    val severity: AlertSeverity,
    val category: String,
    val message: String,
    val relatedField: String? = null
)

enum class AlertSeverity { CRITICAL, WARNING, INFO }

data class AllergyInteraction(
    val allergen: String,
    val contraindicated: List<String>,
    val contraindicatedNames: List<String> = emptyList(),
    val crossReactivity: List<String>,
    val crossReactivityNames: List<String> = emptyList(),
    val severity: String,
    val message: String
)

data class DrugInteraction(
    val drug1: String,
    val drug2: String,
    val drugName1: String? = null,
    val drugName2: String? = null,
    val severity: String,
    val message: String
)

// ── SMS ──

enum class SMSStatus { PENDING, SENT, DELIVERED, FAILED }
