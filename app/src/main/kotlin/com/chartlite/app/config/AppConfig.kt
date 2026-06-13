package com.chartlite.app.config

import android.content.Context
import android.content.SharedPreferences
import android.app.ActivityManager
import androidx.security.crypto.EncryptedSharedPreferences
import androidx.security.crypto.MasterKey
import com.chartlite.app.auth.AuthConfig

class AppConfig(context: Context) : AuthConfig {
    private val appContext = context.applicationContext

    private val masterKey = MasterKey.Builder(context)
        .setKeyScheme(MasterKey.KeyScheme.AES256_GCM)
        .build()

    private val prefs: SharedPreferences = EncryptedSharedPreferences.create(
        context,
        "afrimed_prefs",
        masterKey,
        EncryptedSharedPreferences.PrefKeyEncryptionScheme.AES256_SIV,
        EncryptedSharedPreferences.PrefValueEncryptionScheme.AES256_GCM
    )

    init {
        runMigrations()
    }

    var isSetupComplete: Boolean
        get() = prefs.getBoolean(KEY_SETUP_COMPLETE, false)
        set(value) = prefs.edit().putBoolean(KEY_SETUP_COMPLETE, value).apply()

    var countryCode: String
        get() = prefs.getString(KEY_COUNTRY, "za") ?: "za"
        set(value) = prefs.edit().putString(KEY_COUNTRY, value).apply()

    /** Country-specific date format from country config (e.g., "dd/MM/yyyy" or "MM/dd/yyyy"). */
    var countryDateFormat: String
        get() = prefs.getString(KEY_COUNTRY_DATE_FORMAT, "dd/MM/yyyy") ?: "dd/MM/yyyy"
        set(value) = prefs.edit().putString(KEY_COUNTRY_DATE_FORMAT, value).apply()

    /** Country-specific national ID label (e.g., "SA ID Number", "SSN (optional)"). */
    var countryNationalIdLabel: String
        get() = prefs.getString(KEY_COUNTRY_ID_LABEL, "National ID") ?: "National ID"
        set(value) = prefs.edit().putString(KEY_COUNTRY_ID_LABEL, value).apply()

    var providerId: String
        get() = prefs.getString(KEY_PROVIDER_ID, "") ?: ""
        set(value) = prefs.edit().putString(KEY_PROVIDER_ID, value).apply()

    var facilityId: String
        get() = prefs.getString(KEY_FACILITY_ID, "") ?: ""
        set(value) = prefs.edit().putString(KEY_FACILITY_ID, value).apply()

    var facilityName: String
        get() = prefs.getString(KEY_FACILITY_NAME, "") ?: ""
        set(value) = prefs.edit().putString(KEY_FACILITY_NAME, value).apply()

    var language: String
        get() = prefs.getString(KEY_LANGUAGE, "en") ?: "en"
        set(value) = prefs.edit().putString(KEY_LANGUAGE, value).apply()

    override var autoLockMinutes: Int
        get() = prefs.getInt(KEY_AUTO_LOCK, 5)
        set(value) = prefs.edit().putInt(KEY_AUTO_LOCK, value).apply()

    var maxRecordingMinutes: Int
        get() = prefs.getInt(KEY_MAX_RECORDING, 20)
        set(value) = prefs.edit().putInt(KEY_MAX_RECORDING, value).apply()

    var retainAudioDays: Int
        get() = prefs.getInt(KEY_RETAIN_AUDIO, 0)
        set(value) = prefs.edit().putInt(KEY_RETAIN_AUDIO, value).apply()

    var useBiometric: Boolean
        get() = prefs.getBoolean(KEY_USE_BIOMETRIC, false)
        set(value) = prefs.edit().putBoolean(KEY_USE_BIOMETRIC, value).apply()

    // ASR config — defaults to offline-first (ONNX) per design spec
    var asrMode: String
        get() = prefs.getString(KEY_ASR_MODE, "onnx") ?: "onnx"
        set(value) = prefs.edit().putString(KEY_ASR_MODE, value).apply()

    var modelDownloadUrl: String
        get() {
            val fallback = defaultModelUrlForLanguage(language)
            return prefs.getString(KEY_MODEL_URL, fallback) ?: fallback
        }
        set(value) = prefs.edit().putString(KEY_MODEL_URL, value).apply()

    var vocabDownloadUrl: String
        get() {
            val fallback = defaultVocabUrlForLanguage(language)
            return prefs.getString(KEY_VOCAB_URL, fallback) ?: fallback
        }
        set(value) = prefs.edit().putString(KEY_VOCAB_URL, value).apply()

    var modelExpectedSha256: String
        get() {
            val stored = prefs.getString(KEY_MODEL_SHA256, "")?.trim().orEmpty()
            return stored.ifBlank { defaultModelSha256ForUrl(modelDownloadUrl) }
        }
        set(value) = prefs.edit().putString(KEY_MODEL_SHA256, value).apply()

    var vocabExpectedSha256: String
        get() {
            val stored = prefs.getString(KEY_VOCAB_SHA256, "")?.trim().orEmpty()
            return stored.ifBlank { defaultVocabSha256ForUrl(vocabDownloadUrl) }
        }
        set(value) = prefs.edit().putString(KEY_VOCAB_SHA256, value).apply()

    // Clinic workflow config
    var workflowMode: String
        get() = prefs.getString(KEY_WORKFLOW_MODE, "solo") ?: "solo"
        set(value) = prefs.edit().putString(KEY_WORKFLOW_MODE, value).apply()

    var enabledStations: Set<String>
        get() = prefs.getStringSet(KEY_ENABLED_STATIONS, emptySet()) ?: emptySet()
        set(value) = prefs.edit().putStringSet(KEY_ENABLED_STATIONS, value).apply()

    var activeStation: String
        get() = prefs.getString(KEY_ACTIVE_STATION, "") ?: ""
        set(value) = prefs.edit().putString(KEY_ACTIVE_STATION, value).apply()

    val isMultiStation: Boolean get() = workflowMode == "multi_station"

    /** Persisted LLM model tier override (enum name or blank for hardware-recommended). */
    var llmTierOverride: String
        get() = prefs.getString(KEY_LLM_TIER_OVERRIDE, "") ?: ""
        set(value) = prefs.edit().putString(KEY_LLM_TIER_OVERRIDE, value).apply()

    // AI mode: "cloud" (Claude API), "on_device" (local Qwen), or "auto" (cloud with local Qwen fallback)
    var aiMode: String
        get() = prefs.getString(KEY_AI_MODE, "on_device") ?: "on_device"
        set(value) = prefs.edit().putString(KEY_AI_MODE, value).apply()

    /** Cloud notes AI model. Prefix determines provider: claude- for Claude, gemini- for Gemini, gpt- for OpenAI */
    var cloudNotesModel: String
        get() = prefs.getString(KEY_CLOUD_NOTES_MODEL, "claude-sonnet-4-6") ?: "claude-sonnet-4-6"
        set(value) = prefs.edit().putString(KEY_CLOUD_NOTES_MODEL, value).apply()

    /**
     * Default note-processing workflow.
     * - "immediate": process each consultation as soon as clinician taps Process Notes
     * - "batch": queue consultations and process later from Extraction Queue
     *
     * On constrained phones we default to batch to avoid repeated model load/unload churn.
     */
    var noteProcessingMode: String
        get() {
            val defaultValue = if (isConstrainedPhone()) "batch" else "immediate"
            val value = prefs.getString(KEY_NOTE_PROCESSING_MODE, defaultValue) ?: defaultValue
            return if (value == "batch") "batch" else "immediate"
        }
        set(value) {
            val normalized = if (value == "batch") "batch" else "immediate"
            prefs.edit().putString(KEY_NOTE_PROCESSING_MODE, normalized).apply()
        }

    /**
     * Default recording mode for encounter capture.
     * - "ambient": full patient-doctor transcript (recommended)
     * - "snippet": short dictation snippets
     */
    var recordingModeDefault: String
        get() {
            val defaultValue = "ambient"
            val value = prefs.getString(KEY_RECORDING_MODE_DEFAULT, defaultValue) ?: defaultValue
            return if (value == "snippet") "snippet" else "ambient"
        }
        set(value) {
            val normalized = if (value == "snippet") "snippet" else "ambient"
            prefs.edit().putString(KEY_RECORDING_MODE_DEFAULT, normalized).apply()
        }

    // Claude API key (stored encrypted via EncryptedSharedPreferences)
    var claudeApiKey: String
        get() = prefs.getString(KEY_CLAUDE_API_KEY, "") ?: ""
        set(value) = prefs.edit().putString(KEY_CLAUDE_API_KEY, value).apply()

    // ── Cloud ASR provider configuration (stored encrypted) ──

    var cloudAsrProvider: String
        get() = prefs.getString(KEY_CLOUD_ASR_PROVIDER, "gemini") ?: "gemini"
        set(value) = prefs.edit().putString(KEY_CLOUD_ASR_PROVIDER, value).apply()

    var geminiApiKey: String
        get() = prefs.getString(KEY_GEMINI_API_KEY, "") ?: ""
        set(value) = prefs.edit().putString(KEY_GEMINI_API_KEY, value).apply()

    var openaiApiKey: String
        get() = prefs.getString(KEY_OPENAI_API_KEY, "") ?: ""
        set(value) = prefs.edit().putString(KEY_OPENAI_API_KEY, value).apply()

    var deepgramApiKey: String
        get() = prefs.getString(KEY_DEEPGRAM_API_KEY, "") ?: ""
        set(value) = prefs.edit().putString(KEY_DEEPGRAM_API_KEY, value).apply()

    // ── Cloud key mode: "chartlite" (proxy, no user API key) or "byok" (bring your own key) ──

    var cloudKeyMode: String
        get() = prefs.getString(KEY_CLOUD_KEY_MODE, "chartlite") ?: "chartlite"
        set(value) = prefs.edit().putString(KEY_CLOUD_KEY_MODE, value).apply()

    /**
     * Device ID for ChartLite Cloud proxy authentication.
     * Auto-generated on first access (UUID v4). Persisted across sessions.
     */
    var deviceId: String
        get() {
            val existing = prefs.getString(KEY_DEVICE_TOKEN, "") ?: ""
            if (existing.isNotBlank()) return existing
            val generated = java.util.UUID.randomUUID().toString()
            prefs.edit().putString(KEY_DEVICE_TOKEN, generated).apply()
            return generated
        }
        set(value) = prefs.edit().putString(KEY_DEVICE_TOKEN, value).apply()

    /**
     * One-time non-GMS enrollment code for ChartLite Cloud.
     * Stored encrypted and cleared after successful device enrollment.
     */
    var chartliteEnrollmentCode: String
        get() = prefs.getString(KEY_CHARTLITE_ENROLLMENT_CODE, "") ?: ""
        set(value) = prefs.edit().putString(KEY_CHARTLITE_ENROLLMENT_CODE, value).apply()

    /**
     * Per-facility HMAC secret for signing QR invite codes.
     * Auto-generated on first access (256-bit random). Persisted in EncryptedSharedPreferences.
     */
    var inviteSecret: String
        get() {
            val existing = prefs.getString(KEY_INVITE_SECRET, "") ?: ""
            if (existing.isNotBlank()) return existing
            val generated = com.chartlite.app.auth.InviteHmac.generateSecret()
            prefs.edit().putString(KEY_INVITE_SECRET, generated).apply()
            return generated
        }
        set(value) = prefs.edit().putString(KEY_INVITE_SECRET, value).apply()

    // Auth / session config (implements AuthConfig)
    override var currentUserId: String
        get() = prefs.getString(KEY_CURRENT_USER_ID, "") ?: ""
        set(value) = prefs.edit().putString(KEY_CURRENT_USER_ID, value).apply()

    override var sessionStartedAt: Long
        get() = prefs.getLong(KEY_SESSION_STARTED_AT, 0L)
        set(value) = prefs.edit().putLong(KEY_SESSION_STARTED_AT, value).apply()

    override var autoLockEnabled: Boolean
        get() = prefs.getBoolean(KEY_AUTO_LOCK_ENABLED, true)
        set(value) = prefs.edit().putBoolean(KEY_AUTO_LOCK_ENABLED, value).apply()

    override var pinLength: Int
        get() = prefs.getInt(KEY_PIN_LENGTH, 4)
        set(value) = prefs.edit().putInt(KEY_PIN_LENGTH, value).apply()

    override var failedAttempts: Int
        get() = prefs.getInt(KEY_FAILED_ATTEMPTS, 0)
        set(value) = prefs.edit().putInt(KEY_FAILED_ATTEMPTS, value).apply()

    override var lockoutUntil: Long
        get() = prefs.getLong(KEY_LOCKOUT_UNTIL, 0L)
        set(value) = prefs.edit().putLong(KEY_LOCKOUT_UNTIL, value).apply()

    override var lockoutStatesJson: String
        get() = prefs.getString(KEY_LOCKOUT_STATES, "") ?: ""
        set(value) = prefs.edit().putString(KEY_LOCKOUT_STATES, value).apply()

    override var lastActiveAt: Long
        get() = prefs.getLong(KEY_LAST_ACTIVE_AT, System.currentTimeMillis())
        set(value) = prefs.edit().putLong(KEY_LAST_ACTIVE_AT, value).apply()

    // Join codes for self-registration (JSON array stored in prefs)
    var joinCodes: String
        get() = prefs.getString(KEY_JOIN_CODES, "[]") ?: "[]"
        set(value) = prefs.edit().putString(KEY_JOIN_CODES, value).apply()

    // DHIS2 integration config (stored encrypted)
    var dhis2ServerUrl: String
        get() = prefs.getString(KEY_DHIS2_SERVER_URL, "") ?: ""
        set(value) = prefs.edit().putString(KEY_DHIS2_SERVER_URL, value).apply()

    var dhis2Username: String
        get() = prefs.getString(KEY_DHIS2_USERNAME, "") ?: ""
        set(value) = prefs.edit().putString(KEY_DHIS2_USERNAME, value).apply()

    var dhis2Password: String
        get() = prefs.getString(KEY_DHIS2_PASSWORD, "") ?: ""
        set(value) = prefs.edit().putString(KEY_DHIS2_PASSWORD, value).apply()

    var dhis2OrgUnit: String
        get() = prefs.getString(KEY_DHIS2_ORG_UNIT, "") ?: ""
        set(value) = prefs.edit().putString(KEY_DHIS2_ORG_UNIT, value).apply()

    // Sync state
    var lastSyncTimestamp: Long
        get() = prefs.getLong(KEY_LAST_SYNC, 0L)
        set(value) = prefs.edit().putLong(KEY_LAST_SYNC, value).apply()

    // Twilio SMS config (stored encrypted)
    var twilioAccountSid: String
        get() = prefs.getString(KEY_TWILIO_SID, "") ?: ""
        set(value) = prefs.edit().putString(KEY_TWILIO_SID, value).apply()

    var twilioAuthToken: String
        get() = prefs.getString(KEY_TWILIO_TOKEN, "") ?: ""
        set(value) = prefs.edit().putString(KEY_TWILIO_TOKEN, value).apply()

    var twilioFromNumber: String
        get() = prefs.getString(KEY_TWILIO_FROM, "") ?: ""
        set(value) = prefs.edit().putString(KEY_TWILIO_FROM, value).apply()

    private fun isEnglishLanguage(languageCode: String): Boolean =
        languageCode.trim().lowercase().startsWith("en")

    /**
     * Default model URL for fresh installs. Uses hardware-aware tier recommendation:
     *   English: ≥4GB RAM → Parakeet TDT, <4GB → medASR
     *   Non-English: ≥4GB → Omnilingual 1B, <4GB → Omnilingual 300M
     */
    private fun defaultModelUrlForLanguage(languageCode: String): String {
        val ramGb = deviceRamGb()
        return if (isEnglishLanguage(languageCode)) {
            if (ramGb >= 4.0) PARAKEET_EN_ENCODER_URL else DEFAULT_MEDASR_EN_MODEL_URL
        } else {
            if (ramGb >= 4.0) DEFAULT_STANDARD_MODEL_URL else DEFAULT_MODEL_URL
        }
    }

    private fun defaultVocabUrlForLanguage(languageCode: String): String {
        val ramGb = deviceRamGb()
        return if (isEnglishLanguage(languageCode)) {
            if (ramGb >= 4.0) PARAKEET_EN_VOCAB_URL else DEFAULT_MEDASR_EN_VOCAB_URL
        } else {
            if (ramGb >= 4.0) DEFAULT_STANDARD_VOCAB_URL else DEFAULT_VOCAB_URL
        }
    }

    private fun defaultModelSha256ForUrl(url: String): String {
        val normalized = url.trim()
        return when (normalized) {
            DEFAULT_MODEL_URL -> DEFAULT_MODEL_SHA256
            DEFAULT_STANDARD_MODEL_URL -> DEFAULT_STANDARD_MODEL_SHA256
            DEFAULT_MEDASR_EN_MODEL_URL -> DEFAULT_MEDASR_EN_MODEL_SHA256
            PARAKEET_EN_ENCODER_URL -> PARAKEET_EN_ENCODER_SHA256
            MOONSHINE_TINY_ENCODER_URL -> MOONSHINE_TINY_ENCODER_SHA256
            MOONSHINE_BASE_ENCODER_URL -> MOONSHINE_BASE_ENCODER_SHA256
            SENSE_VOICE_MODEL_URL -> SENSE_VOICE_MODEL_SHA256
            else -> ""
        }
    }

    private fun defaultVocabSha256ForUrl(url: String): String {
        val normalized = url.trim()
        return when (normalized) {
            DEFAULT_VOCAB_URL -> DEFAULT_VOCAB_SHA256
            DEFAULT_STANDARD_VOCAB_URL -> DEFAULT_STANDARD_VOCAB_SHA256
            DEFAULT_MEDASR_EN_VOCAB_URL -> DEFAULT_MEDASR_EN_VOCAB_SHA256
            PARAKEET_EN_VOCAB_URL -> PARAKEET_EN_VOCAB_SHA256
            MOONSHINE_TINY_VOCAB_URL -> MOONSHINE_TINY_VOCAB_SHA256
            MOONSHINE_BASE_VOCAB_URL -> MOONSHINE_BASE_VOCAB_SHA256
            SENSE_VOICE_VOCAB_URL -> SENSE_VOICE_VOCAB_SHA256
            else -> ""
        }
    }

    private fun deviceRamGb(): Double {
        val am = appContext.getSystemService(Context.ACTIVITY_SERVICE) as? android.app.ActivityManager ?: return 2.0
        val memInfo = android.app.ActivityManager.MemoryInfo()
        am.getMemoryInfo(memInfo)
        return memInfo.totalMem / (1024.0 * 1024.0 * 1024.0)
    }

    private fun isConstrainedPhone(): Boolean {
        val am = appContext.getSystemService(Context.ACTIVITY_SERVICE) as? ActivityManager ?: return false
        val memInfo = ActivityManager.MemoryInfo()
        am.getMemoryInfo(memInfo)
        return memInfo.totalMem <= 6L * 1024L * 1024L * 1024L
    }

    // ── Migrations ──

    /**
     * Run one-time data migrations when the app upgrades.
     *
     * Migration 1 (v1): Hardware-aware ASR tier defaults.
     *   Before this change, fresh installs always got medASR (English) or Omni 300M
     *   (non-English) regardless of device RAM. Existing users who never changed their
     *   tier still have those old defaults persisted. This migration upgrades them to
     *   the hardware-recommended tier if their stored URL matches the old default.
     */
    private fun runMigrations() {
        val currentVersion = prefs.getInt(KEY_MIGRATION_VERSION, 0)
        if (currentVersion >= LATEST_MIGRATION_VERSION) return

        if (currentVersion < 1) {
            migrateV1HardwareAwareTier()
        }
        if (currentVersion < 2) {
            migrateV2ModelUpgrade()
        }

        prefs.edit().putInt(KEY_MIGRATION_VERSION, LATEST_MIGRATION_VERSION).apply()
    }

    /**
     * V1: Upgrade users on old non-hardware-aware default tiers to the
     * hardware-recommended tier. Only affects users whose stored URLs exactly
     * match the old defaults (i.e., they never manually selected a different tier).
     */
    private fun migrateV1HardwareAwareTier() {
        val storedModelUrl = prefs.getString(KEY_MODEL_URL, null) ?: return // No stored URL → fresh install, nothing to migrate
        val ramGb = deviceRamGb()

        // English users on medASR who have enough RAM for Parakeet
        if (storedModelUrl == DEFAULT_MEDASR_EN_MODEL_URL && ramGb >= 4.0) {
            prefs.edit()
                .putString(KEY_MODEL_URL, PARAKEET_EN_ENCODER_URL)
                .putString(KEY_VOCAB_URL, PARAKEET_EN_VOCAB_URL)
                .remove(KEY_MODEL_SHA256)  // Clear cached SHA so it picks up the new default
                .remove(KEY_VOCAB_SHA256)
                .apply()
            android.util.Log.i("AppConfig", "Migration v1: Upgraded English ASR tier from medASR → Parakeet TDT (RAM=${ramGb}GB)")
            return
        }

        // Non-English users on Omni 300M who have enough RAM for Omni 1B
        if (storedModelUrl == DEFAULT_MODEL_URL && ramGb >= 4.0) {
            prefs.edit()
                .putString(KEY_MODEL_URL, DEFAULT_STANDARD_MODEL_URL)
                .putString(KEY_VOCAB_URL, DEFAULT_STANDARD_VOCAB_URL)
                .remove(KEY_MODEL_SHA256)
                .remove(KEY_VOCAB_SHA256)
                .apply()
            android.util.Log.i("AppConfig", "Migration v1: Upgraded non-English ASR tier from Omni 300M → Omni 1B (RAM=${ramGb}GB)")
            return
        }

        // User's stored URL doesn't match any old default → they chose a specific
        // tier manually, leave it as-is.
    }

    /**
     * V2: Upgrade models to latest versions.
     *   - Parakeet TDT v2 → v3 (adds 25 EU languages, same size)
     *   - Moonshine Tiny v1 → v2 (4 files → 2 files, 125 MB → 43 MB)
     *
     * Clears stored SHA-256 so the new defaults are picked up.
     * Old model files on disk will fail SHA verification → user re-downloads.
     */
    private fun migrateV2ModelUpgrade() {
        val storedModelUrl = prefs.getString(KEY_MODEL_URL, null) ?: return

        // Parakeet TDT v2 → v3
        if (storedModelUrl == LEGACY_PARAKEET_V2_ENCODER_URL) {
            prefs.edit()
                .putString(KEY_MODEL_URL, PARAKEET_EN_ENCODER_URL)
                .putString(KEY_VOCAB_URL, PARAKEET_EN_VOCAB_URL)
                .remove(KEY_MODEL_SHA256)
                .remove(KEY_VOCAB_SHA256)
                .apply()
            android.util.Log.i("AppConfig", "Migration v2: Upgraded Parakeet TDT v2 → v3")
            return
        }

        // Moonshine Tiny v1 → v2
        if (storedModelUrl == MOONSHINE_TINY_V1_PREPROCESS_URL) {
            prefs.edit()
                .putString(KEY_MODEL_URL, MOONSHINE_TINY_ENCODER_URL)
                .putString(KEY_VOCAB_URL, MOONSHINE_TINY_VOCAB_URL)
                .remove(KEY_MODEL_SHA256)
                .remove(KEY_VOCAB_SHA256)
                .apply()
            android.util.Log.i("AppConfig", "Migration v2: Upgraded Moonshine Tiny v1 → v2 (125MB → 43MB)")
            return
        }
    }

    companion object {
        // Default Meta Omnilingual ASR model URLs (300M CTC int8, 365MB, 1600+ languages)
        // See: huggingface.co/csukuangfj/sherpa-onnx-omnilingual-asr-1600-languages-300M-ctc-int8-2025-11-12
        const val DEFAULT_MODEL_URL = "https://huggingface.co/csukuangfj/sherpa-onnx-omnilingual-asr-1600-languages-300M-ctc-int8-2025-11-12/resolve/main/model.int8.onnx"
        const val DEFAULT_VOCAB_URL = "https://huggingface.co/csukuangfj/sherpa-onnx-omnilingual-asr-1600-languages-300M-ctc-int8-2025-11-12/resolve/main/tokens.txt"
        const val DEFAULT_MODEL_SHA256 = "e7c4e54ee4c4c47829cc6667d5d00ed8ea7bef1dcfeef0fce766f77752a2726c"
        const val DEFAULT_VOCAB_SHA256 = "a7a044c52cb29cbe8b0dc1953e92cefd4ca16b0ed968177b6beab21f9a7d0b31"

        // Omnilingual 1B defaults.
        // See: huggingface.co/csukuangfj/sherpa-onnx-omnilingual-asr-1600-languages-1B-ctc-int8-2025-11-12
        const val DEFAULT_STANDARD_MODEL_URL = "https://huggingface.co/csukuangfj/sherpa-onnx-omnilingual-asr-1600-languages-1B-ctc-int8-2025-11-12/resolve/main/model.int8.onnx"
        const val DEFAULT_STANDARD_VOCAB_URL = "https://huggingface.co/csukuangfj/sherpa-onnx-omnilingual-asr-1600-languages-1B-ctc-int8-2025-11-12/resolve/main/tokens.txt"
        const val DEFAULT_STANDARD_MODEL_SHA256 = "f7b74c964039162423b83e3fa950ce24810c9a635d9ff8468b5f4d142b7c1e8c"
        const val DEFAULT_STANDARD_VOCAB_SHA256 = "a7a044c52cb29cbe8b0dc1953e92cefd4ca16b0ed968177b6beab21f9a7d0b31"

        // medASR (English medical ASR) defaults.
        // See: huggingface.co/csukuangfj/sherpa-onnx-medasr-ctc-en-int8-2025-12-25
        const val DEFAULT_MEDASR_EN_MODEL_URL = "https://huggingface.co/csukuangfj/sherpa-onnx-medasr-ctc-en-int8-2025-12-25/resolve/main/model.int8.onnx"
        const val DEFAULT_MEDASR_EN_VOCAB_URL = "https://huggingface.co/csukuangfj/sherpa-onnx-medasr-ctc-en-int8-2025-12-25/resolve/main/tokens.txt"
        const val DEFAULT_MEDASR_EN_MODEL_SHA256 = "2c20f03265ee6144c566fd18b0f7bbb4f0d005d11ce9440dd641920210f4c33a"
        const val DEFAULT_MEDASR_EN_VOCAB_SHA256 = "b43987c0f8f660068a166d155f02b1e439d1f03dda36d50759b4e282e98814f2"

        // Moonshine Tiny v1 (English, 125MB total, encoder-decoder architecture) — LEGACY, kept for migration
        // See: huggingface.co/csukuangfj/sherpa-onnx-moonshine-tiny-en-int8
        private const val MOONSHINE_TINY_V1_BASE = "https://huggingface.co/csukuangfj/sherpa-onnx-moonshine-tiny-en-int8/resolve/main"
        const val MOONSHINE_TINY_V1_PREPROCESS_URL = "$MOONSHINE_TINY_V1_BASE/preprocess.onnx"

        // Moonshine Tiny v2 (English, 43MB total, 2-file merged decoder architecture)
        // See: huggingface.co/csukuangfj2/sherpa-onnx-moonshine-tiny-en-quantized-2026-02-27
        private const val MOONSHINE_TINY_BASE = "https://huggingface.co/csukuangfj2/sherpa-onnx-moonshine-tiny-en-quantized-2026-02-27/resolve/main"
        const val MOONSHINE_TINY_ENCODER_URL = "$MOONSHINE_TINY_BASE/encoder_model.ort"
        const val MOONSHINE_TINY_ENCODER_SHA256 = "94e90a4654fc45cdfedb77c4c08e1739f48862998e58fada384b25118134f221"
        const val MOONSHINE_TINY_DECODER_URL = "$MOONSHINE_TINY_BASE/decoder_model_merged.ort"
        const val MOONSHINE_TINY_DECODER_SHA256 = "cf524c4862d36e9e5ab032eddc73637efd822d70e868ac575cf1a46e1e4708a0"
        const val MOONSHINE_TINY_VOCAB_URL = "$MOONSHINE_TINY_BASE/tokens.txt"
        const val MOONSHINE_TINY_VOCAB_SHA256 = "2870d843e14c1e187bf1913a521562a63b53933814bd7f2145120468f494a049"

        // Moonshine Base v2 (English, 140MB total, better accuracy ~7.4% WER)
        // See: huggingface.co/csukuangfj2/sherpa-onnx-moonshine-base-en-quantized-2026-02-27
        private const val MOONSHINE_BASE_BASE = "https://huggingface.co/csukuangfj2/sherpa-onnx-moonshine-base-en-quantized-2026-02-27/resolve/main"
        const val MOONSHINE_BASE_ENCODER_URL = "$MOONSHINE_BASE_BASE/encoder_model.ort"
        const val MOONSHINE_BASE_ENCODER_SHA256 = "7c66495948d0d08ec1af454cd4b5514862ae6511e94712a60e6d83eaec8dc8cf"
        const val MOONSHINE_BASE_DECODER_URL = "$MOONSHINE_BASE_BASE/decoder_model_merged.ort"
        const val MOONSHINE_BASE_DECODER_SHA256 = "d9d7b333af34bc552580576ddcf248a1c6c839e0d3b43b09afb9376ed009899d"
        const val MOONSHINE_BASE_VOCAB_URL = "$MOONSHINE_BASE_BASE/tokens.txt"
        const val MOONSHINE_BASE_VOCAB_SHA256 = "2870d843e14c1e187bf1913a521562a63b53933814bd7f2145120468f494a049"

        // SenseVoice Small (ZH/EN/JA/KO/YUE, 239MB int8, 5 primary languages)
        // See: huggingface.co/csukuangfj/sherpa-onnx-sense-voice-zh-en-ja-ko-yue-2024-07-17
        private const val SENSE_VOICE_BASE = "https://huggingface.co/csukuangfj/sherpa-onnx-sense-voice-zh-en-ja-ko-yue-2024-07-17/resolve/main"
        const val SENSE_VOICE_MODEL_URL = "$SENSE_VOICE_BASE/model.int8.onnx"
        const val SENSE_VOICE_MODEL_SHA256 = "c71f0ce00bec95b07744e116345e33d8cbbe08cef896382cf907bf4b51a2cd51"
        const val SENSE_VOICE_VOCAB_URL = "$SENSE_VOICE_BASE/tokens.txt"
        const val SENSE_VOICE_VOCAB_SHA256 = "f449eb28dc567533d7fa59be34e2abca8784f771850c78a47fb731a31429a1dc"

        // Parakeet TDT 0.6B v3 (English + 25 EU languages, 671MB total, transducer, best English WER)
        // See: huggingface.co/csukuangfj/sherpa-onnx-nemo-parakeet-tdt-0.6b-v3-int8
        private const val PARAKEET_EN_BASE = "https://huggingface.co/csukuangfj/sherpa-onnx-nemo-parakeet-tdt-0.6b-v3-int8/resolve/main"
        const val PARAKEET_EN_ENCODER_URL = "$PARAKEET_EN_BASE/encoder.int8.onnx"
        const val PARAKEET_EN_ENCODER_SHA256 = "acfc2b4456377e15d04f0243af540b7fe7c992f8d898d751cf134c3a55fd2247"
        const val PARAKEET_EN_DECODER_URL = "$PARAKEET_EN_BASE/decoder.int8.onnx"
        const val PARAKEET_EN_DECODER_SHA256 = "179e50c43d1a9de79c8a24149a2f9bac6eb5981823f2a2ed88d655b24248db4e"
        const val PARAKEET_EN_JOINER_URL = "$PARAKEET_EN_BASE/joiner.int8.onnx"
        const val PARAKEET_EN_JOINER_SHA256 = "3164c13fc2821009440d20fcb5fdc78bff28b4db2f8d0f0b329101719c0948b3"
        const val PARAKEET_EN_VOCAB_URL = "$PARAKEET_EN_BASE/tokens.txt"
        const val PARAKEET_EN_VOCAB_SHA256 = "d58544679ea4bc6ac563d1f545eb7d474bd6cfa467f0a6e2c1dc1c7d37e3c35d"

        // Legacy Parakeet v2 URLs (for migration detection)
        private const val LEGACY_PARAKEET_V2_BASE = "https://huggingface.co/csukuangfj/sherpa-onnx-nemo-parakeet-tdt-0.6b-v2-int8/resolve/main"
        const val LEGACY_PARAKEET_V2_ENCODER_URL = "$LEGACY_PARAKEET_V2_BASE/encoder.int8.onnx"

        private const val KEY_SETUP_COMPLETE = "setup_complete"
        private const val KEY_COUNTRY = "country"
        private const val KEY_COUNTRY_DATE_FORMAT = "country_date_format"
        private const val KEY_COUNTRY_ID_LABEL = "country_id_label"
        private const val KEY_PROVIDER_ID = "provider_id"
        private const val KEY_FACILITY_ID = "facility_id"
        private const val KEY_FACILITY_NAME = "facility_name"
        private const val KEY_LANGUAGE = "language"
        private const val KEY_AUTO_LOCK = "auto_lock_minutes"
        private const val KEY_MAX_RECORDING = "max_recording_minutes"
        private const val KEY_RETAIN_AUDIO = "retain_audio_days"
        private const val KEY_USE_BIOMETRIC = "use_biometric"
        private const val KEY_ASR_MODE = "asr_mode"
        private const val KEY_MODEL_URL = "model_download_url"
        private const val KEY_VOCAB_URL = "vocab_download_url"
        private const val KEY_MODEL_SHA256 = "model_expected_sha256"
        private const val KEY_VOCAB_SHA256 = "vocab_expected_sha256"
        private const val KEY_WORKFLOW_MODE = "workflow_mode"
        private const val KEY_ENABLED_STATIONS = "enabled_stations"
        private const val KEY_ACTIVE_STATION = "active_station"
        private const val KEY_CURRENT_USER_ID = "current_user_id"
        private const val KEY_SESSION_STARTED_AT = "session_started_at"
        private const val KEY_AUTO_LOCK_ENABLED = "auto_lock_enabled"
        private const val KEY_PIN_LENGTH = "pin_length"
        private const val KEY_DHIS2_SERVER_URL = "dhis2_server_url"
        private const val KEY_DHIS2_USERNAME = "dhis2_username"
        private const val KEY_DHIS2_PASSWORD = "dhis2_password"
        private const val KEY_DHIS2_ORG_UNIT = "dhis2_org_unit"
        private const val KEY_TWILIO_SID = "twilio_account_sid"
        private const val KEY_TWILIO_TOKEN = "twilio_auth_token"
        private const val KEY_TWILIO_FROM = "twilio_from_number"
        private const val KEY_FAILED_ATTEMPTS = "failed_auth_attempts"
        private const val KEY_LOCKOUT_UNTIL = "lockout_until"
        private const val KEY_LOCKOUT_STATES = "lockout_states"
        private const val KEY_LAST_ACTIVE_AT = "last_active_at"
        private const val KEY_JOIN_CODES = "join_codes"
        private const val KEY_LLM_TIER_OVERRIDE = "llm_tier_override"
        private const val KEY_AI_MODE = "ai_mode"
        private const val KEY_CLOUD_NOTES_MODEL = "cloud_notes_model"
        private const val KEY_NOTE_PROCESSING_MODE = "note_processing_mode"
        private const val KEY_RECORDING_MODE_DEFAULT = "recording_mode_default"
        private const val KEY_CLAUDE_API_KEY = "claude_api_key"
        private const val KEY_CLOUD_ASR_PROVIDER = "cloud_asr_provider"
        private const val KEY_GEMINI_API_KEY = "gemini_api_key"
        private const val KEY_OPENAI_API_KEY = "openai_api_key"
        private const val KEY_DEEPGRAM_API_KEY = "deepgram_api_key"
        private const val KEY_CLOUD_KEY_MODE = "cloud_key_mode"
        private const val KEY_DEVICE_TOKEN = "device_token"
        private const val KEY_CHARTLITE_ENROLLMENT_CODE = "chartlite_enrollment_code"
        private const val KEY_INVITE_SECRET = "invite_secret"
        private const val KEY_LAST_SYNC = "last_sync_timestamp"
        private const val KEY_MIGRATION_VERSION = "config_migration_version"
        private const val LATEST_MIGRATION_VERSION = 2
    }
}
