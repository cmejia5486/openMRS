package com.chartlite.app.ui.screens

import androidx.activity.compose.rememberLauncherForActivityResult
import androidx.activity.result.contract.ActivityResultContracts
import androidx.compose.animation.animateContentSize
import androidx.compose.foundation.background
import androidx.compose.foundation.clickable
import androidx.compose.foundation.horizontalScroll
import androidx.compose.foundation.layout.*
import androidx.compose.foundation.rememberScrollState
import androidx.compose.foundation.shape.RoundedCornerShape
import androidx.compose.foundation.text.KeyboardOptions
import androidx.compose.foundation.verticalScroll
import androidx.compose.material.icons.Icons
import androidx.compose.material.icons.automirrored.filled.ArrowBack
import androidx.compose.material.icons.filled.*
import androidx.compose.material3.*
import androidx.compose.runtime.*
import androidx.compose.runtime.saveable.rememberSaveable
import androidx.compose.ui.Alignment
import androidx.compose.ui.Modifier
import androidx.compose.ui.draw.clip
import androidx.compose.ui.graphics.Color
import androidx.compose.ui.platform.LocalContext
import androidx.compose.ui.res.stringResource
import androidx.compose.ui.text.font.FontWeight
import androidx.compose.ui.text.style.TextAlign
import com.chartlite.app.R
import androidx.compose.ui.text.input.ImeAction
import androidx.compose.ui.text.input.KeyboardType
import androidx.compose.ui.text.input.PasswordVisualTransformation
import androidx.compose.ui.unit.dp
import androidx.compose.ui.unit.sp
import com.chartlite.app.ui.components.QrCodeImage
import com.chartlite.app.ui.theme.*
import kotlinx.coroutines.Dispatchers
import androidx.appcompat.app.AppCompatDelegate
import androidx.core.os.LocaleListCompat
import com.chartlite.app.App
import com.chartlite.app.asr.ASREngine
import com.chartlite.app.extraction.ModelDownloadService
import com.chartlite.app.asr.ModelDownloader
import com.chartlite.app.auth.UserRole
import com.chartlite.app.model.ClinicStation
import com.chartlite.app.sms.TwilioSMSProvider
import kotlinx.coroutines.flow.first
import kotlinx.coroutines.launch
import kotlinx.coroutines.withContext
import okhttp3.MediaType.Companion.toMediaType
import okhttp3.RequestBody.Companion.toRequestBody
import java.util.UUID

@Composable
private fun ProviderOptionRow(
    selected: Boolean,
    label: String,
    description: String,
    recommended: Boolean = false,
    onClick: () -> Unit
) {
    Row(
        modifier = Modifier
            .fillMaxWidth()
            .clickable(onClick = onClick)
            .padding(horizontal = 4.dp, vertical = 6.dp),
        verticalAlignment = Alignment.CenterVertically
    ) {
        RadioButton(selected = selected, onClick = onClick)
        Spacer(Modifier.width(8.dp))
        Column(modifier = Modifier.weight(1f)) {
            Row(verticalAlignment = Alignment.CenterVertically, horizontalArrangement = Arrangement.spacedBy(6.dp)) {
                Text(label, style = MaterialTheme.typography.bodyMedium, fontWeight = if (selected) FontWeight.SemiBold else FontWeight.Normal)
                if (recommended) {
                    SuggestionChip(
                        onClick = {},
                        label = { Text("Recommended", style = MaterialTheme.typography.labelSmall) },
                        modifier = Modifier.height(22.dp)
                    )
                }
            }
            Text(description, style = MaterialTheme.typography.bodySmall, color = MaterialTheme.colorScheme.outline)
        }
    }
}

private enum class SettingsCategory(val label: String, val summary: String) {
    ESSENTIALS("Essentials", "General, recording, and security"),
    AI_SPEECH("AI & Speech", "ASR and clinical extraction models"),
    OPERATIONS("Operations", "SMS and clinic workflow"),
    REGIONS("Regions", "Country packs and expansion roadmap"),
    ADMIN("Admin", "User management, facility tools, and app info")
}

@OptIn(ExperimentalMaterial3Api::class)
@Composable
fun SettingsScreen(onBack: () -> Unit, onUserManagement: () -> Unit = {}) {
    val context = LocalContext.current
    val app = context.applicationContext as App
    val config = app.appConfig
    val scope = rememberCoroutineScope()
    val currentRole = app.sessionManager.currentSession?.role
    var selectedCategory by rememberSaveable { mutableStateOf(SettingsCategory.ESSENTIALS.name) }
    var asrImportStatus by remember { mutableStateOf<String?>(null) }
    var llmImportStatus by remember { mutableStateOf<String?>(null) }
    var showFacilityQrDialog by remember { mutableStateOf(false) }
    var showFacilityQrReauthDialog by remember { mutableStateOf(false) }
    var showFacilityQrRoleDialog by remember { mutableStateOf(false) }
    var facilityQrSelectedRole by remember { mutableStateOf(UserRole.NURSE) }
    var facilityQrPin by remember { mutableStateOf("") }
    var facilityQrError by remember { mutableStateOf<String?>(null) }
    var facilityQrAuthenticating by remember { mutableStateOf(false) }
    var facilityInviteQrPayload by remember { mutableStateOf("") }
    var facilityInviteConfirmCode by remember { mutableStateOf("") }
    var facilityInviteExpiresAt by remember { mutableLongStateOf(0L) }
    var facilityQrCountdownNow by remember { mutableLongStateOf(System.currentTimeMillis()) }

    var language by remember { mutableStateOf(config.language) }
    var countryCode by remember { mutableStateOf(config.countryCode) }
    var autoLockMinutes by remember { mutableIntStateOf(config.autoLockMinutes) }
    var maxRecordingMinutes by remember { mutableIntStateOf(config.maxRecordingMinutes) }
    var useBiometric by remember { mutableStateOf(config.useBiometric) }
    var retainAudioDays by remember { mutableIntStateOf(config.retainAudioDays) }

    // ASR state
    var asrMode by remember { mutableStateOf(config.asrMode) }
    val downloadState by app.asr.modelDownloader.state.collectAsState()
    val rankedTiers = remember(config.language) {
        app.asr.modelDownloader.rankTiersForDevice(config.language)
    }
    val recommendedTier = remember(rankedTiers) { rankedTiers.firstOrNull { it.isCompatible }?.tier }
    val defaultTierForLanguage = remember(config.language) {
        app.asr.modelDownloader.defaultTierForLanguage(config.language)
    }
    val deviceRam = remember { app.asr.modelDownloader.deviceRamGb() }
    val deviceName = remember { app.asr.modelDownloader.deviceName() }
    var selectedTier by remember {
        // Restore from persisted config URL, not just hardware recommendation
        val currentUrl = config.modelDownloadUrl
        val currentVocabUrl = config.vocabDownloadUrl
        val matchingTier = ModelDownloader.ModelTier.entries.find {
            it.modelUrl == currentUrl && it.vocabUrl == currentVocabUrl && it.isDownloadable
        }
        mutableStateOf(matchingTier ?: defaultTierForLanguage)
    }
    var modelUrl by remember { mutableStateOf(config.modelDownloadUrl) }
    var vocabUrl by remember { mutableStateOf(config.vocabDownloadUrl) }
    var showUrlEditor by remember { mutableStateOf(false) }
    var chartliteEnrollmentCode by remember { mutableStateOf(config.chartliteEnrollmentCode) }
    var enrollmentVerifying by remember { mutableStateOf(false) }
    // null = not yet tested, true = success, false = failed
    var enrollmentSuccess by remember { mutableStateOf<Boolean?>(null) }
    var enrollmentError by remember { mutableStateOf<String?>(null) }

    // Admin — generate per-device enrollment codes
    var showGenerateCodeDialog by remember { mutableStateOf(false) }
    var generatedDeviceCode by remember { mutableStateOf<String?>(null) }
    var generateCodeLoading by remember { mutableStateOf(false) }
    var generateCodeError by remember { mutableStateOf<String?>(null) }

    // Single-file import (CTC / CTC_MEDASR tiers)
    val importAsrModelLauncher = rememberLauncherForActivityResult(
        ActivityResultContracts.OpenDocument()
    ) { uri ->
        if (uri == null) return@rememberLauncherForActivityResult
        scope.launch(Dispatchers.IO) {
            val message = try {
                if (app.asr.modelDownloader.isMultiFileTier()) {
                    "This tier requires multiple model files. Use 'Import Model Folder' instead."
                } else {
                    val tmpModel = java.io.File.createTempFile("asr_model_", ".onnx", context.cacheDir)
                    context.contentResolver.openInputStream(uri)?.use { input ->
                        tmpModel.outputStream().use { output -> input.copyTo(output) }
                    } ?: throw IllegalStateException("Unable to read selected model file")

                    val imported = app.asr.modelDownloader.importModelFile(
                        sourceFile = tmpModel,
                        expectedSha256 = config.modelExpectedSha256
                    )
                    tmpModel.delete()
                    when {
                        !imported -> "ASR model import failed."
                        app.asr.modelDownloader.isReady() -> "ASR model and vocabulary are ready."
                        else -> "ASR model imported. Import tokens.txt to enable offline recognition."
                    }
                }
            } catch (e: Exception) {
                "Model import failed. Please try again."
            }
            withContext(Dispatchers.Main) {
                asrImportStatus = message
            }
        }
    }

    // Multi-file directory import (Moonshine / Transducer tiers)
    val importAsrDirectoryLauncher = rememberLauncherForActivityResult(
        ActivityResultContracts.OpenDocumentTree()
    ) { treeUri ->
        if (treeUri == null) return@rememberLauncherForActivityResult
        scope.launch(Dispatchers.IO) {
            val message = try {
                val tmpDir = java.io.File(context.cacheDir, "asr_import_${System.currentTimeMillis()}")
                tmpDir.mkdirs()
                val requiredFiles = app.asr.modelDownloader.requiredArtifactFilenames() + "tokens.txt"
                val missingFiles = mutableListOf<String>()

                // Build children URI for the selected tree
                val childrenUri = android.provider.DocumentsContract.buildChildDocumentsUriUsingTree(
                    treeUri, android.provider.DocumentsContract.getTreeDocumentId(treeUri)
                )
                // Query children to find required files
                val foundFiles = mutableMapOf<String, android.net.Uri>()
                context.contentResolver.query(childrenUri, arrayOf(
                    android.provider.DocumentsContract.Document.COLUMN_DISPLAY_NAME,
                    android.provider.DocumentsContract.Document.COLUMN_DOCUMENT_ID
                ), null, null, null)?.use { cursor ->
                    val nameIdx = cursor.getColumnIndex(android.provider.DocumentsContract.Document.COLUMN_DISPLAY_NAME)
                    val idIdx = cursor.getColumnIndex(android.provider.DocumentsContract.Document.COLUMN_DOCUMENT_ID)
                    while (cursor.moveToNext()) {
                        val name = cursor.getString(nameIdx)
                        val docId = cursor.getString(idIdx)
                        if (name in requiredFiles) {
                            foundFiles[name] = android.provider.DocumentsContract.buildDocumentUriUsingTree(treeUri, docId)
                        }
                    }
                }

                for (filename in requiredFiles) {
                    val fileUri = foundFiles[filename]
                    if (fileUri != null) {
                        context.contentResolver.openInputStream(fileUri)?.use { input ->
                            java.io.File(tmpDir, filename).outputStream().use { output ->
                                input.copyTo(output)
                            }
                        } ?: missingFiles.add(filename)
                    } else {
                        missingFiles.add(filename)
                    }
                }

                if (missingFiles.isNotEmpty()) {
                    tmpDir.deleteRecursively()
                    "Some required files are missing from the selected folder. Please ensure all model files are included."
                } else {
                    val imported = app.asr.modelDownloader.importModelDirectory(tmpDir)
                    tmpDir.deleteRecursively()
                    when {
                        !imported -> "Import failed. The files may be corrupted or incompatible."
                        app.asr.modelDownloader.isReady() -> "All model files and vocabulary imported and verified."
                        else -> "Model files imported. Some verification may still be needed."
                    }
                }
            } catch (e: Exception) {
                "Import failed. Please check the folder and try again."
            }
            withContext(Dispatchers.Main) {
                asrImportStatus = message
            }
        }
    }

    val importAsrVocabLauncher = rememberLauncherForActivityResult(
        ActivityResultContracts.OpenDocument()
    ) { uri ->
        if (uri == null) return@rememberLauncherForActivityResult
        scope.launch(Dispatchers.IO) {
            val message = try {
                val tmpVocab = java.io.File.createTempFile("asr_vocab_", ".txt", context.cacheDir)
                context.contentResolver.openInputStream(uri)?.use { input ->
                    tmpVocab.outputStream().use { output -> input.copyTo(output) }
                } ?: throw IllegalStateException("Unable to read selected vocabulary file")

                val imported = app.asr.modelDownloader.importVocabFile(
                    sourceFile = tmpVocab,
                    expectedSha256 = config.vocabExpectedSha256
                )
                tmpVocab.delete()
                when {
                    !imported -> "Vocabulary import failed."
                    app.asr.modelDownloader.isReady() -> "ASR model and vocabulary are ready."
                    else -> "Vocabulary imported. Import ONNX model file to complete setup."
                }
            } catch (e: Exception) {
                "Vocabulary import failed. Please try again."
            }
            withContext(Dispatchers.Main) {
                asrImportStatus = message
            }
        }
    }

    val importLlmModelLauncher = rememberLauncherForActivityResult(
        ActivityResultContracts.OpenDocument()
    ) { uri ->
        if (uri == null) return@rememberLauncherForActivityResult
        scope.launch(Dispatchers.IO) {
            val message = try {
                val tmpModel = java.io.File.createTempFile("llm_model_", ".zip", context.cacheDir)
                context.contentResolver.openInputStream(uri)?.use { input ->
                    tmpModel.outputStream().use { output -> input.copyTo(output) }
                } ?: throw IllegalStateException("Unable to read selected model file")

                val imported = app.llmModelManager.importModelFile(
                    sourceFile = tmpModel,
                    expectedSha256 = app.llmModelManager.activeTier().sha256
                )
                tmpModel.delete()
                if (imported) {
                    "${app.llmModelManager.activeTier().label} imported and ready."
                } else {
                    "LLM model import failed."
                }
            } catch (e: Exception) {
                "LLM model import failed. Please try again."
            }
            withContext(Dispatchers.Main) {
                llmImportStatus = message
            }
        }
    }

    // Twilio config
    var twilioSid by remember { mutableStateOf(config.twilioAccountSid) }
    var twilioToken by remember { mutableStateOf(config.twilioAuthToken) }
    var twilioFrom by remember { mutableStateOf(config.twilioFromNumber) }
    var twilioVerifying by remember { mutableStateOf(false) }
    val twilioVerifiedStr = stringResource(R.string.twilio_credentials_verified)
    val twilioInvalidStr = stringResource(R.string.twilio_invalid_credentials)
    val twilioSavedNativeStr = stringResource(R.string.twilio_saved_native_sms)
    val twilioClearedNativeStr = stringResource(R.string.twilio_cleared_native_sms)
    var twilioStatus by remember { mutableStateOf<String?>(null) }

    // Country change confirmation dialog
    var pendingCountryChange by remember { mutableStateOf<String?>(null) }
    pendingCountryChange?.let { newCountry ->
        val countryLabel = listOf(
            "za" to "South Africa", "et" to "Ethiopia", "mw" to "Malawi", "us" to "United States"
        ).find { it.first == newCountry }?.second ?: newCountry

        AlertDialog(
            onDismissRequest = { pendingCountryChange = null },
            title = { Text(stringResource(R.string.settings_change_country)) },
            text = {
                Text(stringResource(R.string.settings_country_change_body, countryLabel))
            },
            confirmButton = {
                TextButton(onClick = {
                    val oldCountry = countryCode
                    countryCode = newCountry
                    config.countryCode = newCountry
                    pendingCountryChange = null
                    scope.launch(Dispatchers.IO) {
                        app.loadCountryData()
                    }
                    scope.launch {
                        app.auditLogger.log("SETTINGS_CHANGE", targetType = "SETTING",
                            details = """{"field":"country","from":"$oldCountry","to":"$newCountry"}""")
                    }
                }) {
                    Text(stringResource(R.string.settings_change))
                }
            },
            dismissButton = {
                TextButton(onClick = { pendingCountryChange = null }) {
                    Text(stringResource(R.string.cancel))
                }
            }
        )
    }

    Scaffold(
        topBar = {
            TopAppBar(
                title = { Text(stringResource(R.string.settings)) },
                navigationIcon = {
                    IconButton(onClick = onBack) {
                        Icon(Icons.AutoMirrored.Filled.ArrowBack, contentDescription = stringResource(R.string.content_desc_back))
                    }
                }
            )
        }
    ) { padding ->
        Column(
            modifier = Modifier
                .fillMaxSize()
                .padding(padding)
        ) {
            // v1: only Essentials + AI/Speech. Operations, Regions, Admin hidden (see ROADMAP.md).
            val visibleCategories = remember(currentRole) {
                buildList {
                    add(SettingsCategory.ESSENTIALS)
                    add(SettingsCategory.AI_SPEECH)
                    // v2:
                    // add(SettingsCategory.OPERATIONS)
                    // add(SettingsCategory.REGIONS)
                    // if (currentRole?.canManageUsers == true) add(SettingsCategory.ADMIN)
                }
            }
            val activeCategory = remember(selectedCategory, visibleCategories) {
                val parsed = try { SettingsCategory.valueOf(selectedCategory) } catch (_: Exception) { null }
                if (parsed != null && parsed in visibleCategories) parsed else visibleCategories.first()
            }
            val selectedTabIndex = visibleCategories.indexOf(activeCategory)

            PrimaryScrollableTabRow(
                selectedTabIndex = selectedTabIndex,
                edgePadding = 16.dp,
                divider = { HorizontalDivider() }
            ) {
                visibleCategories.forEachIndexed { index, category ->
                    val tabLabel = when (category) {
                        SettingsCategory.ESSENTIALS -> stringResource(R.string.settings_tab_essentials)
                        SettingsCategory.AI_SPEECH -> stringResource(R.string.settings_tab_ai_speech)
                        SettingsCategory.OPERATIONS -> stringResource(R.string.settings_tab_operations)
                        SettingsCategory.REGIONS -> stringResource(R.string.settings_tab_regions)
                        SettingsCategory.ADMIN -> stringResource(R.string.settings_tab_admin)
                    }
                    Tab(
                        selected = selectedTabIndex == index,
                        onClick = { selectedCategory = category.name },
                        text = { Text(tabLabel) }
                    )
                }
            }

            Column(
                modifier = Modifier
                    .fillMaxSize()
                    .imePadding()
                    .verticalScroll(rememberScrollState())
            ) {

            if (activeCategory == SettingsCategory.ESSENTIALS) {
            // General
            SettingsSection(stringResource(R.string.settings_general)) {
                // Filter languages by selected country — all include French
                val languagesByCountry = mapOf(
                    "za" to listOf("en" to "English", "zu" to "isiZulu", "xh" to "isiXhosa", "fr" to "Français"),
                    "et" to listOf("en" to "English", "am" to "Amharic", "fr" to "Français"),
                    "mw" to listOf("en" to "English", "ny" to "Chichewa", "fr" to "Français"),
                    "ke" to listOf("en" to "English", "sw" to "Kiswahili", "fr" to "Français"),
                    "ng" to listOf("en" to "English", "yo" to "Yorùbá", "ha" to "Hausa", "fr" to "Français"),
                    "us" to listOf("en" to "English", "fr" to "Français")
                )
                val languageOptions = languagesByCountry[countryCode] ?: listOf("en" to "English", "fr" to "Français")
                SettingsDropdown(
                    title = stringResource(R.string.language_settings),
                    subtitle = stringResource(R.string.settings_asr_interface_lang),
                    value = language,
                    options = languageOptions,
                    onValueChange = { newLang ->
                        val oldLang = language
                        language = newLang
                        config.language = newLang
                        // Apply locale — triggers activity recreation with new language
                        AppCompatDelegate.setApplicationLocales(
                            LocaleListCompat.forLanguageTags(newLang)
                        )
                        scope.launch {
                            app.auditLogger.log("SETTINGS_CHANGE", targetType = "SETTING",
                                details = """{"field":"language","from":"$oldLang","to":"$newLang"}""")
                        }
                    }
                )
                SettingsDropdown(
                    title = stringResource(R.string.country),
                    subtitle = stringResource(R.string.settings_formulary_clinical),
                    value = countryCode,
                    options = listOf(
                        "za" to "South Africa", "us" to "United States",
                        "et" to "Ethiopia", "mw" to "Malawi",
                        "ke" to "Kenya", "ng" to "Nigeria"
                    ),
                    onValueChange = { newCode ->
                        if (newCode != countryCode) {
                            pendingCountryChange = newCode
                        }
                    }
                )
            }
            }


            // ── AI & Speech — Simplified view with Advanced toggle ──
            if (activeCategory == SettingsCategory.AI_SPEECH) {
                // Derive simple booleans from current config
                var voiceOffline by remember {
                    mutableStateOf(asrMode == "onnx")
                }
                var notesOffline by remember {
                    mutableStateOf(config.aiMode == "on_device")
                }
                var showAdvanced by rememberSaveable { mutableStateOf(false) }
                var noteProcessingMode by remember { mutableStateOf(config.noteProcessingMode) }
                var claudeApiKey by remember { mutableStateOf(config.claudeApiKey) }
                var geminiApiKey by remember { mutableStateOf(config.geminiApiKey) }
                var openaiApiKey by remember { mutableStateOf(config.openaiApiKey) }
                var deepgramApiKey by remember { mutableStateOf(config.deepgramApiKey) }
                var cloudAsrProvider by remember { mutableStateOf(config.cloudAsrProvider) }
                var cloudNotesModel by remember { mutableStateOf(config.cloudNotesModel) }
                var aiMode by remember { mutableStateOf(config.aiMode) }
                val llmModelState by app.llmModelManager.state.collectAsState()
                val llmRecommended = remember { app.llmModelManager.recommendedTier() }
                val deviceRamGb = remember { app.llmModelManager.deviceRamGb() }
                var selectedLlmTier by remember {
                    mutableStateOf(app.llmModelManager.activeTier())
                }

                fun notesProvider(model: String): String = when {
                    model.startsWith("claude") -> "claude"
                    model.startsWith("gemini") -> "gemini"
                    model.startsWith("gpt") -> "openai"
                    else -> "claude"
                }

                fun missingAsrKeyMessage(provider: String): String? {
                    if (config.cloudKeyMode != "byok") return null
                    return when (provider) {
                        "gemini" -> if (geminiApiKey.isBlank()) "Requires Gemini API key in Advanced settings" else null
                        "openai" -> if (openaiApiKey.isBlank()) "Requires OpenAI API key in Advanced settings" else null
                        "deepgram" -> if (deepgramApiKey.isBlank()) "Requires Deepgram API key in Advanced settings" else null
                        else -> null
                    }
                }

                fun missingNotesKeyMessage(model: String): String? {
                    if (config.cloudKeyMode != "byok") return null
                    return when (notesProvider(model)) {
                        "claude" -> if (claudeApiKey.isBlank()) "Requires Anthropic API key in Advanced settings" else null
                        "gemini" -> if (geminiApiKey.isBlank()) "Requires Gemini API key in Advanced settings" else null
                        "openai" -> if (openaiApiKey.isBlank()) "Requires OpenAI API key in Advanced settings" else null
                        else -> null
                    }
                }

                // Auto-select best ASR tier
                val bestAsrTier = remember(rankedTiers) {
                    rankedTiers.firstOrNull { it.isCompatible }?.tier
                }

                // Helper to apply simple toggle changes to config
                fun applyVoiceMode(offline: Boolean) {
                    voiceOffline = offline
                    val newMode = if (offline) "onnx" else "cloud"
                    asrMode = newMode
                    config.asrMode = newMode
                    app.asr.mode = when (newMode) {
                        "onnx" -> ASREngine.Mode.ONNX_OFFLINE
                        "cloud" -> ASREngine.Mode.CLOUD_ASR
                        else -> ASREngine.Mode.GOOGLE_ONLINE
                    }
                }

                fun applyNotesMode(offline: Boolean) {
                    notesOffline = offline
                    val newMode = if (offline) "on_device" else "auto"
                    aiMode = newMode
                    config.aiMode = newMode
                    if (!offline) app.llmModelManager.unloadModel()
                    scope.launch(Dispatchers.IO) { app.loadCountryData() }
                }

                // Device info
                SettingsSection(stringResource(R.string.settings_speech_recognition)) {
                    Text(
                        stringResource(R.string.setup_device_info_format, deviceName, "%.1f".format(deviceRam)),
                        style = MaterialTheme.typography.bodySmall,
                        color = MaterialTheme.colorScheme.onSurfaceVariant,
                        modifier = Modifier.padding(horizontal = 16.dp, vertical = 4.dp)
                    )

                    Spacer(Modifier.height(8.dp))

                    // ── Voice Recognition toggle ──
                    ElevatedCard(
                        modifier = Modifier.fillMaxWidth().padding(horizontal = 16.dp)
                    ) {
                        Column(modifier = Modifier.padding(16.dp)) {
                            Text(stringResource(R.string.settings_voice_recognition_card), style = MaterialTheme.typography.titleSmall, fontWeight = FontWeight.SemiBold)
                            Spacer(Modifier.height(8.dp))
                            SingleChoiceSegmentedButtonRow(modifier = Modifier.fillMaxWidth()) {
                                SegmentedButton(
                                    selected = voiceOffline,
                                    onClick = { applyVoiceMode(true) },
                                    shape = SegmentedButtonDefaults.itemShape(index = 0, count = 2)
                                ) { Text(stringResource(R.string.setup_works_offline)) }
                                SegmentedButton(
                                    selected = !voiceOffline,
                                    onClick = { applyVoiceMode(false) },
                                    shape = SegmentedButtonDefaults.itemShape(index = 1, count = 2)
                                ) { Text(stringResource(R.string.setup_uses_internet)) }
                            }
                            Spacer(Modifier.height(4.dp))
                            Text(
                                when {
                                    voiceOffline -> stringResource(R.string.setup_voice_offline_desc)
                                    asrMode == "google" -> stringResource(R.string.setup_google_speech_desc)
                                    else -> stringResource(R.string.setup_voice_internet_desc)
                                },
                                style = MaterialTheme.typography.bodySmall,
                                color = MaterialTheme.colorScheme.outline
                            )
                            // Cloud ASR provider picker — shown when Uses Internet is selected
                            if (!voiceOffline && asrMode == "cloud") {
                                Spacer(Modifier.height(8.dp))
                                Text("Transcription service", style = MaterialTheme.typography.labelSmall,
                                    color = MaterialTheme.colorScheme.outline, modifier = Modifier.padding(start = 8.dp))
                                Spacer(Modifier.height(4.dp))
                                listOf(
                                    Triple("gemini", "Gemini 3.1 Flash Lite", "Recommended · Great with African accents"),
                                    Triple("openai", "OpenAI gpt-4o Transcribe", "High accuracy, optimized for English"),
                                    Triple("deepgram", "Deepgram Nova", "Ultra-fast, ideal for real-time use"),
                                ).forEach { (value, label, desc) ->
                                    ProviderOptionRow(
                                        selected = cloudAsrProvider == value,
                                        label = label,
                                        description = desc,
                                        recommended = value == "gemini",
                                        onClick = { cloudAsrProvider = value; config.cloudAsrProvider = value }
                                    )
                                }
                                missingAsrKeyMessage(cloudAsrProvider)?.let { message ->
                                    Text(message, style = MaterialTheme.typography.bodySmall, color = MaterialTheme.colorScheme.outline, modifier = Modifier.padding(start = 40.dp, bottom = 4.dp))
                                }
                            }
                        }
                    }

                    Spacer(Modifier.height(12.dp))

                    // ── Clinical Notes AI toggle ──
                    ElevatedCard(
                        modifier = Modifier.fillMaxWidth().padding(horizontal = 16.dp)
                    ) {
                        Column(modifier = Modifier.padding(16.dp)) {
                            Text(stringResource(R.string.settings_clinical_notes_card), style = MaterialTheme.typography.titleSmall, fontWeight = FontWeight.SemiBold)
                            Spacer(Modifier.height(8.dp))
                            val notesSupportsOffline = app.llmModelManager.isSupportedAbi()
                            SingleChoiceSegmentedButtonRow(modifier = Modifier.fillMaxWidth()) {
                                SegmentedButton(
                                    selected = notesOffline,
                                    onClick = { if (notesSupportsOffline) applyNotesMode(true) },
                                    enabled = notesSupportsOffline,
                                    shape = SegmentedButtonDefaults.itemShape(index = 0, count = 2)
                                ) { Text(stringResource(R.string.setup_works_offline)) }
                                SegmentedButton(
                                    selected = !notesOffline,
                                    onClick = { applyNotesMode(false) },
                                    shape = SegmentedButtonDefaults.itemShape(index = 1, count = 2)
                                ) { Text(stringResource(R.string.setup_uses_internet)) }
                            }
                            Spacer(Modifier.height(4.dp))
                            Text(
                                if (notesOffline) stringResource(R.string.setup_notes_offline_desc)
                                else stringResource(R.string.setup_notes_internet_desc),
                                style = MaterialTheme.typography.bodySmall,
                                color = MaterialTheme.colorScheme.outline
                            )
                            if (!notesSupportsOffline) {
                                Spacer(Modifier.height(4.dp))
                                Text(
                                    stringResource(R.string.setup_offline_not_supported),
                                    style = MaterialTheme.typography.bodySmall,
                                    color = MaterialTheme.colorScheme.error
                                )
                            }
                            // Cloud notes model picker — shown when Uses Internet is selected
                            if (!notesOffline) {
                                Spacer(Modifier.height(8.dp))
                                Text("Note-writing AI", style = MaterialTheme.typography.labelSmall,
                                    color = MaterialTheme.colorScheme.outline, modifier = Modifier.padding(start = 8.dp))
                                Spacer(Modifier.height(4.dp))
                                listOf(
                                    Triple("claude-sonnet-4-6", "Claude Sonnet", "Recommended · Smart, fast clinical notes"),
                                    Triple("claude-opus-4-6", "Claude Opus", "Most thorough clinical documentation"),
                                    Triple("gemini-3.1-flash-lite-preview", "Gemini Flash", "Fast and cost-effective"),
                                    Triple("gpt-5.4", "GPT-5", "OpenAI's latest model"),
                                    Triple("gpt-4.1", "GPT-4.1", "Reliable and efficient"),
                                ).forEach { (value, label, desc) ->
                                    ProviderOptionRow(
                                        selected = cloudNotesModel == value,
                                        label = label,
                                        description = desc,
                                        recommended = value == "claude-sonnet-4-6",
                                        onClick = {
                                            cloudNotesModel = value; config.cloudNotesModel = value
                                            app.rebuildExtractionPipeline()
                                        }
                                    )
                                }
                                missingNotesKeyMessage(cloudNotesModel)?.let { message ->
                                    Text(message, style = MaterialTheme.typography.bodySmall, color = MaterialTheme.colorScheme.outline, modifier = Modifier.padding(start = 40.dp, bottom = 4.dp))
                                }
                            }
                        }
                    }

                    Spacer(Modifier.height(12.dp))

                    // ── Processing workflow toggle ──
                    ElevatedCard(
                        modifier = Modifier.fillMaxWidth().padding(horizontal = 16.dp)
                    ) {
                        Column(modifier = Modifier.padding(16.dp)) {
                            Text(stringResource(R.string.settings_processing_workflow), style = MaterialTheme.typography.titleSmall, fontWeight = FontWeight.SemiBold)
                            if (app.shouldUseStrictLowRamSerialization(aiMode)) {
                                Spacer(Modifier.height(4.dp))
                                Text(
                                    stringResource(R.string.settings_batch_recommended),
                                    style = MaterialTheme.typography.bodySmall,
                                    color = MaterialTheme.colorScheme.outline
                                )
                            }
                            Spacer(Modifier.height(8.dp))
                            SingleChoiceSegmentedButtonRow(modifier = Modifier.fillMaxWidth()) {
                                SegmentedButton(
                                    selected = noteProcessingMode == "immediate",
                                    enabled = true,
                                    onClick = { noteProcessingMode = "immediate"; config.noteProcessingMode = "immediate" },
                                    shape = SegmentedButtonDefaults.itemShape(index = 0, count = 2)
                                ) { Text(stringResource(R.string.settings_process_immediately)) }
                                SegmentedButton(
                                    selected = noteProcessingMode == "batch",
                                    onClick = { noteProcessingMode = "batch"; config.noteProcessingMode = "batch" },
                                    shape = SegmentedButtonDefaults.itemShape(index = 1, count = 2)
                                ) { Text(stringResource(R.string.settings_process_batch)) }
                            }
                            Spacer(Modifier.height(4.dp))
                            Text(
                                if (noteProcessingMode == "immediate") stringResource(R.string.settings_process_immediately_desc)
                                else stringResource(R.string.settings_process_batch_desc),
                                style = MaterialTheme.typography.bodySmall,
                                color = MaterialTheme.colorScheme.outline
                            )
                            if (app.shouldUseStrictLowRamSerialization(aiMode)) {
                                Spacer(Modifier.height(4.dp))
                                Text(
                                    "Strict low-RAM mode serializes voice capture and the local model so immediate mode can stay enabled.",
                                    style = MaterialTheme.typography.bodySmall,
                                    color = MaterialTheme.colorScheme.outline
                                )
                            }
                        }
                    }

                    Spacer(Modifier.height(12.dp))

                    // ── Download status (only when offline modes need models) ──
                    val needsAsrDownload = voiceOffline && bestAsrTier != null &&
                        downloadState !is ModelDownloader.DownloadState.Complete
                    val needsLlmDownload = notesOffline &&
                        llmModelState !is com.chartlite.app.extraction.LlmModelManager.ModelState.Ready
                    val asrReady = downloadState is ModelDownloader.DownloadState.Complete
                    val llmReady = llmModelState is com.chartlite.app.extraction.LlmModelManager.ModelState.Ready

                    if (voiceOffline || notesOffline) {
                        ElevatedCard(
                            modifier = Modifier.fillMaxWidth().padding(horizontal = 16.dp)
                        ) {
                            Column(modifier = Modifier.padding(16.dp)) {
                                Text(stringResource(R.string.setup_downloads_required), style = MaterialTheme.typography.titleSmall, fontWeight = FontWeight.SemiBold)
                                Spacer(Modifier.height(8.dp))

                                if (voiceOffline && bestAsrTier != null) {
                                    Row(modifier = Modifier.fillMaxWidth(), horizontalArrangement = Arrangement.SpaceBetween) {
                                        Text(bestAsrTier.friendlyName, style = MaterialTheme.typography.bodyMedium)
                                        if (asrReady) Icon(Icons.Default.CheckCircle, contentDescription = null, tint = MaterialTheme.colorScheme.primary, modifier = Modifier.size(18.dp))
                                        else Text("${bestAsrTier.sizeMb} MB", style = MaterialTheme.typography.bodySmall, color = MaterialTheme.colorScheme.outline)
                                    }
                                }
                                if (notesOffline) {
                                    Row(modifier = Modifier.fillMaxWidth(), horizontalArrangement = Arrangement.SpaceBetween) {
                                        Text(selectedLlmTier.friendlyName, style = MaterialTheme.typography.bodyMedium)
                                        if (llmReady) Icon(Icons.Default.CheckCircle, contentDescription = null, tint = MaterialTheme.colorScheme.primary, modifier = Modifier.size(18.dp))
                                        else Text("${selectedLlmTier.sizeMb} MB", style = MaterialTheme.typography.bodySmall, color = MaterialTheme.colorScheme.outline)
                                    }
                                }

                                val isDownloading = downloadState is ModelDownloader.DownloadState.Downloading ||
                                    llmModelState is com.chartlite.app.extraction.LlmModelManager.ModelState.Downloading
                                val isVerifying = downloadState is ModelDownloader.DownloadState.Verifying ||
                                    llmModelState is com.chartlite.app.extraction.LlmModelManager.ModelState.Verifying ||
                                    llmModelState is com.chartlite.app.extraction.LlmModelManager.ModelState.Installing

                                if (isDownloading || isVerifying) {
                                    Spacer(Modifier.height(8.dp))
                                    val isAsrPhase = downloadState is ModelDownloader.DownloadState.Downloading ||
                                        downloadState is ModelDownloader.DownloadState.Verifying
                                    Text(
                                        if (isAsrPhase) stringResource(R.string.setup_downloading_voice)
                                        else stringResource(R.string.setup_downloading_notes_ai),
                                        style = MaterialTheme.typography.bodySmall, color = MaterialTheme.colorScheme.outline
                                    )
                                    Spacer(Modifier.height(4.dp))

                                    if (isAsrPhase && downloadState is ModelDownloader.DownloadState.Downloading) {
                                        val dl = downloadState as ModelDownloader.DownloadState.Downloading
                                        if (dl.totalBytes > 0) {
                                            val progress = dl.bytesDownloaded.toFloat() / dl.totalBytes.toFloat()
                                            Text("${dl.bytesDownloaded / (1024 * 1024)} / ${dl.totalBytes / (1024 * 1024)} MB",
                                                style = MaterialTheme.typography.bodySmall, color = MaterialTheme.colorScheme.outline)
                                            LinearProgressIndicator(progress = { progress.coerceIn(0f, 1f) }, modifier = Modifier.fillMaxWidth())
                                        } else {
                                            LinearProgressIndicator(modifier = Modifier.fillMaxWidth())
                                        }
                                    } else if (!isAsrPhase && llmModelState is com.chartlite.app.extraction.LlmModelManager.ModelState.Downloading) {
                                        val dl = llmModelState as com.chartlite.app.extraction.LlmModelManager.ModelState.Downloading
                                        if (dl.totalBytes > 0) {
                                            val progress = dl.bytesDownloaded.toFloat() / dl.totalBytes.toFloat()
                                            Text("${dl.bytesDownloaded / (1024 * 1024)} / ${dl.totalBytes / (1024 * 1024)} MB",
                                                style = MaterialTheme.typography.bodySmall, color = MaterialTheme.colorScheme.outline)
                                            LinearProgressIndicator(progress = { progress.coerceIn(0f, 1f) }, modifier = Modifier.fillMaxWidth())
                                        } else {
                                            LinearProgressIndicator(modifier = Modifier.fillMaxWidth())
                                        }
                                    } else if (!isAsrPhase && llmModelState is com.chartlite.app.extraction.LlmModelManager.ModelState.Installing) {
                                        val install = llmModelState as com.chartlite.app.extraction.LlmModelManager.ModelState.Installing
                                        Text(stringResource(R.string.settings_installing_model),
                                            style = MaterialTheme.typography.bodySmall, color = MaterialTheme.colorScheme.outline)
                                        if (install.totalBytes > 0) {
                                            val progress = install.bytesProcessed.toFloat() / install.totalBytes.toFloat()
                                            Text("${install.bytesProcessed / (1024 * 1024)} / ${install.totalBytes / (1024 * 1024)} MB",
                                                style = MaterialTheme.typography.bodySmall, color = MaterialTheme.colorScheme.outline)
                                            LinearProgressIndicator(progress = { progress.coerceIn(0f, 1f) }, modifier = Modifier.fillMaxWidth())
                                        } else {
                                            LinearProgressIndicator(modifier = Modifier.fillMaxWidth())
                                        }
                                    } else {
                                        Text(stringResource(R.string.settings_verifying_download),
                                            style = MaterialTheme.typography.bodySmall, color = MaterialTheme.colorScheme.outline)
                                        LinearProgressIndicator(modifier = Modifier.fillMaxWidth())
                                    }

                                    Spacer(Modifier.height(4.dp))
                                    TextButton(onClick = { app.asr.modelDownloader.cancel(); app.llmModelManager.cancelDownload() }) {
                                        Text(stringResource(R.string.cancel))
                                    }
                                } else if (needsAsrDownload || needsLlmDownload) {
                                    val hasError = downloadState is ModelDownloader.DownloadState.Error ||
                                        llmModelState is com.chartlite.app.extraction.LlmModelManager.ModelState.Error
                                    if (hasError) {
                                        Spacer(Modifier.height(4.dp))
                                        Text(stringResource(R.string.setup_download_failed_retry), style = MaterialTheme.typography.bodySmall, color = MaterialTheme.colorScheme.error)
                                    }
                                    Spacer(Modifier.height(8.dp))
                                    Button(
                                        onClick = {
                                            // Start foreground service to survive screen-off
                                            val downloadType = when {
                                                needsAsrDownload && needsLlmDownload -> "both"
                                                needsAsrDownload -> "asr"
                                                needsLlmDownload -> "llm"
                                                else -> null
                                            }
                                            if (downloadType != null) {
                                                ModelDownloadService.start(context, downloadType)
                                            }
                                            scope.launch {
                                                // Download ASR first, then auto-chain to LLM
                                                if (needsAsrDownload && bestAsrTier != null) {
                                                    selectedTier = bestAsrTier
                                                    config.modelDownloadUrl = bestAsrTier.modelUrl
                                                    config.vocabDownloadUrl = bestAsrTier.vocabUrl
                                                    config.modelExpectedSha256 = bestAsrTier.modelSha256
                                                    config.vocabExpectedSha256 = bestAsrTier.vocabSha256
                                                    app.asr.modelDownloader.startDownload(
                                                        modelUrl = bestAsrTier.modelUrl, vocabUrl = bestAsrTier.vocabUrl,
                                                        expectedSha256 = bestAsrTier.modelSha256, expectedVocabSha256 = bestAsrTier.vocabSha256
                                                    )
                                                    // Wait for ASR download to complete before chaining LLM
                                                    app.asr.modelDownloader.state.first { state ->
                                                        state is ModelDownloader.DownloadState.Complete ||
                                                            state is ModelDownloader.DownloadState.Error
                                                    }
                                                }
                                                // Auto-start LLM after ASR completes (or if ASR wasn't needed)
                                                if (needsLlmDownload &&
                                                    (!needsAsrDownload || app.asr.modelDownloader.state.value is ModelDownloader.DownloadState.Complete)) {
                                                    app.llmModelManager.startDownload()
                                                }
                                            }
                                        },
                                        modifier = Modifier.fillMaxWidth()
                                    ) {
                                        Icon(Icons.Default.Download, contentDescription = null, modifier = Modifier.size(18.dp))
                                        Spacer(Modifier.width(8.dp))
                                        Text(stringResource(R.string.setup_download_all))
                                    }
                                } else if (asrReady && (!notesOffline || llmReady)) {
                                    Spacer(Modifier.height(8.dp))
                                    Text(stringResource(R.string.setup_all_models_ready), style = MaterialTheme.typography.bodyMedium, color = MaterialTheme.colorScheme.primary)
                                }
                            }
                        }
                    } else {
                        Text(stringResource(R.string.setup_no_downloads_needed), style = MaterialTheme.typography.bodyMedium,
                            color = MaterialTheme.colorScheme.primary, modifier = Modifier.padding(horizontal = 16.dp))
                    }

                    // Enrollment code — only shown when using ChartLite cloud and internet mode is active
                    if (config.cloudKeyMode == "chartlite" && (!voiceOffline || !notesOffline)) {
                        Spacer(Modifier.height(12.dp))
                        ElevatedCard(modifier = Modifier.fillMaxWidth().padding(horizontal = 16.dp)) {
                            Column(modifier = Modifier.padding(16.dp)) {
                                Text("ChartLite Cloud Access", style = MaterialTheme.typography.titleSmall, fontWeight = FontWeight.SemiBold)
                                Spacer(Modifier.height(2.dp))
                                Text("Enter your enrollment code to use ChartLite's AI backend", style = MaterialTheme.typography.bodySmall, color = MaterialTheme.colorScheme.outline)
                                Spacer(Modifier.height(12.dp))
                                OutlinedTextField(
                                    value = chartliteEnrollmentCode,
                                    onValueChange = {
                                        chartliteEnrollmentCode = it.trim()
                                        config.chartliteEnrollmentCode = it.trim()
                                        enrollmentSuccess = null
                                        enrollmentError = null
                                    },
                                    label = { Text("Enrollment code") },
                                    placeholder = { Text("Enter code from your facility admin") },
                                    modifier = Modifier.fillMaxWidth(),
                                    singleLine = true,
                                    keyboardOptions = KeyboardOptions(
                                        keyboardType = KeyboardType.Password,
                                        imeAction = ImeAction.Done,
                                    ),
                                    visualTransformation = PasswordVisualTransformation(),
                                    isError = enrollmentSuccess == false,
                                    trailingIcon = when {
                                        enrollmentVerifying -> {{ CircularProgressIndicator(modifier = Modifier.size(18.dp), strokeWidth = 2.dp) }}
                                        enrollmentSuccess == true -> {{ Icon(Icons.Default.CheckCircle, contentDescription = "Enrolled", tint = MaterialTheme.colorScheme.primary) }}
                                        enrollmentSuccess == false -> {{ Icon(Icons.Default.Error, contentDescription = "Error", tint = MaterialTheme.colorScheme.error) }}
                                        else -> null
                                    },
                                )
                                Spacer(Modifier.height(4.dp))
                                when {
                                    enrollmentSuccess == true ->
                                        Text(
                                            "✓ Enrolled successfully",
                                            style = MaterialTheme.typography.bodySmall,
                                            color = MaterialTheme.colorScheme.primary
                                        )
                                    enrollmentError != null ->
                                        Text(
                                            enrollmentError.orEmpty(),
                                            style = MaterialTheme.typography.bodySmall,
                                            color = MaterialTheme.colorScheme.error
                                        )
                                    else ->
                                        Text(
                                            stringResource(R.string.setup_enrollment_helper),
                                            style = MaterialTheme.typography.bodySmall,
                                            color = MaterialTheme.colorScheme.outline
                                        )
                                }
                                Spacer(Modifier.height(10.dp))
                                Button(
                                    onClick = {
                                        scope.launch {
                                            enrollmentVerifying = true
                                            enrollmentSuccess = null
                                            enrollmentError = null
                                            val result = withContext(Dispatchers.IO) {
                                                app.playIntegrityManager.testDeviceEnrollment(chartliteEnrollmentCode)
                                            }
                                            enrollmentVerifying = false
                                            when (result) {
                                                is com.chartlite.app.auth.DeviceKeyAuthManager.EnrollmentResult.Success -> {
                                                    enrollmentSuccess = true
                                                    enrollmentError = null
                                                }
                                                is com.chartlite.app.auth.DeviceKeyAuthManager.EnrollmentResult.Error -> {
                                                    enrollmentSuccess = false
                                                    enrollmentError = result.message
                                                }
                                            }
                                        }
                                    },
                                    enabled = chartliteEnrollmentCode.isNotBlank() && !enrollmentVerifying,
                                    modifier = Modifier.fillMaxWidth()
                                ) {
                                    if (enrollmentVerifying) {
                                        CircularProgressIndicator(modifier = Modifier.size(18.dp), strokeWidth = 2.dp, color = MaterialTheme.colorScheme.onPrimary)
                                        Spacer(Modifier.width(8.dp))
                                        Text("Verifying…")
                                    } else {
                                        Text("Verify Enrollment Code")
                                    }
                                }
                            }
                        }
                    }

                    Spacer(Modifier.height(16.dp))

                    // ── Advanced settings toggle ──
                    TextButton(onClick = { showAdvanced = !showAdvanced }, modifier = Modifier.padding(horizontal = 16.dp)) {
                        Icon(if (showAdvanced) Icons.Default.ExpandLess else Icons.Default.ExpandMore, contentDescription = null, modifier = Modifier.size(18.dp))
                        Spacer(Modifier.width(4.dp))
                        Text(stringResource(R.string.setup_advanced_settings))
                    }

                    androidx.compose.animation.AnimatedVisibility(
                        visible = showAdvanced,
                        enter = androidx.compose.animation.expandVertically(),
                        exit = androidx.compose.animation.shrinkVertically()
                    ) {
                        Column(modifier = Modifier.padding(horizontal = 16.dp)) {
                            HorizontalDivider(modifier = Modifier.padding(vertical = 8.dp))

                            // ASR mode radio buttons
                            Text(stringResource(R.string.settings_speech_mode), style = MaterialTheme.typography.titleSmall)
                            Spacer(Modifier.height(4.dp))
                            listOf(
                                Triple("onnx", stringResource(R.string.settings_asr_on_device_onnx), stringResource(R.string.settings_asr_on_device_onnx_desc)),
                                Triple("google", "Android Speech (free)", stringResource(R.string.settings_asr_google_free_desc)),
                                Triple("cloud", stringResource(R.string.settings_asr_cloud), stringResource(R.string.settings_asr_cloud_desc))
                            ).forEach { (value, label, description) ->
                                Row(modifier = Modifier.fillMaxWidth().clickable {
                                    asrMode = value; config.asrMode = value; voiceOffline = value == "onnx"
                                    app.asr.mode = when (value) { "onnx" -> ASREngine.Mode.ONNX_OFFLINE; "cloud" -> ASREngine.Mode.CLOUD_ASR; else -> ASREngine.Mode.GOOGLE_ONLINE }
                                }.padding(vertical = 4.dp), verticalAlignment = Alignment.CenterVertically) {
                                    RadioButton(selected = asrMode == value, onClick = null)
                                    Column(modifier = Modifier.padding(start = 8.dp)) {
                                        Text(label, fontWeight = if (asrMode == value) FontWeight.SemiBold else FontWeight.Normal)
                                        Text(description, style = MaterialTheme.typography.bodySmall, color = MaterialTheme.colorScheme.outline)
                                    }
                                }
                            }

                            // ASR tier picker
                            Spacer(Modifier.height(12.dp))
                            Text(stringResource(R.string.settings_recommended_for_device), style = MaterialTheme.typography.labelMedium, color = MaterialTheme.colorScheme.primary)
                            rankedTiers.filter { it.isCompatible }.take(3).forEach { ranked ->
                                val tier = ranked.tier
                                Row(modifier = Modifier.fillMaxWidth().clickable {
                                    selectedTier = tier; config.modelDownloadUrl = tier.modelUrl; config.vocabDownloadUrl = tier.vocabUrl
                                    config.modelExpectedSha256 = tier.modelSha256; config.vocabExpectedSha256 = tier.vocabSha256
                                    modelUrl = tier.modelUrl; vocabUrl = tier.vocabUrl
                                }.padding(vertical = 4.dp), verticalAlignment = Alignment.CenterVertically) {
                                    RadioButton(selected = tier == selectedTier, onClick = null)
                                    Column(modifier = Modifier.padding(start = 8.dp)) {
                                        Text("#${ranked.rank} ${tier.label}" + if (ranked.rank == 1) " ★" else "")
                                        Text("~${tier.sizeMb} MB — ${ranked.reason}", style = MaterialTheme.typography.bodySmall, color = MaterialTheme.colorScheme.outline)
                                    }
                                }
                            }

                            // ASR download card
                            Spacer(Modifier.height(8.dp))
                            ModelDownloadCard(
                                downloadState = downloadState, modelSizeBytes = app.asr.modelDownloader.modelSizeBytes(),
                                selectedTierSizeMb = selectedTier.sizeMb,
                                onDownload = { ModelDownloadService.start(context, "asr"); app.asr.modelDownloader.startDownload(modelUrl = selectedTier.modelUrl, vocabUrl = selectedTier.vocabUrl, expectedSha256 = config.modelExpectedSha256, expectedVocabSha256 = config.vocabExpectedSha256) },
                                onCancel = { app.asr.modelDownloader.cancel() },
                                onRetry = { ModelDownloadService.start(context, "asr"); app.asr.modelDownloader.retry(modelUrl = selectedTier.modelUrl, vocabUrl = selectedTier.vocabUrl, expectedSha256 = config.modelExpectedSha256, expectedVocabSha256 = config.vocabExpectedSha256) },
                                onDelete = { app.asr.modelDownloader.deleteModel() },
                                onLoadModel = { scope.launch { app.asr.loadModel(config.language) } }
                            )

                            // Sideload
                            Spacer(Modifier.height(12.dp))
                            Text(stringResource(R.string.settings_sideload_usb_sd), style = MaterialTheme.typography.bodySmall, color = MaterialTheme.colorScheme.onSurfaceVariant)
                            Spacer(Modifier.height(6.dp))
                            val isMultiFile = remember(selectedTier) { selectedTier.artifacts.size > 1 }
                            if (isMultiFile) {
                                OutlinedButton(onClick = { importAsrDirectoryLauncher.launch(null) }, modifier = Modifier.fillMaxWidth()) {
                                    Icon(Icons.Default.FolderOpen, contentDescription = null, modifier = Modifier.size(16.dp))
                                    Spacer(Modifier.width(6.dp)); Text(stringResource(R.string.settings_import_model_folder))
                                }
                            } else {
                                Row(horizontalArrangement = Arrangement.spacedBy(8.dp)) {
                                    OutlinedButton(onClick = { importAsrModelLauncher.launch(arrayOf("*/*")) }, modifier = Modifier.weight(1f)) { Text(stringResource(R.string.settings_import_onnx)) }
                                    OutlinedButton(onClick = { importAsrVocabLauncher.launch(arrayOf("text/plain", "*/*")) }, modifier = Modifier.weight(1f)) { Text(stringResource(R.string.settings_import_tokens)) }
                                }
                            }
                            asrImportStatus?.let { msg -> Spacer(Modifier.height(6.dp)); Text(msg, style = MaterialTheme.typography.bodySmall, color = if (msg.contains("failed", true)) MaterialTheme.colorScheme.error else MaterialTheme.colorScheme.onSurfaceVariant) }

                            HorizontalDivider(modifier = Modifier.padding(vertical = 12.dp))

                            // Clinical Notes AI mode
                            Text(stringResource(R.string.settings_note_processing_ai), style = MaterialTheme.typography.titleSmall)
                            Spacer(Modifier.height(4.dp))
                            listOf(
                                Triple("cloud", stringResource(R.string.settings_cloud_ai), stringResource(R.string.settings_cloud_ai_desc)),
                                Triple("on_device", stringResource(R.string.settings_on_device_qwen), stringResource(R.string.settings_on_device_qwen_desc)),
                                Triple("auto", stringResource(R.string.settings_auto_mode), stringResource(R.string.settings_auto_mode_desc))
                            ).forEach { (value, label, description) ->
                                Row(modifier = Modifier.fillMaxWidth().clickable {
                                    aiMode = value; config.aiMode = value; notesOffline = value == "on_device"
                                    if (value == "cloud") app.llmModelManager.unloadModel()
                                    scope.launch(Dispatchers.IO) { app.loadCountryData() }
                                }.padding(vertical = 4.dp), verticalAlignment = Alignment.CenterVertically) {
                                    RadioButton(selected = aiMode == value, onClick = null)
                                    Column(modifier = Modifier.padding(start = 8.dp)) {
                                        Text(label, fontWeight = if (aiMode == value) FontWeight.SemiBold else FontWeight.Normal)
                                        Text(description, style = MaterialTheme.typography.bodySmall, color = MaterialTheme.colorScheme.outline)
                                    }
                                }
                            }

                            // LLM tier + download
                            if (aiMode == "on_device" || aiMode == "auto") {
                                Spacer(Modifier.height(8.dp))
                                Text(stringResource(R.string.settings_on_device_qwen_model), fontWeight = FontWeight.Medium)
                                com.chartlite.app.extraction.LlmModelManager.supportedModelTiers().forEach { tier ->
                                    Row(modifier = Modifier.fillMaxWidth().padding(vertical = 2.dp), verticalAlignment = Alignment.CenterVertically) {
                                        RadioButton(selected = tier == selectedLlmTier, onClick = {
                                            if (tier != selectedLlmTier) { app.llmModelManager.deleteModel(); selectedLlmTier = tier
                                                val ov = if (tier == llmRecommended) null else tier; app.llmModelManager.overrideTier = ov; app.appConfig.llmTierOverride = ov?.name ?: ""; app.llmModelManager.refreshState() }
                                        })
                                        Column(modifier = Modifier.padding(start = 4.dp)) {
                                            Text("${tier.label} (${tier.sizeMb} MB)" + if (tier == llmRecommended) " ★" else "", fontWeight = if (tier == selectedLlmTier) FontWeight.SemiBold else FontWeight.Normal)
                                            Text(tier.description, style = MaterialTheme.typography.bodySmall, color = MaterialTheme.colorScheme.outline)
                                        }
                                    }
                                }
                                Spacer(Modifier.height(8.dp))
                                val trustedTier = app.llmModelManager.hasPinnedChecksum(selectedLlmTier)
                                when (llmModelState) {
                                    is com.chartlite.app.extraction.LlmModelManager.ModelState.NotDownloaded -> {
                                        Button(onClick = { ModelDownloadService.start(context, "llm"); app.llmModelManager.startDownload() }, enabled = app.llmModelManager.isSupportedAbi() && trustedTier) {
                                            Text(stringResource(R.string.settings_download_tier_format, selectedLlmTier.label)) }
                                    }
                                    is com.chartlite.app.extraction.LlmModelManager.ModelState.Ready -> {
                                        val sizeMb = app.llmModelManager.modelSizeBytes() / (1024 * 1024)
                                        Text(stringResource(R.string.settings_tier_ready_format, selectedLlmTier.label, sizeMb), color = MaterialTheme.colorScheme.primary)
                                        TextButton(onClick = { app.llmModelManager.deleteModel() }) { Text(stringResource(R.string.settings_delete_model), color = MaterialTheme.colorScheme.error) }
                                    }
                                    is com.chartlite.app.extraction.LlmModelManager.ModelState.Downloading -> {
                                        LinearProgressIndicator(modifier = Modifier.fillMaxWidth())
                                        TextButton(onClick = { app.llmModelManager.cancelDownload() }) { Text(stringResource(R.string.cancel)) }
                                    }
                                    is com.chartlite.app.extraction.LlmModelManager.ModelState.Verifying,
                                    is com.chartlite.app.extraction.LlmModelManager.ModelState.Installing -> {
                                        val install = llmModelState as? com.chartlite.app.extraction.LlmModelManager.ModelState.Installing
                                        Text(
                                            if (install != null) stringResource(R.string.settings_installing_model)
                                            else stringResource(R.string.settings_verifying_download),
                                            color = MaterialTheme.colorScheme.outline
                                        )
                                        if (install != null && install.totalBytes > 0) {
                                            val progress = install.bytesProcessed.toFloat() / install.totalBytes.toFloat()
                                            LinearProgressIndicator(progress = { progress.coerceIn(0f, 1f) }, modifier = Modifier.fillMaxWidth())
                                        } else {
                                            LinearProgressIndicator(modifier = Modifier.fillMaxWidth())
                                        }
                                        TextButton(onClick = { app.llmModelManager.cancelDownload() }) { Text(stringResource(R.string.cancel)) }
                                    }
                                    is com.chartlite.app.extraction.LlmModelManager.ModelState.Error -> {
                                        val err = llmModelState as com.chartlite.app.extraction.LlmModelManager.ModelState.Error
                                        Text(err.message, color = MaterialTheme.colorScheme.error)
                                        Button(onClick = { ModelDownloadService.start(context, "llm"); app.llmModelManager.startDownload() }, enabled = trustedTier) { Text(stringResource(R.string.sync_retry)) }
                                    }
                                    else -> {}
                                }
                                Spacer(Modifier.height(8.dp))
                                OutlinedButton(onClick = { importLlmModelLauncher.launch(arrayOf("*/*")) }, enabled = app.llmModelManager.isSupportedAbi()) { Text(stringResource(R.string.settings_import_gguf)) }
                                llmImportStatus?.let { msg -> Text(msg, style = MaterialTheme.typography.bodySmall, color = if (msg.contains("failed", true)) MaterialTheme.colorScheme.error else MaterialTheme.colorScheme.onSurfaceVariant) }
                            }

                            // API keys
                            if (aiMode == "cloud" || aiMode == "auto" || asrMode == "cloud") {
                                HorizontalDivider(modifier = Modifier.padding(vertical = 12.dp))
                                Text(stringResource(R.string.settings_api_key_mode), style = MaterialTheme.typography.titleSmall)
                                Spacer(Modifier.height(4.dp))
                                var extractionKeyMode by remember { mutableStateOf(config.cloudKeyMode) }
                                listOf("chartlite" to stringResource(R.string.settings_chartlite_cloud), "byok" to stringResource(R.string.settings_byok)).forEach { (value, label) ->
                                    Row(modifier = Modifier.fillMaxWidth().clickable { extractionKeyMode = value; config.cloudKeyMode = value; app.rebuildExtractionPipeline() }.padding(vertical = 4.dp), verticalAlignment = Alignment.CenterVertically) {
                                        RadioButton(selected = extractionKeyMode == value, onClick = null)
                                        Text(label, modifier = Modifier.padding(start = 8.dp), fontWeight = if (extractionKeyMode == value) FontWeight.SemiBold else FontWeight.Normal)
                                    }
                                }
                                if (extractionKeyMode == "byok") {
                                    Spacer(Modifier.height(8.dp))
                                    OutlinedTextField(
                                        value = claudeApiKey,
                                        onValueChange = {
                                            claudeApiKey = it.trim()
                                            config.claudeApiKey = it.trim()
                                        },
                                        label = { Text("Anthropic API key") },
                                        placeholder = { Text("sk-ant-...") },
                                        modifier = Modifier.fillMaxWidth(),
                                        singleLine = true,
                                        visualTransformation = PasswordVisualTransformation()
                                    )
                                    Spacer(Modifier.height(8.dp))
                                    OutlinedTextField(
                                        value = geminiApiKey,
                                        onValueChange = {
                                            geminiApiKey = it.trim()
                                            config.geminiApiKey = it.trim()
                                        },
                                        label = { Text("Gemini API key") },
                                        placeholder = { Text("AIza...") },
                                        modifier = Modifier.fillMaxWidth(),
                                        singleLine = true,
                                        visualTransformation = PasswordVisualTransformation()
                                    )
                                    Spacer(Modifier.height(8.dp))
                                    OutlinedTextField(
                                        value = openaiApiKey,
                                        onValueChange = {
                                            openaiApiKey = it.trim()
                                            config.openaiApiKey = it.trim()
                                        },
                                        label = { Text("OpenAI API key") },
                                        placeholder = { Text("sk-proj-...") },
                                        modifier = Modifier.fillMaxWidth(),
                                        singleLine = true,
                                        visualTransformation = PasswordVisualTransformation()
                                    )
                                    Spacer(Modifier.height(8.dp))
                                    OutlinedTextField(
                                        value = deepgramApiKey,
                                        onValueChange = {
                                            deepgramApiKey = it.trim()
                                            config.deepgramApiKey = it.trim()
                                        },
                                        label = { Text("Deepgram API key") },
                                        placeholder = { Text("dg_...") },
                                        modifier = Modifier.fillMaxWidth(),
                                        singleLine = true,
                                        visualTransformation = PasswordVisualTransformation()
                                    )
                                }
                            }

                            // URL editor
                            Spacer(Modifier.height(8.dp))
                            TextButton(onClick = { showUrlEditor = !showUrlEditor }) { Text(stringResource(R.string.settings_configure_model_url)) }
                            if (showUrlEditor) {
                                OutlinedTextField(value = modelUrl, onValueChange = { modelUrl = it }, label = { Text(stringResource(R.string.settings_model_url_label)) }, modifier = Modifier.fillMaxWidth(), singleLine = true)
                                Spacer(Modifier.height(8.dp))
                                OutlinedTextField(value = vocabUrl, onValueChange = { vocabUrl = it }, label = { Text(stringResource(R.string.settings_vocab_url_label)) }, modifier = Modifier.fillMaxWidth(), singleLine = true)
                                Spacer(Modifier.height(8.dp))
                                Button(onClick = { config.modelDownloadUrl = modelUrl; config.vocabDownloadUrl = vocabUrl }) { Text(stringResource(R.string.settings_save_urls)) }
                            }
                        }
                    }
                }
            }

            // Recording
            if (activeCategory == SettingsCategory.ESSENTIALS) {
            SettingsSection(stringResource(R.string.settings_recording)) {
                var recordingModeDefault by remember { mutableStateOf(config.recordingModeDefault) }
                SettingsSlider(
                    title = stringResource(R.string.settings_max_recording),
                    subtitle = stringResource(R.string.settings_minutes_format, maxRecordingMinutes),
                    value = maxRecordingMinutes.toFloat(),
                    range = 1f..30f,
                    steps = 29,
                    onValueChange = {
                        maxRecordingMinutes = it.toInt()
                        config.maxRecordingMinutes = it.toInt()
                    }
                )
                SettingsSlider(
                    title = stringResource(R.string.settings_audio_retention),
                    subtitle = if (retainAudioDays == 0) stringResource(R.string.settings_delete_immediately)
                              else stringResource(R.string.settings_days_format, retainAudioDays),
                    value = retainAudioDays.toFloat(),
                    range = 0f..30f,
                    steps = 30,
                    onValueChange = {
                        retainAudioDays = it.toInt()
                        config.retainAudioDays = it.toInt()
                    }
                )
                Spacer(Modifier.height(12.dp))
                Text(stringResource(R.string.settings_default_consultation_capture), fontWeight = FontWeight.Medium)
                Spacer(Modifier.height(4.dp))
                val ambientLabel = stringResource(R.string.settings_ambient_full_transcript)
                val ambientDesc = stringResource(R.string.settings_ambient_full_transcript_desc)
                val snippetLabel = stringResource(R.string.settings_dictation_snippets)
                val snippetDesc = stringResource(R.string.settings_dictation_snippets_desc)
                listOf(
                    Triple("ambient", ambientLabel, ambientDesc),
                    Triple("snippet", snippetLabel, snippetDesc)
                ).forEach { (value, label, description) ->
                    Row(
                        modifier = Modifier.fillMaxWidth(),
                        verticalAlignment = Alignment.CenterVertically
                    ) {
                        RadioButton(
                            selected = recordingModeDefault == value,
                            onClick = {
                                recordingModeDefault = value
                                config.recordingModeDefault = value
                            }
                        )
                        Column(modifier = Modifier.padding(start = 4.dp)) {
                            Text(label, fontWeight = if (recordingModeDefault == value) FontWeight.SemiBold else FontWeight.Normal)
                            Text(
                                description,
                                style = MaterialTheme.typography.bodySmall,
                                color = MaterialTheme.colorScheme.outline
                            )
                        }
                    }
                }
            }
            }

            // Security
            if (activeCategory == SettingsCategory.ESSENTIALS) {
            SettingsSection(stringResource(R.string.settings_security)) {
                SettingsSwitch(
                    title = stringResource(R.string.settings_biometric_unlock),
                    subtitle = stringResource(R.string.settings_biometric_subtitle),
                    checked = useBiometric,
                    onCheckedChange = { enabled ->
                        useBiometric = enabled
                        config.useBiometric = enabled
                        scope.launch {
                            app.auditLogger.log("SETTINGS_CHANGE", targetType = "SETTING",
                                details = """{"field":"biometric","enabled":$enabled}""")
                        }
                    }
                )
                SettingsSlider(
                    title = stringResource(R.string.auto_lock),
                    subtitle = stringResource(R.string.settings_autolock_subtitle, autoLockMinutes),
                    value = autoLockMinutes.toFloat(),
                    range = 1f..30f,
                    steps = 29,
                    onValueChange = {
                        autoLockMinutes = it.toInt()
                        config.autoLockMinutes = it.toInt()
                    }
                )
            }
            }

            // SMS
            if (activeCategory == SettingsCategory.OPERATIONS) {
            SettingsSection(stringResource(R.string.settings_sms_referrals)) {
                // Native SMS — the default, zero-config path
                ListItem(
                    headlineContent = { Text(stringResource(R.string.settings_send_via_sim)) },
                    supportingContent = {
                        Text(
                            if (config.twilioAccountSid.isBlank())
                                stringResource(R.string.settings_sim_active_sms_permission)
                            else stringResource(R.string.settings_sim_inactive)
                        )
                    },
                    leadingContent = {
                        Icon(Icons.Default.SimCard, contentDescription = stringResource(R.string.content_desc_sim))
                    },
                    trailingContent = {
                        if (config.twilioAccountSid.isBlank()) {
                            Icon(Icons.Default.CheckCircle, contentDescription = stringResource(R.string.content_desc_active),
                                tint = MaterialTheme.colorScheme.primary)
                        }
                    }
                )

                // Twilio — collapsed advanced option
                var showTwilio by remember { mutableStateOf(config.twilioAccountSid.isNotBlank()) }
                Column(modifier = Modifier.padding(horizontal = 16.dp)) {
                    TextButton(onClick = { showTwilio = !showTwilio }) {
                        Icon(
                            if (showTwilio) Icons.Default.ExpandLess else Icons.Default.ExpandMore,
                            contentDescription = if (showTwilio) stringResource(R.string.content_desc_collapse) else stringResource(R.string.content_desc_expand),
                            modifier = Modifier.size(18.dp)
                        )
                        Spacer(Modifier.width(4.dp))
                        Text(stringResource(R.string.settings_twilio_advanced))
                    }

                    if (showTwilio) {
                        Text(
                            stringResource(R.string.settings_twilio_hint),
                            style = MaterialTheme.typography.bodySmall,
                            color = MaterialTheme.colorScheme.onSurfaceVariant,
                            modifier = Modifier.padding(bottom = 8.dp)
                        )

                        OutlinedTextField(
                            value = twilioSid,
                            onValueChange = { twilioSid = it },
                            label = { Text(stringResource(R.string.settings_account_sid)) },
                            modifier = Modifier.fillMaxWidth(),
                            singleLine = true,
                            keyboardOptions = KeyboardOptions(imeAction = ImeAction.Next)
                        )
                        Spacer(Modifier.height(8.dp))
                        OutlinedTextField(
                            value = twilioToken,
                            onValueChange = { twilioToken = it },
                            label = { Text(stringResource(R.string.settings_auth_token)) },
                            modifier = Modifier.fillMaxWidth(),
                            singleLine = true,
                            visualTransformation = PasswordVisualTransformation(),
                            keyboardOptions = KeyboardOptions(imeAction = ImeAction.Next)
                        )
                        Spacer(Modifier.height(8.dp))
                        OutlinedTextField(
                            value = twilioFrom,
                            onValueChange = { twilioFrom = it },
                            label = { Text(stringResource(R.string.settings_from_number)) },
                            modifier = Modifier.fillMaxWidth(),
                            singleLine = true,
                            placeholder = { Text("+1234567890") },
                            keyboardOptions = KeyboardOptions(
                                keyboardType = KeyboardType.Phone,
                                imeAction = ImeAction.Done
                            )
                        )
                        Spacer(Modifier.height(12.dp))

                        twilioStatus?.let { status ->
                            Text(
                                status,
                                style = MaterialTheme.typography.bodySmall,
                                color = if (status.startsWith("✓")) MaterialTheme.colorScheme.primary
                                       else MaterialTheme.colorScheme.error,
                                modifier = Modifier.padding(bottom = 8.dp)
                            )
                        }

                        Row(horizontalArrangement = Arrangement.spacedBy(8.dp)) {
                            Button(
                                onClick = {
                                    config.twilioAccountSid = twilioSid
                                    config.twilioAuthToken = twilioToken
                                    config.twilioFromNumber = twilioFrom

                                    if (twilioSid.isNotBlank() && twilioToken.isNotBlank()) {
                                        twilioVerifying = true
                                        twilioStatus = null
                                        scope.launch {
                                            val provider = TwilioSMSProvider(twilioSid, twilioToken, twilioFrom)
                                            val valid = provider.verifyCredentials()
                                            twilioStatus = if (valid) "✓ $twilioVerifiedStr"
                                                           else "✗ $twilioInvalidStr"
                                            twilioVerifying = false
                                        }
                                    } else {
                                        twilioStatus = "✓ $twilioSavedNativeStr"
                                    }
                                },
                                enabled = !twilioVerifying
                            ) {
                                if (twilioVerifying) {
                                    CircularProgressIndicator(
                                        modifier = Modifier.size(16.dp),
                                        color = MaterialTheme.colorScheme.onPrimary
                                    )
                                } else {
                                    Text(stringResource(R.string.settings_save_verify))
                                }
                            }

                            if (twilioSid.isNotBlank()) {
                                OutlinedButton(onClick = {
                                    twilioSid = ""
                                    twilioToken = ""
                                    twilioFrom = ""
                                    config.twilioAccountSid = ""
                                    config.twilioAuthToken = ""
                                    config.twilioFromNumber = ""
                                    twilioStatus = twilioClearedNativeStr
                                }) {
                                    Text(stringResource(R.string.settings_clear))
                                }
                            }
                        }
                        Spacer(Modifier.height(8.dp))
                    }
                }
            }
            }

            // Clinic Workflow
            if (activeCategory == SettingsCategory.OPERATIONS) {
            SettingsSection(stringResource(R.string.settings_clinic_workflow)) {
                var isMultiStation by remember { mutableStateOf(config.isMultiStation) }
                var enabledStations by remember { mutableStateOf(config.enabledStations) }

                SettingsSwitch(
                    title = stringResource(R.string.settings_multi_station),
                    subtitle = if (isMultiStation) stringResource(R.string.settings_multi_station_on)
                               else stringResource(R.string.settings_multi_station_off),
                    checked = isMultiStation,
                    onCheckedChange = { enabled ->
                        isMultiStation = enabled
                        config.workflowMode = if (enabled) "multi_station" else "solo"
                        if (enabled) {
                            val allStations = ClinicStation.entries.map { it.name }.toSet()
                            enabledStations = allStations
                            config.enabledStations = allStations
                        } else {
                            enabledStations = emptySet()
                            config.enabledStations = emptySet()
                        }
                        scope.launch {
                            app.auditLogger.log("SETTINGS_CHANGE", targetType = "SETTING",
                                details = """{"field":"workflow_mode","to":"${if (enabled) "multi_station" else "solo"}"}""")
                        }
                    }
                )

                if (isMultiStation) {
                    Text(
                        stringResource(R.string.settings_active_stations),
                        style = MaterialTheme.typography.labelLarge,
                        modifier = Modifier.padding(horizontal = 16.dp, vertical = 4.dp)
                    )
                    ClinicStation.entries.forEach { station ->
                        val checked = station.name in enabledStations
                        ListItem(
                            headlineContent = { Text(station.displayName) },
                            leadingContent = {
                                Checkbox(
                                    checked = checked,
                                    onCheckedChange = { isChecked ->
                                        enabledStations = if (isChecked) {
                                            enabledStations + station.name
                                        } else {
                                            enabledStations - station.name
                                        }
                                        config.enabledStations = enabledStations
                                    }
                                )
                            },
                            modifier = Modifier.padding(start = 8.dp)
                        )
                    }
                    Text(
                        stringResource(R.string.settings_stations_hint),
                        style = MaterialTheme.typography.bodySmall,
                        color = MaterialTheme.colorScheme.onSurfaceVariant,
                        modifier = Modifier.padding(horizontal = 16.dp, vertical = 8.dp)
                    )
                }
            }
            }

            // Market Expansion — collapsed by default to reduce cognitive load
            if (activeCategory == SettingsCategory.REGIONS) {
            var showRegionSection by remember { mutableStateOf(false) }
            SettingsSection(stringResource(R.string.settings_switch_region)) {
                TextButton(
                    onClick = { showRegionSection = !showRegionSection },
                    modifier = Modifier.fillMaxWidth()
                ) {
                    Text(
                        if (showRegionSection) stringResource(R.string.settings_hide_regions) else stringResource(R.string.settings_show_regions),
                        style = MaterialTheme.typography.bodySmall
                    )
                    Spacer(Modifier.weight(1f))
                    Icon(
                        if (showRegionSection) Icons.Default.ExpandLess else Icons.Default.ExpandMore,
                        contentDescription = if (showRegionSection) stringResource(R.string.content_desc_collapse) else stringResource(R.string.content_desc_expand),
                        modifier = Modifier.size(18.dp)
                    )
                }
            }
            if (showRegionSection) {
            SettingsSection(stringResource(R.string.settings_available_regions)) {
                // Active regions header
                Text(stringResource(R.string.settings_tap_to_switch),
                    style = MaterialTheme.typography.bodySmall,
                    color = Neutral500,
                    modifier = Modifier.padding(horizontal = 16.dp, vertical = 4.dp))

                // ── South Africa — ACTIVE ──
                MarketCard(
                    flag = "🇿🇦",
                    country = "South Africa",
                    status = if (countryCode == "za") "ACTIVE" else "SWITCH",
                    statusColor = if (countryCode == "za") BrandGreen else InfoBlue,
                    bgColor = if (countryCode == "za") BrandGreenSurface else Neutral100,
                    subtitle = "515 STG/EML drugs · 300 ICD-10 codes · SAMA tariffs · ZAR billing",
                    onSwitch = if (countryCode != "za") { { pendingCountryChange = "za" } } else null
                ) {
                    MarketFeatureRow("ICD-10 diagnosis coding", "300 PHC codes")
                    MarketFeatureRow("SAMA tariff billing", "ZAR + CPT mapping")
                    MarketFeatureRow("SA STG/EML formulary", "515 drugs, S1–S6")
                    MarketFeatureRow("DHIS2 facility reporting", "Monthly indicator export")
                    MarketFeatureRow("SQLCipher + POPIA", "AES-256 at rest")
                    MarketFeatureRow("Native SIM SMS referrals", "Zero-config, no Twilio")
                }

                // ── United States ──
                MarketCard(
                    flag = "🇺🇸",
                    country = "United States",
                    status = if (countryCode == "us") "ACTIVE" else "SWITCH",
                    statusColor = if (countryCode == "us") BrandGreen else InfoBlue,
                    bgColor = if (countryCode == "us") BrandGreenSurface else InfoBlueSurface,
                    subtitle = "US formulary · CPT/HCPCS billing · 2026 CF \$33.40/RVU",
                    onSwitch = if (countryCode != "us") { { pendingCountryChange = "us" } } else null
                ) {
                    MarketFeatureRow("CPT/HCPCS billing", "E/M levels 99211–99215")
                    MarketFeatureRow("HIPAA compliant", "Encrypted storage & transmission")
                    MarketFeatureRow("HL7 FHIR R4", "EHR interoperability")
                    MarketFeatureRow("EDI claim submission", "837P electronic claims")
                    MarketFeatureRow("NDC drug formulary", "8,000+ FDA-approved drugs")
                    MarketFeatureRow("ONC certified", "USCDI v3 data standards")
                }

                // ── Ethiopia — SWITCHABLE ──
                MarketCard(
                    flag = "🇪🇹",
                    country = "Ethiopia",
                    status = if (countryCode == "et") "ACTIVE" else "SWITCH",
                    statusColor = if (countryCode == "et") BrandGreen else InfoBlue,
                    bgColor = if (countryCode == "et") BrandGreenSurface else BrandGreenSurface.copy(alpha = 0.5f),
                    subtitle = "138 EML drugs · DHIS2 v40 · 30K+ facilities · CBHI 22.5M",
                    onSwitch = if (countryCode != "et") { { pendingCountryChange = "et" } } else null
                ) {
                    MarketFeatureRow("DHIS2 v40 reporting", "30K+ public facilities")
                    MarketFeatureRow("EML 7th Ed. formulary", "484+ essential medicines")
                    MarketFeatureRow("CBHI insurance", "22.5M enrolled")
                    MarketFeatureRow("Amharic language", "Native script support")
                    MarketFeatureRow("District reporting", "Monthly health indicators")
                    MarketFeatureRow("Multi-language", "Oromiffa + Tigrinya planned")
                }

                // Malawi
                MarketCard(
                    flag = "🇲🇼",
                    country = "Malawi",
                    status = if (countryCode == "mw") "ACTIVE" else "SWITCH",
                    statusColor = if (countryCode == "mw") BrandGreen else InfoBlue,
                    bgColor = if (countryCode == "mw") BrandGreenSurface else Neutral100,
                    subtitle = "106 MSTG drugs · DOTS TB · First-line AL antimalarial",
                    onSwitch = if (countryCode != "mw") { { pendingCountryChange = "mw" } } else null
                ) {
                    MarketFeatureRow("MSTG formulary", "106 essential drugs")
                    MarketFeatureRow("TB treatment protocols", "Standard regimens")
                    MarketFeatureRow("HIV/ARV support", "First-line regimens")
                    MarketFeatureRow("Malaria protocols", "AL + artesunate")
                    MarketFeatureRow("ICD-10 diagnosis codes", "300 PHC codes")
                }

                // ── Coming Soon ──
                HorizontalDivider(modifier = Modifier.padding(horizontal = 16.dp, vertical = 8.dp))
                Text(stringResource(R.string.settings_coming_soon),
                    style = MaterialTheme.typography.labelMedium,
                    fontWeight = FontWeight.Bold,
                    color = Neutral500,
                    modifier = Modifier.padding(start = 16.dp, bottom = 4.dp))

                Text(stringResource(R.string.settings_africa),
                    style = MaterialTheme.typography.labelMedium,
                    fontWeight = FontWeight.Bold,
                    color = Neutral700,
                    modifier = Modifier.padding(start = 16.dp, top = 4.dp, bottom = 4.dp))

                // Kenya
                MarketCard(
                    flag = "🇰🇪",
                    country = "Kenya",
                    status = "Coming Soon",
                    statusColor = AccentOrange,
                    bgColor = WarningAmberSurface.copy(alpha = 0.5f),
                    subtitle = "47 counties · 15,000 facilities · KEML 2023 · SHA launched Oct 2024"
                ) {
                    MarketFeatureRow("National health reporting", "All 47 counties")
                    MarketFeatureRow("KEML 2023 formulary", "35 therapeutic groups")
                    MarketFeatureRow("SHA health insurance", "15.5M members")
                    MarketFeatureRow("M-PESA payments", "Mobile billing")
                    MarketFeatureRow("EHR integration", "OpenMRS compatible")
                    MarketFeatureRow("Facility registry", "National master list")
                }

                // Nigeria
                MarketCard(
                    flag = "🇳🇬",
                    country = "Nigeria",
                    status = "Coming Soon",
                    statusColor = Neutral500,
                    bgColor = Neutral100,
                    subtitle = "34,076 PHCs · 21.7M NHIA enrolled · DHIS2 in all 36 states"
                ) {
                    MarketFeatureRow("NHIA insurance", "21.7M enrolled")
                    MarketFeatureRow("Drug registry", "NAFDAC approved products")
                    MarketFeatureRow("NEML formulary", "350+ essential medicines")
                    MarketFeatureRow("National reporting", "All 36 states + FCT")
                    MarketFeatureRow("PHC network", "34,000+ primary health centres")
                }

                // Compact Africa row
                Row(
                    modifier = Modifier
                        .fillMaxWidth()
                        .padding(horizontal = 16.dp, vertical = 4.dp),
                    horizontalArrangement = Arrangement.spacedBy(8.dp)
                ) {
                    CompactMarketCard("🇷🇼", "Rwanda", "Coming Soon", Neutral500, Modifier.weight(1f))
                    CompactMarketCard("🇹🇿", "Tanzania", "Coming Soon", Neutral500, Modifier.weight(1f))
                    CompactMarketCard("🇺🇬", "Uganda", "Coming Soon", Neutral500, Modifier.weight(1f))
                }

                // ── International Expansion ──
                Text(stringResource(R.string.settings_international),
                    style = MaterialTheme.typography.labelMedium,
                    fontWeight = FontWeight.Bold,
                    color = Neutral700,
                    modifier = Modifier.padding(start = 16.dp, top = 12.dp, bottom = 4.dp))

                // United Kingdom
                MarketCard(
                    flag = "🇬🇧",
                    country = "United Kingdom",
                    status = "Coming Soon",
                    statusColor = Neutral500,
                    bgColor = Neutral100,
                    subtitle = "6,172 GP practices · NHS Spine · SNOMED CT"
                ) {
                    MarketFeatureRow("SNOMED CT coding", "Mandatory clinical coding")
                    MarketFeatureRow("BNF formulary", "1,500+ drugs")
                    MarketFeatureRow("NHS Spine integration", "GP Connect FHIR")
                    MarketFeatureRow("Clinical safety", "DCB0129 compliant")
                    MarketFeatureRow("DTAC assessed", "NHS digital standards")
                }

                // India
                MarketCard(
                    flag = "🇮🇳",
                    country = "India",
                    status = "Coming Soon",
                    statusColor = Neutral500,
                    bgColor = Neutral100,
                    subtitle = "ABHA health IDs · 384 NLEM drugs · PM-JAY coverage"
                ) {
                    MarketFeatureRow("ABDM / ABHA health ID", "National health accounts")
                    MarketFeatureRow("NLEM 2022 formulary", "384 essential drugs")
                    MarketFeatureRow("PM-JAY insurance", "550M beneficiaries")
                    MarketFeatureRow("UPI payments", "Integrated billing")
                    MarketFeatureRow("Multi-language support", "Hindi + 22 languages")
                }

            }
            } // end if (showRegionSection)
            } // end if (activeCategory == REGIONS)

            // User Management (Admin only)
            if (activeCategory == SettingsCategory.ADMIN && currentRole?.canManageUsers == true) {
                SettingsSection(stringResource(R.string.settings_administration)) {
                    Surface(onClick = onUserManagement) {
                        ListItem(
                            headlineContent = { Text(stringResource(R.string.user_management)) },
                            supportingContent = { Text(stringResource(R.string.settings_user_mgmt_subtitle)) },
                            leadingContent = { Icon(Icons.Default.Group, contentDescription = stringResource(R.string.content_desc_users)) },
                            trailingContent = { Icon(Icons.Default.ChevronRight, contentDescription = stringResource(R.string.content_desc_open)) }
                        )
                    }
                    Surface(onClick = {
                        facilityQrPin = ""
                        facilityQrError = null
                        showFacilityQrReauthDialog = true
                    }) {
                        ListItem(
                            headlineContent = { Text(stringResource(R.string.settings_facility_qr)) },
                            supportingContent = { Text(stringResource(R.string.settings_facility_qr_subtitle)) },
                            leadingContent = { Icon(Icons.Default.QrCode, contentDescription = stringResource(R.string.content_desc_facility_qr)) }
                        )
                    }
                    Surface(onClick = {
                        generatedDeviceCode = null
                        generateCodeError = null
                        showGenerateCodeDialog = true
                    }) {
                        ListItem(
                            headlineContent = { Text("Generate Device Code") },
                            supportingContent = { Text("Create a one-time enrollment code for a non-GMS device") },
                            leadingContent = { Icon(Icons.Default.PhoneAndroid, contentDescription = "Generate device code") }
                        )
                    }
                }
                Spacer(Modifier.height(8.dp))
            }

            // About
            if (activeCategory == SettingsCategory.ADMIN) {
            SettingsSection(stringResource(R.string.about)) {
                ListItem(
                    headlineContent = { Text(stringResource(R.string.app_name)) },
                    supportingContent = { Text(stringResource(R.string.settings_version)) },
                    leadingContent = { Icon(Icons.Default.Info, contentDescription = stringResource(R.string.content_desc_app_info)) }
                )
                ListItem(
                    headlineContent = { Text(stringResource(R.string.settings_provider)) },
                    supportingContent = { Text(config.providerId) },
                    leadingContent = { Icon(Icons.Default.Person, contentDescription = stringResource(R.string.content_desc_provider)) }
                )
                ListItem(
                    headlineContent = { Text(stringResource(R.string.settings_facility)) },
                    supportingContent = { Text(config.facilityId) },
                    leadingContent = { Icon(Icons.Default.LocalHospital, contentDescription = stringResource(R.string.content_desc_facility)) }
                )
            }
            }
            }
        }
    }

    // ── Generate Device Code Dialog ──
    if (showGenerateCodeDialog) {
        AlertDialog(
            onDismissRequest = {
                if (!generateCodeLoading) showGenerateCodeDialog = false
            },
            title = { Text("Generate Device Code") },
            text = {
                Column {
                    if (generatedDeviceCode != null) {
                        Text(
                            "Give this code to the device user. It expires in 24 hours and can only be used by one device.",
                            style = MaterialTheme.typography.bodySmall,
                            color = MaterialTheme.colorScheme.onSurfaceVariant
                        )
                        Spacer(Modifier.height(16.dp))
                        Surface(
                            shape = RoundedCornerShape(12.dp),
                            color = MaterialTheme.colorScheme.primaryContainer
                        ) {
                            Text(
                                text = generatedDeviceCode!!,
                                modifier = Modifier.padding(horizontal = 20.dp, vertical = 14.dp).fillMaxWidth(),
                                style = MaterialTheme.typography.headlineMedium,
                                fontWeight = FontWeight.Bold,
                                letterSpacing = 3.sp,
                                textAlign = TextAlign.Center,
                                color = MaterialTheme.colorScheme.onPrimaryContainer
                            )
                        }
                    } else if (generateCodeLoading) {
                        Row(verticalAlignment = Alignment.CenterVertically) {
                            CircularProgressIndicator(modifier = Modifier.size(20.dp), strokeWidth = 2.dp)
                            Spacer(Modifier.width(12.dp))
                            Text("Generating code…")
                        }
                    } else if (generateCodeError != null) {
                        Text(
                            generateCodeError!!,
                            style = MaterialTheme.typography.bodySmall,
                            color = MaterialTheme.colorScheme.error
                        )
                    } else {
                        Text(
                            "This will generate a one-time enrollment code for a non-GMS device. The code expires after 24 hours and binds to the first device that uses it.",
                            style = MaterialTheme.typography.bodySmall,
                            color = MaterialTheme.colorScheme.onSurfaceVariant
                        )
                    }
                }
            },
            confirmButton = {
                if (generatedDeviceCode != null) {
                    TextButton(onClick = { showGenerateCodeDialog = false }) {
                        Text("Done")
                    }
                } else {
                    TextButton(
                        onClick = {
                            scope.launch {
                                generateCodeLoading = true
                                generateCodeError = null
                                try {
                                    val result = withContext(Dispatchers.IO) {
                                        val requestBody = org.json.JSONObject().apply {
                                            put("admin_secret", config.chartliteEnrollmentCode)
                                        }.toString()
                                        val request = okhttp3.Request.Builder()
                                            .url("https://api.chartlite.health/v1/device/generate-code")
                                            .addHeader("Content-Type", "application/json")
                                            .post(requestBody.toRequestBody("application/json".toMediaType()))
                                            .build()
                                        com.chartlite.app.asr.cloud.SharedHttpClient.instance
                                            .newCall(request).execute()
                                    }
                                    result.use { response ->
                                        val body = response.body?.string().orEmpty()
                                        if (response.isSuccessful) {
                                            val json = org.json.JSONObject(body)
                                            generatedDeviceCode = json.getString("code")
                                        } else {
                                            generateCodeError = "Failed: ${org.json.JSONObject(body).optString("error", "Unknown error")}"
                                        }
                                    }
                                } catch (e: Exception) {
                                    generateCodeError = "Network error: ${e.message ?: "check your connection"}"
                                } finally {
                                    generateCodeLoading = false
                                }
                            }
                        },
                        enabled = !generateCodeLoading
                    ) {
                        Text("Generate")
                    }
                }
            },
            dismissButton = {
                if (generatedDeviceCode == null) {
                    TextButton(onClick = { showGenerateCodeDialog = false }) {
                        Text("Cancel")
                    }
                }
            }
        )
    }

    val settingsTooManyAttemptsFormat = stringResource(R.string.settings_too_many_attempts)
    val settingsIncorrectPinMsg = stringResource(R.string.settings_incorrect_pin)
    if (showFacilityQrReauthDialog) {
        AlertDialog(
            onDismissRequest = {
                if (!facilityQrAuthenticating) {
                    showFacilityQrReauthDialog = false
                }
            },
            title = { Text(stringResource(R.string.settings_confirm_admin_pin)) },
            text = {
                Column(verticalArrangement = Arrangement.spacedBy(8.dp)) {
                    Text(
                        stringResource(R.string.settings_enter_pin_for_qr),
                        style = MaterialTheme.typography.bodyMedium,
                        color = MaterialTheme.colorScheme.onSurfaceVariant
                    )
                    OutlinedTextField(
                        value = facilityQrPin,
                        onValueChange = {
                            if (it.length <= 6 && it.all(Char::isDigit)) {
                                facilityQrPin = it
                                facilityQrError = null
                            }
                        },
                        label = { Text(stringResource(R.string.settings_admin_pin)) },
                        singleLine = true,
                        isError = facilityQrError != null,
                        supportingText = facilityQrError?.let { { Text(it) } },
                        visualTransformation = PasswordVisualTransformation(),
                        modifier = Modifier.fillMaxWidth()
                    )
                }
            },
            confirmButton = {
                Button(
                    onClick = {
                        if (facilityQrAuthenticating) return@Button
                        facilityQrAuthenticating = true
                        scope.launch {
                            val ok = app.sessionManager.reauthenticate(facilityQrPin)
                            facilityQrAuthenticating = false
                            if (ok) {
                                showFacilityQrReauthDialog = false
                                showFacilityQrRoleDialog = true
                                facilityQrPin = ""
                                facilityQrError = null
                            } else {
                                val remaining = app.sessionManager.lockoutRemainingSeconds()
                                facilityQrError = if (remaining > 0) {
                                    String.format(settingsTooManyAttemptsFormat, remaining)
                                } else {
                                    settingsIncorrectPinMsg
                                }
                            }
                        }
                    },
                    enabled = facilityQrPin.length >= 4 && !facilityQrAuthenticating
                ) {
                    if (facilityQrAuthenticating) {
                        CircularProgressIndicator(
                            modifier = Modifier.size(16.dp),
                            color = MaterialTheme.colorScheme.onPrimary,
                            strokeWidth = 2.dp
                        )
                    } else {
                        Text(stringResource(R.string.settings_verify))
                    }
                }
            },
            dismissButton = {
                TextButton(
                    onClick = { showFacilityQrReauthDialog = false },
                    enabled = !facilityQrAuthenticating
                ) {
                    Text(stringResource(R.string.cancel))
                }
            }
        )
    }

    // Role selection dialog (shown after admin PIN verification)
    if (showFacilityQrRoleDialog) {
        var roleExpanded by remember { mutableStateOf(false) }
        AlertDialog(
            onDismissRequest = { showFacilityQrRoleDialog = false },
            title = { Text("Select Role for New Staff") },
            text = {
                Column(verticalArrangement = Arrangement.spacedBy(12.dp)) {
                    Text(
                        "Choose the role for the person who will scan this QR code.",
                        style = MaterialTheme.typography.bodyMedium,
                        color = MaterialTheme.colorScheme.onSurfaceVariant
                    )
                    ExposedDropdownMenuBox(
                        expanded = roleExpanded,
                        onExpandedChange = { roleExpanded = it }
                    ) {
                        OutlinedTextField(
                            value = facilityQrSelectedRole.displayName,
                            onValueChange = {},
                            readOnly = true,
                            label = { Text("Role") },
                            trailingIcon = { ExposedDropdownMenuDefaults.TrailingIcon(roleExpanded) },
                            modifier = Modifier.menuAnchor().fillMaxWidth()
                        )
                        ExposedDropdownMenu(
                            expanded = roleExpanded,
                            onDismissRequest = { roleExpanded = false }
                        ) {
                            UserRole.entries.filter { it != UserRole.ADMIN }.forEach { role ->
                                DropdownMenuItem(
                                    text = {
                                        Column {
                                            Text(role.displayName, fontWeight = FontWeight.Medium)
                                            Text(role.description, style = MaterialTheme.typography.bodySmall, color = MaterialTheme.colorScheme.onSurfaceVariant)
                                        }
                                    },
                                    onClick = {
                                        facilityQrSelectedRole = role
                                        roleExpanded = false
                                    }
                                )
                            }
                        }
                    }
                }
            },
            confirmButton = {
                Button(onClick = {
                    val expiresAt = System.currentTimeMillis() + (10 * 60 * 1000L)
                    val nonce = UUID.randomUUID().toString().take(8).uppercase()
                    val hmacTag = com.chartlite.app.auth.InviteHmac.computeTag(
                        config.facilityId, facilityQrSelectedRole.name, expiresAt, nonce, config.inviteSecret
                    )
                    facilityInviteQrPayload =
                        "chartlite-invite-v2:${config.facilityId}:${facilityQrSelectedRole.name}:$expiresAt:$nonce:$hmacTag"
                    facilityInviteConfirmCode = com.chartlite.app.auth.InviteHmac.deriveConfirmCode(hmacTag)
                    facilityInviteExpiresAt = expiresAt
                    facilityQrCountdownNow = System.currentTimeMillis()
                    showFacilityQrRoleDialog = false
                    showFacilityQrDialog = true
                }) {
                    Text("Generate QR Code")
                }
            },
            dismissButton = {
                TextButton(onClick = { showFacilityQrRoleDialog = false }) {
                    Text(stringResource(R.string.cancel))
                }
            }
        )
    }

    if (showFacilityQrDialog) {
        // Live countdown timer
        LaunchedEffect(showFacilityQrDialog) {
            while (showFacilityQrDialog && facilityInviteExpiresAt > System.currentTimeMillis()) {
                kotlinx.coroutines.delay(15_000L)
                facilityQrCountdownNow = System.currentTimeMillis()
            }
        }
        AlertDialog(
            onDismissRequest = { showFacilityQrDialog = false },
            title = { Text(stringResource(R.string.settings_facility_qr_title)) },
            text = {
                Column(
                    modifier = Modifier.fillMaxWidth(),
                    horizontalAlignment = Alignment.CenterHorizontally,
                    verticalArrangement = Arrangement.spacedBy(12.dp)
                ) {
                    QrCodeImage(
                        content = facilityInviteQrPayload,
                        size = 200.dp
                    )
                    if (facilityInviteConfirmCode.isNotBlank()) {
                        Surface(
                            shape = RoundedCornerShape(12.dp),
                            color = MaterialTheme.colorScheme.primaryContainer
                        ) {
                            Column(
                                modifier = Modifier.padding(horizontal = 20.dp, vertical = 12.dp),
                                horizontalAlignment = Alignment.CenterHorizontally
                            ) {
                                Text(
                                    "Confirmation code",
                                    style = MaterialTheme.typography.labelSmall,
                                    color = MaterialTheme.colorScheme.onPrimaryContainer.copy(alpha = 0.7f)
                                )
                                Text(
                                    facilityInviteConfirmCode,
                                    style = MaterialTheme.typography.headlineMedium,
                                    fontWeight = FontWeight.Bold,
                                    letterSpacing = 4.sp,
                                    color = MaterialTheme.colorScheme.onPrimaryContainer
                                )
                                Text(
                                    "Tell this code to the person joining",
                                    style = MaterialTheme.typography.bodySmall,
                                    color = MaterialTheme.colorScheme.onPrimaryContainer.copy(alpha = 0.7f)
                                )
                            }
                        }
                    }
                    Text(
                        "Joining as: ${facilityQrSelectedRole.displayName}",
                        style = MaterialTheme.typography.labelLarge,
                        fontWeight = FontWeight.Medium,
                        color = MaterialTheme.colorScheme.primary
                    )
                    Text(
                        stringResource(R.string.settings_facility_id_format, config.facilityId),
                        style = MaterialTheme.typography.labelMedium,
                        color = MaterialTheme.colorScheme.onSurfaceVariant
                    )
                    Text(
                        stringResource(R.string.settings_facility_qr_instructions),
                        style = MaterialTheme.typography.bodySmall,
                        color = MaterialTheme.colorScheme.onSurfaceVariant
                    )
                    if (facilityInviteExpiresAt > 0L) {
                        val minutesLeft = ((facilityInviteExpiresAt - facilityQrCountdownNow) / (60 * 1000))
                            .coerceAtLeast(0L)
                        Text(
                            stringResource(R.string.settings_time_left_format, minutesLeft),
                            style = MaterialTheme.typography.bodySmall,
                            color = if (minutesLeft < 3) MaterialTheme.colorScheme.error
                                   else MaterialTheme.colorScheme.onSurfaceVariant
                        )
                    }
                }
            },
            confirmButton = {
                TextButton(onClick = { showFacilityQrDialog = false }) {
                    Text(stringResource(R.string.done))
                }
            }
        )
    }
}

// ── Model Download Card ──

@Composable
private fun ModelDownloadCard(
    downloadState: ModelDownloader.DownloadState,
    modelSizeBytes: Long,
    selectedTierSizeMb: Int = 63,
    onDownload: () -> Unit,
    onCancel: () -> Unit,
    onRetry: () -> Unit,
    onDelete: () -> Unit,
    onLoadModel: () -> Unit
) {
    Card(
        modifier = Modifier
            .fillMaxWidth()
            .padding(horizontal = 16.dp, vertical = 8.dp),
        colors = CardDefaults.cardColors(
            containerColor = MaterialTheme.colorScheme.surfaceVariant
        )
    ) {
        Column(modifier = Modifier.padding(16.dp)) {
            Row(
                modifier = Modifier.fillMaxWidth(),
                horizontalArrangement = Arrangement.SpaceBetween,
                verticalAlignment = Alignment.CenterVertically
            ) {
                Column(modifier = Modifier.weight(1f)) {
                    Text(
                        stringResource(R.string.settings_meta_mms_model),
                        style = MaterialTheme.typography.titleSmall
                    )
                    Text(
                        when (downloadState) {
                            is ModelDownloader.DownloadState.Idle -> stringResource(R.string.settings_not_downloaded)
                            is ModelDownloader.DownloadState.Downloading -> stringResource(R.string.settings_downloading_ellipsis)
                            is ModelDownloader.DownloadState.Verifying -> stringResource(R.string.settings_verifying_ellipsis)
                            is ModelDownloader.DownloadState.Complete -> stringResource(R.string.settings_ready_size_format, formatBytes(modelSizeBytes))
                            is ModelDownloader.DownloadState.Error -> stringResource(R.string.settings_download_failed)
                            is ModelDownloader.DownloadState.Paused -> stringResource(R.string.settings_paused)
                        },
                        style = MaterialTheme.typography.bodySmall,
                        color = MaterialTheme.colorScheme.onSurfaceVariant
                    )
                }
                ModelStatusIcon(downloadState)
            }

            // Progress bar for downloading state
            if (downloadState is ModelDownloader.DownloadState.Downloading) {
                Spacer(Modifier.height(12.dp))
                if (downloadState.totalBytes > 0) {
                    val progress = downloadState.bytesDownloaded.toFloat() / downloadState.totalBytes
                    LinearProgressIndicator(
                        progress = { progress },
                        modifier = Modifier.fillMaxWidth()
                    )
                    Spacer(Modifier.height(4.dp))
                    Text(
                        stringResource(R.string.settings_download_progress_format, formatBytes(downloadState.bytesDownloaded), formatBytes(downloadState.totalBytes), (progress * 100).toInt()),
                        style = MaterialTheme.typography.labelSmall,
                        color = MaterialTheme.colorScheme.onSurfaceVariant
                    )
                } else {
                    LinearProgressIndicator(modifier = Modifier.fillMaxWidth())
                    Spacer(Modifier.height(4.dp))
                    Text(
                        stringResource(R.string.settings_downloaded_progress, formatBytes(downloadState.bytesDownloaded)),
                        style = MaterialTheme.typography.labelSmall,
                        color = MaterialTheme.colorScheme.onSurfaceVariant
                    )
                }
            }

            if (downloadState is ModelDownloader.DownloadState.Verifying) {
                Spacer(Modifier.height(12.dp))
                Row(verticalAlignment = Alignment.CenterVertically) {
                    CircularProgressIndicator(modifier = Modifier.size(16.dp))
                    Spacer(Modifier.width(8.dp))
                    Text(stringResource(R.string.settings_verifying_integrity), style = MaterialTheme.typography.bodySmall)
                }
            }

            if (downloadState is ModelDownloader.DownloadState.Error) {
                Spacer(Modifier.height(8.dp))
                Text(
                    downloadState.message,
                    style = MaterialTheme.typography.bodySmall,
                    color = MaterialTheme.colorScheme.error
                )
            }

            // Action buttons
            Spacer(Modifier.height(12.dp))
            Row(horizontalArrangement = Arrangement.spacedBy(8.dp)) {
                when (downloadState) {
                    is ModelDownloader.DownloadState.Idle -> {
                        Button(onClick = onDownload) {
                            Icon(Icons.Default.Download, contentDescription = stringResource(R.string.content_desc_download), modifier = Modifier.size(18.dp))
                            Spacer(Modifier.width(4.dp))
                            Text(stringResource(R.string.settings_download_model_size_format, selectedTierSizeMb))
                        }
                    }
                    is ModelDownloader.DownloadState.Downloading -> {
                        OutlinedButton(onClick = onCancel) {
                            Text(stringResource(R.string.cancel))
                        }
                    }
                    is ModelDownloader.DownloadState.Paused -> {
                        Button(onClick = onRetry) {
                            Text(stringResource(R.string.settings_resume))
                        }
                        OutlinedButton(onClick = onDelete) {
                            Text(stringResource(R.string.settings_remove))
                        }
                    }
                    is ModelDownloader.DownloadState.Error -> {
                        Button(onClick = onRetry) {
                            Text(stringResource(R.string.sync_retry))
                        }
                        OutlinedButton(onClick = onDelete) {
                            Text(stringResource(R.string.settings_remove))
                        }
                    }
                    is ModelDownloader.DownloadState.Complete -> {
                        FilledTonalButton(onClick = onLoadModel) {
                            Icon(Icons.Default.Check, contentDescription = stringResource(R.string.content_desc_confirm), modifier = Modifier.size(18.dp))
                            Spacer(Modifier.width(4.dp))
                            Text(stringResource(R.string.settings_ready))
                        }
                        OutlinedButton(onClick = onDelete) {
                            Text(stringResource(R.string.delete))
                        }
                    }
                    is ModelDownloader.DownloadState.Verifying -> {
                        // No buttons during verification
                    }
                }
            }
        }
    }
}

@Composable
private fun ModelStatusIcon(state: ModelDownloader.DownloadState) {
    when (state) {
        is ModelDownloader.DownloadState.Idle ->
            Icon(Icons.Default.CloudDownload, contentDescription = stringResource(R.string.content_desc_not_downloaded),
                tint = MaterialTheme.colorScheme.onSurfaceVariant)
        is ModelDownloader.DownloadState.Downloading ->
            CircularProgressIndicator(modifier = Modifier.size(24.dp))
        is ModelDownloader.DownloadState.Verifying ->
            CircularProgressIndicator(modifier = Modifier.size(24.dp))
        is ModelDownloader.DownloadState.Complete ->
            Icon(Icons.Default.CheckCircle, contentDescription = stringResource(R.string.content_desc_ready),
                tint = MaterialTheme.colorScheme.primary)
        is ModelDownloader.DownloadState.Error ->
            Icon(Icons.Default.Error, contentDescription = stringResource(R.string.content_desc_error),
                tint = MaterialTheme.colorScheme.error)
        is ModelDownloader.DownloadState.Paused ->
            Icon(Icons.Default.Pause, contentDescription = stringResource(R.string.content_desc_paused),
                tint = MaterialTheme.colorScheme.tertiary)
    }
}

private fun formatBytes(bytes: Long): String = when {
    bytes < 1024 -> "$bytes B"
    bytes < 1024 * 1024 -> "${bytes / 1024} KB"
    else -> "%.1f MB".format(bytes / (1024.0 * 1024.0))
}

// ── Reusable setting components ──

@Composable
private fun SettingsSection(title: String, content: @Composable ColumnScope.() -> Unit) {
    Column(modifier = Modifier.padding(horizontal = 16.dp, vertical = 6.dp)) {
        Text(
            title,
            style = MaterialTheme.typography.labelLarge,
            color = MaterialTheme.colorScheme.primary,
            modifier = Modifier.padding(bottom = 8.dp)
        )
        OutlinedCard(
            modifier = Modifier.fillMaxWidth(),
            shape = RoundedCornerShape(12.dp)
        ) {
            Column(modifier = Modifier.padding(vertical = 4.dp)) {
                content()
            }
        }
    }
}

@Composable
private fun SettingsSwitch(
    title: String,
    subtitle: String,
    checked: Boolean,
    onCheckedChange: (Boolean) -> Unit
) {
    ListItem(
        headlineContent = { Text(title) },
        supportingContent = { Text(subtitle) },
        trailingContent = {
            Switch(checked = checked, onCheckedChange = onCheckedChange)
        }
    )
}

@Composable
private fun SettingsSlider(
    title: String,
    subtitle: String,
    value: Float,
    range: ClosedFloatingPointRange<Float>,
    steps: Int,
    onValueChange: (Float) -> Unit
) {
    Column(modifier = Modifier.padding(horizontal = 16.dp, vertical = 8.dp)) {
        Row(
            modifier = Modifier.fillMaxWidth(),
            horizontalArrangement = Arrangement.SpaceBetween
        ) {
            Text(title, style = MaterialTheme.typography.bodyLarge)
            Text(subtitle, style = MaterialTheme.typography.bodyMedium,
                color = MaterialTheme.colorScheme.onSurfaceVariant)
        }
        Slider(
            value = value,
            onValueChange = onValueChange,
            valueRange = range,
            steps = steps
        )
    }
}

@OptIn(ExperimentalMaterial3Api::class)
@Composable
private fun SettingsDropdown(
    title: String,
    subtitle: String,
    value: String,
    options: List<Pair<String, String>>,
    onValueChange: (String) -> Unit
) {
    var expanded by remember { mutableStateOf(false) }
    val selectedLabel = options.find { it.first == value }?.second ?: value

    ExposedDropdownMenuBox(
        expanded = expanded,
        onExpandedChange = { expanded = it }
    ) {
        ListItem(
            headlineContent = { Text(title) },
            supportingContent = { Text(subtitle) },
            trailingContent = { Text(selectedLabel, color = MaterialTheme.colorScheme.primary) },
            modifier = Modifier.menuAnchor(MenuAnchorType.PrimaryNotEditable)
        )
        ExposedDropdownMenu(expanded = expanded, onDismissRequest = { expanded = false }) {
            options.forEach { (code, label) ->
                DropdownMenuItem(
                    text = { Text(label) },
                    onClick = {
                        onValueChange(code)
                        expanded = false
                    }
                )
            }
        }
    }
}

@Composable
private fun MarketCard(
    flag: String,
    country: String,
    status: String,
    statusColor: Color,
    bgColor: Color,
    subtitle: String,
    onSwitch: (() -> Unit)? = null,
    content: @Composable ColumnScope.() -> Unit
) {
    var expanded by remember { mutableStateOf(false) }
    Card(
        modifier = Modifier
            .fillMaxWidth()
            .padding(horizontal = 16.dp, vertical = 4.dp),
        colors = CardDefaults.cardColors(containerColor = bgColor),
        onClick = { expanded = !expanded }
    ) {
        Column(modifier = Modifier.padding(16.dp).animateContentSize()) {
            Row(verticalAlignment = Alignment.CenterVertically) {
                Box(
                    modifier = Modifier
                        .size(40.dp)
                        .clip(RoundedCornerShape(8.dp))
                        .background(statusColor.copy(alpha = 0.15f)),
                    contentAlignment = Alignment.Center
                ) {
                    Text(flag, style = MaterialTheme.typography.titleLarge)
                }
                Spacer(Modifier.width(12.dp))
                Column(modifier = Modifier.weight(1f)) {
                    Text(country, style = MaterialTheme.typography.titleSmall,
                        fontWeight = FontWeight.Bold)
                    Text(subtitle, style = MaterialTheme.typography.bodySmall,
                        color = Neutral600, maxLines = if (expanded) 3 else 1)
                }
                if (onSwitch != null) {
                    FilledTonalButton(
                        onClick = onSwitch,
                        modifier = Modifier.defaultMinSize(minHeight = 40.dp),
                        contentPadding = PaddingValues(horizontal = 16.dp, vertical = 6.dp)
                    ) {
                        Text(stringResource(R.string.settings_switch_button), style = MaterialTheme.typography.labelSmall,
                            fontWeight = FontWeight.Bold)
                    }
                } else if (status == "ACTIVE") {
                    Icon(Icons.Default.CheckCircle, contentDescription = stringResource(R.string.content_desc_active),
                        tint = BrandGreen, modifier = Modifier.size(24.dp))
                } else {
                    Surface(
                        color = statusColor.copy(alpha = 0.15f),
                        shape = RoundedCornerShape(12.dp)
                    ) {
                        Text(status, modifier = Modifier.padding(horizontal = 8.dp, vertical = 2.dp),
                            style = MaterialTheme.typography.labelSmall,
                            fontWeight = FontWeight.Bold, color = statusColor)
                    }
                }
            }
            if (expanded) {
                Spacer(Modifier.height(12.dp))
                content()
            }
        }
    }
}

@Composable
private fun CompactMarketCard(
    flag: String,
    country: String,
    status: String,
    statusColor: Color,
    modifier: Modifier = Modifier
) {
    Card(
        modifier = modifier,
        colors = CardDefaults.cardColors(containerColor = Neutral100)
    ) {
        Column(
            modifier = Modifier.padding(12.dp),
            horizontalAlignment = Alignment.CenterHorizontally
        ) {
            Text(flag, style = MaterialTheme.typography.titleLarge)
            Text(country, style = MaterialTheme.typography.labelMedium,
                fontWeight = FontWeight.Medium)
            Text(status, style = MaterialTheme.typography.labelSmall,
                color = statusColor, fontWeight = FontWeight.SemiBold)
        }
    }
}

@Composable
private fun MarketFeatureRow(feature: String, detail: String) {
    Row(
        modifier = Modifier.fillMaxWidth().padding(vertical = 3.dp),
        verticalAlignment = Alignment.CenterVertically
    ) {
        Icon(Icons.Default.CheckCircle, contentDescription = null,
            tint = BrandGreen, modifier = Modifier.size(14.dp))
        Spacer(Modifier.width(8.dp))
        Text(feature, style = MaterialTheme.typography.bodySmall,
            fontWeight = FontWeight.Medium, modifier = Modifier.weight(1f))
        Text(detail, style = MaterialTheme.typography.labelSmall,
            color = Neutral500)
    }
}
