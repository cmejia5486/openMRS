package com.chartlite.app.ui.screens

import androidx.activity.compose.rememberLauncherForActivityResult
import androidx.activity.result.contract.ActivityResultContracts
import androidx.compose.foundation.clickable
import androidx.compose.foundation.layout.*
import androidx.compose.foundation.rememberScrollState
import androidx.compose.foundation.shape.RoundedCornerShape
import androidx.compose.foundation.verticalScroll
import androidx.compose.animation.AnimatedVisibility
import androidx.compose.animation.expandVertically
import androidx.compose.animation.shrinkVertically
import androidx.compose.material.icons.Icons
import androidx.compose.material.icons.filled.CheckCircle
import androidx.compose.material.icons.filled.Error
import androidx.compose.material.icons.filled.ExpandMore
import androidx.compose.material.icons.filled.ExpandLess
import androidx.compose.material.icons.filled.Lock
import androidx.compose.material.icons.filled.WifiOff
import androidx.compose.material3.*
import androidx.compose.runtime.*
import androidx.compose.runtime.saveable.rememberSaveable
import androidx.compose.ui.Alignment
import androidx.compose.ui.Modifier
import androidx.compose.ui.graphics.Color
import androidx.compose.ui.platform.LocalContext
import androidx.compose.ui.text.font.FontWeight
import androidx.compose.ui.text.input.KeyboardType
import androidx.compose.ui.text.input.PasswordVisualTransformation
import androidx.compose.ui.text.style.TextAlign
import androidx.compose.ui.res.stringResource
import androidx.compose.ui.unit.dp
import androidx.compose.foundation.text.KeyboardOptions
import androidx.room.withTransaction
import com.chartlite.app.App
import com.chartlite.app.R
import com.chartlite.app.asr.ModelDownloader
import com.chartlite.app.auth.AuthResult
import com.chartlite.app.auth.PinHasher
import com.chartlite.app.auth.UserRole
import com.chartlite.app.database.entity.FacilityEntity
import com.chartlite.app.database.entity.ProviderEntity
import com.chartlite.app.database.entity.UserEntity
import com.chartlite.app.extraction.LlmModelManager
import com.chartlite.app.extraction.ModelDownloadService
import com.chartlite.app.ui.theme.WarningAmber
import com.chartlite.app.ui.theme.WarningAmberSurface
import com.journeyapps.barcodescanner.ScanContract
import com.journeyapps.barcodescanner.ScanOptions
import kotlinx.coroutines.CancellationException
import kotlinx.coroutines.Dispatchers
import kotlinx.coroutines.flow.first
import kotlinx.coroutines.launch
import kotlinx.coroutines.withContext
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
                    Surface(
                        color = MaterialTheme.colorScheme.primaryContainer,
                        shape = RoundedCornerShape(4.dp)
                    ) {
                        Text(
                            "Recommended",
                            style = MaterialTheme.typography.labelSmall,
                            color = MaterialTheme.colorScheme.onPrimaryContainer,
                            modifier = Modifier.padding(horizontal = 6.dp, vertical = 2.dp)
                        )
                    }
                }
            }
            Text(description, style = MaterialTheme.typography.bodySmall, color = MaterialTheme.colorScheme.outline)
        }
    }
}

private enum class FacilitySetupMode {
    CREATE_NEW,
    JOIN_EXISTING
}

@Composable
fun SetupScreen(onSetupComplete: () -> Unit) {
    val context = LocalContext.current
    val app = context.applicationContext as App
    val scope = rememberCoroutineScope()

    var step by rememberSaveable { mutableIntStateOf(0) }
    var country by rememberSaveable { mutableStateOf("za") }
    var providerName by rememberSaveable { mutableStateOf("") }
    var qualification by rememberSaveable { mutableStateOf("") }
    var facilityName by rememberSaveable { mutableStateOf("") }
    var facilityLocation by rememberSaveable { mutableStateOf("") }
    var facilityMode by rememberSaveable { mutableStateOf(FacilitySetupMode.CREATE_NEW.name) }
    var existingFacilityId by rememberSaveable { mutableStateOf("") }
    var facilityScanError by rememberSaveable { mutableStateOf<String?>(null) }
    var scannedInviteFacilityId by rememberSaveable { mutableStateOf("") }
    var invitedRoleName by rememberSaveable { mutableStateOf("") }
    var inviteExpiresAtMs by rememberSaveable { mutableLongStateOf(0L) }
    var inviteHmacTag by rememberSaveable { mutableStateOf("") }
    var inviteIsV2 by rememberSaveable { mutableStateOf(false) }
    var inviteConfirmCodeInput by rememberSaveable { mutableStateOf("") }
    var adminUsername by rememberSaveable { mutableStateOf("") }
    var adminPin by rememberSaveable { mutableStateOf("") }
    var adminPinConfirm by rememberSaveable { mutableStateOf("") }
    var completeSetupError by rememberSaveable { mutableStateOf<String?>(null) }
    // isSaving must NOT survive config changes — could get stuck as true
    var isSaving by remember { mutableStateOf(false) }

    // AI Setup state (Step 5)
    var asrMode by rememberSaveable { mutableStateOf(app.appConfig.asrMode) }
    var aiMode by rememberSaveable { mutableStateOf(app.appConfig.aiMode) }
    var claudeApiKey by remember { mutableStateOf(app.appConfig.claudeApiKey) }
    var geminiApiKey by remember { mutableStateOf(app.appConfig.geminiApiKey) }
    var openaiApiKey by remember { mutableStateOf(app.appConfig.openaiApiKey) }
    var deepgramApiKey by remember { mutableStateOf(app.appConfig.deepgramApiKey) }
    var chartliteEnrollmentCode by remember { mutableStateOf(app.appConfig.chartliteEnrollmentCode) }
    var noteProcessingMode by rememberSaveable { mutableStateOf(app.appConfig.noteProcessingMode) }
    var recordingModeDefault by rememberSaveable { mutableStateOf(app.appConfig.recordingModeDefault) }
    var asrImportStatus by remember { mutableStateOf<String?>(null) }
    var llmImportStatus by remember { mutableStateOf<String?>(null) }
    var enrollmentVerifying by remember { mutableStateOf(false) }
    var enrollmentSuccess by remember { mutableStateOf<Boolean?>(null) }
    var enrollmentError by remember { mutableStateOf<String?>(null) }
    val scanLauncher = rememberLauncherForActivityResult(ScanContract()) { result ->
        val scanned = result.contents
        if (scanned == null) {
            // User cancelled scanner — if on welcome, just stay there
            if (step == 0) facilityMode = FacilitySetupMode.CREATE_NEW.name
            return@rememberLauncherForActivityResult
        }
        val parsedInvite = parseFacilityInviteFromQr(scanned)
        if (parsedInvite != null) {
            val now = System.currentTimeMillis()
            if (parsedInvite.expiresAtMs != null && parsedInvite.expiresAtMs <= now) {
                facilityScanError = "Invitation QR expired. Ask admin to generate a new one."
                if (step == 0) step = 1 // Advance so user can see the error
                return@rememberLauncherForActivityResult
            }
            facilityMode = FacilitySetupMode.JOIN_EXISTING.name
            scannedInviteFacilityId = parsedInvite.facilityId
            existingFacilityId = parsedInvite.facilityId
            parsedInvite.roleName?.let { invitedRoleName = it }
            inviteExpiresAtMs = parsedInvite.expiresAtMs ?: 0L
            inviteHmacTag = parsedInvite.hmacTag ?: ""
            inviteIsV2 = parsedInvite.isV2
            inviteConfirmCodeInput = ""
            facilityScanError = when {
                parseUserRole(invitedRoleName) == null ->
                    "Facility detected. Ask admin for an invitation QR that includes your role."
                !parsedInvite.isV2 && parsedInvite.roleName != null ->
                    "Unsigned invite (old format). Ask admin to regenerate for better security."
                else -> null
            }
            if (step == 0) step = 1
        } else {
            facilityScanError = "QR does not contain a valid facility ID."
            if (step == 0) step = 1 // Advance so user can see the error
        }
    }

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
                        expectedSha256 = app.appConfig.modelExpectedSha256
                    )
                    tmpModel.delete()
                    when {
                        !imported -> "ASR model import failed."
                        app.asr.modelDownloader.isReady() -> "ASR model and vocabulary are ready."
                        else -> "ASR model imported. Import tokens.txt to enable offline recognition."
                    }
                }
            } catch (e: Exception) {
                "Model import failed: ${e.message}"
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
                    expectedSha256 = app.appConfig.vocabExpectedSha256
                )
                tmpVocab.delete()
                when {
                    !imported -> "Vocabulary import failed."
                    app.asr.modelDownloader.isReady() -> "ASR model and vocabulary are ready."
                    else -> "Vocabulary imported. Import ONNX model file to complete setup."
                }
            } catch (e: Exception) {
                "Vocabulary import failed: ${e.message}"
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

                val childrenUri = android.provider.DocumentsContract.buildChildDocumentsUriUsingTree(
                    treeUri, android.provider.DocumentsContract.getTreeDocumentId(treeUri)
                )
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
                    "Missing files: ${missingFiles.joinToString(", ")}. " +
                        "The folder must contain: ${requiredFiles.joinToString(", ")}"
                } else {
                    val imported = app.asr.modelDownloader.importModelDirectory(tmpDir)
                    tmpDir.deleteRecursively()
                    when {
                        !imported -> "Model directory import failed. Check SHA-256 hashes."
                        app.asr.modelDownloader.isReady() -> "All model files and vocabulary imported and verified."
                        else -> "Model files imported. Some verification may still be needed."
                    }
                }
            } catch (e: Exception) {
                "Directory import failed: ${e.message}"
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
                "LLM model import failed: ${e.message}"
            }
            withContext(Dispatchers.Main) {
                llmImportStatus = message
            }
        }
    }

    Scaffold { padding ->
        Column(
            modifier = Modifier
                .fillMaxSize()
                .padding(padding)
                .imePadding()
                .verticalScroll(rememberScrollState())
                .padding(24.dp),
            verticalArrangement = Arrangement.Top,
            horizontalAlignment = Alignment.CenterHorizontally
        ) {
            // Step indicator
            if (step > 0) {
                val stepNames = listOf("Welcome", "Country", "Provider", "Facility", "PIN", "AI Setup")
                val totalSteps = stepNames.size - 1  // Welcome is step 0, progress is 1..5
                val stepName = stepNames.getOrElse(step) { "" }
                Column(
                    modifier = Modifier
                        .fillMaxWidth()
                        .padding(bottom = 24.dp),
                    horizontalAlignment = Alignment.CenterHorizontally
                ) {
                    LinearProgressIndicator(
                        progress = { step.toFloat() / totalSteps.toFloat() },
                        modifier = Modifier
                            .fillMaxWidth()
                            .height(6.dp),
                        trackColor = MaterialTheme.colorScheme.outlineVariant,
                    )
                    Spacer(Modifier.height(8.dp))
                    Text(
                        "Step $step of $totalSteps \u2014 $stepName",
                        style = MaterialTheme.typography.labelMedium,
                        color = MaterialTheme.colorScheme.onSurfaceVariant
                    )
                }
            }

            when (step) {
                0 -> {
                    Text(stringResource(R.string.setup_welcome),
                        style = MaterialTheme.typography.headlineLarge,
                        textAlign = TextAlign.Center)
                    Spacer(Modifier.height(16.dp))
                    Text(stringResource(R.string.setup_welcome_subtitle),
                        style = MaterialTheme.typography.bodyLarge,
                        textAlign = TextAlign.Center)
                    Spacer(Modifier.height(32.dp))
                    Button(
                        onClick = {
                            facilityMode = FacilitySetupMode.CREATE_NEW.name
                            step = 1
                        },
                        modifier = Modifier.fillMaxWidth()
                    ) {
                        Text(stringResource(R.string.setup_create_new_facility))
                    }
                    Spacer(Modifier.height(12.dp))
                    OutlinedButton(
                        onClick = {
                            facilityMode = FacilitySetupMode.JOIN_EXISTING.name
                            scanLauncher.launch(
                                ScanOptions().apply {
                                    setDesiredBarcodeFormats(ScanOptions.QR_CODE)
                                    setPrompt("Scan the invitation QR from the admin's phone")
                                    setBeepEnabled(false)
                                    setOrientationLocked(false)
                                }
                            )
                        },
                        modifier = Modifier.fillMaxWidth()
                    ) {
                        Text(stringResource(R.string.setup_join_existing_facility))
                    }
                }

                1 -> {
                    Text(stringResource(R.string.setup_select_country), style = MaterialTheme.typography.headlineMedium)
                    Spacer(Modifier.height(16.dp))

                    val countries = listOf(
                        Triple("za", "\uD83C\uDDFF\uD83C\uDDE6", "South Africa"),
                        Triple("us", "\uD83C\uDDFA\uD83C\uDDF8", "United States"),
                        Triple("et", "\uD83C\uDDEA\uD83C\uDDF9", "Ethiopia"),
                        Triple("mw", "\uD83C\uDDF2\uD83C\uDDFC", "Malawi")
                    )
                    countries.forEach { (code, flag, name) ->
                        val isSelected = country == code
                        ElevatedCard(
                            onClick = { country = code },
                            modifier = Modifier
                                .fillMaxWidth()
                                .padding(vertical = 4.dp),
                            colors = if (isSelected) CardDefaults.elevatedCardColors(
                                containerColor = MaterialTheme.colorScheme.primaryContainer
                            ) else CardDefaults.elevatedCardColors(),
                            elevation = if (isSelected) CardDefaults.elevatedCardElevation(
                                defaultElevation = 4.dp
                            ) else CardDefaults.elevatedCardElevation()
                        ) {
                            Row(
                                modifier = Modifier
                                    .fillMaxWidth()
                                    .padding(horizontal = 16.dp, vertical = 14.dp),
                                verticalAlignment = Alignment.CenterVertically
                            ) {
                                Text(flag, style = MaterialTheme.typography.headlineMedium)
                                Spacer(Modifier.width(12.dp))
                                Text(
                                    name,
                                    style = MaterialTheme.typography.titleMedium,
                                    fontWeight = if (isSelected) FontWeight.Bold else FontWeight.Normal,
                                    color = if (isSelected) MaterialTheme.colorScheme.onPrimaryContainer
                                    else MaterialTheme.colorScheme.onSurface
                                )
                            }
                        }
                    }

                    Spacer(Modifier.height(16.dp))
                    Button(onClick = { step = 2 }, modifier = Modifier.fillMaxWidth()) {
                        Text(stringResource(R.string.next))
                    }
                }

                2 -> {
                    Text(stringResource(R.string.setup_provider_details), style = MaterialTheme.typography.headlineMedium)
                    Spacer(Modifier.height(16.dp))

                    Card(
                        modifier = Modifier.fillMaxWidth(),
                        colors = CardDefaults.cardColors(
                            containerColor = MaterialTheme.colorScheme.surfaceVariant.copy(alpha = 0.4f)
                        )
                    ) {
                        Column(modifier = Modifier.padding(16.dp)) {
                            Text(
                                "Personal Information",
                                style = MaterialTheme.typography.titleSmall,
                                color = MaterialTheme.colorScheme.onSurfaceVariant
                            )
                            Spacer(Modifier.height(12.dp))
                            OutlinedTextField(
                                value = providerName,
                                onValueChange = { providerName = it },
                                label = { Text(stringResource(R.string.setup_full_name)) },
                                modifier = Modifier.fillMaxWidth(),
                                singleLine = true
                            )
                            Spacer(Modifier.height(12.dp))
                            OutlinedTextField(
                                value = qualification,
                                onValueChange = { qualification = it },
                                label = { Text(stringResource(R.string.setup_qualification)) },
                                modifier = Modifier.fillMaxWidth(),
                                singleLine = true
                            )
                        }
                    }

                    Spacer(Modifier.height(16.dp))
                    Button(
                        onClick = { step = 3 },
                        enabled = providerName.isNotBlank() && qualification.isNotBlank(),
                        modifier = Modifier.fillMaxWidth()
                    ) {
                        Text(stringResource(R.string.next))
                    }
                }

                3 -> {
                    Text(stringResource(R.string.setup_facility_details), style = MaterialTheme.typography.headlineMedium)
                    Spacer(Modifier.height(16.dp))

                    val selectedMode = FacilitySetupMode.valueOf(facilityMode)

                    Card(
                        modifier = Modifier.fillMaxWidth(),
                        colors = CardDefaults.cardColors(
                            containerColor = MaterialTheme.colorScheme.surfaceVariant.copy(alpha = 0.4f)
                        )
                    ) {
                        Column(modifier = Modifier.padding(16.dp)) {
                            Text(
                                "Setup Mode",
                                style = MaterialTheme.typography.titleSmall,
                                color = MaterialTheme.colorScheme.onSurfaceVariant
                            )
                            Spacer(Modifier.height(12.dp))
                            Row(
                                modifier = Modifier.fillMaxWidth(),
                                verticalAlignment = Alignment.CenterVertically
                            ) {
                                RadioButton(
                                    selected = selectedMode == FacilitySetupMode.CREATE_NEW,
                                    onClick = { facilityMode = FacilitySetupMode.CREATE_NEW.name }
                                )
                                Text(stringResource(R.string.setup_create_new), modifier = Modifier.weight(1f))
                            }
                            Row(
                                modifier = Modifier.fillMaxWidth(),
                                verticalAlignment = Alignment.CenterVertically
                            ) {
                                RadioButton(
                                    selected = selectedMode == FacilitySetupMode.JOIN_EXISTING,
                                    onClick = { facilityMode = FacilitySetupMode.JOIN_EXISTING.name }
                                )
                                Text(stringResource(R.string.setup_join_existing), modifier = Modifier.weight(1f))
                            }
                        }
                    }

                    Spacer(Modifier.height(16.dp))

                    if (selectedMode == FacilitySetupMode.CREATE_NEW) {
                        Card(
                            modifier = Modifier.fillMaxWidth(),
                            colors = CardDefaults.cardColors(
                                containerColor = MaterialTheme.colorScheme.surfaceVariant.copy(alpha = 0.4f)
                            )
                        ) {
                            Column(modifier = Modifier.padding(16.dp)) {
                                Text(
                                    "Facility Information",
                                    style = MaterialTheme.typography.titleSmall,
                                    color = MaterialTheme.colorScheme.onSurfaceVariant
                                )
                                Spacer(Modifier.height(12.dp))
                                OutlinedTextField(
                                    value = facilityName,
                                    onValueChange = { facilityName = it },
                                    label = { Text(stringResource(R.string.setup_facility_name)) },
                                    modifier = Modifier.fillMaxWidth(),
                                    singleLine = true
                                )
                                Spacer(Modifier.height(12.dp))
                                OutlinedTextField(
                                    value = facilityLocation,
                                    onValueChange = { facilityLocation = it },
                                    label = { Text(stringResource(R.string.setup_location_address)) },
                                    modifier = Modifier.fillMaxWidth(),
                                    singleLine = true
                                )
                            }
                        }
                    } else {
                        Text(
                            stringResource(R.string.setup_join_instruction),
                            style = MaterialTheme.typography.bodySmall,
                            color = MaterialTheme.colorScheme.onSurfaceVariant
                        )
                        Spacer(Modifier.height(8.dp))
                        OutlinedTextField(
                            value = existingFacilityId,
                            onValueChange = {
                                if (scannedInviteFacilityId.isBlank()) {
                                    existingFacilityId = it.uppercase().filter { c ->
                                        c.isLetterOrDigit() || c == '-' || c == '_'
                                    }
                                    facilityScanError = null
                                }
                            },
                            label = { Text(stringResource(R.string.setup_existing_facility_id)) },
                            supportingText = {
                                Text(
                                    if (scannedInviteFacilityId.isBlank()) {
                                        "Scan an invitation QR from admin."
                                    } else {
                                        "Locked to scanned invitation."
                                    }
                                )
                            },
                            modifier = Modifier.fillMaxWidth(),
                            singleLine = true,
                            readOnly = scannedInviteFacilityId.isNotBlank()
                        )
                        Spacer(Modifier.height(8.dp))
                        OutlinedButton(
                            onClick = {
                                scanLauncher.launch(
                                    ScanOptions().apply {
                                        setDesiredBarcodeFormats(ScanOptions.QR_CODE)
                                        setPrompt("Scan invitation QR from the admin's phone")
                                        setBeepEnabled(false)
                                        setOrientationLocked(false)
                                    }
                                )
                            },
                            modifier = Modifier.fillMaxWidth()
                        ) {
                            Text(stringResource(R.string.setup_scan_invitation_qr))
                        }
                        facilityScanError?.let { err ->
                            Spacer(Modifier.height(6.dp))
                            Text(
                                err,
                                style = MaterialTheme.typography.bodySmall,
                                color = MaterialTheme.colorScheme.error
                            )
                        }
                        Spacer(Modifier.height(8.dp))
                        val invitedRole = parseUserRole(invitedRoleName)
                        if (invitedRole != null) {
                            Text(
                                "Invited role: ${invitedRole.displayName}",
                                style = MaterialTheme.typography.bodySmall,
                                color = MaterialTheme.colorScheme.primary
                            )
                            if (inviteExpiresAtMs > 0L) {
                                val minutesLeft =
                                    ((inviteExpiresAtMs - System.currentTimeMillis()) / (60 * 1000))
                                        .coerceAtLeast(0L)
                                val expiryText = when {
                                    minutesLeft < 1 -> "Invite expiring now"
                                    minutesLeft < 60 -> "Invite expires in $minutesLeft minutes"
                                    minutesLeft < 1440 -> "Invite expires in ${minutesLeft / 60} hours"
                                    else -> "Invite expires in ${minutesLeft / 1440} days"
                                }
                                Text(
                                    expiryText,
                                    style = MaterialTheme.typography.bodySmall,
                                    color = if (minutesLeft < 30) MaterialTheme.colorScheme.error
                                           else MaterialTheme.colorScheme.onSurfaceVariant
                                )
                            }
                        } else {
                            Text(
                                "No role found yet. Scan the invitation QR from an admin to continue.",
                                style = MaterialTheme.typography.bodySmall,
                                color = MaterialTheme.colorScheme.error
                            )
                        }
                        // V2 signed invites require a 4-digit verbal confirmation code
                        if (inviteIsV2 && inviteHmacTag.isNotBlank()) {
                            Spacer(Modifier.height(12.dp))
                            OutlinedTextField(
                                value = inviteConfirmCodeInput,
                                onValueChange = { if (it.length <= 4) inviteConfirmCodeInput = it.filter { c -> c.isDigit() } },
                                label = { Text("Confirmation code from admin") },
                                placeholder = { Text("4-digit code") },
                                keyboardOptions = KeyboardOptions(keyboardType = KeyboardType.Number),
                                singleLine = true,
                                modifier = Modifier.fillMaxWidth(),
                                isError = inviteConfirmCodeInput.length == 4 &&
                                    com.chartlite.app.auth.InviteHmac.deriveConfirmCode(inviteHmacTag) != inviteConfirmCodeInput,
                                supportingText = if (inviteConfirmCodeInput.length == 4 &&
                                    com.chartlite.app.auth.InviteHmac.deriveConfirmCode(inviteHmacTag) != inviteConfirmCodeInput
                                ) {
                                    { Text("Code does not match. Check with the admin.") }
                                } else null
                            )
                        }
                        Spacer(Modifier.height(12.dp))
                        OutlinedTextField(
                            value = facilityName,
                            onValueChange = { facilityName = it },
                            label = { Text(stringResource(R.string.setup_facility_name_optional)) },
                            modifier = Modifier.fillMaxWidth(),
                            singleLine = true
                        )
                    }

                    Spacer(Modifier.height(16.dp))
                    Button(
                        onClick = { step = 4 },
                        enabled = when (selectedMode) {
                            FacilitySetupMode.CREATE_NEW -> facilityName.isNotBlank()
                            FacilitySetupMode.JOIN_EXISTING ->
                                scannedInviteFacilityId.isNotBlank() &&
                                    normalizeFacilityId(existingFacilityId) != null &&
                                    normalizeFacilityId(existingFacilityId) ==
                                        normalizeFacilityId(scannedInviteFacilityId) &&
                                    parseUserRole(invitedRoleName) != null &&
                                    (inviteExpiresAtMs == 0L || inviteExpiresAtMs > System.currentTimeMillis()) &&
                                    // V2 invites require valid confirmation code
                                    (!inviteIsV2 || inviteHmacTag.isBlank() ||
                                        (inviteConfirmCodeInput.length == 4 &&
                                            com.chartlite.app.auth.InviteHmac.deriveConfirmCode(inviteHmacTag) == inviteConfirmCodeInput))
                        },
                        modifier = Modifier.fillMaxWidth()
                    ) {
                        Text(stringResource(R.string.next))
                    }
                }

                4 -> {
                    val selectedMode = FacilitySetupMode.valueOf(facilityMode)
                    val invitedRole = parseUserRole(invitedRoleName)

                    // Auto-generate username from provider name (e.g. "Dr. John Smith" -> "dr.john.smith")
                    val autoUsername = remember(providerName) {
                        providerName.trim().lowercase()
                            .replace(Regex("[^a-z0-9\\s.]"), "")
                            .split(Regex("\\s+"))
                            .filter { it.isNotBlank() }
                            .joinToString(".")
                            .ifBlank { "user" }
                    }
                    // Sync to state so it's used at save time
                    LaunchedEffect(autoUsername) { adminUsername = autoUsername }

                    Text(stringResource(R.string.setup_set_your_pin), style = MaterialTheme.typography.headlineMedium)
                    Spacer(Modifier.height(8.dp))
                    Text(
                        stringResource(R.string.setup_pin_instruction),
                        style = MaterialTheme.typography.bodyMedium,
                        textAlign = TextAlign.Center,
                        color = MaterialTheme.colorScheme.onSurfaceVariant
                    )
                    if (selectedMode == FacilitySetupMode.JOIN_EXISTING && invitedRole != null) {
                        Spacer(Modifier.height(4.dp))
                        Text(
                            stringResource(R.string.setup_joining_as, invitedRole.displayName),
                            style = MaterialTheme.typography.labelLarge,
                            color = MaterialTheme.colorScheme.primary
                        )
                    }
                    Spacer(Modifier.height(16.dp))

                    Card(
                        modifier = Modifier.fillMaxWidth(),
                        colors = CardDefaults.cardColors(
                            containerColor = MaterialTheme.colorScheme.surfaceVariant.copy(alpha = 0.4f)
                        )
                    ) {
                        Column(modifier = Modifier.padding(16.dp)) {
                            OutlinedTextField(
                                value = adminPin,
                                onValueChange = {
                                    if (it.length <= 6 && it.all { c -> c.isDigit() }) {
                                        adminPin = it
                                        completeSetupError = null
                                    }
                                },
                                label = { Text(stringResource(R.string.pin_label)) },
                                modifier = Modifier.fillMaxWidth(),
                                singleLine = true,
                                visualTransformation = PasswordVisualTransformation(),
                                keyboardOptions = KeyboardOptions(keyboardType = KeyboardType.NumberPassword)
                            )
                            Spacer(Modifier.height(12.dp))
                            OutlinedTextField(
                                value = adminPinConfirm,
                                onValueChange = {
                                    if (it.length <= 6 && it.all { c -> c.isDigit() }) {
                                        adminPinConfirm = it
                                        completeSetupError = null
                                    }
                                },
                                label = { Text(stringResource(R.string.confirm_pin)) },
                                modifier = Modifier.fillMaxWidth(),
                                singleLine = true,
                                visualTransformation = PasswordVisualTransformation(),
                                keyboardOptions = KeyboardOptions(keyboardType = KeyboardType.NumberPassword),
                                isError = adminPinConfirm.isNotEmpty() && adminPin != adminPinConfirm,
                                supportingText = if (adminPinConfirm.isNotEmpty() && adminPin != adminPinConfirm) {
                                    { Text(stringResource(R.string.pins_dont_match)) }
                                } else null
                            )
                        }
                    }

                    Spacer(Modifier.height(16.dp))
                    val canProceed = adminPin.length >= 4
                        && adminPin == adminPinConfirm
                        && (selectedMode == FacilitySetupMode.CREATE_NEW || invitedRole != null)

                    Button(
                        onClick = { step = 5 },
                        enabled = canProceed,
                        modifier = Modifier.fillMaxWidth()
                    ) {
                        Text(stringResource(R.string.next))
                    }
                }

                5 -> {
                    // ---- Simplified AI Setup Step ----
                    // Auto-select best models for this device
                    val deviceRam = remember { app.asr.modelDownloader.deviceRamGb() }
                    val deviceName = remember { app.asr.modelDownloader.deviceName() }
                    val rankedTiers = remember(app.appConfig.language) {
                        app.asr.modelDownloader.rankTiersForDevice(app.appConfig.language)
                    }
                    val bestAsrTier = remember(rankedTiers) {
                        rankedTiers.firstOrNull { it.isCompatible }?.tier
                            ?: ModelDownloader.ModelTier.MOONSHINE_TINY
                    }
                    val llmRecommended = remember { app.llmModelManager.recommendedTier() }
                    val llmAbiSupported = remember { app.llmModelManager.isSupportedAbi() }

                    // Simple mode choices
                    var voiceOffline by rememberSaveable { mutableStateOf(app.appConfig.asrMode == "onnx") }
                    var notesOffline by rememberSaveable { mutableStateOf(app.appConfig.aiMode == "on_device" && llmAbiSupported) }
                    var showAdvanced by rememberSaveable { mutableStateOf(false) }
                    var cloudAsrProvider by rememberSaveable { mutableStateOf(app.appConfig.cloudAsrProvider) }
                    var cloudNotesModel by rememberSaveable { mutableStateOf(app.appConfig.cloudNotesModel) }
                    // Progressive disclosure: start collapsed so most users just tap Continue
                    var showAllAsrProviders by rememberSaveable { mutableStateOf(false) }
                    var showAllNotesModels by rememberSaveable { mutableStateOf(false) }

                    // Advanced overrides (sync with simple toggles)
                    var selectedAsrTier by rememberSaveable { mutableStateOf(bestAsrTier.name) }
                    var selectedLlmTier by rememberSaveable { mutableStateOf(llmRecommended.name) }
                    val selectedAsrTierObj = remember(selectedAsrTier) {
                        ModelDownloader.ModelTier.entries.find { it.name == selectedAsrTier && it.isDownloadable }
                            ?: bestAsrTier
                    }
                    val selectedLlmTierEntry = remember(selectedLlmTier) {
                        LlmModelManager.ModelTier.entries.firstOrNull { it.name == selectedLlmTier }
                            ?: llmRecommended
                    }

                    // Download states
                    val asrDownloadState by app.asr.modelDownloader.state.collectAsState()
                    val llmModelState by app.llmModelManager.state.collectAsState()
                    val llmInstallInProgress =
                        llmModelState is LlmModelManager.ModelState.Downloading ||
                            llmModelState is LlmModelManager.ModelState.Verifying ||
                            llmModelState is LlmModelManager.ModelState.Installing
                    val asrReady = asrDownloadState is ModelDownloader.DownloadState.Complete ||
                        app.asr.isOnnxModelDownloadedFast()
                    val llmReady = llmModelState is LlmModelManager.ModelState.Ready ||
                        (!llmInstallInProgress && app.llmModelManager.isModelDownloaded())
                    val isDownloading = asrDownloadState is ModelDownloader.DownloadState.Downloading ||
                        asrDownloadState is ModelDownloader.DownloadState.Verifying ||
                        llmInstallInProgress

                    fun notesProvider(model: String): String = when {
                        model.startsWith("claude") -> "claude"
                        model.startsWith("gemini") -> "gemini"
                        model.startsWith("gpt") -> "openai"
                        else -> "claude"
                    }

                    fun missingAsrKeyMessage(provider: String): String? {
                        if (app.appConfig.cloudKeyMode != "byok" || asrMode != "cloud") return null
                        return when (provider) {
                            "gemini" -> if (geminiApiKey.isBlank()) "Requires Gemini API key below" else null
                            "openai" -> if (openaiApiKey.isBlank()) "Requires OpenAI API key below" else null
                            "deepgram" -> if (deepgramApiKey.isBlank()) "Requires Deepgram API key below" else null
                            else -> null
                        }
                    }

                    fun missingNotesKeyMessage(model: String): String? {
                        if (app.appConfig.cloudKeyMode != "byok" || notesOffline) return null
                        return when (notesProvider(model)) {
                            "claude" -> if (claudeApiKey.isBlank()) "Requires Anthropic API key below" else null
                            "gemini" -> if (geminiApiKey.isBlank()) "Requires Gemini API key below" else null
                            "openai" -> if (openaiApiKey.isBlank()) "Requires OpenAI API key below" else null
                            else -> null
                        }
                    }

                    // Ensure ASR tier config is set
                    LaunchedEffect(selectedAsrTierObj) {
                        app.appConfig.modelDownloadUrl = selectedAsrTierObj.modelUrl
                        app.appConfig.vocabDownloadUrl = selectedAsrTierObj.vocabUrl
                        app.appConfig.modelExpectedSha256 = selectedAsrTierObj.modelSha256
                        app.appConfig.vocabExpectedSha256 = selectedAsrTierObj.vocabSha256
                    }

                    // ── Header ──
                    Text(stringResource(R.string.setup_ai_setup), style = MaterialTheme.typography.headlineMedium)
                    Text(
                        "$deviceName · ${"%.1f".format(deviceRam)} GB RAM",
                        style = MaterialTheme.typography.bodySmall,
                        color = MaterialTheme.colorScheme.outline
                    )
                    Spacer(Modifier.height(20.dp))

                    // ── Voice Recognition Card ──
                    @OptIn(ExperimentalMaterial3Api::class)
                    ElevatedCard(modifier = Modifier.fillMaxWidth()) {
                        Column(modifier = Modifier.padding(16.dp)) {
                            Text(stringResource(R.string.setup_speech_recognition), style = MaterialTheme.typography.titleMedium, fontWeight = FontWeight.SemiBold)
                            Spacer(Modifier.height(12.dp))
                            SingleChoiceSegmentedButtonRow(modifier = Modifier.fillMaxWidth()) {
                                SegmentedButton(
                                    selected = voiceOffline,
                                    onClick = {
                                        voiceOffline = true
                                        asrMode = "onnx"
                                    },
                                    shape = SegmentedButtonDefaults.itemShape(index = 0, count = 2)
                                ) { Text(stringResource(R.string.setup_works_offline)) }
                                SegmentedButton(
                                    selected = !voiceOffline,
                                    onClick = {
                                        voiceOffline = false
                                        asrMode = "cloud"
                                    },
                                    shape = SegmentedButtonDefaults.itemShape(index = 1, count = 2)
                                ) { Text(stringResource(R.string.setup_uses_internet)) }
                            }
                            Spacer(Modifier.height(8.dp))
                            Text(
                                when {
                                    voiceOffline -> stringResource(R.string.setup_voice_offline_desc)
                                    asrMode == "google" -> stringResource(R.string.setup_google_speech_desc)
                                    else -> stringResource(R.string.setup_voice_internet_desc)
                                },
                                style = MaterialTheme.typography.bodySmall,
                                color = MaterialTheme.colorScheme.onSurfaceVariant
                            )
                            // Cloud ASR provider picker — shown when Uses Internet is selected
                            if (!voiceOffline && asrMode == "cloud") {
                                Spacer(Modifier.height(8.dp))
                                val asrProviders = listOf(
                                    Triple("gemini", "Gemini 3.1 Flash Lite", "Recommended · Great with African accents"),
                                    Triple("openai", "OpenAI gpt-4o Transcribe", "High accuracy, optimized for English"),
                                    Triple("deepgram", "Deepgram Nova", "Ultra-fast, ideal for real-time use"),
                                )
                                val selectedAsrLabel = asrProviders.first { it.first == cloudAsrProvider }
                                if (!showAllAsrProviders) {
                                    // Collapsed: just show the current selection + expand link
                                    Row(
                                        modifier = Modifier.fillMaxWidth().padding(start = 4.dp),
                                        verticalAlignment = Alignment.CenterVertically,
                                        horizontalArrangement = Arrangement.SpaceBetween
                                    ) {
                                        Row(
                                            modifier = Modifier.weight(1f),
                                            verticalAlignment = Alignment.CenterVertically
                                        ) {
                                            RadioButton(selected = true, onClick = null)
                                            Spacer(Modifier.width(4.dp))
                                            Column {
                                                Row(verticalAlignment = Alignment.CenterVertically, horizontalArrangement = Arrangement.spacedBy(6.dp)) {
                                                    Text(selectedAsrLabel.second, style = MaterialTheme.typography.bodyMedium, fontWeight = FontWeight.SemiBold)
                                                    if (cloudAsrProvider == "gemini") Surface(color = MaterialTheme.colorScheme.primaryContainer, shape = RoundedCornerShape(4.dp)) {
                                                        Text("Recommended", style = MaterialTheme.typography.labelSmall, color = MaterialTheme.colorScheme.onPrimaryContainer, modifier = Modifier.padding(horizontal = 6.dp, vertical = 2.dp))
                                                    }
                                                }
                                                Text(selectedAsrLabel.third, style = MaterialTheme.typography.bodySmall, color = MaterialTheme.colorScheme.outline)
                                            }
                                        }
                                        TextButton(onClick = { showAllAsrProviders = true }) {
                                            Text("Change", style = MaterialTheme.typography.labelMedium)
                                        }
                                    }
                                } else {
                                    Text("Transcription service", style = MaterialTheme.typography.labelSmall,
                                        color = MaterialTheme.colorScheme.outline, modifier = Modifier.padding(start = 8.dp))
                                    Spacer(Modifier.height(4.dp))
                                    asrProviders.forEach { (value, label, desc) ->
                                        ProviderOptionRow(
                                            selected = cloudAsrProvider == value,
                                            label = label,
                                            description = desc,
                                            recommended = value == "gemini",
                                            onClick = {
                                                cloudAsrProvider = value
                                                app.appConfig.cloudAsrProvider = value
                                                showAllAsrProviders = false
                                            }
                                        )
                                    }
                                }
                                missingAsrKeyMessage(cloudAsrProvider)?.let { message ->
                                    Spacer(Modifier.height(4.dp))
                                    Text(message, style = MaterialTheme.typography.bodySmall, color = MaterialTheme.colorScheme.outline, modifier = Modifier.padding(start = 8.dp))
                                }
                            }
                        }
                    }

                    Spacer(Modifier.height(12.dp))

                    // ── Clinical Notes AI Card ──
                    @OptIn(ExperimentalMaterial3Api::class)
                    ElevatedCard(modifier = Modifier.fillMaxWidth()) {
                        Column(modifier = Modifier.padding(16.dp)) {
                            Text(stringResource(R.string.setup_clinical_note_ai), style = MaterialTheme.typography.titleMedium, fontWeight = FontWeight.SemiBold)
                            Spacer(Modifier.height(12.dp))
                            SingleChoiceSegmentedButtonRow(modifier = Modifier.fillMaxWidth()) {
                                SegmentedButton(
                                    selected = notesOffline,
                                    onClick = {
                                        if (llmAbiSupported) {
                                            notesOffline = true
                                            aiMode = "on_device"
                                        }
                                    },
                                    enabled = llmAbiSupported,
                                    shape = SegmentedButtonDefaults.itemShape(index = 0, count = 2)
                                ) { Text(stringResource(R.string.setup_works_offline)) }
                                SegmentedButton(
                                    selected = !notesOffline,
                                    onClick = {
                                        notesOffline = false
                                        aiMode = "auto"
                                    },
                                    shape = SegmentedButtonDefaults.itemShape(index = 1, count = 2)
                                ) { Text(stringResource(R.string.setup_uses_internet)) }
                            }
                            Spacer(Modifier.height(8.dp))
                            if (!llmAbiSupported) {
                                Text(
                                    stringResource(R.string.setup_offline_not_supported),
                                    style = MaterialTheme.typography.bodySmall,
                                    color = MaterialTheme.colorScheme.error
                                )
                            } else {
                                Text(
                                    if (notesOffline) stringResource(R.string.setup_notes_offline_desc)
                                    else stringResource(R.string.setup_notes_internet_desc),
                                    style = MaterialTheme.typography.bodySmall,
                                    color = MaterialTheme.colorScheme.onSurfaceVariant
                                )
                            }
                            // Cloud notes model picker — shown when Uses Internet is selected
                            if (!notesOffline) {
                                Spacer(Modifier.height(8.dp))
                                val notesModels = listOf(
                                    Triple("claude-sonnet-4-6", "Claude Sonnet", "Recommended · Smart, fast clinical notes"),
                                    Triple("claude-opus-4-6", "Claude Opus", "Most thorough clinical documentation"),
                                    Triple("gemini-3.1-flash-lite-preview", "Gemini Flash", "Fast and cost-effective"),
                                    Triple("gpt-5.4", "GPT-5", "OpenAI's latest model"),
                                    Triple("gpt-4.1", "GPT-4.1", "Reliable and efficient"),
                                )
                                val selectedNotesLabel = notesModels.firstOrNull { it.first == cloudNotesModel }
                                    ?: notesModels.first()
                                if (!showAllNotesModels) {
                                    // Collapsed: just show the current selection + expand link
                                    Row(
                                        modifier = Modifier.fillMaxWidth().padding(start = 4.dp),
                                        verticalAlignment = Alignment.CenterVertically,
                                        horizontalArrangement = Arrangement.SpaceBetween
                                    ) {
                                        Row(
                                            modifier = Modifier.weight(1f),
                                            verticalAlignment = Alignment.CenterVertically
                                        ) {
                                            RadioButton(selected = true, onClick = null)
                                            Spacer(Modifier.width(4.dp))
                                            Column {
                                                Row(verticalAlignment = Alignment.CenterVertically, horizontalArrangement = Arrangement.spacedBy(6.dp)) {
                                                    Text(selectedNotesLabel.second, style = MaterialTheme.typography.bodyMedium, fontWeight = FontWeight.SemiBold)
                                                    if (cloudNotesModel == "claude-sonnet-4-6") Surface(color = MaterialTheme.colorScheme.primaryContainer, shape = RoundedCornerShape(4.dp)) {
                                                        Text("Recommended", style = MaterialTheme.typography.labelSmall, color = MaterialTheme.colorScheme.onPrimaryContainer, modifier = Modifier.padding(horizontal = 6.dp, vertical = 2.dp))
                                                    }
                                                }
                                                Text(selectedNotesLabel.third, style = MaterialTheme.typography.bodySmall, color = MaterialTheme.colorScheme.outline)
                                            }
                                        }
                                        TextButton(onClick = { showAllNotesModels = true }) {
                                            Text("Change", style = MaterialTheme.typography.labelMedium)
                                        }
                                    }
                                } else {
                                    Text("Note-writing AI", style = MaterialTheme.typography.labelSmall,
                                        color = MaterialTheme.colorScheme.outline, modifier = Modifier.padding(start = 8.dp))
                                    Spacer(Modifier.height(4.dp))
                                    notesModels.forEach { (value, label, desc) ->
                                        ProviderOptionRow(
                                            selected = cloudNotesModel == value,
                                            label = label,
                                            description = desc,
                                            recommended = value == "claude-sonnet-4-6",
                                            onClick = {
                                                cloudNotesModel = value
                                                app.appConfig.cloudNotesModel = value
                                                showAllNotesModels = false
                                            }
                                        )
                                    }
                                }
                                missingNotesKeyMessage(cloudNotesModel)?.let { message ->
                                    Spacer(Modifier.height(4.dp))
                                    Text(message, style = MaterialTheme.typography.bodySmall, color = MaterialTheme.colorScheme.outline, modifier = Modifier.padding(start = 8.dp))
                                }
                            }
                        }
                    }

                    Spacer(Modifier.height(12.dp))

                    // ── Enrollment Code (shown when using ChartLite cloud proxy) ──
                    val needsEnrollment = app.appConfig.cloudKeyMode == "chartlite" &&
                        (!voiceOffline || !notesOffline)
                    if (needsEnrollment) {
                        @OptIn(ExperimentalMaterial3Api::class)
                        ElevatedCard(modifier = Modifier.fillMaxWidth()) {
                            Column(modifier = Modifier.padding(16.dp)) {
                                Text("ChartLite Cloud Access", style = MaterialTheme.typography.titleSmall, fontWeight = FontWeight.SemiBold)
                                Spacer(Modifier.height(2.dp))
                                Text("Enter your enrollment code to use ChartLite's AI backend", style = MaterialTheme.typography.bodySmall, color = MaterialTheme.colorScheme.outline)
                                Spacer(Modifier.height(12.dp))
                                OutlinedTextField(
                                    value = chartliteEnrollmentCode,
                                    onValueChange = {
                                        chartliteEnrollmentCode = it.trim()
                                        app.appConfig.chartliteEnrollmentCode = it.trim()
                                        enrollmentSuccess = null
                                        enrollmentError = null
                                    },
                                    label = { Text("Enrollment code") },
                                    placeholder = { Text("Enter enrollment code") },
                                    modifier = Modifier.fillMaxWidth(),
                                    singleLine = true,
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
                                        Text("✓ Enrolled successfully", style = MaterialTheme.typography.bodySmall, color = MaterialTheme.colorScheme.primary)
                                    enrollmentError != null ->
                                        Text(enrollmentError!!, style = MaterialTheme.typography.bodySmall, color = MaterialTheme.colorScheme.error)
                                    else ->
                                        Text(stringResource(R.string.setup_enrollment_helper), style = MaterialTheme.typography.bodySmall, color = MaterialTheme.colorScheme.outline)
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
                        Spacer(Modifier.height(12.dp))
                    }

                    // ── Download Card ──
                    val needsAsrDownload = voiceOffline && !asrReady
                    val needsLlmDownload = notesOffline && !llmReady
                    val needsAnyDownload = needsAsrDownload || needsLlmDownload

                    suspend fun downloadRequiredSetupModels() {
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

                        var asrOk = !needsAsrDownload
                        if (needsAsrDownload) {
                            app.asr.modelDownloader.startDownload(
                                modelUrl = selectedAsrTierObj.modelUrl,
                                vocabUrl = selectedAsrTierObj.vocabUrl,
                                expectedSha256 = app.appConfig.modelExpectedSha256,
                                expectedVocabSha256 = app.appConfig.vocabExpectedSha256
                            )
                            val finalState = app.asr.modelDownloader.state.first { state ->
                                state is ModelDownloader.DownloadState.Complete ||
                                    state is ModelDownloader.DownloadState.Error
                            }
                            asrOk = finalState is ModelDownloader.DownloadState.Complete
                        }
                        if (needsLlmDownload && asrOk) {
                            app.llmModelManager.startDownload()
                        }
                    }

                    ElevatedCard(modifier = Modifier.fillMaxWidth()) {
                        Column(modifier = Modifier.padding(16.dp)) {
                            if (!voiceOffline && !notesOffline) {
                                // Both internet — no downloads needed
                                Row(verticalAlignment = Alignment.CenterVertically) {
                                    Icon(
                                        Icons.Default.CheckCircle,
                                        contentDescription = null,
                                        tint = Color(0xFF2E7D32),
                                        modifier = Modifier.size(20.dp)
                                    )
                                    Spacer(Modifier.width(8.dp))
                                    Text(
                                        stringResource(R.string.setup_no_downloads_needed),
                                        style = MaterialTheme.typography.bodyMedium,
                                        color = Color(0xFF2E7D32)
                                    )
                                }
                            } else if (asrReady && (!notesOffline || llmReady)) {
                                // All needed models already downloaded
                                Row(verticalAlignment = Alignment.CenterVertically) {
                                    Icon(
                                        Icons.Default.CheckCircle,
                                        contentDescription = null,
                                        tint = Color(0xFF2E7D32),
                                        modifier = Modifier.size(20.dp)
                                    )
                                    Spacer(Modifier.width(8.dp))
                                    Text(
                                        stringResource(R.string.setup_all_models_ready),
                                        style = MaterialTheme.typography.bodyMedium,
                                        color = Color(0xFF2E7D32)
                                    )
                                }
                            } else {
                                Text(stringResource(R.string.setup_downloads_required), style = MaterialTheme.typography.titleSmall, fontWeight = FontWeight.SemiBold)
                                Spacer(Modifier.height(8.dp))

                                // Download line items
                                if (voiceOffline) {
                                    Row(modifier = Modifier.fillMaxWidth()) {
                                        Text(
                                            stringResource(R.string.setup_voice_model_label),
                                            style = MaterialTheme.typography.bodyMedium,
                                            modifier = Modifier.weight(1f)
                                        )
                                        if (asrReady) {
                                            Icon(Icons.Default.CheckCircle, contentDescription = null, tint = Color(0xFF2E7D32), modifier = Modifier.size(16.dp))
                                        } else {
                                            Text("${selectedAsrTierObj.sizeMb} MB", style = MaterialTheme.typography.bodyMedium, color = MaterialTheme.colorScheme.outline)
                                        }
                                    }
                                }
                                if (notesOffline) {
                                    Spacer(Modifier.height(4.dp))
                                    Row(modifier = Modifier.fillMaxWidth()) {
                                        Text(
                                            stringResource(R.string.setup_notes_model_label),
                                            style = MaterialTheme.typography.bodyMedium,
                                            modifier = Modifier.weight(1f)
                                        )
                                        if (llmReady) {
                                            Icon(Icons.Default.CheckCircle, contentDescription = null, tint = Color(0xFF2E7D32), modifier = Modifier.size(16.dp))
                                        } else {
                                            Text("${selectedLlmTierEntry.sizeMb} MB", style = MaterialTheme.typography.bodyMedium, color = MaterialTheme.colorScheme.outline)
                                        }
                                    }
                                }

                                // Total line
                                if (needsAnyDownload) {
                                    Spacer(Modifier.height(4.dp))
                                    HorizontalDivider()
                                    Spacer(Modifier.height(4.dp))
                                    Row(modifier = Modifier.fillMaxWidth()) {
                                        Text(stringResource(R.string.setup_total_size), style = MaterialTheme.typography.bodyMedium, fontWeight = FontWeight.SemiBold, modifier = Modifier.weight(1f))
                                        val totalMb = (if (needsAsrDownload) selectedAsrTierObj.sizeMb else 0) +
                                            (if (needsLlmDownload) selectedLlmTierEntry.sizeMb else 0)
                                        Text("$totalMb MB", style = MaterialTheme.typography.bodyMedium, fontWeight = FontWeight.SemiBold)
                                    }
                                }

                                Spacer(Modifier.height(12.dp))

                                // Download progress or button
                                if (isDownloading) {
                                    // Show progress for whichever is currently downloading
                                    val isAsrPhase = asrDownloadState is ModelDownloader.DownloadState.Downloading ||
                                        asrDownloadState is ModelDownloader.DownloadState.Verifying
                                    Text(
                                        if (isAsrPhase) stringResource(R.string.setup_downloading_voice)
                                        else stringResource(R.string.setup_downloading_notes_ai),
                                        style = MaterialTheme.typography.bodySmall
                                    )
                                    Spacer(Modifier.height(4.dp))

                                    // Progress bar
                                    if (isAsrPhase && asrDownloadState is ModelDownloader.DownloadState.Downloading) {
                                        val dl = asrDownloadState as ModelDownloader.DownloadState.Downloading
                                        if (dl.totalBytes > 0) {
                                            val progress = dl.bytesDownloaded.toFloat() / dl.totalBytes.toFloat()
                                            Text("${dl.bytesDownloaded / (1024 * 1024)} / ${dl.totalBytes / (1024 * 1024)} MB", style = MaterialTheme.typography.bodySmall, color = MaterialTheme.colorScheme.outline)
                                            LinearProgressIndicator(progress = { progress.coerceIn(0f, 1f) }, modifier = Modifier.fillMaxWidth())
                                        } else {
                                            LinearProgressIndicator(modifier = Modifier.fillMaxWidth())
                                        }
                                    } else if (!isAsrPhase && llmModelState is LlmModelManager.ModelState.Downloading) {
                                        val dl = llmModelState as LlmModelManager.ModelState.Downloading
                                        if (dl.totalBytes > 0) {
                                            val progress = dl.bytesDownloaded.toFloat() / dl.totalBytes.toFloat()
                                            Text("${dl.bytesDownloaded / (1024 * 1024)} / ${dl.totalBytes / (1024 * 1024)} MB", style = MaterialTheme.typography.bodySmall, color = MaterialTheme.colorScheme.outline)
                                            LinearProgressIndicator(progress = { progress.coerceIn(0f, 1f) }, modifier = Modifier.fillMaxWidth())
                                        } else {
                                            LinearProgressIndicator(modifier = Modifier.fillMaxWidth())
                                        }
                                    } else if (!isAsrPhase && llmModelState is LlmModelManager.ModelState.Installing) {
                                        val install = llmModelState as LlmModelManager.ModelState.Installing
                                        Text(stringResource(R.string.setup_installing_model), style = MaterialTheme.typography.bodySmall, color = MaterialTheme.colorScheme.outline)
                                        if (install.totalBytes > 0) {
                                            val progress = install.bytesProcessed.toFloat() / install.totalBytes.toFloat()
                                            Text("${install.bytesProcessed / (1024 * 1024)} / ${install.totalBytes / (1024 * 1024)} MB", style = MaterialTheme.typography.bodySmall, color = MaterialTheme.colorScheme.outline)
                                            LinearProgressIndicator(progress = { progress.coerceIn(0f, 1f) }, modifier = Modifier.fillMaxWidth())
                                        } else {
                                            LinearProgressIndicator(modifier = Modifier.fillMaxWidth())
                                        }
                                    } else {
                                        Text(stringResource(R.string.setup_verifying_download), style = MaterialTheme.typography.bodySmall, color = MaterialTheme.colorScheme.outline)
                                        LinearProgressIndicator(modifier = Modifier.fillMaxWidth())
                                    }

                                    Spacer(Modifier.height(4.dp))
                                    TextButton(onClick = {
                                        app.asr.modelDownloader.cancel()
                                        app.llmModelManager.cancelDownload()
                                    }) {
                                        Text(stringResource(R.string.setup_cancel_download))
                                    }
                                } else if (needsAnyDownload) {
                                    // Check for errors
                                    val hasError = asrDownloadState is ModelDownloader.DownloadState.Error ||
                                        llmModelState is LlmModelManager.ModelState.Error
                                    if (hasError) {
                                        val errorMsg = when {
                                            asrDownloadState is ModelDownloader.DownloadState.Error ->
                                                (asrDownloadState as ModelDownloader.DownloadState.Error).message
                                            llmModelState is LlmModelManager.ModelState.Error ->
                                                (llmModelState as LlmModelManager.ModelState.Error).message
                                            else -> ""
                                        }
                                        Text(errorMsg, style = MaterialTheme.typography.bodySmall, color = MaterialTheme.colorScheme.error)
                                        Spacer(Modifier.height(4.dp))
                                    }

                                    Button(
                                        onClick = {
                                            scope.launch { downloadRequiredSetupModels() }
                                        },
                                        modifier = Modifier.fillMaxWidth()
                                    ) {
                                        Text(stringResource(R.string.setup_download_all))
                                    }
                                }
                            }
                        }
                    }

                    Spacer(Modifier.height(16.dp))

                    // ── Advanced Settings (collapsed) ──
                    Row(
                        modifier = Modifier
                            .fillMaxWidth()
                            .clickable { showAdvanced = !showAdvanced }
                            .padding(vertical = 8.dp),
                        verticalAlignment = Alignment.CenterVertically
                    ) {
                        Text(
                            stringResource(R.string.setup_advanced_settings),
                            style = MaterialTheme.typography.labelLarge,
                            color = MaterialTheme.colorScheme.onSurfaceVariant
                        )
                        Spacer(Modifier.weight(1f))
                        Icon(
                            if (showAdvanced) Icons.Default.ExpandLess else Icons.Default.ExpandMore,
                            contentDescription = null,
                            tint = MaterialTheme.colorScheme.onSurfaceVariant
                        )
                    }

                    AnimatedVisibility(
                        visible = showAdvanced,
                        enter = expandVertically(),
                        exit = shrinkVertically()
                    ) {
                        Column(verticalArrangement = Arrangement.spacedBy(8.dp)) {
                            HorizontalDivider()

                            // ── ASR mode override ──
                            Text(stringResource(R.string.setup_speech_recognition), fontWeight = FontWeight.SemiBold, style = MaterialTheme.typography.titleSmall)
                            listOf(
                                Triple("onnx", stringResource(R.string.setup_on_device), stringResource(R.string.setup_on_device_desc)),
                                Triple("google", "Android Speech (built-in)", stringResource(R.string.setup_google_speech_desc)),
                                Triple("cloud", stringResource(R.string.setup_cloud_asr), stringResource(R.string.setup_cloud_asr_desc))
                            ).forEach { (value, label, description) ->
                                Row(modifier = Modifier.fillMaxWidth(), verticalAlignment = Alignment.CenterVertically) {
                                    RadioButton(selected = asrMode == value, onClick = {
                                        asrMode = value
                                        voiceOffline = value == "onnx"
                                    })
                                    Column(modifier = Modifier.padding(start = 4.dp)) {
                                        Text(label, fontWeight = if (asrMode == value) FontWeight.SemiBold else FontWeight.Normal)
                                        Text(description, style = MaterialTheme.typography.bodySmall, color = MaterialTheme.colorScheme.outline)
                                    }
                                }
                            }

                            // ── ASR tier picker ──
                            if (asrMode == "onnx") {
                                Text(stringResource(R.string.settings_recommended_for_device), style = MaterialTheme.typography.labelMedium, color = MaterialTheme.colorScheme.primary)
                                rankedTiers.forEach { ranked ->
                                    val tier = ranked.tier
                                    val isSelected = tier.name == selectedAsrTier
                                    val isAvailable = tier.isDownloadable && ranked.isCompatible
                                    Row(modifier = Modifier.fillMaxWidth(), verticalAlignment = Alignment.CenterVertically) {
                                        RadioButton(selected = isSelected, enabled = isAvailable, onClick = {
                                            if (isAvailable && tier.name != selectedAsrTier) {
                                                selectedAsrTier = tier.name
                                                app.appConfig.modelDownloadUrl = tier.modelUrl
                                                app.appConfig.vocabDownloadUrl = tier.vocabUrl
                                                app.appConfig.modelExpectedSha256 = tier.modelSha256
                                                app.appConfig.vocabExpectedSha256 = tier.vocabSha256
                                                app.asr.modelDownloader.deleteModel()
                                            }
                                        })
                                        Column(modifier = Modifier.padding(start = 4.dp)) {
                                            Text(
                                                "${tier.label} (${tier.sizeMb} MB)" + if (!isAvailable) " — ${ranked.reason}" else "",
                                                fontWeight = if (isSelected) FontWeight.SemiBold else FontWeight.Normal,
                                                color = if (isAvailable) MaterialTheme.colorScheme.onSurface else MaterialTheme.colorScheme.onSurfaceVariant
                                            )
                                            Text(tier.description, style = MaterialTheme.typography.bodySmall, color = MaterialTheme.colorScheme.outline)
                                        }
                                    }
                                }

                                // Sideload buttons
                                Spacer(Modifier.height(4.dp))
                                Text("Or sideload from USB / SD card", style = MaterialTheme.typography.bodySmall, color = MaterialTheme.colorScheme.outline)
                                val isMultiFileTier = remember(selectedAsrTierObj) { selectedAsrTierObj.artifacts.size > 1 }
                                if (isMultiFileTier) {
                                    OutlinedButton(onClick = { importAsrDirectoryLauncher.launch(null) }, modifier = Modifier.fillMaxWidth()) {
                                        Text(stringResource(R.string.setup_import_model_folder))
                                    }
                                } else {
                                    Row(horizontalArrangement = Arrangement.spacedBy(8.dp)) {
                                        OutlinedButton(onClick = { importAsrModelLauncher.launch(arrayOf("*/*")) }, modifier = Modifier.weight(1f)) {
                                            Text(stringResource(R.string.setup_import_onnx))
                                        }
                                        OutlinedButton(onClick = { importAsrVocabLauncher.launch(arrayOf("text/plain", "*/*")) }, modifier = Modifier.weight(1f)) {
                                            Text(stringResource(R.string.setup_import_tokens))
                                        }
                                    }
                                }
                                asrImportStatus?.let { message ->
                                    Text(message, style = MaterialTheme.typography.bodySmall, color = if (message.contains("failed", ignoreCase = true)) MaterialTheme.colorScheme.error else MaterialTheme.colorScheme.onSurfaceVariant)
                                }
                            }

                            HorizontalDivider()

                            // ── Clinical Note AI override ──
                            Text(stringResource(R.string.setup_clinical_note_ai), fontWeight = FontWeight.SemiBold, style = MaterialTheme.typography.titleSmall)
                            listOf(
                                Triple("cloud", stringResource(R.string.setup_cloud_ai), stringResource(R.string.setup_cloud_asr_desc)),
                                Triple("on_device", stringResource(R.string.setup_on_device), stringResource(R.string.setup_on_device_ai_desc)),
                                Triple("auto", stringResource(R.string.setup_auto), stringResource(R.string.setup_auto_desc))
                            ).forEach { (value, label, description) ->
                                Row(modifier = Modifier.fillMaxWidth(), verticalAlignment = Alignment.CenterVertically) {
                                    RadioButton(selected = aiMode == value, onClick = {
                                        aiMode = value
                                        notesOffline = value == "on_device"
                                    })
                                    Column(modifier = Modifier.padding(start = 4.dp)) {
                                        Text(label, fontWeight = if (aiMode == value) FontWeight.SemiBold else FontWeight.Normal)
                                        Text(description, style = MaterialTheme.typography.bodySmall, color = MaterialTheme.colorScheme.outline)
                                    }
                                }
                            }

                            // Cloud API keys (BYOK mode only)
                            if (app.appConfig.cloudKeyMode == "byok") {
                                val needsClaudeKey = (aiMode == "cloud" || aiMode == "auto") && cloudNotesModel.startsWith("claude")
                                val needsGeminiKey = ((aiMode == "cloud" || aiMode == "auto") && cloudNotesModel.startsWith("gemini")) ||
                                    (asrMode == "cloud" && cloudAsrProvider == "gemini")
                                val needsOpenAiKey = ((aiMode == "cloud" || aiMode == "auto") && cloudNotesModel.startsWith("gpt")) ||
                                    (asrMode == "cloud" && cloudAsrProvider == "openai")
                                val needsDeepgramKey = asrMode == "cloud" && cloudAsrProvider == "deepgram"

                                if (needsClaudeKey) {
                                    OutlinedTextField(
                                        value = claudeApiKey,
                                        onValueChange = { claudeApiKey = it.trim() },
                                        label = { Text("Anthropic API key") },
                                        placeholder = { Text("sk-ant-...") },
                                        modifier = Modifier.fillMaxWidth(),
                                        singleLine = true,
                                        visualTransformation = PasswordVisualTransformation()
                                    )
                                    Text(stringResource(R.string.setup_claude_api_hint), style = MaterialTheme.typography.bodySmall, color = MaterialTheme.colorScheme.outline)
                                    Spacer(Modifier.height(8.dp))
                                }
                                if (needsGeminiKey) {
                                    OutlinedTextField(
                                        value = geminiApiKey,
                                        onValueChange = { geminiApiKey = it.trim() },
                                        label = { Text("Gemini API key") },
                                        placeholder = { Text("AIza...") },
                                        modifier = Modifier.fillMaxWidth(),
                                        singleLine = true,
                                        visualTransformation = PasswordVisualTransformation()
                                    )
                                    Text("Get a key at ai.google.dev", style = MaterialTheme.typography.bodySmall, color = MaterialTheme.colorScheme.outline)
                                    Spacer(Modifier.height(8.dp))
                                }
                                if (needsOpenAiKey) {
                                    OutlinedTextField(
                                        value = openaiApiKey,
                                        onValueChange = { openaiApiKey = it.trim() },
                                        label = { Text("OpenAI API key") },
                                        placeholder = { Text("sk-proj-...") },
                                        modifier = Modifier.fillMaxWidth(),
                                        singleLine = true,
                                        visualTransformation = PasswordVisualTransformation()
                                    )
                                    Text("Get a key at platform.openai.com", style = MaterialTheme.typography.bodySmall, color = MaterialTheme.colorScheme.outline)
                                    Spacer(Modifier.height(8.dp))
                                }
                                if (needsDeepgramKey) {
                                    OutlinedTextField(
                                        value = deepgramApiKey,
                                        onValueChange = { deepgramApiKey = it.trim() },
                                        label = { Text("Deepgram API key") },
                                        placeholder = { Text("dg_...") },
                                        modifier = Modifier.fillMaxWidth(),
                                        singleLine = true,
                                        visualTransformation = PasswordVisualTransformation()
                                    )
                                    Text("Get a key at console.deepgram.com", style = MaterialTheme.typography.bodySmall, color = MaterialTheme.colorScheme.outline)
                                }
                            }

                            // ── LLM tier picker ──
                            if (aiMode == "on_device" || aiMode == "auto") {
                                Text(stringResource(R.string.setup_on_device_model), fontWeight = FontWeight.Medium)
                                LlmModelManager.supportedModelTiers().forEach { tier ->
                                    val isSelected = tier.name == selectedLlmTier
                                    val isRecommended = tier == llmRecommended
                                    Row(modifier = Modifier.fillMaxWidth(), verticalAlignment = Alignment.CenterVertically) {
                                        RadioButton(selected = isSelected, onClick = {
                                            if (tier.name != selectedLlmTier) {
                                                app.llmModelManager.deleteModel()
                                                selectedLlmTier = tier.name
                                                val override = if (tier == llmRecommended) null else tier
                                                app.llmModelManager.overrideTier = override
                                                app.appConfig.llmTierOverride = override?.name ?: ""
                                                app.llmModelManager.refreshState()
                                            }
                                        })
                                        Column(modifier = Modifier.padding(start = 4.dp)) {
                                            Text(
                                                "${tier.label} (${tier.sizeMb} MB)" + if (isRecommended) " — Recommended" else "",
                                                fontWeight = if (isSelected) FontWeight.SemiBold else FontWeight.Normal
                                            )
                                            Text(tier.description, style = MaterialTheme.typography.bodySmall, color = MaterialTheme.colorScheme.outline)
                                        }
                                    }
                                }

                                // LLM sideload
                                val trustedTier = app.llmModelManager.hasPinnedChecksum(selectedLlmTierEntry)
                                OutlinedButton(onClick = { importLlmModelLauncher.launch(arrayOf("*/*")) }, enabled = trustedTier && llmAbiSupported) {
                                    Text(stringResource(R.string.setup_import_gguf))
                                }
                                llmImportStatus?.let { message ->
                                    Text(message, style = MaterialTheme.typography.bodySmall, color = if (message.contains("failed", ignoreCase = true)) MaterialTheme.colorScheme.error else MaterialTheme.colorScheme.onSurfaceVariant)
                                }
                            }
                        }
                    }

                    // ── Complete Setup ──
                    Spacer(Modifier.height(16.dp))
                    HorizontalDivider()
                    Spacer(Modifier.height(12.dp))

                    // Offline readiness warning
                    val requiresOfflineAsr = asrMode == "onnx"
                    val requiresOfflineLlm = aiMode == "on_device"
                    val requiresOfflineModels = requiresOfflineAsr || requiresOfflineLlm
                    val offlineReady =
                        (!requiresOfflineAsr || app.asr.isOnnxModelDownloadedFast()) &&
                            (!requiresOfflineLlm || llmReady)

                    // Enrollment required when cloud mode is selected with ChartLite proxy
                    val requiresEnrollment = app.appConfig.cloudKeyMode == "chartlite" &&
                        (!voiceOffline || !notesOffline)
                    val enrollmentVerified = enrollmentSuccess == true

                    if (requiresEnrollment && !enrollmentVerified) {
                        Surface(
                            color = WarningAmberSurface,
                            shape = RoundedCornerShape(8.dp),
                            modifier = Modifier.fillMaxWidth()
                        ) {
                            Row(modifier = Modifier.padding(12.dp), verticalAlignment = Alignment.CenterVertically) {
                                Icon(Icons.Default.Lock, contentDescription = null, tint = WarningAmber, modifier = Modifier.size(20.dp))
                                Spacer(Modifier.width(8.dp))
                                Column {
                                    Text(
                                        "Cloud AI requires a valid enrollment code",
                                        style = MaterialTheme.typography.labelLarge,
                                        color = WarningAmber
                                    )
                                    Text(
                                        "You can still complete setup — cloud features will be unavailable until enrollment is verified in Settings",
                                        style = MaterialTheme.typography.bodySmall,
                                        color = MaterialTheme.colorScheme.onSurfaceVariant
                                    )
                                }
                            }
                        }
                        Spacer(Modifier.height(8.dp))
                    }

                    if (requiresOfflineModels && !offlineReady) {
                        Surface(
                            color = WarningAmberSurface,
                            shape = RoundedCornerShape(8.dp),
                            modifier = Modifier.fillMaxWidth()
                        ) {
                            Row(modifier = Modifier.padding(12.dp), verticalAlignment = Alignment.CenterVertically) {
                                Icon(Icons.Default.WifiOff, contentDescription = null, tint = WarningAmber, modifier = Modifier.size(20.dp))
                                Spacer(Modifier.width(8.dp))
                                Column {
                                    Text(stringResource(R.string.setup_offline_models_warning), style = MaterialTheme.typography.labelLarge, color = WarningAmber)
                                    Text(
                                        stringResource(R.string.setup_offline_fallback),
                                        style = MaterialTheme.typography.bodySmall,
                                        color = MaterialTheme.colorScheme.onSurfaceVariant
                                    )
                                }
                            }
                        }
                        Spacer(Modifier.height(8.dp))
                    }

                    completeSetupError?.let { message ->
                        Text(
                            message,
                            style = MaterialTheme.typography.bodySmall,
                            color = MaterialTheme.colorScheme.error
                        )
                        Spacer(Modifier.height(8.dp))
                    }

                    val canCompleteSetup = !isSaving &&
                        !isDownloading &&
                        adminPin.length >= 4 &&
                        adminPin == adminPinConfirm

                    suspend fun performSetupCompletion() {
                        try {
                            val providerId = UUID.randomUUID().toString().take(8)
                            val selectedMode = FacilitySetupMode.valueOf(facilityMode)
                            if (
                                selectedMode == FacilitySetupMode.JOIN_EXISTING &&
                                inviteExpiresAtMs > 0L &&
                                inviteExpiresAtMs <= System.currentTimeMillis()
                            ) {
                                completeSetupError = "Invitation QR expired. Ask admin to generate a new one."
                                return
                            }

                            val facilityId = when (selectedMode) {
                                FacilitySetupMode.CREATE_NEW ->
                                    "${country.uppercase()}-${UUID.randomUUID().toString().take(6).uppercase()}"
                                FacilitySetupMode.JOIN_EXISTING ->
                                    normalizeFacilityId(scannedInviteFacilityId)
                                        ?: run {
                                            completeSetupError = "Invite is missing a valid facility ID."
                                            return
                                        }
                            }
                            val invitedRole = parseUserRole(invitedRoleName)
                            if (selectedMode == FacilitySetupMode.JOIN_EXISTING && invitedRole == UserRole.ADMIN) {
                                completeSetupError = "ADMIN role cannot be granted via invite. Ask admin to assign role manually."
                                return
                            }
                            val newUserRole = when (selectedMode) {
                                FacilitySetupMode.CREATE_NEW -> UserRole.ADMIN.name
                                FacilitySetupMode.JOIN_EXISTING -> invitedRole?.name
                                    ?: run {
                                        completeSetupError = "Invite is missing a valid role."
                                        return
                                    }
                            }

                            val resolvedFacilityName = when (selectedMode) {
                                FacilitySetupMode.CREATE_NEW -> facilityName
                                FacilitySetupMode.JOIN_EXISTING ->
                                    facilityName.ifBlank { "Facility $facilityId" }
                            }
                            val resolvedFacilityLocation = when (selectedMode) {
                                FacilitySetupMode.CREATE_NEW -> facilityLocation
                                FacilitySetupMode.JOIN_EXISTING ->
                                    facilityLocation.ifBlank { "Joined existing facility" }
                            }
                            val normalizedUsername = adminUsername.trim().lowercase()
                                .ifBlank {
                                    completeSetupError = "Unable to create an admin username. Check the provider name."
                                    return
                                }
                            val salt = PinHasher.generateSalt()
                            val hash = PinHasher.hash(adminPin, salt)
                            val userId = UUID.randomUUID().toString()
                            val now = System.currentTimeMillis()
                            val createdBy = when (selectedMode) {
                                FacilitySetupMode.CREATE_NEW -> "setup"
                                FacilitySetupMode.JOIN_EXISTING -> "invite_qr"
                            }

                            val finalUsername = withContext(Dispatchers.IO) {
                                app.database.withTransaction {
                                    val providerDao = app.database.providerDao()
                                    val userDao = app.database.userDao()
                                    providerDao.insertProvider(
                                        ProviderEntity(providerId, providerName, qualification, facilityId)
                                    )
                                    providerDao.insertFacility(
                                        FacilityEntity(facilityId, resolvedFacilityName, resolvedFacilityLocation)
                                    )

                                    try {
                                        userDao.insert(
                                            UserEntity(
                                                id = userId,
                                                username = normalizedUsername,
                                                displayName = providerName,
                                                pinHash = hash,
                                                pinSalt = salt,
                                                role = newUserRole,
                                                facilityId = facilityId,
                                                isActive = true,
                                                createdBy = createdBy,
                                                createdAt = now,
                                                updatedAt = now
                                            )
                                        )
                                        normalizedUsername
                                    } catch (_: android.database.sqlite.SQLiteConstraintException) {
                                        val suffixedUsername = "${normalizedUsername}.${(1..999).first { n ->
                                            userDao.getByUsername("$normalizedUsername.$n", facilityId) == null
                                        }}"
                                        userDao.insert(
                                            UserEntity(
                                                id = userId,
                                                username = suffixedUsername,
                                                displayName = providerName,
                                                pinHash = hash,
                                                pinSalt = salt,
                                                role = newUserRole,
                                                facilityId = facilityId,
                                                isActive = true,
                                                createdBy = createdBy,
                                                createdAt = now,
                                                updatedAt = now
                                            )
                                        )
                                        suffixedUsername
                                    }
                                }
                            }

                            app.appConfig.countryCode = country
                            app.appConfig.providerId = providerId
                            app.appConfig.facilityId = facilityId
                            app.appConfig.facilityName = resolvedFacilityName
                            app.appConfig.asrMode = asrMode
                            app.asr.mode = when (asrMode) {
                                "onnx" -> com.chartlite.app.asr.ASREngine.Mode.ONNX_OFFLINE
                                "cloud" -> com.chartlite.app.asr.ASREngine.Mode.CLOUD_ASR
                                else -> com.chartlite.app.asr.ASREngine.Mode.GOOGLE_ONLINE
                            }
                            app.appConfig.aiMode = aiMode
                            app.appConfig.noteProcessingMode = noteProcessingMode
                            app.appConfig.recordingModeDefault = recordingModeDefault
                            app.appConfig.claudeApiKey = claudeApiKey.trim()
                            app.appConfig.geminiApiKey = geminiApiKey.trim()
                            app.appConfig.openaiApiKey = openaiApiKey.trim()
                            app.appConfig.deepgramApiKey = deepgramApiKey.trim()
                            app.appConfig.chartliteEnrollmentCode = chartliteEnrollmentCode
                            app.appConfig.isSetupComplete = true

                            withContext(Dispatchers.IO) {
                                app.loadCountryData(deferExtraction = true)
                            }

                            when (val loginResult = app.sessionManager.login(finalUsername, adminPin, facilityId)) {
                                is AuthResult.Success -> {
                                    app.auditLogger.log(
                                        "CREATE_USER",
                                        targetType = "USER",
                                        targetId = userId,
                                        details = """{"role":"$newUserRole","source":"setup","mode":"${selectedMode.name.lowercase()}"}"""
                                    )
                                    onSetupComplete()
                                }
                                is AuthResult.Failed -> {
                                    completeSetupError = "Setup saved, but automatic sign-in failed: ${loginResult.reason}"
                                }
                                AuthResult.AccountDisabled -> {
                                    completeSetupError = "Setup saved, but the new account is disabled."
                                }
                                AuthResult.TooManyAttempts -> {
                                    completeSetupError = "Setup saved, but automatic sign-in is temporarily locked. Sign in manually in a moment."
                                }
                            }
                        } catch (e: CancellationException) {
                            throw e
                        } catch (e: Exception) {
                            completeSetupError = e.message ?: "Unable to complete setup."
                        } finally {
                            isSaving = false
                        }
                    }

                    Button(
                        onClick = {
                            if (isSaving || isDownloading) return@Button
                            if (adminPin.length < 4) {
                                completeSetupError = "Enter a 4-6 digit PIN before completing setup."
                                return@Button
                            }
                            if (adminPin != adminPinConfirm) {
                                completeSetupError = "PINs do not match."
                                return@Button
                            }
                            completeSetupError = null
                            isSaving = true
                            scope.launch { performSetupCompletion() }
                        },
                        enabled = canCompleteSetup,
                        modifier = Modifier.fillMaxWidth()
                    ) {
                        if (isSaving) {
                            CircularProgressIndicator(
                                modifier = Modifier.size(20.dp),
                                color = MaterialTheme.colorScheme.onPrimary
                            )
                        } else {
                            Text(stringResource(R.string.setup_complete_setup))
                        }
                    }
                    Spacer(Modifier.height(32.dp))
                }
            }

            if (step > 0) {
                Spacer(Modifier.height(12.dp))
                TextButton(onClick = { step-- }) {
                    Text(stringResource(R.string.back))
                }
            }
        }
    }
}

private fun normalizeFacilityId(raw: String): String? {
    val cleaned = raw.trim().uppercase()
    return if (Regex("^[A-Z0-9_-]{4,40}$").matches(cleaned)) cleaned else null
}

private data class FacilityInvitePayload(
    val facilityId: String,
    val roleName: String? = null,
    val expiresAtMs: Long? = null,
    val hmacTag: String? = null,
    val isV2: Boolean = false
)

private fun parseFacilityInviteFromQr(raw: String): FacilityInvitePayload? {
    val trimmed = raw.trim()
    if (trimmed.isBlank()) return null

    val facilityPayload = Regex("(?i)^chartlite-facility:(.+)$").find(trimmed)?.groupValues?.getOrNull(1)
    if (facilityPayload != null) {
        val facilityId = normalizeFacilityId(facilityPayload) ?: return null
        return FacilityInvitePayload(facilityId = facilityId)
    }

    // V2 signed invites: chartlite-invite-v2:facilityId:role:expires:nonce:hmacTag
    val v2Payload = Regex("(?i)^chartlite-invite-v2:(.+)$").find(trimmed)?.groupValues?.getOrNull(1)
    if (v2Payload != null) {
        val parts = v2Payload.split(":")
        if (parts.size >= 5) {
            val facilityId = normalizeFacilityId(parts[0]) ?: return null
            val role = parseUserRole(parts[1]) ?: return null
            // Block ADMIN role from QR invites — admin must be created on-device
            if (role == UserRole.ADMIN) return null
            val expiresAtMs = parts[2].toLongOrNull() ?: return null
            val hmacTag = parts[4]
            return FacilityInvitePayload(
                facilityId = facilityId,
                roleName = role.name,
                expiresAtMs = expiresAtMs,
                hmacTag = hmacTag,
                isV2 = true
            )
        }
        return null
    }

    // V1 unsigned invites (backward compat — warn user to regenerate)
    val invitePayload = Regex("(?i)^chartlite-invite:(.+)$").find(trimmed)?.groupValues?.getOrNull(1)
    if (invitePayload != null) {
        val parts = invitePayload.split(":")
        if (parts.size >= 4) {
            val facilityId = normalizeFacilityId(parts[0]) ?: return null
            val role = parseUserRole(parts[1]) ?: return null
            if (role == UserRole.ADMIN) return null
            val expiresAtMs = parts[2].toLongOrNull() ?: return null
            return FacilityInvitePayload(
                facilityId = facilityId,
                roleName = role.name,
                expiresAtMs = expiresAtMs,
                isV2 = false
            )
        }
        return null
    }

    return normalizeFacilityId(trimmed)?.let { FacilityInvitePayload(facilityId = it) }
}

private fun parseUserRole(raw: String): UserRole? {
    return try {
        UserRole.valueOf(raw.trim().uppercase())
    } catch (_: Exception) {
        null
    }
}
