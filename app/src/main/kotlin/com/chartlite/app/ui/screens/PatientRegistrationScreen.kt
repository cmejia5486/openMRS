package com.chartlite.app.ui.screens

import android.Manifest
import android.content.pm.PackageManager
import androidx.activity.compose.rememberLauncherForActivityResult
import androidx.activity.result.contract.ActivityResultContracts
import androidx.compose.foundation.clickable
import androidx.compose.foundation.layout.*
import androidx.compose.foundation.rememberScrollState
import androidx.compose.foundation.text.KeyboardOptions
import androidx.compose.foundation.verticalScroll
import androidx.compose.material.icons.Icons
import androidx.compose.material.icons.automirrored.filled.ArrowBack
import androidx.compose.material.icons.filled.Mic
import androidx.compose.material.icons.filled.Stop
import androidx.compose.material3.*
import androidx.compose.runtime.*
import androidx.compose.runtime.saveable.rememberSaveable
import androidx.compose.ui.Alignment
import androidx.compose.ui.Modifier
import androidx.compose.ui.platform.LocalContext
import androidx.compose.ui.text.font.FontStyle
import androidx.compose.ui.text.input.ImeAction
import androidx.compose.ui.text.input.KeyboardType
import androidx.compose.ui.text.input.PasswordVisualTransformation
import androidx.compose.ui.res.stringResource
import androidx.compose.ui.unit.dp
import androidx.core.content.ContextCompat
import com.chartlite.app.App
import com.chartlite.app.R
import com.chartlite.app.database.entity.PatientEntity
import com.chartlite.app.extraction.EncounterSaveCoordinator
import com.chartlite.app.extraction.PatientDemographicsExtractor
import com.chartlite.app.patientid.PatientIdGenerator
import com.chartlite.app.ui.components.PatientIdDisplay
import com.google.gson.Gson
import kotlinx.coroutines.Dispatchers
import kotlinx.coroutines.launch
import kotlinx.coroutines.withContext

@OptIn(ExperimentalMaterial3Api::class)
@Composable
fun PatientRegistrationScreen(
    onPatientRegistered: (String) -> Unit,
    onBack: () -> Unit,
    prefillAllergies: String? = null,
    prefillPatientId: String? = null
) {
    val context = LocalContext.current
    val app = context.applicationContext as App
    val scope = rememberCoroutineScope()
    val asr = app.asr

    // ASR state
    val isListening by asr.isListening.collectAsState()
    val liveTranscript by asr.transcript.collectAsState()

    var hasPermission by remember {
        mutableStateOf(
            ContextCompat.checkSelfPermission(context, Manifest.permission.RECORD_AUDIO)
                == PackageManager.PERMISSION_GRANTED
        )
    }
    val permissionLauncher = rememberLauncherForActivityResult(
        ActivityResultContracts.RequestPermission()
    ) { granted -> hasPermission = granted }

    // ── Link Existing vs Register New mode ──
    var isLinkExistingMode by rememberSaveable { mutableStateOf(prefillPatientId != null) }
    var linkPatientId by rememberSaveable { mutableStateOf(prefillPatientId?.let { PatientIdGenerator.normalize(it) } ?: "") }
    var linkPatientError by rememberSaveable { mutableStateOf<String?>(null) }
    var linkLookupName by remember { mutableStateOf<String?>(null) }

    // Form fields
    var firstName by rememberSaveable { mutableStateOf("") }
    var lastName by rememberSaveable { mutableStateOf("") }
    var dateOfBirth by rememberSaveable { mutableStateOf("") }
    var ageYears by rememberSaveable { mutableStateOf("") }
    var gender by rememberSaveable { mutableStateOf("male") }
    var phoneNumber by rememberSaveable { mutableStateOf("") }
    var nationalId by rememberSaveable { mutableStateOf("") }
    // PIN must NOT survive config changes — use remember for security
    var pin by remember { mutableStateOf("") }
    var allergies by rememberSaveable { mutableStateOf(prefillAllergies ?: "") }
    var consentGiven by rememberSaveable { mutableStateOf(false) }
    var generatedId by rememberSaveable { mutableStateOf<String?>(null) }
    var saving by remember { mutableStateOf(false) }

    // Track which fields were filled by voice
    var voiceFilledFields by remember { mutableStateOf(setOf<String>()) }
    var voiceError by remember { mutableStateOf<String?>(null) }
    var preparingVoiceModel by remember { mutableStateOf(false) }

    // Track whether form has any user-entered data
    val hasUnsavedData = firstName.isNotBlank() || lastName.isNotBlank() ||
        dateOfBirth.isNotBlank() || ageYears.isNotBlank() || phoneNumber.isNotBlank() ||
        nationalId.isNotBlank() || allergies.isNotBlank()
    var showDiscardDialog by remember { mutableStateOf(false) }

    // Country-aware date format (e.g., DD/MM/YYYY or MM/DD/YYYY)
    val dateFormat = app.appConfig.countryDateFormat
    val dateFormatDisplay = dateFormat.uppercase()

    // Validation — date format is country-aware
    val dobError = dateOfBirth.isNotBlank() &&
        !dateOfBirth.matches(Regex("\\d{2}/\\d{2}/\\d{4}"))
    val ageError = ageYears.isNotBlank() &&
        (ageYears.toIntOrNull()?.let { it !in 0..150 } ?: true)

    DisposableEffect(Unit) {
        onDispose {
            if (asr.isListening.value) asr.cancelListening(releaseOnnxAfterCancel = true)
        }
    }

    // Discard confirmation dialog
    if (showDiscardDialog) {
        AlertDialog(
            onDismissRequest = { showDiscardDialog = false },
            title = { Text(stringResource(R.string.discard_changes)) },
            text = { Text(stringResource(R.string.discard_changes_body)) },
            confirmButton = {
                TextButton(onClick = {
                    showDiscardDialog = false
                    if (isListening) asr.cancelListening(releaseOnnxAfterCancel = true)
                    onBack()
                }) {
                    Text(stringResource(R.string.discard))
                }
            },
            dismissButton = {
                TextButton(onClick = { showDiscardDialog = false }) {
                    Text(stringResource(R.string.keep_editing))
                }
            }
        )
    }

    Scaffold(
        topBar = {
            TopAppBar(
                title = { Text(if (isLinkExistingMode) stringResource(R.string.link_existing_patient) else stringResource(R.string.new_patient)) },
                navigationIcon = {
                    IconButton(onClick = {
                        if (hasUnsavedData && generatedId == null) {
                            showDiscardDialog = true
                        } else {
                            if (isListening) asr.cancelListening(releaseOnnxAfterCancel = true)
                            onBack()
                        }
                    }) {
                        Icon(Icons.AutoMirrored.Filled.ArrowBack, stringResource(R.string.back))
                    }
                }
            )
        }
    ) { padding ->
        Column(
            modifier = Modifier
                .fillMaxSize()
                .padding(padding)
                .imePadding()
                .padding(16.dp)
                .verticalScroll(rememberScrollState()),
            verticalArrangement = Arrangement.spacedBy(12.dp)
        ) {
            // Generated ID display (if saved)
            generatedId?.let { id ->
                PatientIdDisplay(
                    patientId = id,
                    modifier = Modifier.fillMaxWidth()
                )

                Spacer(Modifier.height(16.dp))

                Button(
                    onClick = { onPatientRegistered(id) },
                    modifier = Modifier.fillMaxWidth().height(52.dp),
                    shape = MaterialTheme.shapes.medium
                ) {
                    Text(
                        if (app.appConfig.isMultiStation) stringResource(R.string.done_patient_queued)
                        else stringResource(R.string.start_encounter),
                        style = MaterialTheme.typography.titleMedium
                    )
                }
                return@Scaffold
            }

            // ── Mode toggle: Register New / Link Existing ──
            SingleChoiceSegmentedButtonRow(modifier = Modifier.fillMaxWidth()) {
                SegmentedButton(
                    selected = !isLinkExistingMode,
                    onClick = {
                        isLinkExistingMode = false
                        linkPatientId = ""  // Clear stale link ID to prevent accidental reuse
                        linkPatientError = null
                        linkLookupName = null
                    },
                    shape = SegmentedButtonDefaults.itemShape(index = 0, count = 2)
                ) {
                    Text(stringResource(R.string.register_new))
                }
                SegmentedButton(
                    selected = isLinkExistingMode,
                    onClick = { isLinkExistingMode = true },
                    shape = SegmentedButtonDefaults.itemShape(index = 1, count = 2)
                ) {
                    Text(stringResource(R.string.link_existing))
                }
            }

            // ── Link Existing Patient mode ──
            if (isLinkExistingMode) {
                Card(
                    modifier = Modifier.fillMaxWidth(),
                    colors = CardDefaults.cardColors(
                        containerColor = MaterialTheme.colorScheme.secondaryContainer
                    )
                ) {
                    Column(
                        modifier = Modifier.padding(16.dp),
                        verticalArrangement = Arrangement.spacedBy(12.dp)
                    ) {
                        Text(
                            stringResource(R.string.link_existing_instruction),
                            style = MaterialTheme.typography.bodySmall,
                            color = MaterialTheme.colorScheme.onSecondaryContainer
                        )

                        OutlinedTextField(
                            value = linkPatientId,
                            onValueChange = {
                                linkPatientId = it
                                linkPatientError = null
                                linkLookupName = null
                            },
                            label = { Text(stringResource(R.string.patient_id_label)) },
                            singleLine = true,
                            isError = linkPatientError != null,
                            supportingText = {
                                when {
                                    linkPatientError != null -> Text(linkPatientError.orEmpty())
                                    linkLookupName != null -> Text(
                                        linkLookupName.orEmpty(),
                                        color = MaterialTheme.colorScheme.primary
                                    )
                                }
                            },
                            modifier = Modifier.fillMaxWidth()
                        )

                        Button(
                            onClick = {
                                val normalized = PatientIdGenerator.normalize(linkPatientId)
                                if (!PatientIdGenerator.isValid(normalized)) {
                                    linkPatientError = "Invalid patient ID format"
                                    return@Button
                                }
                                scope.launch {
                                    val existing = app.patientRepository.getById(normalized)
                                    if (existing != null) {
                                        // Patient already in local DB — create visit if multi-station (and not already checked in today), then navigate
                                        linkLookupName = "${existing.firstName} ${existing.lastName}"
                                        if (app.appConfig.isMultiStation) {
                                            val todayVisit = app.visitRepository.getTodayVisitForPatient(normalized)
                                            if (todayVisit == null) {
                                                app.visitRepository.createVisit(
                                                    patientId = normalized,
                                                    facilityId = app.appConfig.facilityId,
                                                    providerId = app.sessionManager.currentSession?.userId ?: app.appConfig.providerId
                                                )
                                            }
                                        }
                                        onPatientRegistered(normalized)
                                    } else {
                                        // Patient not found locally — use entered ID for new registration
                                        linkLookupName = null
                                        linkPatientError = "Patient not in local database. Fill in details below to register with this ID."
                                        // Switch to register mode but pre-set the ID
                                        isLinkExistingMode = false
                                    }
                                }
                            },
                            modifier = Modifier.fillMaxWidth(),
                            enabled = linkPatientId.isNotBlank()
                        ) {
                            Text(stringResource(R.string.look_up_link))
                        }
                    }
                }
                return@Scaffold
            }

            // ── Voice Registration Button ──
            Card(
                modifier = Modifier.fillMaxWidth(),
                colors = CardDefaults.cardColors(
                    containerColor = if (isListening)
                        MaterialTheme.colorScheme.errorContainer
                    else
                        MaterialTheme.colorScheme.primaryContainer
                )
            ) {
                Column(
                    modifier = Modifier.padding(16.dp),
                    horizontalAlignment = Alignment.CenterHorizontally
                ) {
                    if (isListening) {
                        // Listening state
                        Text(
                            stringResource(R.string.listening_say_details),
                            style = MaterialTheme.typography.titleSmall,
                            color = MaterialTheme.colorScheme.onErrorContainer
                        )
                        Spacer(Modifier.height(8.dp))
                        if (liveTranscript.isNotBlank()) {
                            Text(
                                liveTranscript,
                                style = MaterialTheme.typography.bodySmall,
                                fontStyle = FontStyle.Italic,
                                color = MaterialTheme.colorScheme.onErrorContainer.copy(alpha = 0.7f)
                            )
                            Spacer(Modifier.height(8.dp))
                        }
                        FilledTonalButton(
                            onClick = {
                                // Use stopListeningAndAwait to capture all buffered audio
                                scope.launch {
                                    val result = asr.stopListeningAndAwait(
                                        // Keep ONNX session warm on this screen so repeated
                                        // registration attempts don't pay model-load latency.
                                        releaseOnnxAfterStop = false,
                                        finalizeTimeoutMs = 25_000L
                                    )
                                    val text = result.text.ifBlank { liveTranscript.trim() }

                                    if (text.isNotBlank()) {
                                        val extractor = PatientDemographicsExtractor()
                                        val demo = extractor.extract(text)
                                        val filled = mutableSetOf<String>()

                                        demo.firstName?.let { firstName = it; filled.add("firstName") }
                                        demo.lastName?.let { lastName = it; filled.add("lastName") }
                                        demo.ageYears?.let { ageYears = it.toString(); filled.add("age") }
                                        demo.dateOfBirth?.let { dateOfBirth = it; filled.add("dob") }
                                        demo.gender?.let { gender = it; filled.add("gender") }
                                        demo.phoneNumber?.let { phoneNumber = it; filled.add("phone") }
                                        if (demo.allergies.isNotEmpty()) {
                                            allergies = demo.allergies.joinToString(", ")
                                            filled.add("allergies")
                                        }

                                        voiceFilledFields = filled
                                        voiceError = if (filled.isEmpty())
                                            "Could not extract patient details. Please try again or type manually."
                                        else null
                                    } else {
                                        voiceError = result.error ?: "No speech detected. Please try again."
                                    }
                                }
                            },
                            colors = ButtonDefaults.filledTonalButtonColors(
                                containerColor = MaterialTheme.colorScheme.error
                            )
                        ) {
                            Icon(Icons.Default.Stop, contentDescription = stringResource(R.string.stop),
                                tint = MaterialTheme.colorScheme.onError)
                            Spacer(Modifier.width(8.dp))
                            Text(stringResource(R.string.done), color = MaterialTheme.colorScheme.onError)
                        }
                    } else {
                        // Ready to record
                        Text(
                            if (preparingVoiceModel) stringResource(R.string.preparing_voice_model) else stringResource(R.string.voice_registration),
                            style = MaterialTheme.typography.titleSmall,
                            color = MaterialTheme.colorScheme.onPrimaryContainer
                        )
                        Spacer(Modifier.height(4.dp))
                        if (preparingVoiceModel) {
                            Text(
                                stringResource(R.string.please_wait_before_speaking),
                                style = MaterialTheme.typography.bodySmall,
                                color = MaterialTheme.colorScheme.onPrimaryContainer.copy(alpha = 0.7f)
                            )
                            Spacer(Modifier.height(8.dp))
                            LinearProgressIndicator(modifier = Modifier.fillMaxWidth())
                        } else {
                            Text(
                                stringResource(R.string.voice_example),
                                style = MaterialTheme.typography.bodySmall,
                                color = MaterialTheme.colorScheme.onPrimaryContainer.copy(alpha = 0.7f)
                            )
                        }
                        Spacer(Modifier.height(8.dp))
                        FilledTonalButton(
                            onClick = {
                                if (!hasPermission) {
                                    permissionLauncher.launch(Manifest.permission.RECORD_AUDIO)
                                    return@FilledTonalButton
                                }
                                voiceError = null
                                voiceFilledFields = emptySet()
                                scope.launch {
                                    preparingVoiceModel = true
                                    try {
                                        app.startAsrCaptureWithLowMemoryHandoff(
                                            language = app.appConfig.language,
                                            onError = { msg -> voiceError = msg },
                                            disableSilenceAutoStop = true
                                        )
                                    } finally {
                                        preparingVoiceModel = false
                                    }
                                }
                            },
                            enabled = !preparingVoiceModel
                        ) {
                            Icon(Icons.Default.Mic, contentDescription = stringResource(R.string.voice_input))
                            Spacer(Modifier.width(8.dp))
                            Text(if (preparingVoiceModel) stringResource(R.string.preparing) else stringResource(R.string.speak_patient_details))
                        }
                    }
                }
            }

            // Voice results feedback
            if (voiceFilledFields.isNotEmpty()) {
                Card(
                    modifier = Modifier.fillMaxWidth(),
                    colors = CardDefaults.cardColors(
                        containerColor = MaterialTheme.colorScheme.tertiaryContainer
                    )
                ) {
                    Text(
                        stringResource(R.string.voice_filled_fields, voiceFilledFields.size),
                        modifier = Modifier.padding(12.dp),
                        style = MaterialTheme.typography.bodySmall,
                        color = MaterialTheme.colorScheme.onTertiaryContainer
                    )
                }
            }

            voiceError?.let { err ->
                Card(
                    modifier = Modifier.fillMaxWidth(),
                    colors = CardDefaults.cardColors(
                        containerColor = MaterialTheme.colorScheme.errorContainer
                    )
                ) {
                    Text(err, modifier = Modifier.padding(12.dp),
                        style = MaterialTheme.typography.bodySmall,
                        color = MaterialTheme.colorScheme.onErrorContainer)
                }
            }

            // ══════════════════════════════════════
            // ── Personal Information ──
            // ══════════════════════════════════════
            Text(
                stringResource(R.string.personal_information),
                style = MaterialTheme.typography.titleSmall,
                color = MaterialTheme.colorScheme.primary
            )

            OutlinedTextField(
                value = firstName,
                onValueChange = { firstName = it },
                label = { Text(stringResource(R.string.first_name_required)) },
                modifier = Modifier.fillMaxWidth(),
                singleLine = true,
                keyboardOptions = KeyboardOptions(imeAction = ImeAction.Next),
                trailingIcon = if ("firstName" in voiceFilledFields) {
                    { VoiceChip() }
                } else null
            )
            OutlinedTextField(
                value = lastName,
                onValueChange = { lastName = it },
                label = { Text(stringResource(R.string.last_name_required)) },
                modifier = Modifier.fillMaxWidth(),
                singleLine = true,
                keyboardOptions = KeyboardOptions(imeAction = ImeAction.Next),
                trailingIcon = if ("lastName" in voiceFilledFields) {
                    { VoiceChip() }
                } else null
            )

            Row(
                modifier = Modifier.fillMaxWidth(),
                horizontalArrangement = Arrangement.spacedBy(12.dp)
            ) {
                OutlinedTextField(
                    value = dateOfBirth,
                    onValueChange = { dateOfBirth = it },
                    label = { Text(stringResource(R.string.dob_format_label, dateFormatDisplay)) },
                    modifier = Modifier.weight(1f),
                    singleLine = true,
                    keyboardOptions = KeyboardOptions(keyboardType = KeyboardType.Number, imeAction = ImeAction.Next),
                    isError = dobError,
                    supportingText = if (dobError) {{ Text(stringResource(R.string.date_format_hint, dateFormatDisplay)) }} else null,
                    trailingIcon = if ("dob" in voiceFilledFields) {
                        { VoiceChip() }
                    } else null
                )
                Text(stringResource(R.string.or), modifier = Modifier.align(Alignment.CenterVertically),
                    style = MaterialTheme.typography.bodySmall,
                    color = MaterialTheme.colorScheme.onSurfaceVariant)
                OutlinedTextField(
                    value = ageYears,
                    onValueChange = { ageYears = it },
                    label = { Text(stringResource(R.string.age_years)) },
                    modifier = Modifier.weight(0.6f),
                    singleLine = true,
                    keyboardOptions = KeyboardOptions(keyboardType = KeyboardType.Number, imeAction = ImeAction.Next),
                    isError = ageError,
                    supportingText = if (ageError) {{ Text(stringResource(R.string.age_range)) }} else null,
                    trailingIcon = if ("age" in voiceFilledFields) {
                        { VoiceChip() }
                    } else null
                )
            }

            // Gender — segmented button
            Row(
                verticalAlignment = Alignment.CenterVertically,
                horizontalArrangement = Arrangement.spacedBy(8.dp)
            ) {
                Text(stringResource(R.string.gender), style = MaterialTheme.typography.labelLarge)
                if ("gender" in voiceFilledFields) { VoiceChip() }
            }
            SingleChoiceSegmentedButtonRow(modifier = Modifier.fillMaxWidth()) {
                listOf("male" to stringResource(R.string.male), "female" to stringResource(R.string.female), "other" to "Other").forEachIndexed { index, (value, label) ->
                    SegmentedButton(
                        selected = gender == value,
                        onClick = { gender = value },
                        shape = SegmentedButtonDefaults.itemShape(index = index, count = 3)
                    ) {
                        Text(label)
                    }
                }
            }

            Spacer(Modifier.height(4.dp))

            // ══════════════════════════════════════
            // ── Contact Details ──
            // ══════════════════════════════════════
            Text(
                stringResource(R.string.contact_details),
                style = MaterialTheme.typography.titleSmall,
                color = MaterialTheme.colorScheme.primary
            )

            OutlinedTextField(
                value = nationalId,
                onValueChange = { nationalId = it },
                label = { Text(stringResource(R.string.national_id_optional, app.appConfig.countryNationalIdLabel)) },
                modifier = Modifier.fillMaxWidth(),
                singleLine = true,
                keyboardOptions = KeyboardOptions(imeAction = ImeAction.Next)
            )

            OutlinedTextField(
                value = phoneNumber,
                onValueChange = { phoneNumber = it },
                label = { Text(stringResource(R.string.phone_optional)) },
                modifier = Modifier.fillMaxWidth(),
                singleLine = true,
                keyboardOptions = KeyboardOptions(keyboardType = KeyboardType.Phone, imeAction = ImeAction.Next),
                supportingText = { Text(stringResource(R.string.phone_enables_sms)) },
                trailingIcon = if ("phone" in voiceFilledFields) {
                    { VoiceChip() }
                } else null
            )

            if (phoneNumber.isNotBlank()) {
                OutlinedTextField(
                    value = pin,
                    onValueChange = { if (it.length <= 4) pin = it },
                    label = { Text(stringResource(R.string.optional_pin)) },
                    modifier = Modifier.fillMaxWidth(),
                    singleLine = true,
                    keyboardOptions = KeyboardOptions(keyboardType = KeyboardType.NumberPassword, imeAction = ImeAction.Next),
                    visualTransformation = PasswordVisualTransformation(),
                    supportingText = { Text(stringResource(R.string.pin_shared_phone_hint)) }
                )
            }

            Spacer(Modifier.height(4.dp))

            // ══════════════════════════════════════
            // ── Clinical ──
            // ══════════════════════════════════════
            Text(
                stringResource(R.string.clinical),
                style = MaterialTheme.typography.titleSmall,
                color = MaterialTheme.colorScheme.primary
            )

            OutlinedTextField(
                value = allergies,
                onValueChange = { allergies = it },
                label = { Text(stringResource(R.string.known_allergies)) },
                modifier = Modifier.fillMaxWidth(),
                singleLine = true,
                supportingText = { Text(stringResource(R.string.allergies_hint)) },
                keyboardOptions = KeyboardOptions(imeAction = ImeAction.Done),
                trailingIcon = if ("allergies" in voiceFilledFields) {
                    { VoiceChip() }
                } else null
            )

            // Consent
            Spacer(Modifier.height(4.dp))
            Row(
                verticalAlignment = Alignment.CenterVertically,
                modifier = Modifier
                    .fillMaxWidth()
                    .clickable { consentGiven = !consentGiven }
                    .padding(vertical = 4.dp)
            ) {
                Checkbox(checked = consentGiven, onCheckedChange = { consentGiven = it })
                Spacer(Modifier.width(8.dp))
                Text(stringResource(R.string.consent_checkbox),
                    style = MaterialTheme.typography.bodyMedium)
            }

            Spacer(Modifier.height(8.dp))

            // Register button
            Button(
                onClick = {
                    saving = true
                    scope.launch {
                        try {
                            // Only use linkPatientId when it's a valid ID from an intentional
                            // link flow (e.g., patient not found locally → register with that ID).
                            // The linkPatientId is cleared when the user manually switches to
                            // Register New mode, preventing stale IDs from being reused.
                            val linkId = linkPatientId
                                .takeIf { it.isNotBlank() && PatientIdGenerator.isValid(PatientIdGenerator.normalize(it)) }
                                ?.let { PatientIdGenerator.normalize(it) }
                            val patientId = linkId ?: PatientIdGenerator.generateUnique { id ->
                                app.patientRepository.getById(id) != null
                            }
                            val allergyList = allergies.split(",")
                                .map { it.trim() }
                                .filter { it.isNotBlank() }

                            val patient = PatientEntity(
                                id = patientId,
                                firstName = firstName.trim(),
                                lastName = lastName.trim(),
                                dateOfBirth = dateOfBirth.takeIf { it.isNotBlank() },
                                ageYears = ageYears.toIntOrNull(),
                                gender = gender,
                                phoneNumber = phoneNumber.takeIf { it.isNotBlank() },
                                nationalId = nationalId.takeIf { it.isNotBlank() },
                                pin = pin.takeIf { it.isNotBlank() },
                                allergies = Gson().toJson(allergyList),
                                consentGiven = consentGiven,
                                consentTimestamp = if (consentGiven) System.currentTimeMillis() else null
                            )
                            app.patientRepository.register(patient)

                            app.auditLogger.log(
                                "CREATE_PATIENT",
                                targetType = "PATIENT",
                                targetId = patientId
                            )

                            if (app.appConfig.isMultiStation) {
                                app.visitRepository.createVisit(
                                    patientId = patientId,
                                    facilityId = app.appConfig.facilityId,
                                    providerId = app.sessionManager.currentSession?.userId ?: app.appConfig.providerId
                                )
                            }

                            // Import full health record from decoded SMS if available
                            app.pendingSmsImport?.let { decoded ->
                                try {
                                    EncounterSaveCoordinator.importFromDecodedSms(
                                        app, patientId, decoded
                                    )
                                } catch (e: Exception) {
                                    android.util.Log.w("PatientReg", "SMS import failed", e)
                                } finally {
                                    app.pendingSmsImport = null
                                }
                            }

                            generatedId = patientId
                        } catch (e: Exception) {
                            android.util.Log.e("PatientReg", "Registration failed", e)
                        } finally {
                            saving = false
                        }
                    }
                },
                enabled = firstName.isNotBlank() && lastName.isNotBlank() && consentGiven && !saving
                        && !dobError && !ageError
                        && (pin.isBlank() || pin.length == 4),
                modifier = Modifier.fillMaxWidth().height(52.dp)
            ) {
                if (saving) {
                    CircularProgressIndicator(modifier = Modifier.size(20.dp),
                        color = MaterialTheme.colorScheme.onPrimary)
                } else {
                    Text(stringResource(R.string.register_patient), style = MaterialTheme.typography.titleMedium)
                }
            }
        }
    }
}

/** Chip indicator showing a field was populated by voice. */
@Composable
private fun VoiceChip() {
    Surface(
        color = MaterialTheme.colorScheme.primaryContainer,
        shape = MaterialTheme.shapes.extraSmall
    ) {
        Row(
            modifier = Modifier.padding(horizontal = 6.dp, vertical = 3.dp),
            verticalAlignment = Alignment.CenterVertically,
            horizontalArrangement = Arrangement.spacedBy(3.dp)
        ) {
            Icon(
                Icons.Default.Mic,
                contentDescription = null,
                modifier = Modifier.size(12.dp),
                tint = MaterialTheme.colorScheme.onPrimaryContainer
            )
            Text(
                stringResource(R.string.voice),
                style = MaterialTheme.typography.labelSmall,
                color = MaterialTheme.colorScheme.onPrimaryContainer
            )
        }
    }
}
