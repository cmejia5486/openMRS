package com.chartlite.app.ui.components

import android.Manifest
import android.content.pm.PackageManager
import androidx.activity.compose.rememberLauncherForActivityResult
import androidx.activity.result.contract.ActivityResultContracts
import androidx.compose.animation.animateContentSize
import androidx.compose.animation.core.spring
import androidx.compose.foundation.background
import androidx.compose.foundation.layout.*
import androidx.compose.foundation.shape.CircleShape
import androidx.compose.foundation.shape.RoundedCornerShape
import androidx.compose.foundation.text.KeyboardOptions
import androidx.compose.material.icons.Icons
import androidx.compose.material.icons.filled.*
import androidx.compose.material3.*
import androidx.compose.runtime.*
import androidx.compose.runtime.rememberCoroutineScope
import androidx.compose.runtime.saveable.rememberSaveable
import androidx.compose.ui.Alignment
import androidx.compose.ui.Modifier
import androidx.compose.ui.draw.clip
import androidx.compose.ui.graphics.Color
import androidx.compose.ui.platform.LocalContext
import androidx.compose.ui.text.font.FontStyle
import androidx.compose.ui.text.font.FontWeight
import androidx.compose.ui.text.input.KeyboardType
import androidx.compose.ui.text.style.TextOverflow
import androidx.compose.ui.unit.dp
import androidx.core.content.ContextCompat
import com.chartlite.app.App
import com.chartlite.app.extraction.VitalsExtractor
import kotlinx.coroutines.launch
import com.chartlite.app.model.VitalSigns
import com.chartlite.app.ui.theme.*
import androidx.compose.ui.res.stringResource
import com.chartlite.app.R

/**
 * Voice-first triage card: nurse taps mic, dictates vitals + chief complaint,
 * extraction auto-populates editable fields, one tap to save.
 *
 * States:
 *   Collapsed → Recording → Confirm (editable) → Saved
 *   Collapsed → Manual (traditional form)
 */
@OptIn(ExperimentalMaterial3Api::class)
@Composable
fun VoiceTriageCard(
    patientName: String,
    patientId: String,
    expanded: Boolean,
    onToggle: () -> Unit,
    onSave: (
        systolic: Int?,
        diastolic: Int?,
        temp: Float?,
        pulse: Int?,
        spo2: Int?,
        weight: Float?,
        chiefComplaint: String,
        priority: Int
    ) -> Unit,
    onFullTriage: () -> Unit,
    modifier: Modifier = Modifier
) {
    val context = LocalContext.current
    val app = context.applicationContext as App
    val asr = app.asr
    val triageScope = rememberCoroutineScope()
    val vitalsExtractor = remember { VitalsExtractor() }

    // ASR state
    val isRecording by asr.isListening.collectAsState()
    val isPreparing by asr.isPreparing.collectAsState()
    val liveTranscript by asr.transcript.collectAsState()
    val amplitude by asr.amplitude.collectAsState()

    // Card mode: voice (default) vs manual fallback
    var isManualMode by rememberSaveable { mutableStateOf(false) }
    var hasRecorded by rememberSaveable { mutableStateOf(false) }
    var transcript by remember { mutableStateOf("") }
    var asrError by rememberSaveable { mutableStateOf<String?>(null) }
    var saveError by rememberSaveable { mutableStateOf<String?>(null) }
    var isSaving by remember { mutableStateOf(false) }

    // Editable vital fields (populated by extraction or manual entry)
    var systolicText by remember { mutableStateOf("") }
    var diastolicText by remember { mutableStateOf("") }
    var tempText by remember { mutableStateOf("") }
    var pulseText by remember { mutableStateOf("") }
    var spo2Text by remember { mutableStateOf("") }
    var weightText by remember { mutableStateOf("") }
    var chiefComplaint by remember { mutableStateOf("") }
    var priority by rememberSaveable { mutableIntStateOf(0) }

    // Permission handling
    var hasPermission by remember {
        mutableStateOf(
            ContextCompat.checkSelfPermission(context, Manifest.permission.RECORD_AUDIO)
                == PackageManager.PERMISSION_GRANTED
        )
    }
    val permissionLauncher = rememberLauncherForActivityResult(
        ActivityResultContracts.RequestPermission()
    ) { granted -> hasPermission = granted }

    // Stop ASR if recording when the card leaves composition (e.g., navigation away)
    DisposableEffect(Unit) {
        onDispose {
            if (asr.isListening.value) {
                asr.cancelListening()
            }
        }
    }

    // Extract vitals from transcript when recording stops
    fun extractAndPopulate(text: String) {
        transcript = text
        val vitals = vitalsExtractor.extract(text)
        if (vitals != null) {
            vitals.systolicBP?.let { systolicText = it.toString() }
            vitals.diastolicBP?.let { diastolicText = it.toString() }
            vitals.temperature?.let { tempText = "%.1f".format(it) }
            vitals.pulse?.let { pulseText = it.toString() }
            vitals.oxygenSaturation?.let { spo2Text = it.toString() }
            vitals.weight?.let { weightText = "%.1f".format(it) }
        }
        // Use the full transcript as chief complaint if not already set
        if (chiefComplaint.isBlank() && text.isNotBlank()) {
            chiefComplaint = text
        }
        hasRecorded = true
    }

    LaunchedEffect(expanded, hasRecorded) {
        if (
            expanded &&
            !hasRecorded &&
            asr.mode == com.chartlite.app.asr.ASREngine.Mode.ONNX_OFFLINE &&
            asr.isOnnxModelDownloadedFast() &&
            !asr.isModelLoaded() &&
            !asr.isPreparing.value
        ) {
            app.prepareOfflineAsrForCapture(app.appConfig.language)
        }
    }

    Card(
        modifier = modifier
            .fillMaxWidth()
            .animateContentSize(animationSpec = spring(stiffness = 300f)),
        shape = RoundedCornerShape(14.dp),
        colors = CardDefaults.cardColors(containerColor = Color.White),
        elevation = CardDefaults.cardElevation(defaultElevation = 1.dp)
    ) {
        Column(modifier = Modifier.padding(14.dp)) {

            // ── Collapsed header ──
            Row(
                modifier = Modifier.fillMaxWidth(),
                verticalAlignment = Alignment.CenterVertically
            ) {
                Column(modifier = Modifier.weight(1f)) {
                    Text(
                        text = patientName,
                        style = MaterialTheme.typography.titleSmall,
                        fontWeight = FontWeight.SemiBold,
                        maxLines = 1,
                        overflow = TextOverflow.Ellipsis
                    )
                    Text(
                        text = patientId,
                        style = MaterialTheme.typography.bodySmall,
                        color = Neutral500
                    )
                }

                Button(
                    onClick = onToggle,
                    colors = ButtonDefaults.buttonColors(
                        containerColor = if (expanded) BrandGreenDark else BrandGreen
                    ),
                    shape = RoundedCornerShape(10.dp),
                    contentPadding = PaddingValues(horizontal = 14.dp, vertical = 6.dp)
                ) {
                    Icon(
                        Icons.Default.Mic,
                        contentDescription = null,
                        modifier = Modifier.size(16.dp)
                    )
                    Spacer(Modifier.width(6.dp))
                    Text(stringResource(R.string.triage_button), style = MaterialTheme.typography.labelLarge)
                }
            }

            // ── Expanded content ──
            if (expanded) {
                Spacer(Modifier.height(14.dp))
                HorizontalDivider(color = Neutral200)
                Spacer(Modifier.height(14.dp))

                if (!isManualMode && !hasRecorded) {
                    // ── Voice recording mode ──
                    VoiceRecordingSection(
                        isRecording = isRecording,
                        isPreparing = isPreparing,
                        amplitude = amplitude,
                        liveTranscript = liveTranscript,
                        hasPermission = hasPermission,
                        errorMessage = asrError,
                        onRequestPermission = {
                            permissionLauncher.launch(Manifest.permission.RECORD_AUDIO)
                        },
                        onStartRecording = {
                            asrError = null
                            triageScope.launch {
                                app.startAsrCaptureWithLowMemoryHandoff(
                                    language = app.appConfig.language,
                                    onError = { msg -> asrError = msg }
                                )
                            }
                        },
                        onStopRecording = {
                            // Use stopListeningAndAwait() to capture all buffered audio
                            triageScope.launch {
                                try {
                                    val result = asr.stopListeningAndAwait(releaseOnnxAfterStop = false)
                                    if (result.text.isBlank()) {
                                        asrError = result.error ?: "No speech detected. Try again."
                                    } else {
                                        extractAndPopulate(result.text)
                                    }
                                } catch (e: Exception) {
                                    asrError = "Recording failed: ${e.message}"
                                    isManualMode = true
                                }
                            }
                        }
                    )

                    Spacer(Modifier.height(12.dp))

                    // Manual fallback link
                    TextButton(
                        onClick = { isManualMode = true },
                        modifier = Modifier.align(Alignment.CenterHorizontally)
                    ) {
                        Icon(
                            Icons.Default.Edit,
                            contentDescription = null,
                            modifier = Modifier.size(16.dp),
                            tint = Neutral500
                        )
                        Spacer(Modifier.width(4.dp))
                        Text(
                            stringResource(R.string.enter_manually_instead),
                            style = MaterialTheme.typography.labelMedium,
                            color = Neutral500
                        )
                    }
                } else {
                    // ── Confirm / Edit mode (after voice or manual) ──

                    // Show transcript if voice was used
                    if (hasRecorded && transcript.isNotBlank()) {
                        Surface(
                            shape = RoundedCornerShape(10.dp),
                            color = Neutral100,
                            modifier = Modifier.fillMaxWidth()
                        ) {
                            Column(modifier = Modifier.padding(10.dp)) {
                                Text(
                                    stringResource(R.string.voice_transcript),
                                    style = MaterialTheme.typography.labelSmall,
                                    color = Neutral500
                                )
                                Spacer(Modifier.height(4.dp))
                                Text(
                                    transcript,
                                    style = MaterialTheme.typography.bodySmall,
                                    fontStyle = FontStyle.Italic,
                                    color = Neutral700,
                                    maxLines = 3,
                                    overflow = TextOverflow.Ellipsis
                                )
                            }
                        }
                        Spacer(Modifier.height(10.dp))

                        // Re-record button
                        TextButton(
                            onClick = {
                                hasRecorded = false
                                transcript = ""
                            },
                            modifier = Modifier.align(Alignment.End)
                        ) {
                            Icon(
                                Icons.Default.Mic,
                                contentDescription = null,
                                modifier = Modifier.size(14.dp),
                                tint = BrandGreen
                            )
                            Spacer(Modifier.width(4.dp))
                            Text(stringResource(R.string.re_record), color = BrandGreen, style = MaterialTheme.typography.labelSmall)
                        }
                    }

                    // Editable vital fields
                    VitalsForm(
                        systolicText = systolicText,
                        diastolicText = diastolicText,
                        tempText = tempText,
                        pulseText = pulseText,
                        spo2Text = spo2Text,
                        weightText = weightText,
                        onSystolicChange = { systolicText = it },
                        onDiastolicChange = { diastolicText = it },
                        onTempChange = { tempText = it },
                        onPulseChange = { pulseText = it },
                        onSpo2Change = { spo2Text = it },
                        onWeightChange = { weightText = it }
                    )

                    Spacer(Modifier.height(10.dp))

                    // Chief complaint
                    OutlinedTextField(
                        value = chiefComplaint,
                        onValueChange = { chiefComplaint = it },
                        label = { Text(stringResource(R.string.chief_complaint_field)) },
                        modifier = Modifier.fillMaxWidth(),
                        singleLine = false,
                        maxLines = 3,
                        shape = RoundedCornerShape(10.dp),
                        colors = OutlinedTextFieldDefaults.colors(
                            focusedBorderColor = BrandGreen,
                            focusedLabelColor = BrandGreen,
                            cursorColor = BrandGreen
                        )
                    )

                    Spacer(Modifier.height(12.dp))

                    // Priority selection
                    Text(stringResource(R.string.priority_label), style = MaterialTheme.typography.labelMedium, color = Neutral600)
                    Spacer(Modifier.height(6.dp))

                    Row(horizontalArrangement = Arrangement.spacedBy(8.dp)) {
                        PriorityChip(stringResource(R.string.priority_normal), BrandGreen, priority == 0) { priority = 0 }
                        PriorityChip(stringResource(R.string.priority_priority), WarningAmber, priority == 1) { priority = 1 }
                        PriorityChip(stringResource(R.string.priority_emergency), AlertRed, priority == 2) { priority = 2 }
                    }

                    Spacer(Modifier.height(14.dp))

                    // Save error feedback
                    saveError?.let { error ->
                        Surface(
                            shape = RoundedCornerShape(8.dp),
                            color = AlertRed.copy(alpha = 0.1f),
                            modifier = Modifier.fillMaxWidth()
                        ) {
                            Text(
                                error,
                                modifier = Modifier.padding(10.dp),
                                style = MaterialTheme.typography.bodySmall,
                                color = AlertRed
                            )
                        }
                        Spacer(Modifier.height(8.dp))
                    }

                    // Action buttons
                    val hasAnyVital = systolicText.isNotBlank() || tempText.isNotBlank() ||
                        pulseText.isNotBlank() || spo2Text.isNotBlank() || weightText.isNotBlank()
                    val canSave = hasAnyVital || chiefComplaint.isNotBlank()

                    val saveValidationErrorMsg = stringResource(R.string.save_validation_error)
                    Row(
                        modifier = Modifier.fillMaxWidth(),
                        horizontalArrangement = Arrangement.spacedBy(10.dp),
                        verticalAlignment = Alignment.CenterVertically
                    ) {
                        Button(
                            onClick = {
                                saveError = null
                                if (!canSave) {
                                    saveError = saveValidationErrorMsg
                                    return@Button
                                }
                                isSaving = true
                                onSave(
                                    systolicText.toIntOrNull(),
                                    diastolicText.toIntOrNull(),
                                    tempText.toFloatOrNull(),
                                    pulseText.toIntOrNull(),
                                    spo2Text.toIntOrNull(),
                                    weightText.toFloatOrNull(),
                                    chiefComplaint,
                                    priority
                                )
                            },
                            modifier = Modifier.weight(1f),
                            enabled = !isSaving,
                            colors = ButtonDefaults.buttonColors(containerColor = BrandGreen),
                            shape = RoundedCornerShape(10.dp)
                        ) {
                            if (isSaving) {
                                CircularProgressIndicator(
                                    modifier = Modifier.size(16.dp),
                                    strokeWidth = 2.dp,
                                    color = Color.White
                                )
                                Spacer(Modifier.width(6.dp))
                            }
                            Text(stringResource(R.string.save_send_consultation), style = MaterialTheme.typography.labelLarge, maxLines = 1)
                        }

                        TextButton(onClick = onFullTriage, shape = RoundedCornerShape(10.dp)) {
                            Text(
                                stringResource(R.string.full_triage),
                                style = MaterialTheme.typography.labelLarge,
                                color = BrandGreen,
                                fontWeight = FontWeight.Medium
                            )
                        }
                    }
                }
            }
        }
    }
}

// ── Voice recording section ──

@Composable
private fun VoiceRecordingSection(
    isRecording: Boolean,
    isPreparing: Boolean,
    amplitude: Float,
    liveTranscript: String,
    hasPermission: Boolean,
    errorMessage: String?,
    onRequestPermission: () -> Unit,
    onStartRecording: () -> Unit,
    onStopRecording: () -> Unit
) {
    Column(
        modifier = Modifier.fillMaxWidth(),
        horizontalAlignment = Alignment.CenterHorizontally
    ) {
        if (!hasPermission) {
            // Permission needed
            Text(
                stringResource(R.string.microphone_permission_required),
                style = MaterialTheme.typography.bodySmall,
                color = Neutral500
            )
            Spacer(Modifier.height(8.dp))
            Button(
                onClick = onRequestPermission,
                colors = ButtonDefaults.buttonColors(containerColor = BrandGreen),
                shape = RoundedCornerShape(10.dp)
            ) {
                Text(stringResource(R.string.grant_permission))
            }
        } else {
            // ASR error feedback
            errorMessage?.let { msg ->
                Surface(
                    shape = RoundedCornerShape(8.dp),
                    color = AlertRed.copy(alpha = 0.1f),
                    modifier = Modifier.fillMaxWidth()
                ) {
                    Text(
                        msg,
                        modifier = Modifier.padding(10.dp),
                        style = MaterialTheme.typography.bodySmall,
                        color = AlertRed
                    )
                }
                Spacer(Modifier.height(8.dp))
            }

            // Instruction text
            if (!isRecording) {
                Text(
                    if (isPreparing) stringResource(R.string.preparing_offline_asr) else stringResource(R.string.tap_to_dictate),
                    style = MaterialTheme.typography.bodySmall,
                    color = Neutral500
                )
                Text(
                    if (isPreparing)
                        stringResource(R.string.first_load_slow)
                    else
                        stringResource(R.string.dictation_example),
                    style = MaterialTheme.typography.labelSmall,
                    color = Neutral400,
                    fontStyle = FontStyle.Italic,
                    modifier = Modifier.padding(horizontal = 16.dp, vertical = 4.dp)
                )
            }

            Spacer(Modifier.height(12.dp))

            // Record button (compact version)
            RecordButton(
                isRecording = isRecording,
                amplitude = amplitude,
                enabled = !isPreparing,
                isPreparing = isPreparing,
                onClick = {
                    if (isRecording) onStopRecording() else onStartRecording()
                },
                modifier = Modifier.size(100.dp)
            )

            // Live transcript
            if (isRecording && liveTranscript.isNotBlank()) {
                Spacer(Modifier.height(8.dp))
                Surface(
                    shape = RoundedCornerShape(8.dp),
                    color = Neutral100,
                    modifier = Modifier.fillMaxWidth()
                ) {
                    Text(
                        liveTranscript,
                        modifier = Modifier.padding(10.dp),
                        style = MaterialTheme.typography.bodySmall,
                        color = Neutral700,
                        maxLines = 3,
                        overflow = TextOverflow.Ellipsis
                    )
                }
            }

            if (isPreparing) {
                Spacer(Modifier.height(4.dp))
                Text(
                    stringResource(R.string.loading_voice_model),
                    style = MaterialTheme.typography.labelSmall,
                    color = Neutral500
                )
            } else if (isRecording) {
                Spacer(Modifier.height(4.dp))
                Text(
                    stringResource(R.string.listening_tap_to_stop),
                    style = MaterialTheme.typography.labelSmall,
                    color = AlertRed
                )
            }
        }
    }
}

// ── Vitals form (shared between voice-confirm and manual modes) ──

@Composable
private fun VitalsForm(
    systolicText: String,
    diastolicText: String,
    tempText: String,
    pulseText: String,
    spo2Text: String,
    weightText: String,
    onSystolicChange: (String) -> Unit,
    onDiastolicChange: (String) -> Unit,
    onTempChange: (String) -> Unit,
    onPulseChange: (String) -> Unit,
    onSpo2Change: (String) -> Unit,
    onWeightChange: (String) -> Unit
) {
    // Row 1: Blood pressure
    Row(
        modifier = Modifier.fillMaxWidth(),
        horizontalArrangement = Arrangement.spacedBy(10.dp)
    ) {
        VitalField(systolicText, onSystolicChange, "Systolic", "mmHg", Modifier.weight(1f))
        VitalField(diastolicText, onDiastolicChange, "Diastolic", "mmHg", Modifier.weight(1f))
    }
    Spacer(Modifier.height(10.dp))
    // Row 2: Temp + Pulse
    Row(
        modifier = Modifier.fillMaxWidth(),
        horizontalArrangement = Arrangement.spacedBy(10.dp)
    ) {
        VitalField(tempText, onTempChange, "Temp", "\u00B0C", Modifier.weight(1f), allowDecimal = true)
        VitalField(pulseText, onPulseChange, "Pulse", "bpm", Modifier.weight(1f))
    }
    Spacer(Modifier.height(10.dp))
    // Row 3: SpO2 + Weight
    Row(
        modifier = Modifier.fillMaxWidth(),
        horizontalArrangement = Arrangement.spacedBy(10.dp)
    ) {
        VitalField(spo2Text, onSpo2Change, "SpO2", "%", Modifier.weight(1f))
        VitalField(weightText, onWeightChange, "Weight", "kg", Modifier.weight(1f), allowDecimal = true)
    }
}

// ── Compact numeric field ──

@Composable
private fun VitalField(
    value: String,
    onValueChange: (String) -> Unit,
    label: String,
    suffix: String,
    modifier: Modifier = Modifier,
    allowDecimal: Boolean = false
) {
    OutlinedTextField(
        value = value,
        onValueChange = { text ->
            val filtered = if (allowDecimal) {
                val raw = text.filter { it.isDigit() || it == '.' }
                if (raw.count { it == '.' } > 1) value else raw
            } else {
                text.filter { it.isDigit() }
            }
            onValueChange(filtered)
        },
        label = { Text(label) },
        suffix = { Text(suffix, style = MaterialTheme.typography.labelSmall, color = Neutral500) },
        modifier = modifier,
        singleLine = true,
        keyboardOptions = KeyboardOptions(keyboardType = KeyboardType.Number),
        shape = RoundedCornerShape(10.dp),
        colors = OutlinedTextFieldDefaults.colors(
            focusedBorderColor = BrandGreen,
            focusedLabelColor = BrandGreen,
            cursorColor = BrandGreen
        )
    )
}

// ── Priority chip ──

@OptIn(ExperimentalMaterial3Api::class)
@Composable
private fun PriorityChip(
    label: String,
    chipColor: Color,
    isSelected: Boolean,
    onClick: () -> Unit
) {
    FilterChip(
        selected = isSelected,
        onClick = onClick,
        label = {
            Text(
                label,
                style = MaterialTheme.typography.labelMedium,
                fontWeight = if (isSelected) FontWeight.Bold else FontWeight.Normal
            )
        },
        colors = FilterChipDefaults.filterChipColors(
            containerColor = Neutral100,
            labelColor = Neutral700,
            selectedContainerColor = chipColor,
            selectedLabelColor = Color.White
        ),
        border = FilterChipDefaults.filterChipBorder(
            borderColor = Neutral300,
            selectedBorderColor = chipColor,
            enabled = true,
            selected = isSelected
        ),
        shape = RoundedCornerShape(10.dp)
    )
}
