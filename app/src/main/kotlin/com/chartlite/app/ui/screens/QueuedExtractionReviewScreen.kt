package com.chartlite.app.ui.screens

import androidx.compose.foundation.BorderStroke
import androidx.compose.foundation.layout.Arrangement
import androidx.compose.foundation.layout.Column
import androidx.compose.foundation.layout.Spacer
import androidx.compose.foundation.layout.fillMaxSize
import androidx.compose.foundation.layout.fillMaxWidth
import androidx.compose.foundation.layout.height
import androidx.compose.foundation.layout.padding
import androidx.compose.foundation.rememberScrollState
import androidx.compose.foundation.verticalScroll
import androidx.compose.material.icons.Icons
import androidx.compose.material.icons.automirrored.filled.ArrowBack
import androidx.compose.material3.Button
import androidx.compose.material3.Card
import androidx.compose.material3.CardDefaults
import androidx.compose.material3.CircularProgressIndicator
import androidx.compose.material3.ExperimentalMaterial3Api
import androidx.compose.material3.Icon
import androidx.compose.material3.IconButton
import androidx.compose.material3.MaterialTheme
import androidx.compose.material3.OutlinedButton
import androidx.compose.material3.Scaffold
import androidx.compose.material3.Text
import androidx.compose.material3.TopAppBar
import androidx.compose.runtime.Composable
import androidx.compose.runtime.LaunchedEffect
import androidx.compose.runtime.collectAsState
import androidx.compose.runtime.getValue
import androidx.compose.runtime.mutableStateOf
import androidx.compose.runtime.remember
import androidx.compose.runtime.rememberCoroutineScope
import androidx.compose.runtime.setValue
import androidx.compose.ui.Modifier
import androidx.compose.ui.platform.LocalContext
import androidx.compose.ui.text.font.FontStyle
import androidx.compose.ui.text.font.FontWeight
import androidx.compose.ui.unit.dp
import androidx.compose.foundation.layout.heightIn
import androidx.compose.material3.HorizontalDivider
import androidx.compose.material3.OutlinedTextField
import androidx.compose.material3.Surface
import androidx.compose.material3.TextButton
import androidx.compose.foundation.clickable
import androidx.compose.material.icons.filled.KeyboardArrowDown
import androidx.compose.material.icons.filled.KeyboardArrowUp
import androidx.compose.foundation.layout.Row
import androidx.compose.runtime.saveable.rememberSaveable
import com.chartlite.app.App
import com.chartlite.app.ui.components.MarkdownText
import com.chartlite.app.extraction.EncounterSaveCoordinator
import com.chartlite.app.extraction.ExtractionQueueRepository
import com.chartlite.app.model.ClinicStation
import com.chartlite.app.model.Medication
import kotlinx.coroutines.launch
import androidx.compose.ui.res.stringResource
import com.chartlite.app.R

@OptIn(ExperimentalMaterial3Api::class)
@Composable
fun QueuedExtractionReviewScreen(
    queueId: String,
    onBack: () -> Unit,
    onSaved: (String, String?) -> Unit
) {
    val context = LocalContext.current
    val app = context.applicationContext as App
    val scope = rememberCoroutineScope()
    val queueState by app.extractionQueue.state.collectAsState()

    // ── SMS permission — request once so encounter save can send natively ──
    val smsPermissionLauncher = androidx.activity.compose.rememberLauncherForActivityResult(
        androidx.activity.result.contract.ActivityResultContracts.RequestPermission()
    ) { /* granted state not needed — SMSSender checks at send time */ }
    LaunchedEffect(Unit) {
        if (androidx.core.content.ContextCompat.checkSelfPermission(
                context, android.Manifest.permission.SEND_SMS
            ) != android.content.pm.PackageManager.PERMISSION_GRANTED
        ) {
            smsPermissionLauncher.launch(android.Manifest.permission.SEND_SMS)
        }
    }

    var item by remember { mutableStateOf<ExtractionQueueRepository.QueueItem?>(null) }
    var patientName by remember { mutableStateOf<String?>(null) }
    var isSaving by remember { mutableStateOf(false) }
    var isProcessingItem by remember { mutableStateOf(false) }
    var loadError by remember { mutableStateOf<String?>(null) }
    var actionError by remember { mutableStateOf<String?>(null) }
    val queuedNoteNotFoundMsg = stringResource(R.string.queued_note_not_found)
    val statusMsg = stringResource(R.string.status)
    val loadingMsg = stringResource(R.string.loading)
    val readyForReviewMsg = stringResource(R.string.ready_for_review_label)
    val errorMsg = stringResource(R.string.error)
    val saveMsg = stringResource(R.string.save)
    val onDeviceAiMsg = stringResource(R.string.on_device_ai)
    val cloudAiMsg = stringResource(R.string.cloud_ai)
    val patternMatchingMsg = stringResource(R.string.pattern_matching_label)

    suspend fun reloadQueueItem() {
        val queueItem = app.extractionQueue.getItem(queueId)
        item = queueItem
        if (queueItem == null) {
            loadError = queuedNoteNotFoundMsg
            return
        }
        loadError = null
        actionError = null
        val patient = app.patientRepository.getById(queueItem.patientId)
        patientName = patient?.let { "${it.firstName} ${it.lastName}" } ?: queueItem.patientId
    }

    LaunchedEffect(queueId) {
        reloadQueueItem()
    }

    val queueItem = item
    val encounter = queueItem?.encounter

    Scaffold(
        topBar = {
            TopAppBar(
                title = { Text(stringResource(R.string.queued_note_review)) },
                navigationIcon = {
                    IconButton(onClick = onBack) {
                        Icon(Icons.AutoMirrored.Filled.ArrowBack, contentDescription = stringResource(R.string.back))
                    }
                }
            )
        }
    ) { padding ->
        when {
            queueItem == null && loadError == null -> {
                Column(
                    modifier = Modifier
                        .fillMaxSize()
                        .padding(padding),
                    verticalArrangement = Arrangement.Center
                ) {
                    CircularProgressIndicator()
                }
            }
            loadError != null -> {
                Column(
                    modifier = Modifier
                        .fillMaxSize()
                        .padding(padding)
                        .padding(24.dp),
                    verticalArrangement = Arrangement.Center
                ) {
                    Text(loadError ?: stringResource(R.string.unable_to_load_queued_note))
                }
            }
            else -> {
                val currentItem = queueItem ?: return@Scaffold
                val interruptedProcessing =
                    currentItem.status == ExtractionQueueRepository.QueueStatus.PROCESSING &&
                        queueState == com.chartlite.app.extraction.ExtractionQueue.QueueState.IDLE
                Column(
                    modifier = Modifier
                        .fillMaxSize()
                        .padding(padding)
                        .verticalScroll(rememberScrollState())
                        .padding(16.dp),
                    verticalArrangement = Arrangement.spacedBy(12.dp)
                ) {
                    Text(patientName ?: currentItem.patientId, style = MaterialTheme.typography.titleLarge)
                    Text(
                        buildString {
                            append(when (currentItem.status) {
                                ExtractionQueueRepository.QueueStatus.QUEUED -> statusMsg
                                ExtractionQueueRepository.QueueStatus.PROCESSING -> loadingMsg
                                ExtractionQueueRepository.QueueStatus.READY -> readyForReviewMsg
                                ExtractionQueueRepository.QueueStatus.FAILED -> errorMsg
                                ExtractionQueueRepository.QueueStatus.SAVED -> saveMsg
                            })
                            currentItem.strategyUsed?.let { strategy ->
                                val label = when {
                                    "qwen" in strategy.lowercase() -> onDeviceAiMsg
                                    "claude" in strategy.lowercase() -> cloudAiMsg
                                    "regex" in strategy.lowercase() -> patternMatchingMsg
                                    else -> strategy
                                }
                                append(" • $label")
                            }
                        },
                        style = MaterialTheme.typography.labelSmall,
                        color = MaterialTheme.colorScheme.outline
                    )

                    if (currentItem.fallbacksAttempted.isNotEmpty()) {
                        SummaryBlock(
                            stringResource(R.string.fallbacks_attempted),
                            currentItem.fallbacksAttempted.joinToString("\n") { "• $it" }
                        )
                    }

                    actionError?.let {
                        SummaryBlock(stringResource(R.string.action_error_title), it)
                    }

                    // Show transcript collapsed by default (the draft note is the primary document)
                    var showTranscript by rememberSaveable { mutableStateOf(false) }
                    Card(
                        modifier = Modifier
                            .fillMaxWidth()
                            .clickable { showTranscript = !showTranscript },
                        colors = CardDefaults.cardColors(containerColor = MaterialTheme.colorScheme.surfaceVariant)
                    ) {
                        Column(modifier = Modifier.padding(16.dp)) {
                            Row {
                                Text(
                                    if (showTranscript) stringResource(R.string.hide_original_transcript)
                                    else stringResource(R.string.show_original_transcript),
                                    style = MaterialTheme.typography.labelLarge,
                                    fontWeight = FontWeight.SemiBold,
                                    modifier = Modifier.weight(1f)
                                )
                                Icon(
                                    if (showTranscript) Icons.Default.KeyboardArrowUp else Icons.Default.KeyboardArrowDown,
                                    contentDescription = null
                                )
                            }
                            if (showTranscript) {
                                Spacer(Modifier.height(6.dp))
                                Text(currentItem.transcript, style = MaterialTheme.typography.bodyMedium, fontStyle = FontStyle.Italic)
                            }
                        }
                    }

                    when (currentItem.status) {
                        ExtractionQueueRepository.QueueStatus.QUEUED,
                        ExtractionQueueRepository.QueueStatus.PROCESSING,
                        ExtractionQueueRepository.QueueStatus.FAILED -> {
                            SummaryBlock(
                                stringResource(R.string.status),
                                when (currentItem.status) {
                                    ExtractionQueueRepository.QueueStatus.QUEUED ->
                                        stringResource(R.string.queue_status_queued)
                                    ExtractionQueueRepository.QueueStatus.PROCESSING ->
                                        if (interruptedProcessing) {
                                            stringResource(R.string.queue_status_interrupted)
                                        } else {
                                            stringResource(R.string.queue_status_processing_now)
                                        }
                                    else ->
                                        currentItem.errorMessage ?: stringResource(R.string.last_processing_failed)
                                }
                            )

                            Button(
                                onClick = {
                                    if (
                                        isProcessingItem ||
                                            (
                                                currentItem.status == ExtractionQueueRepository.QueueStatus.PROCESSING &&
                                                    !interruptedProcessing
                                                )
                                    ) return@Button
                                    isProcessingItem = true
                                    actionError = null
                                    scope.launch {
                                        try {
                                            if (!app.prepareOnDeviceNoteProcessingForLowRam { actionError = it }) return@launch
                                            app.extractionQueue.processItem(queueId)
                                            reloadQueueItem()
                                        } catch (e: Exception) {
                                            actionError = "Processing failed: ${e.message}"
                                        } finally {
                                            isProcessingItem = false
                                        }
                                    }
                                },
                                enabled = !isProcessingItem &&
                                    (
                                        currentItem.status != ExtractionQueueRepository.QueueStatus.PROCESSING ||
                                            interruptedProcessing
                                        ),
                                modifier = Modifier.fillMaxWidth()
                            ) {
                                if (isProcessingItem) {
                                    CircularProgressIndicator(modifier = Modifier.height(20.dp))
                                } else {
                                    Text(
                                        if (
                                            currentItem.status == ExtractionQueueRepository.QueueStatus.FAILED ||
                                                interruptedProcessing
                                            )
                                            stringResource(R.string.retry_processing)
                                        else
                                            stringResource(R.string.process_this_note)
                                    )
                                }
                            }
                        }

                        ExtractionQueueRepository.QueueStatus.READY -> {
                            val readyEncounter = encounter ?: return@Column

                            Text(stringResource(R.string.review_edit_title), style = MaterialTheme.typography.titleMedium, fontWeight = FontWeight.SemiBold)
                            Text(stringResource(R.string.review_note_before_saving), style = MaterialTheme.typography.bodySmall, color = MaterialTheme.colorScheme.onSurfaceVariant)
                            Spacer(Modifier.height(8.dp))

                            // ── Draft Clinical Note (primary document) ──
                            val draftNote = currentItem.draftNote ?: readyEncounter.freeTextNote
                            var editDraftNote by remember(draftNote) { mutableStateOf(draftNote) }

                            currentItem.noteStrategyUsed?.let { strategy ->
                                val label = when {
                                    "qwen" in strategy.lowercase() -> onDeviceAiMsg
                                    "claude" in strategy.lowercase() -> cloudAiMsg
                                    else -> strategy
                                }
                                Text(
                                    stringResource(R.string.note_generated_via, label),
                                    style = MaterialTheme.typography.labelSmall,
                                    color = MaterialTheme.colorScheme.primary
                                )
                                Spacer(Modifier.height(4.dp))
                            }

                            var isEditingNote by remember { mutableStateOf(false) }
                            if (isEditingNote) {
                                OutlinedTextField(
                                    value = editDraftNote,
                                    onValueChange = { editDraftNote = it },
                                    label = { Text(stringResource(R.string.draft_clinical_note)) },
                                    modifier = Modifier.fillMaxWidth().heightIn(min = 150.dp),
                                    maxLines = 12
                                )
                                TextButton(onClick = { isEditingNote = false }) {
                                    Text(stringResource(R.string.done_editing))
                                }
                            } else {
                                Surface(
                                    modifier = Modifier
                                        .fillMaxWidth()
                                        .clickable { isEditingNote = true },
                                    shape = MaterialTheme.shapes.medium,
                                    border = BorderStroke(1.dp, MaterialTheme.colorScheme.outlineVariant)
                                ) {
                                    Column(modifier = Modifier.padding(16.dp)) {
                                        MarkdownText(
                                            text = editDraftNote,
                                            style = MaterialTheme.typography.bodyMedium
                                        )
                                    }
                                }
                                Text(
                                    text = stringResource(R.string.tap_to_edit),
                                    style = MaterialTheme.typography.labelSmall,
                                    color = MaterialTheme.colorScheme.onSurfaceVariant,
                                    modifier = Modifier.padding(top = 4.dp)
                                )
                            }

                            Spacer(Modifier.height(16.dp))
                            HorizontalDivider()
                            Spacer(Modifier.height(12.dp))

                            // ── Extracted structured fields ──
                            Text(stringResource(R.string.extracted_fields), style = MaterialTheme.typography.titleSmall, fontWeight = FontWeight.SemiBold)
                            Text(stringResource(R.string.edit_any_field), style = MaterialTheme.typography.bodySmall, color = MaterialTheme.colorScheme.onSurfaceVariant)
                            Spacer(Modifier.height(8.dp))

                            var editMedications by remember(readyEncounter) {
                                mutableStateOf(readyEncounter.medications.joinToString("\n") { med ->
                                    "${med.name} ${med.dose ?: ""}${med.unit ?: ""} ${med.frequency ?: ""}".trim()
                                })
                            }
                            var editExamFindings by remember(readyEncounter) { mutableStateOf(readyEncounter.examFindings.joinToString("\n")) }
                            var editPlan by remember(readyEncounter) { mutableStateOf(readyEncounter.plan.joinToString("\n")) }
                            var editAllergies by remember(readyEncounter) { mutableStateOf(readyEncounter.allergies.joinToString("\n")) }

                            OutlinedTextField(value = editExamFindings, onValueChange = { editExamFindings = it }, label = { Text(stringResource(R.string.exam_findings_one_per_line)) }, modifier = Modifier.fillMaxWidth().heightIn(min = 60.dp), maxLines = 4)
                            OutlinedTextField(value = editMedications, onValueChange = { editMedications = it }, label = { Text(stringResource(R.string.medications_one_per_line)) }, modifier = Modifier.fillMaxWidth().heightIn(min = 60.dp), maxLines = 4)
                            OutlinedTextField(value = editPlan, onValueChange = { editPlan = it }, label = { Text(stringResource(R.string.plan_one_per_line)) }, modifier = Modifier.fillMaxWidth().heightIn(min = 60.dp), maxLines = 4)
                            OutlinedTextField(value = editAllergies, onValueChange = { editAllergies = it }, label = { Text(stringResource(R.string.allergies_one_per_line)) }, modifier = Modifier.fillMaxWidth(), maxLines = 3)

                            // Read-only sections
                            if (readyEncounter.suggestedDiagnoses.isNotEmpty()) {
                                SummaryBlock("Suggested Diagnoses", readyEncounter.suggestedDiagnoses.joinToString("\n") { "${it.icd10Code} - ${it.description}" })
                            }
                            readyEncounter.vitals?.let { vitals ->
                                SummaryBlock("Vitals", listOfNotNull(
                                    vitals.systolicBP?.let { "BP ${it}/${vitals.diastolicBP ?: "?"}" },
                                    vitals.temperature?.let { "Temp ${"%.1f".format(it)} C" },
                                    vitals.pulse?.let { "Pulse $it" },
                                    vitals.oxygenSaturation?.let { "SpO2 $it%" }
                                ).joinToString(" • "))
                            }

                            Button(
                                onClick = {
                                    if (isSaving) return@Button
                                    isSaving = true
                                    actionError = null
                                    scope.launch {
                                        try {
                                            val editedEncounter = readyEncounter.copy(
                                                freeTextNote = editDraftNote,
                                                examFindings = editExamFindings.lines().map { it.trim() }.filter { it.isNotBlank() },
                                                medications = editMedications.lines().map { it.trim() }.filter { it.isNotBlank() }.map { line ->
                                                    val orig = readyEncounter.medications.firstOrNull { m -> line.startsWith(m.name, ignoreCase = true) }
                                                    orig ?: Medication(formularyCode = "", name = line)
                                                },
                                                plan = editPlan.lines().map { it.trim() }.filter { it.isNotBlank() },
                                                allergies = editAllergies.lines().map { it.trim() }.filter { it.isNotBlank() }
                                            )
                                            val station = currentItem.stationType?.let {
                                                runCatching { ClinicStation.valueOf(it) }.getOrNull()
                                            }
                                            val savedId = EncounterSaveCoordinator.saveEncounter(
                                                app = app,
                                                encounter = editedEncounter,
                                                patientId = currentItem.patientId,
                                                visitId = currentItem.visitId,
                                                station = station
                                            )
                                            app.extractionQueue.markSaved(queueId, savedId)
                                            onSaved(savedId, currentItem.visitId)
                                        } catch (e: Exception) {
                                            actionError = "Save failed: ${e.message}"
                                            isSaving = false
                                        }
                                    }
                                },
                                enabled = !isSaving,
                                modifier = Modifier.fillMaxWidth()
                            ) {
                                if (isSaving) {
                                    CircularProgressIndicator(modifier = Modifier.height(20.dp))
                                } else {
                                    Text(stringResource(R.string.save))
                                }
                            }
                        }

                        ExtractionQueueRepository.QueueStatus.SAVED -> Unit
                    }

                    OutlinedButton(
                        onClick = { app.extractionQueue.delete(queueId); onBack() },
                        modifier = Modifier.fillMaxWidth()
                    ) {
                        Text(stringResource(R.string.remove_from_queue))
                    }
                }
            }
        }
    }
}

@Composable
private fun SummaryBlock(title: String, body: String) {
    Card(
        modifier = Modifier.fillMaxWidth(),
        colors = CardDefaults.cardColors(containerColor = MaterialTheme.colorScheme.surfaceVariant)
    ) {
        Column(modifier = Modifier.padding(16.dp)) {
            Text(title, style = MaterialTheme.typography.labelLarge, fontWeight = FontWeight.SemiBold)
            Spacer(Modifier.height(6.dp))
            Text(body, style = MaterialTheme.typography.bodyMedium)
        }
    }
}
