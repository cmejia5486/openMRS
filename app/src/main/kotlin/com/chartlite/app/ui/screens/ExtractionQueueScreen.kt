package com.chartlite.app.ui.screens

import android.widget.Toast
import androidx.compose.foundation.layout.Arrangement
import androidx.compose.foundation.layout.Column
import androidx.compose.foundation.layout.Row
import androidx.compose.foundation.layout.Spacer
import androidx.compose.foundation.layout.fillMaxSize
import androidx.compose.foundation.layout.fillMaxWidth
import androidx.compose.foundation.layout.height
import androidx.compose.foundation.layout.padding
import androidx.compose.foundation.layout.width
import androidx.compose.foundation.lazy.LazyColumn
import androidx.compose.foundation.lazy.items
import androidx.compose.material.icons.Icons
import androidx.compose.material.icons.automirrored.filled.ArrowBack
import androidx.compose.material.icons.filled.AutoAwesome
import androidx.compose.material.icons.filled.Delete
import androidx.compose.material.icons.filled.PlayArrow
import androidx.compose.material.icons.filled.Refresh
import androidx.compose.material3.Button
import androidx.compose.material3.Card
import androidx.compose.material3.CardDefaults
import androidx.compose.material3.ExperimentalMaterial3Api
import androidx.compose.material3.HorizontalDivider
import androidx.compose.material3.Icon
import androidx.compose.material3.IconButton
import androidx.compose.material3.MaterialTheme
import androidx.compose.material3.OutlinedButton
import androidx.compose.material3.Scaffold
import androidx.compose.material3.Surface
import androidx.compose.material3.Text
import androidx.compose.material3.TopAppBar
import androidx.compose.runtime.Composable
import androidx.compose.runtime.LaunchedEffect
import androidx.compose.runtime.collectAsState
import androidx.compose.runtime.getValue
import androidx.compose.runtime.mutableStateMapOf
import androidx.compose.runtime.remember
import androidx.compose.runtime.rememberCoroutineScope
import androidx.compose.ui.Modifier
import androidx.compose.ui.platform.LocalContext
import androidx.compose.ui.text.font.FontWeight
import androidx.compose.ui.unit.dp
import com.chartlite.app.App
import com.chartlite.app.extraction.ExtractionQueueRepository
import com.chartlite.app.ui.components.BatchProcessingStatusCard
import java.time.ZoneId
import java.time.format.DateTimeFormatter
import androidx.compose.ui.res.stringResource
import com.chartlite.app.R
import kotlinx.coroutines.launch

@OptIn(ExperimentalMaterial3Api::class)
@Composable
fun ExtractionQueueScreen(
    onBack: () -> Unit,
    onReviewQueueItem: (String) -> Unit
) {
    val context = LocalContext.current
    val app = context.applicationContext as App
    val items by app.extractionQueue.items.collectAsState()
    val queueState by app.extractionQueue.state.collectAsState()
    val processedCount by app.extractionQueue.processedCount.collectAsState()
    val currentStep by app.extractionQueue.processingStep.collectAsState()
    val patientNames = remember { mutableStateMapOf<String, String>() }
    val scope = rememberCoroutineScope()

    LaunchedEffect(items) {
        items.map { it.patientId }.distinct().forEach { patientId ->
            if (patientId !in patientNames) {
                val patient = app.patientRepository.getById(patientId)
                patientNames[patientId] = patient?.let { "${it.firstName} ${it.lastName}" } ?: patientId
            }
        }
    }

    val queuedItems = items.filter {
        it.status == ExtractionQueueRepository.QueueStatus.QUEUED ||
            it.status == ExtractionQueueRepository.QueueStatus.PROCESSING
    }
    val readyItems = items.filter { it.status == ExtractionQueueRepository.QueueStatus.READY }
    val failedItems = items.filter { it.status == ExtractionQueueRepository.QueueStatus.FAILED }
    val totalBatchItems = (processedCount + queuedItems.size).coerceAtLeast(queuedItems.size)

    Scaffold(
        topBar = {
            TopAppBar(
                title = { Text(stringResource(R.string.extraction_queue)) },
                navigationIcon = {
                    IconButton(onClick = onBack) {
                        Icon(Icons.AutoMirrored.Filled.ArrowBack, contentDescription = stringResource(R.string.back))
                    }
                }
            )
        }
    ) { padding ->
        if (items.isEmpty() && queueState != com.chartlite.app.extraction.ExtractionQueue.QueueState.PROCESSING) {
            Column(
                modifier = Modifier
                    .fillMaxSize()
                    .padding(padding)
                    .padding(24.dp),
                verticalArrangement = Arrangement.Center
            ) {
                Text(stringResource(R.string.no_queued_jobs), style = MaterialTheme.typography.titleMedium)
                Spacer(Modifier.height(8.dp))
                Text(
                    stringResource(R.string.queue_batch_hint),
                    style = MaterialTheme.typography.bodyMedium,
                    color = MaterialTheme.colorScheme.onSurfaceVariant
                )
            }
            return@Scaffold
        }

        LazyColumn(
            modifier = Modifier
                .fillMaxSize()
                .padding(padding),
            verticalArrangement = Arrangement.spacedBy(12.dp)
        ) {
            item {
                Card(
                    modifier = Modifier
                        .fillMaxWidth()
                        .padding(horizontal = 16.dp, vertical = 12.dp),
                    colors = CardDefaults.cardColors(containerColor = MaterialTheme.colorScheme.surfaceVariant)
                ) {
                    Column(modifier = Modifier.padding(16.dp)) {
                        Row(horizontalArrangement = Arrangement.spacedBy(8.dp)) {
                            StatusPill(stringResource(R.string.pending_count_format, queuedItems.size))
                            StatusPill(stringResource(R.string.ready_count_format, readyItems.size))
                            if (failedItems.isNotEmpty()) {
                                StatusPill(stringResource(R.string.failed_count_format, failedItems.size))
                            }
                        }
                        Spacer(Modifier.height(12.dp))
                        if (queueState == com.chartlite.app.extraction.ExtractionQueue.QueueState.PROCESSING) {
                            BatchProcessingStatusCard(
                                processedCount = processedCount,
                                totalCount = totalBatchItems,
                                title = stringResource(R.string.processing_queued_notes_title),
                                subtitle = stringResource(R.string.processing_queued_subtitle),
                                processingStep = currentStep
                            )
                            Spacer(Modifier.height(12.dp))
                            OutlinedButton(onClick = { app.extractionQueue.cancelBatch() }) {
                                Text(stringResource(R.string.cancel_batch_label))
                            }
                        } else {
                            Button(
                                onClick = {
                                    scope.launch {
                                        if (!app.prepareOnDeviceNoteProcessingForLowRam { msg ->
                                                Toast.makeText(context, msg, Toast.LENGTH_SHORT).show()
                                            }) {
                                            return@launch
                                        }
                                        app.extractionQueue.processBatch()
                                    }
                                },
                                enabled = queuedItems.isNotEmpty()
                            ) {
                                Icon(Icons.Default.PlayArrow, contentDescription = stringResource(R.string.process_queued_notes))
                                Spacer(Modifier.width(8.dp))
                                Text(stringResource(R.string.process_queued_notes))
                            }
                        }
                    }
                }
            }

            if (readyItems.isNotEmpty()) {
                item { SectionHeader(stringResource(R.string.ready_for_review_section)) }
                items(readyItems, key = { it.id }) { item ->
                    QueueItemCard(
                        item = item,
                        patientName = patientNames[item.patientId] ?: item.patientId,
                        primaryActionLabel = stringResource(R.string.review_and_save),
                        onPrimaryAction = { onReviewQueueItem(item.id) },
                        onSecondaryAction = { app.extractionQueue.delete(item.id) },
                        secondaryIcon = Icons.Default.Delete,
                        secondaryLabel = stringResource(R.string.remove)
                    )
                }
            }

            if (queuedItems.isNotEmpty()) {
                item { SectionHeader(stringResource(R.string.pending_section)) }
                items(queuedItems, key = { it.id }) { item ->
                    QueueItemCard(
                        item = item,
                        patientName = patientNames[item.patientId] ?: item.patientId,
                        primaryActionLabel = stringResource(R.string.review_transcript),
                        onPrimaryAction = { onReviewQueueItem(item.id) },
                        onSecondaryAction = { app.extractionQueue.delete(item.id) },
                        secondaryIcon = Icons.Default.Delete,
                        secondaryLabel = stringResource(R.string.delete)
                    )
                }
            }

            if (failedItems.isNotEmpty()) {
                item { SectionHeader(stringResource(R.string.failed_section)) }
                items(failedItems, key = { it.id }) { item ->
                    QueueItemCard(
                        item = item,
                        patientName = patientNames[item.patientId] ?: item.patientId,
                        primaryActionLabel = stringResource(R.string.retry_label),
                        onPrimaryAction = { app.extractionQueue.retry(item.id) },
                        onSecondaryAction = { app.extractionQueue.delete(item.id) },
                        secondaryIcon = Icons.Default.Delete,
                        secondaryLabel = stringResource(R.string.delete)
                    )
                }
            }
        }
    }
}

@Composable
private fun SectionHeader(title: String) {
    Column(modifier = Modifier.padding(horizontal = 16.dp)) {
        Text(title, style = MaterialTheme.typography.titleMedium, fontWeight = FontWeight.SemiBold)
        Spacer(Modifier.height(8.dp))
        HorizontalDivider()
    }
}

@Composable
private fun StatusPill(label: String) {
    Surface(
        color = MaterialTheme.colorScheme.primary.copy(alpha = 0.12f),
        shape = MaterialTheme.shapes.small
    ) {
        Text(
            label,
            modifier = Modifier.padding(horizontal = 8.dp, vertical = 4.dp),
            style = MaterialTheme.typography.labelMedium,
            color = MaterialTheme.colorScheme.primary
        )
    }
}

@Composable
private fun QueueItemCard(
    item: ExtractionQueueRepository.QueueItem,
    patientName: String,
    primaryActionLabel: String,
    onPrimaryAction: () -> Unit,
    onSecondaryAction: () -> Unit,
    secondaryIcon: androidx.compose.ui.graphics.vector.ImageVector,
    secondaryLabel: String
) {
    val formatter = remember {
        DateTimeFormatter.ofPattern("dd MMM, HH:mm").withZone(ZoneId.systemDefault())
    }
    Card(
        modifier = Modifier
            .fillMaxWidth()
            .padding(horizontal = 16.dp),
        colors = CardDefaults.cardColors(containerColor = MaterialTheme.colorScheme.surface)
    ) {
        Column(modifier = Modifier.padding(16.dp)) {
            Text(patientName, style = MaterialTheme.typography.titleSmall, fontWeight = FontWeight.SemiBold)
            Text(item.patientId, style = MaterialTheme.typography.bodySmall, color = MaterialTheme.colorScheme.outline)
            Spacer(Modifier.height(4.dp))
            Text(
                "${when (item.status) {
                    ExtractionQueueRepository.QueueStatus.QUEUED -> "Queued"
                    ExtractionQueueRepository.QueueStatus.PROCESSING -> "Processing"
                    ExtractionQueueRepository.QueueStatus.READY -> "Ready for review"
                    ExtractionQueueRepository.QueueStatus.FAILED -> "Failed"
                    ExtractionQueueRepository.QueueStatus.SAVED -> "Saved"
                }} • ${formatter.format(item.createdAt)}",
                style = MaterialTheme.typography.labelSmall,
                color = MaterialTheme.colorScheme.outline
            )
            item.errorMessage?.let {
                Spacer(Modifier.height(8.dp))
                Text(it, style = MaterialTheme.typography.bodySmall, color = MaterialTheme.colorScheme.error)
            }
            Spacer(Modifier.height(8.dp))
            Text(item.transcript.take(220), style = MaterialTheme.typography.bodySmall)
            Spacer(Modifier.height(12.dp))
            Row(horizontalArrangement = Arrangement.spacedBy(8.dp)) {
                Button(onClick = onPrimaryAction) {
                    if (item.status == ExtractionQueueRepository.QueueStatus.FAILED) {
                        Icon(Icons.Default.Refresh, contentDescription = "Refresh")
                    } else {
                        Icon(Icons.Default.AutoAwesome, contentDescription = "Auto extract")
                    }
                    Text(primaryActionLabel)
                }
                OutlinedButton(onClick = onSecondaryAction) {
                    Icon(secondaryIcon, contentDescription = secondaryLabel)
                    Text(secondaryLabel)
                }
            }
        }
    }
}
