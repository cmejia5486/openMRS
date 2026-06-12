package com.chartlite.app.ui.screens

import android.content.ClipData
import android.content.ClipboardManager
import android.content.Context
import android.widget.Toast
import androidx.compose.foundation.background
import androidx.compose.foundation.layout.*
import androidx.compose.foundation.lazy.LazyColumn
import androidx.compose.foundation.rememberScrollState
import androidx.compose.foundation.shape.RoundedCornerShape
import androidx.compose.foundation.verticalScroll
import androidx.compose.material.icons.Icons
import androidx.compose.material.icons.automirrored.filled.ArrowBack
import androidx.compose.material.icons.filled.*
import androidx.compose.material3.*
import androidx.compose.runtime.*
import androidx.compose.ui.Alignment
import androidx.compose.ui.Modifier
import androidx.compose.ui.draw.clip
import androidx.compose.ui.graphics.Color
import androidx.compose.ui.graphics.vector.ImageVector
import androidx.compose.ui.platform.LocalContext
import androidx.compose.ui.res.stringResource
import androidx.compose.ui.text.font.FontFamily
import androidx.compose.ui.text.font.FontWeight
import androidx.compose.ui.unit.dp
import com.chartlite.app.App
import com.chartlite.app.R
import com.chartlite.app.billing.IntegrationPayloads
import com.chartlite.app.database.entity.EncounterEntity
import com.chartlite.app.model.Diagnosis
import com.chartlite.app.model.Medication
import com.chartlite.app.ui.components.BatchProcessingStatusCard
import com.chartlite.app.ui.theme.*
import com.google.gson.Gson
import com.google.gson.reflect.TypeToken
import kotlinx.coroutines.launch
import java.time.Instant
import java.time.LocalDate
import java.time.ZoneId
import java.time.format.DateTimeFormatter

/**
 * Facility Dashboard — auto-generated from clinical encounters.
 *
 * Aggregates encounter data from the local database:
 * - Patients seen today/this week/this month
 * - Top diagnoses by frequency
 * - Medications prescribed by volume
 * - Vital sign distributions
 *
 * "Export to DHIS2" button navigates to the full DHIS2ExportScreen.
 */
@OptIn(ExperimentalMaterial3Api::class)
@Composable
fun FacilityDashboardScreen(
    onBack: () -> Unit,
    onDHIS2Export: () -> Unit = {},
    onExtractionQueue: () -> Unit = {}
) {
    val context = LocalContext.current
    val app = context.applicationContext as App
    val gson = remember { Gson() }
    val scope = rememberCoroutineScope()

    var encounters by remember { mutableStateOf<List<EncounterEntity>>(emptyList()) }
    var patientCount by remember { mutableIntStateOf(0) }
    var providerCount by remember { mutableIntStateOf(0) }
    var isLoading by remember { mutableStateOf(true) }

    val today = LocalDate.now()
    val todayStart = today.atStartOfDay(ZoneId.systemDefault()).toInstant().toEpochMilli()
    val weekStart = today.minusDays(7).atStartOfDay(ZoneId.systemDefault()).toInstant().toEpochMilli()
    val monthStart = today.minusDays(30).atStartOfDay(ZoneId.systemDefault()).toInstant().toEpochMilli()
    val now = System.currentTimeMillis()

    LaunchedEffect(Unit) {
        // Load only last 30 days instead of entire history for better performance
        encounters = app.encounterRepository.getByDateRange(monthStart, now)
        patientCount = app.patientRepository.getCount()
        val facilityId = app.appConfig.facilityId
        providerCount = app.database.userDao().getActiveByFacilityId(facilityId).size
        isLoading = false
    }

    val todayCount = remember(encounters) { encounters.count { it.timestamp >= todayStart } }
    val weekCount = remember(encounters) { encounters.count { it.timestamp >= weekStart } }
    val monthCount = remember(encounters) { encounters.count { it.timestamp >= monthStart } }

    // Aggregate diagnoses
    val topDiagnoses = remember(encounters) {
        encounters.flatMap { enc ->
            try {
                val dxList: List<Diagnosis> = gson.fromJson(
                    enc.diagnoses, object : TypeToken<List<Diagnosis>>() {}.type
                ) ?: emptyList()
                dxList.map { it.description }
            } catch (_: Exception) { emptyList() }
        }.groupingBy { it }.eachCount().entries
            .sortedByDescending { it.value }
            .take(10)
    }

    // Aggregate medications
    val topMedications = remember(encounters) {
        encounters.flatMap { enc ->
            try {
                val medList: List<Medication> = gson.fromJson(
                    enc.medications, object : TypeToken<List<Medication>>() {}.type
                ) ?: emptyList()
                medList.map { it.name }
            } catch (_: Exception) { emptyList() }
        }.groupingBy { it }.eachCount().entries
            .sortedByDescending { it.value }
            .take(10)
    }

    // Pre-compute disease burden outside LazyColumn (not a composable scope)
    val allDiagnosesWithCodes = remember(encounters) {
        encounters.flatMap { enc ->
            try {
                val dxList: List<Diagnosis> = gson.fromJson(
                    enc.diagnoses, object : TypeToken<List<Diagnosis>>() {}.type
                ) ?: emptyList()
                dxList.map { it.icd10Code to it.description }
            } catch (_: Exception) { emptyList() }
        }
    }
    val diseaseBurden = remember(allDiagnosesWithCodes) {
        IntegrationPayloads.buildPopulationHealth(allDiagnosesWithCodes, encounters.size)
    }
    var showDHIS2 by remember { mutableStateOf(false) }
    val period = remember {
        DateTimeFormatter.ofPattern("yyyyMM").format(LocalDate.now())
    }

    Scaffold(
        topBar = {
            TopAppBar(
                title = {
                    Column {
                        Text(stringResource(R.string.facility_dashboard))
                        Text(stringResource(R.string.dashboard_subtitle),
                            style = MaterialTheme.typography.bodySmall,
                            color = MaterialTheme.colorScheme.onSurfaceVariant)
                    }
                },
                navigationIcon = {
                    IconButton(onClick = onBack) {
                        Icon(Icons.AutoMirrored.Filled.ArrowBack, contentDescription = stringResource(R.string.back))
                    }
                }
            )
        }
    ) { padding ->
        if (isLoading) {
            Box(Modifier.fillMaxSize().padding(padding), contentAlignment = Alignment.Center) {
                CircularProgressIndicator()
            }
            return@Scaffold
        }

        LazyColumn(
            modifier = Modifier
                .fillMaxSize()
                .padding(padding),
            contentPadding = PaddingValues(16.dp),
            verticalArrangement = Arrangement.spacedBy(16.dp)
        ) {
            // Summary stats
            item(key = "stats_row_1") {
                Row(
                    modifier = Modifier.fillMaxWidth(),
                    horizontalArrangement = Arrangement.spacedBy(8.dp)
                ) {
                    DashboardStat(stringResource(R.string.today), "$todayCount", stringResource(R.string.encounters), BrandGreen, Modifier.weight(1f))
                    DashboardStat(stringResource(R.string.encounters_week), "$weekCount", stringResource(R.string.encounters), InfoBlue, Modifier.weight(1f))
                    DashboardStat(stringResource(R.string.encounters_month), "$monthCount", stringResource(R.string.encounters), AccentOrange, Modifier.weight(1f))
                }
            }

            item(key = "stats_row_2") {
                Row(
                    modifier = Modifier.fillMaxWidth(),
                    horizontalArrangement = Arrangement.spacedBy(8.dp)
                ) {
                    DashboardStat(stringResource(R.string.total), "${encounters.size}", stringResource(R.string.encounters), Neutral700, Modifier.weight(1f))
                    DashboardStat(stringResource(R.string.patients), "$patientCount", stringResource(R.string.registered), BrandGreenDark, Modifier.weight(1f))
                    DashboardStat(stringResource(R.string.providers), "$providerCount", stringResource(R.string.active), InfoBlue, Modifier.weight(1f))
                }
            }

            // Top diagnoses
            item(key = "top_diagnoses") { DashboardSection(
                icon = Icons.Default.MedicalServices,
                title = stringResource(R.string.top_diagnoses)
            ) {
                if (topDiagnoses.isEmpty()) {
                    Text(stringResource(R.string.no_encounters_recorded),
                        style = MaterialTheme.typography.bodyMedium,
                        color = Neutral500)
                } else {
                    topDiagnoses.forEachIndexed { index, (name, count) ->
                        Row(
                            modifier = Modifier.fillMaxWidth().padding(vertical = 4.dp),
                            horizontalArrangement = Arrangement.SpaceBetween,
                            verticalAlignment = Alignment.CenterVertically
                        ) {
                            Row(
                                modifier = Modifier.weight(1f),
                                verticalAlignment = Alignment.CenterVertically
                            ) {
                                Text(
                                    "${index + 1}.",
                                    style = MaterialTheme.typography.bodySmall,
                                    color = Neutral500,
                                    modifier = Modifier.width(24.dp)
                                )
                                Text(name, style = MaterialTheme.typography.bodyMedium)
                            }
                            Surface(
                                color = BrandGreenSurface,
                                shape = RoundedCornerShape(4.dp)
                            ) {
                                Text(
                                    "$count",
                                    modifier = Modifier.padding(horizontal = 8.dp, vertical = 2.dp),
                                    style = MaterialTheme.typography.labelMedium,
                                    fontWeight = FontWeight.Bold,
                                    color = BrandGreenDark
                                )
                            }
                        }
                    }
                }
            } }

            // Top medications
            item(key = "top_medications") { DashboardSection(
                icon = Icons.Default.Medication,
                title = stringResource(R.string.medications_prescribed)
            ) {
                if (topMedications.isEmpty()) {
                    Text(stringResource(R.string.no_medications_recorded),
                        style = MaterialTheme.typography.bodyMedium,
                        color = Neutral500)
                } else {
                    topMedications.forEachIndexed { index, (name, count) ->
                        Row(
                            modifier = Modifier.fillMaxWidth().padding(vertical = 4.dp),
                            horizontalArrangement = Arrangement.SpaceBetween,
                            verticalAlignment = Alignment.CenterVertically
                        ) {
                            Row(
                                modifier = Modifier.weight(1f),
                                verticalAlignment = Alignment.CenterVertically
                            ) {
                                Text(
                                    "${index + 1}.",
                                    style = MaterialTheme.typography.bodySmall,
                                    color = Neutral500,
                                    modifier = Modifier.width(24.dp)
                                )
                                Text(name, style = MaterialTheme.typography.bodyMedium)
                            }
                            Surface(
                                color = InfoBlueSurface,
                                shape = RoundedCornerShape(4.dp)
                            ) {
                                Text(
                                    "$count",
                                    modifier = Modifier.padding(horizontal = 8.dp, vertical = 2.dp),
                                    style = MaterialTheme.typography.labelMedium,
                                    fontWeight = FontWeight.Bold,
                                    color = InfoBlue
                                )
                            }
                        }
                    }
                }
            } }

            // ── Population Health / Disease Burden ──
            item(key = "disease_burden") { DashboardSection(
                icon = Icons.Default.BarChart,
                title = stringResource(R.string.disease_burden_icd10)
            ) {
                if (diseaseBurden.isEmpty()) {
                    Text(stringResource(R.string.no_diagnoses_recorded),
                        style = MaterialTheme.typography.bodyMedium, color = Neutral500)
                } else {
                    val maxCount = diseaseBurden.maxOfOrNull { it.count }?.coerceAtLeast(1) ?: 1
                    diseaseBurden.forEach { burden ->
                        Column(modifier = Modifier.padding(vertical = 4.dp)) {
                            Row(
                                modifier = Modifier.fillMaxWidth(),
                                horizontalArrangement = Arrangement.SpaceBetween,
                                verticalAlignment = Alignment.CenterVertically
                            ) {
                                Text("${burden.chapterCode}: ${burden.chapter}",
                                    style = MaterialTheme.typography.bodySmall,
                                    fontWeight = FontWeight.Medium,
                                    modifier = Modifier.weight(1f))
                                Text("${burden.count} (${"%.0f".format(burden.percentage)}%)",
                                    style = MaterialTheme.typography.labelSmall,
                                    fontWeight = FontWeight.Bold, color = InfoBlue)
                            }
                            // Bar
                            val fraction = burden.count.toFloat() / maxCount
                            Box(
                                modifier = Modifier
                                    .fillMaxWidth()
                                    .height(8.dp)
                                    .clip(RoundedCornerShape(4.dp))
                                    .background(Neutral200)
                            ) {
                                Box(
                                    modifier = Modifier
                                        .fillMaxWidth(fraction)
                                        .fillMaxHeight()
                                        .clip(RoundedCornerShape(4.dp))
                                        .background(
                                            when {
                                                burden.percentage > 30f -> AlertRed
                                                burden.percentage > 15f -> AccentOrange
                                                else -> BrandGreen
                                            }
                                        )
                                )
                            }
                            // Top conditions in this chapter
                            burden.conditions.take(3).forEach { (name, count) ->
                                Text("  \u2022 $name ($count)",
                                    style = MaterialTheme.typography.labelSmall,
                                    color = Neutral600)
                            }
                        }
                    }
                }
            } }

            // ── DHIS2 Export ──
            // ── LLM Batch Extraction Queue ──
            item(key = "extraction_queue") {
                val queueState by app.extractionQueue.state.collectAsState()
                val queueItems by app.extractionQueue.items.collectAsState()
                val pendingCount = queueItems.count {
                    it.status == com.chartlite.app.extraction.ExtractionQueueRepository.QueueStatus.QUEUED ||
                        it.status == com.chartlite.app.extraction.ExtractionQueueRepository.QueueStatus.PROCESSING
                }
                val readyCount = queueItems.count {
                    it.status == com.chartlite.app.extraction.ExtractionQueueRepository.QueueStatus.READY
                }
                val failedCount = queueItems.count {
                    it.status == com.chartlite.app.extraction.ExtractionQueueRepository.QueueStatus.FAILED
                }
                val processedCount by app.extractionQueue.processedCount.collectAsState()
                val currentStep by app.extractionQueue.processingStep.collectAsState()
                val isProcessing = queueState == com.chartlite.app.extraction.ExtractionQueue.QueueState.PROCESSING
                val totalBatchItems = (processedCount + pendingCount).coerceAtLeast(pendingCount)

                if (pendingCount > 0 || readyCount > 0 || failedCount > 0 || isProcessing) {
                    Card(colors = CardDefaults.cardColors(containerColor = Neutral100)) {
                        Column(modifier = Modifier.padding(16.dp)) {
                            Row(verticalAlignment = Alignment.CenterVertically) {
                                Icon(Icons.Default.AutoAwesome, contentDescription = null,
                                    tint = BrandGreen)
                                Spacer(Modifier.width(8.dp))
                                Text(stringResource(R.string.extraction_queue),
                                    style = MaterialTheme.typography.titleMedium,
                                    fontWeight = FontWeight.SemiBold)
                            }
                            Spacer(Modifier.height(8.dp))
                            if (isProcessing) {
                                BatchProcessingStatusCard(
                                    processedCount = processedCount,
                                    totalCount = totalBatchItems,
                                    title = stringResource(R.string.batch_extraction_running),
                                    subtitle = stringResource(R.string.batch_extraction_subtitle),
                                    processingStep = currentStep
                                )
                            } else {
                                val failedSuffix = if (failedCount > 0) stringResource(R.string.failed_suffix_format, failedCount) else ""
                                Text(stringResource(R.string.queue_status_format, pendingCount, readyCount, failedSuffix),
                                    style = MaterialTheme.typography.bodySmall, color = Neutral600)
                            }
                            Spacer(Modifier.height(12.dp))
                            Row(horizontalArrangement = Arrangement.spacedBy(8.dp)) {
                                if (isProcessing) {
                                    OutlinedButton(onClick = { app.extractionQueue.cancelBatch() }) {
                                        Text(stringResource(R.string.cancel))
                                    }
                                } else {
                                    Button(onClick = {
                                        scope.launch {
                                            if (!app.prepareOnDeviceNoteProcessingForLowRam { msg ->
                                                    Toast.makeText(context, msg, Toast.LENGTH_SHORT).show()
                                                }) {
                                                return@launch
                                            }
                                            app.extractionQueue.processBatch()
                                        }
                                    }) {
                                        Icon(Icons.Default.PlayArrow, contentDescription = stringResource(R.string.process_queue),
                                            modifier = Modifier.size(18.dp))
                                        Spacer(Modifier.width(4.dp))
                                        Text(stringResource(R.string.process_queue))
                                    }
                                }
                                OutlinedButton(onClick = onExtractionQueue) {
                                    Text(stringResource(R.string.open_queue))
                                }
                            }
                        }
                    }
                    Spacer(Modifier.height(16.dp))
                }
            }

            item(key = "dhis2_export") { Card(
                colors = CardDefaults.cardColors(containerColor = Neutral100)
            ) {
                Column(modifier = Modifier.padding(16.dp)) {
                    Row(verticalAlignment = Alignment.CenterVertically) {
                        Icon(Icons.Default.CloudUpload, contentDescription = null,
                            tint = InfoBlue)
                        Spacer(Modifier.width(8.dp))
                        Text(stringResource(R.string.dhis2_integration),
                            style = MaterialTheme.typography.titleMedium,
                            fontWeight = FontWeight.SemiBold)
                    }
                    Spacer(Modifier.height(8.dp))
                    Text(stringResource(R.string.dhis2_export_description),
                        style = MaterialTheme.typography.bodySmall,
                        color = Neutral600)
                    Spacer(Modifier.height(4.dp))
                    Text(stringResource(R.string.dhis2_period_format, period, encounters.size, topDiagnoses.size),
                        style = MaterialTheme.typography.labelSmall,
                        color = Neutral500)
                    Spacer(Modifier.height(12.dp))
                    Row(horizontalArrangement = Arrangement.spacedBy(8.dp)) {
                        Button(
                            onClick = { showDHIS2 = true },
                            enabled = encounters.isNotEmpty()
                        ) {
                            Icon(Icons.Default.Visibility, contentDescription = stringResource(R.string.preview),
                                modifier = Modifier.size(18.dp))
                            Spacer(Modifier.width(4.dp))
                            Text(stringResource(R.string.preview_dhis2_payload))
                        }
                        OutlinedButton(
                            onClick = onDHIS2Export
                        ) {
                            Icon(Icons.Default.CloudUpload, contentDescription = stringResource(R.string.dhis2_export),
                                modifier = Modifier.size(18.dp))
                            Spacer(Modifier.width(4.dp))
                            Text(stringResource(R.string.dhis2_export))
                        }
                    }
                }
            }

            }
        }

        // DHIS2 preview dialog (outside LazyColumn — dialogs are overlay composables)
        if (showDHIS2) {
            val dhis2Payload = remember {
                IntegrationPayloads.buildDHIS2DataValueSets(
                    facilityId = app.appConfig.facilityId.ifBlank { "FACILITY_001" },
                    period = period,
                    encounters = encounters,
                    topDiagnoses = topDiagnoses.map { it.key to it.value },
                    topMedications = topMedications.map { it.key to it.value },
                    totalPatients = patientCount
                )
            }
            val dhis2CopiedMsg = stringResource(R.string.dhis2_payload_copied)
            AlertDialog(
                onDismissRequest = { showDHIS2 = false },
                title = { Text(stringResource(R.string.dhis2_data_value_sets), fontWeight = FontWeight.Bold) },
                text = {
                    Column(Modifier.verticalScroll(rememberScrollState())) {
                        Card(colors = CardDefaults.cardColors(containerColor = Neutral100)) {
                            Text(
                                dhis2Payload,
                                modifier = Modifier.padding(12.dp),
                                style = MaterialTheme.typography.labelSmall,
                                fontFamily = FontFamily.Monospace
                            )
                        }
                        Spacer(Modifier.height(8.dp))
                        Text(stringResource(R.string.dhis2_post_description),
                            style = MaterialTheme.typography.bodySmall, color = Neutral600)
                    }
                },
                confirmButton = {
                    TextButton(onClick = {
                        val clipboard = context.getSystemService(Context.CLIPBOARD_SERVICE) as? ClipboardManager
                        clipboard?.setPrimaryClip(ClipData.newPlainText("DHIS2", dhis2Payload))
                        Toast.makeText(context, dhis2CopiedMsg, Toast.LENGTH_SHORT).show()
                    }) { Text(stringResource(R.string.copy)) }
                },
                dismissButton = {
                    TextButton(onClick = { showDHIS2 = false }) { Text(stringResource(R.string.close)) }
                }
            )
        }
    }
}

@Composable
private fun DashboardStat(
    label: String,
    value: String,
    unit: String,
    color: Color,
    modifier: Modifier = Modifier
) {
    Surface(
        modifier = modifier,
        shape = RoundedCornerShape(12.dp),
        color = MaterialTheme.colorScheme.surface,
        shadowElevation = 1.dp
    ) {
        Column(
            modifier = Modifier.padding(12.dp),
            horizontalAlignment = Alignment.CenterHorizontally
        ) {
            Text(value,
                style = MaterialTheme.typography.headlineSmall,
                fontWeight = FontWeight.Bold,
                color = color)
            Text(unit,
                style = MaterialTheme.typography.labelSmall,
                color = Neutral500)
            Text(label,
                style = MaterialTheme.typography.labelSmall,
                fontWeight = FontWeight.Medium,
                color = Neutral700)
        }
    }
}

@Composable
private fun DashboardSection(
    icon: ImageVector,
    title: String,
    content: @Composable ColumnScope.() -> Unit
) {
    Card(modifier = Modifier.fillMaxWidth()) {
        Column(modifier = Modifier.padding(16.dp)) {
            Row(
                verticalAlignment = Alignment.CenterVertically,
                modifier = Modifier.padding(bottom = 12.dp)
            ) {
                Icon(icon, contentDescription = title,
                    modifier = Modifier.size(20.dp),
                    tint = MaterialTheme.colorScheme.primary)
                Spacer(Modifier.width(8.dp))
                Text(title,
                    style = MaterialTheme.typography.titleMedium,
                    fontWeight = FontWeight.SemiBold)
            }
            content()
        }
    }
}
