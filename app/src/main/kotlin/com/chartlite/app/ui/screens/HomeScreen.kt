package com.chartlite.app.ui.screens

import android.widget.Toast
import androidx.compose.foundation.background
import androidx.compose.foundation.clickable
import androidx.compose.foundation.layout.*
import androidx.compose.foundation.lazy.LazyColumn
import androidx.compose.foundation.lazy.items
import androidx.compose.foundation.shape.CircleShape
import androidx.compose.foundation.shape.RoundedCornerShape
import androidx.compose.material.icons.Icons
import androidx.compose.material.icons.automirrored.filled.Send
import androidx.compose.material.icons.filled.*
import androidx.compose.material.icons.outlined.*
import androidx.compose.material3.*
import androidx.compose.runtime.*
import androidx.compose.ui.Alignment
import androidx.compose.ui.Modifier
import androidx.compose.ui.draw.clip
import androidx.compose.ui.graphics.Brush
import androidx.compose.ui.graphics.Color
import androidx.compose.ui.graphics.vector.ImageVector
import androidx.compose.ui.platform.LocalContext
import androidx.compose.ui.res.stringResource
import androidx.compose.ui.text.font.FontWeight
import com.chartlite.app.R
import androidx.compose.ui.unit.dp
import androidx.compose.ui.unit.sp
import com.chartlite.app.App
import com.chartlite.app.database.entity.EncounterEntity
import com.chartlite.app.database.entity.PatientEntity
import com.chartlite.app.database.entity.VisitEntity
import com.chartlite.app.model.ClinicStation
import com.chartlite.app.cdss.VitalAlerts
import com.chartlite.app.model.*
import com.chartlite.app.ui.components.EncounterCard
import com.chartlite.app.ui.components.BatchProcessingStatusCard
import com.chartlite.app.ui.components.QueueCard
import com.chartlite.app.ui.components.StationSwitcher
import com.chartlite.app.ui.components.VoiceTriageCard
import com.chartlite.app.asr.ModelDownloader
import com.chartlite.app.ui.theme.*
import kotlinx.coroutines.Dispatchers
import kotlinx.coroutines.launch
import kotlinx.coroutines.withContext
import java.time.Instant
import java.util.UUID

@OptIn(ExperimentalMaterial3Api::class)
@Composable
fun HomeScreen(
    onNewPatient: () -> Unit,
    onFindPatient: () -> Unit,
    onReadSMS: () -> Unit,
    onSync: () -> Unit,
    onSettings: () -> Unit,
    onDashboard: () -> Unit = {},
    onExtractionQueue: () -> Unit = {},
    onAppointments: () -> Unit = {},
    onStockManagement: () -> Unit = {},
    onReferrals: () -> Unit = {},
    onClinicalProtocols: () -> Unit = {},
    onAppointmentReminders: () -> Unit = {},
    onFacilityDirectory: () -> Unit = {},
    onPatientSelected: (String) -> Unit,
    onStartTriage: (patientId: String, visitId: String) -> Unit = { _, _ -> },
    onStartConsultation: (patientId: String, visitId: String) -> Unit = { _, _ -> },
    onStartPharmacy: (visitId: String) -> Unit = {},
) {
    val context = LocalContext.current
    val app = context.applicationContext as App
    var currentRole by remember { mutableStateOf(app.sessionManager.currentSession?.role) }
    val extractionReady by app.extractionServicesReady.collectAsState()
    val extractionQueue = if (extractionReady) app.peekExtractionQueue() else null
    val idleExtractionQueueState = remember {
        kotlinx.coroutines.flow.MutableStateFlow(com.chartlite.app.extraction.ExtractionQueue.QueueState.IDLE)
    }
    val idleProcessedCount = remember { kotlinx.coroutines.flow.MutableStateFlow(0) }
    val idleProcessingStep = remember {
        kotlinx.coroutines.flow.MutableStateFlow(com.chartlite.app.extraction.ExtractionQueue.ProcessingStep.IDLE)
    }
    val extractionItems by app.extractionQueueRepository.observeActiveItems().collectAsState(initial = emptyList())
    val extractionQueueState by (extractionQueue?.state ?: idleExtractionQueueState).collectAsState()
    val processedCount by (extractionQueue?.processedCount ?: idleProcessedCount).collectAsState()
    val currentStep by (extractionQueue?.processingStep ?: idleProcessingStep).collectAsState()

    var recentEncounters by remember { mutableStateOf<List<EncounterEntity>>(emptyList()) }
    var patientCount by remember { mutableIntStateOf(0) }
    var todayCount by remember { mutableIntStateOf(0) }
    var isLoading by remember { mutableStateOf(true) }

    // Multi-station state
    val isMultiStation = app.appConfig.isMultiStation
    val enabledStations = remember(isMultiStation, currentRole) {
        if (isMultiStation) {
            app.appConfig.enabledStations.mapNotNull {
                try { ClinicStation.valueOf(it) } catch (_: Exception) { null }
            }.sortedBy { it.ordinal }.ifEmpty { ClinicStation.entries.toList() }.filter { station ->
                // Filter stations by role capability
                when (station) {
                    ClinicStation.REGISTRATION -> currentRole?.canRegister != false
                    ClinicStation.TRIAGE -> currentRole?.canTriage != false
                    ClinicStation.CONSULTATION -> currentRole?.canConsult != false
                    ClinicStation.PHARMACY -> currentRole?.canDispense != false
                }
            }
        } else emptyList()
    }
    var activeStation by remember {
        mutableStateOf(
            try { ClinicStation.valueOf(app.appConfig.activeStation) } catch (_: Exception) { ClinicStation.REGISTRATION }
        )
    }
    var queueCounts by remember { mutableStateOf<Map<ClinicStation, Int>>(emptyMap()) }
    var queueVisits by remember { mutableStateOf<List<VisitEntity>>(emptyList()) }
    var queuePatients by remember { mutableStateOf<Map<String, PatientEntity>>(emptyMap()) }
    // Badge counts for secondary action icons
    var appointmentBadge by remember { mutableIntStateOf(0) }
    var referralBadge by remember { mutableIntStateOf(0) }
    var reminderBadge by remember { mutableIntStateOf(0) }
    var smsBadge by remember { mutableIntStateOf(0) }
    var stockBadge by remember { mutableIntStateOf(0) }
    val scope = rememberCoroutineScope()

    // ASR offline readiness
    val asrDownloadState by app.asr.modelDownloader.state.collectAsState()
    // Continuous sync status (multi-station)
    val connectedPeers by app.syncEngine.connectedEndpoints.collectAsState()
    var expandedTriageVisitId by remember { mutableStateOf<String?>(null) }
    val snackbarHostState = remember { SnackbarHostState() }
    // Refresh key — incremented to force data reload when returning to HomeScreen
    var refreshKey by remember { mutableIntStateOf(0) }

    // Refresh data whenever HomeScreen becomes visible again
    val lifecycleOwner = androidx.lifecycle.compose.LocalLifecycleOwner.current
    DisposableEffect(lifecycleOwner) {
        val observer = androidx.lifecycle.LifecycleEventObserver { _, event ->
            if (event == androidx.lifecycle.Lifecycle.Event.ON_RESUME) {
                refreshKey++
            }
        }
        lifecycleOwner.lifecycle.addObserver(observer)
        onDispose { lifecycleOwner.lifecycle.removeObserver(observer) }
    }

    LaunchedEffect(refreshKey) {
        currentRole = app.sessionManager.currentSession?.role
        // Only load clinical data for roles that can view it
        if (currentRole?.canViewClinicalHistory != false) {
            recentEncounters = app.encounterRepository.getRecent(10)
        }
        patientCount = app.patientRepository.getCount()
        // Today's encounter count — direct DAO count (not limited by getRecent)
        val todayStart = java.time.LocalDate.now()
            .atStartOfDay(java.time.ZoneId.systemDefault()).toInstant().toEpochMilli()
        val todayEnd = todayStart + 86_400_000L
        todayCount = app.encounterRepository.getCountByDateRange(todayStart, todayEnd)
        // Badge counts
        try {
            appointmentBadge = app.appointmentRepository.getCountForDate(app.appConfig.facilityId, todayStart)
            referralBadge = app.referralRepository.getPendingCount(app.appConfig.facilityId)
            val pending = app.appointmentReminder.getPendingReminders()
            val sameDay = app.appointmentReminder.getSameDayReminders()
            reminderBadge = (pending + sameDay).distinctBy { it.appointment.id }.size
            // Received clinical SMS waiting to be read
            val smsPrefs = context.getSharedPreferences("pending_sms", android.content.Context.MODE_PRIVATE)
            smsBadge = (smsPrefs.getStringSet("messages", emptySet()) ?: emptySet()).size
            // Low stock items
            stockBadge = app.stockRepository.getLowStockCount(app.appConfig.facilityId)
        } catch (_: Exception) { /* non-critical */ }
        isLoading = false
    }

    LaunchedEffect(activeStation, isMultiStation, refreshKey) {
        if (!isMultiStation) return@LaunchedEffect
        // Load queue counts for all stations
        val counts = mutableMapOf<ClinicStation, Int>()
        for (station in ClinicStation.entries) {
            counts[station] = app.visitRepository.getQueueCount(station, app.appConfig.facilityId)
        }
        queueCounts = counts

        // Load queue for active station
        queueVisits = app.visitRepository.getQueueForStation(activeStation, app.appConfig.facilityId)

        // Load patient info for queue
        val patientMap = mutableMapOf<String, PatientEntity>()
        for (visit in queueVisits) {
            if (visit.patientId !in patientMap) {
                app.patientRepository.getById(visit.patientId)?.let {
                    patientMap[visit.patientId] = it
                }
            }
        }
        queuePatients = patientMap
    }

    Scaffold(
        containerColor = Neutral50,
        snackbarHost = { SnackbarHost(snackbarHostState) }
    ) { padding ->
        LazyColumn(
            modifier = Modifier
                .fillMaxSize()
                .padding(padding),
            contentPadding = PaddingValues(bottom = 24.dp)
        ) {
            // -- Header --
            item(key = "header") {
                Column(
                    modifier = Modifier
                        .fillMaxWidth()
                        .background(
                            Brush.verticalGradient(
                                listOf(Color.White, Neutral50)
                            )
                        )
                        .padding(horizontal = 20.dp)
                        .padding(top = 16.dp, bottom = 8.dp)
                ) {
                    Row(
                        modifier = Modifier.fillMaxWidth(),
                        horizontalArrangement = Arrangement.SpaceBetween,
                        verticalAlignment = Alignment.CenterVertically
                    ) {
                        Text(
                            stringResource(R.string.app_name),
                            style = MaterialTheme.typography.headlineLarge,
                            color = BrandGreenDark
                        )
                        if (currentRole?.canEditSettings != false) {
                            IconButton(
                                onClick = { onSettings() },
                                modifier = Modifier.size(48.dp)
                            ) {
                                Icon(Icons.Outlined.Settings, contentDescription = stringResource(R.string.settings),
                                    tint = Neutral500,
                                    modifier = Modifier.size(22.dp))
                            }
                        }
                    }
                    Text(
                        stringResource(R.string.voice_first_subtitle),
                        style = MaterialTheme.typography.bodySmall,
                        color = Neutral500
                    )
                }
            }

            // -- Station Switcher (multi-station only) --
            if (isMultiStation && enabledStations.isNotEmpty()) {
                item(key = "station_switcher") {
                    StationSwitcher(
                        stations = enabledStations,
                        activeStation = activeStation,
                        queueCounts = queueCounts,
                        onStationSelected = { station ->
                            activeStation = station
                            app.appConfig.activeStation = station.name
                        },
                        modifier = Modifier.padding(horizontal = 20.dp, vertical = 4.dp)
                    )
                }
            }

            // -- Stats row (multi-station mode only — operational queue counts) --
            if (isMultiStation) {
                item(key = "stats") {
                    val waiting = queueCounts[activeStation] ?: 0
                    val todayVisits = queueVisits.size
                    Row(
                        modifier = Modifier
                            .fillMaxWidth()
                            .padding(horizontal = 20.dp, vertical = 8.dp),
                        horizontalArrangement = Arrangement.spacedBy(12.dp)
                    ) {
                        StatChip("$waiting", stringResource(R.string.waiting), Modifier.weight(1f), accentColor = WarningAmber)
                        StatChip("$todayVisits", stringResource(R.string.in_queue), Modifier.weight(1f), accentColor = BrandGreen)
                        StatChip("$todayCount", stringResource(R.string.today), Modifier.weight(1f), accentColor = InfoBlue)
                    }
                }
            }

            // -- Quick actions --
            item(key = "actions") {
                if (isMultiStation) {
                    // Station-specific quick actions
                    Column(modifier = Modifier.padding(horizontal = 20.dp, vertical = 8.dp)) {
                        Text(
                            stringResource(R.string.quick_actions),
                            style = MaterialTheme.typography.labelMedium,
                            color = Neutral500,
                            letterSpacing = 1.5.sp,
                            modifier = Modifier.padding(bottom = 10.dp)
                        )
                        // Primary action depends on station; Find Patient is always second
                        val newPatientLabel = stringResource(R.string.new_patient)
                        val nextPatientLabel = stringResource(R.string.next_patient)
                        val (primaryIcon, primaryLabel, primaryClick) = when (activeStation) {
                            ClinicStation.REGISTRATION -> Triple(
                                Icons.Default.PersonAdd, newPatientLabel, onNewPatient
                            )
                            ClinicStation.TRIAGE -> Triple(
                                Icons.Default.MonitorHeart, nextPatientLabel,
                                { queueVisits.firstOrNull()?.let { onStartTriage(it.patientId, it.id) }; Unit }
                            )
                            ClinicStation.CONSULTATION -> Triple(
                                Icons.Default.MedicalServices, nextPatientLabel,
                                { queueVisits.firstOrNull()?.let { onStartConsultation(it.patientId, it.id) }; Unit }
                            )
                            ClinicStation.PHARMACY -> Triple(
                                Icons.Default.Medication, nextPatientLabel,
                                { queueVisits.firstOrNull()?.let { onStartPharmacy(it.id) }; Unit }
                            )
                        }
                        Row(
                            modifier = Modifier.fillMaxWidth(),
                            horizontalArrangement = Arrangement.spacedBy(10.dp)
                        ) {
                            QuickActionCard(
                                icon = primaryIcon,
                                label = primaryLabel,
                                color = BrandGreen,
                                modifier = Modifier.weight(1f),
                                onClick = primaryClick
                            )
                            QuickActionCard(
                                icon = Icons.Default.Search,
                                label = stringResource(R.string.find_patient),
                                color = InfoBlue,
                                modifier = Modifier.weight(1f),
                                onClick = onFindPatient
                            )
                        }
                    }
                } else {
                    // Solo mode quick actions
                    Column(modifier = Modifier.padding(horizontal = 20.dp, vertical = 8.dp)) {
                        Text(
                            stringResource(R.string.quick_actions),
                            style = MaterialTheme.typography.labelMedium,
                            color = Neutral500,
                            letterSpacing = 1.5.sp,
                            modifier = Modifier.padding(bottom = 10.dp)
                        )
                        // ── Primary: New + Find ──
                        Row(
                            modifier = Modifier.fillMaxWidth(),
                            horizontalArrangement = Arrangement.spacedBy(10.dp)
                        ) {
                            QuickActionCard(
                                icon = Icons.Default.PersonAdd,
                                label = stringResource(R.string.new_patient),
                                color = BrandGreen,
                                modifier = Modifier.weight(1f),
                                isPrimary = true,
                                onClick = onNewPatient
                            )
                            QuickActionCard(
                                icon = Icons.Default.Search,
                                label = stringResource(R.string.find_patient),
                                color = InfoBlue,
                                modifier = Modifier.weight(1f),
                                isPrimary = true,
                                onClick = onFindPatient
                            )
                        }
                        Spacer(Modifier.height(12.dp))
                        // ── Secondary: compact 4-column grid ──
                        data class ActionItem(val icon: ImageVector, val label: String, val onClick: () -> Unit, val badge: Int = 0)
                        // v1: focused core actions only. See ROADMAP.md for v2 features.
                        val secondaryActions = buildList {
                            add(ActionItem(Icons.Default.Sms, stringResource(R.string.read_sms), onReadSMS, smsBadge))
                            add(ActionItem(Icons.Default.Settings, stringResource(R.string.settings), onSettings))
                            if (currentRole?.canSync == true) {
                                add(ActionItem(Icons.Default.Sync, stringResource(R.string.sync), onSync))
                            }
                            // v2 features — hidden for v1 to keep the UI focused:
                            // add(ActionItem(Icons.Default.CalendarMonth, stringResource(R.string.appointments), onAppointments, appointmentBadge))
                            // add(ActionItem(Icons.Default.MedicalInformation, stringResource(R.string.protocols), onClinicalProtocols))
                            // add(ActionItem(Icons.AutoMirrored.Filled.Send, stringResource(R.string.referrals), onReferrals, referralBadge))
                            // add(ActionItem(Icons.Default.Inventory, stringResource(R.string.stock), onStockManagement, stockBadge))
                            // add(ActionItem(Icons.Default.NotificationsActive, stringResource(R.string.reminders), onAppointmentReminders, reminderBadge))
                            // add(ActionItem(Icons.Default.Dashboard, stringResource(R.string.dashboard), onDashboard))
                            // add(ActionItem(Icons.Default.LocalHospital, stringResource(R.string.facilities), onFacilityDirectory))
                        }
                        // ── Wrap grid so all actions are visible ──
                        // Use fewer columns on narrow phones to avoid overflow
                        val columns = if (secondaryActions.size <= 3) secondaryActions.size.coerceAtLeast(1) else 4
                        secondaryActions.chunked(columns).forEach { rowItems ->
                            Row(
                                modifier = Modifier.fillMaxWidth(),
                                horizontalArrangement = Arrangement.spacedBy(8.dp)
                            ) {
                                rowItems.forEach { item ->
                                    CompactActionItem(
                                        icon = item.icon,
                                        label = item.label,
                                        modifier = Modifier.weight(1f),
                                        badgeCount = item.badge,
                                        onClick = item.onClick
                                    )
                                }
                                // Fill empty slots to keep alignment
                                repeat(columns - rowItems.size) {
                                    Spacer(Modifier.weight(1f))
                                }
                            }
                            if (rowItems.size == columns) Spacer(Modifier.height(8.dp))
                        }
                    }
                }
            }

            // v2: Extraction queue / batch processing — hidden for v1. See ROADMAP.md.
            item(key = "extraction_queue") {
                val queuedCount = extractionItems.count {
                    it.status == com.chartlite.app.extraction.ExtractionQueueRepository.QueueStatus.QUEUED ||
                        it.status == com.chartlite.app.extraction.ExtractionQueueRepository.QueueStatus.PROCESSING
                }
                val readyCount = extractionItems.count { it.status == com.chartlite.app.extraction.ExtractionQueueRepository.QueueStatus.READY }
                val failedCount = extractionItems.count { it.status == com.chartlite.app.extraction.ExtractionQueueRepository.QueueStatus.FAILED }
                val batchModeEnabled = app.appConfig.noteProcessingMode == "batch"
                val totalBatchItems = (processedCount + queuedCount).coerceAtLeast(queuedCount)
                val hasItems = queuedCount > 0 || readyCount > 0 || failedCount > 0
                val isProcessing = extractionQueueState == com.chartlite.app.extraction.ExtractionQueue.QueueState.PROCESSING

                if (false && (hasItems || isProcessing)) { // v1: hidden
                    // Full card when there are items or processing
                    Card(
                        modifier = Modifier
                            .fillMaxWidth()
                            .padding(horizontal = 20.dp, vertical = 8.dp),
                        colors = CardDefaults.cardColors(containerColor = Neutral100)
                    ) {
                        Column(modifier = Modifier.padding(16.dp)) {
                            Text(
                                buildString {
                                    append(stringResource(R.string.extraction_queue_title))
                                    append(" · ")
                                    append(stringResource(R.string.queued_format, queuedCount))
                                    append(" • ")
                                    append(stringResource(R.string.ready_format, readyCount))
                                    if (failedCount > 0) {
                                        append(" • ")
                                        append(stringResource(R.string.failed_format, failedCount))
                                    }
                                },
                                style = MaterialTheme.typography.titleSmall,
                                fontWeight = FontWeight.SemiBold
                            )
                            if (isProcessing) {
                                Spacer(Modifier.height(8.dp))
                                BatchProcessingStatusCard(
                                    processedCount = processedCount,
                                    totalCount = totalBatchItems,
                                    title = stringResource(R.string.batch_running),
                                    subtitle = stringResource(R.string.processing_queued),
                                    processingStep = currentStep
                                )
                            }
                            Spacer(Modifier.height(10.dp))
                            Row(horizontalArrangement = Arrangement.spacedBy(8.dp)) {
                                if (isProcessing) {
                                    OutlinedButton(
                                        onClick = { app.extractionQueue.cancelBatch() },
                                        modifier = Modifier.height(36.dp),
                                        contentPadding = PaddingValues(horizontal = 16.dp)
                                    ) {
                                        Text(stringResource(R.string.cancel_batch), style = MaterialTheme.typography.labelMedium)
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
                                        enabled = queuedCount > 0,
                                        modifier = Modifier.height(36.dp),
                                        contentPadding = PaddingValues(horizontal = 16.dp)
                                    ) {
                                        Text(stringResource(R.string.process_batch), style = MaterialTheme.typography.labelMedium)
                                    }
                                }
                                OutlinedButton(
                                    onClick = onExtractionQueue,
                                    modifier = Modifier.height(36.dp),
                                    contentPadding = PaddingValues(horizontal = 16.dp)
                                ) {
                                    Text(stringResource(R.string.open_queue), style = MaterialTheme.typography.labelMedium)
                                }
                            }
                        }
                    }
                }
            }

            // -- Main list area --
            if (isMultiStation) {
                // Queue header
                item(key = "recent_header") {
                    Text(
                        stringResource(R.string.queue_header_format, activeStation.displayName.uppercase()),
                        style = MaterialTheme.typography.labelMedium,
                        color = Neutral500,
                        letterSpacing = 1.5.sp,
                        modifier = Modifier.padding(horizontal = 20.dp, vertical = 12.dp)
                    )
                }

                if (activeStation == ClinicStation.TRIAGE) {
                    items(queueVisits, key = { it.id }) { visit ->
                        val patient = queuePatients[visit.patientId]
                        if (patient != null) {
                            VoiceTriageCard(
                                patientName = "${patient.firstName} ${patient.lastName}",
                                patientId = patient.id,
                                expanded = expandedTriageVisitId == visit.id,
                                onToggle = { expandedTriageVisitId = if (expandedTriageVisitId == visit.id) null else visit.id },
                                onSave = { sys, dia, temp, pulse, spo2, weight, complaint, triagePriority ->
                                    scope.launch {
                                        try {
                                            val vitals = VitalSigns(
                                                systolicBP = sys,
                                                diastolicBP = dia,
                                                temperature = temp,
                                                pulse = pulse,
                                                oxygenSaturation = spo2,
                                                weight = weight
                                            )
                                            val encounter = StructuredEncounter(
                                                id = UUID.randomUUID().toString(),
                                                patientId = visit.patientId,
                                                providerId = app.sessionManager.currentSession?.userId ?: "",
                                                facilityId = app.appConfig.facilityId,
                                                timestamp = Instant.now(),
                                                transcript = complaint,
                                                medications = emptyList(),
                                                diagnoses = emptyList(),
                                                vitals = vitals,
                                                allergies = emptyList(),
                                                followUp = null,
                                                referral = null,
                                                freeTextNote = complaint,
                                                extractionConfidence = 1.0f
                                            )

                                            val alerts = VitalAlerts().check(vitals)

                                            withContext(Dispatchers.IO) {
                                                val encId = app.encounterRepository.save(encounter, alerts, "TRIAGE")
                                                app.visitRepository.linkEncounter(visit.id, encId, ClinicStation.TRIAGE)
                                                app.visitRepository.setChiefComplaint(visit.id, complaint)
                                                app.visitRepository.setPriority(visit.id, triagePriority)
                                                app.visitRepository.advanceToNextStation(
                                                    visit.id,
                                                    app.sessionManager.currentSession?.userId ?: "",
                                                    ClinicStation.TRIAGE
                                                )
                                            }

                                            // Show CDSS alerts via Snackbar
                                            if (alerts.isNotEmpty()) {
                                                val critical = alerts.count { it.severity == AlertSeverity.CRITICAL }
                                                val warnings = alerts.count { it.severity == AlertSeverity.WARNING }
                                                val msg = buildString {
                                                    append("⚠ Vitals: ")
                                                    if (critical > 0) append("$critical critical")
                                                    if (critical > 0 && warnings > 0) append(", ")
                                                    if (warnings > 0) append("$warnings warning")
                                                    append(" — ${alerts.first().message}")
                                                }
                                                snackbarHostState.showSnackbar(
                                                    message = msg,
                                                    duration = SnackbarDuration.Long
                                                )
                                            }

                                            // Collapse card and refresh queue
                                            expandedTriageVisitId = null
                                            queueVisits = app.visitRepository.getQueueForStation(activeStation, app.appConfig.facilityId)
                                            val counts = mutableMapOf<ClinicStation, Int>()
                                            for (station in ClinicStation.entries) {
                                                counts[station] = app.visitRepository.getQueueCount(station, app.appConfig.facilityId)
                                            }
                                            queueCounts = counts
                                        } catch (e: Exception) {
                                            android.util.Log.e("HomeScreen", "Triage save failed", e)
                                            // Card stays expanded so user can retry
                                        }
                                    }
                                },
                                onFullTriage = { onStartTriage(visit.patientId, visit.id) },
                                modifier = Modifier.padding(horizontal = 20.dp, vertical = 4.dp)
                            )
                        }
                    }
                } else {
                    items(queueVisits, key = { it.id }) { visit ->
                        val patient = queuePatients[visit.patientId]
                        val name = patient?.let { "${it.firstName} ${it.lastName}" } ?: stringResource(R.string.home_unknown_patient)
                        val waitMins = ((System.currentTimeMillis() - visit.updatedAt) / 60000).toInt()
                        val noComplaint = stringResource(R.string.home_no_complaint)
                        val medsToDispense = stringResource(R.string.home_meds_to_dispense)
                        val contextLine = when (activeStation) {
                            ClinicStation.CONSULTATION -> visit.chiefComplaint ?: noComplaint
                            ClinicStation.PHARMACY -> medsToDispense
                            else -> ""
                        }
                        QueueCard(
                            patientName = name,
                            patientId = visit.patientId,
                            waitMinutes = waitMins,
                            priorityLevel = visit.priorityLevel,
                            contextLine = contextLine,
                            onClick = {
                                when (activeStation) {
                                    ClinicStation.CONSULTATION -> onStartConsultation(visit.patientId, visit.id)
                                    ClinicStation.PHARMACY -> onStartPharmacy(visit.id)
                                    else -> {}
                                }
                            },
                            onMarkPriority = { newLevel ->
                                scope.launch {
                                    app.visitRepository.setPriority(visit.id, newLevel)
                                    // Reload queue
                                    queueVisits = app.visitRepository.getQueueForStation(activeStation, app.appConfig.facilityId)
                                }
                            },
                            modifier = Modifier.padding(horizontal = 20.dp, vertical = 4.dp)
                        )
                    }
                }

                if (queueVisits.isEmpty()) {
                    item(key = "empty_queue") {
                        EmptyState(
                            title = stringResource(R.string.no_patients_waiting),
                            subtitle = stringResource(R.string.patients_will_appear, activeStation.displayName),
                            icon = Icons.Outlined.Groups,
                            modifier = Modifier.padding(horizontal = 20.dp)
                        )
                    }
                }
            } else {
                // -- Solo mode: Recent encounters (clinical roles only) --
                if (currentRole?.canViewClinicalHistory != false) {
                    item(key = "recent_header") {
                        Text(
                            stringResource(R.string.recent_encounters),
                            style = MaterialTheme.typography.labelMedium,
                            color = Neutral500,
                            letterSpacing = 1.5.sp,
                            modifier = Modifier.padding(horizontal = 20.dp, vertical = 12.dp)
                        )
                    }

                    if (isLoading) {
                        item(key = "loading") {
                            Box(
                                Modifier.fillMaxWidth().padding(vertical = 40.dp),
                                contentAlignment = Alignment.Center
                            ) {
                                CircularProgressIndicator()
                            }
                        }
                    } else if (recentEncounters.isEmpty()) {
                        item(key = "empty") {
                            EmptyState(
                                title = stringResource(R.string.no_encounters_yet),
                                subtitle = stringResource(R.string.no_encounters_subtitle),
                                icon = Icons.Outlined.Mic,
                                modifier = Modifier.padding(horizontal = 20.dp)
                            )
                        }
                    } else {
                        items(recentEncounters, key = { it.id }) { encounter ->
                            EncounterCard(
                                encounter = encounter,
                                onClick = { onPatientSelected(encounter.patientId) },
                                modifier = Modifier.padding(horizontal = 20.dp, vertical = 4.dp)
                                    .animateItem()
                            )
                        }
                    }
                }
            }
        }
    }
}

@Composable
private fun StatChip(
    value: String,
    label: String,
    modifier: Modifier = Modifier,
    accentColor: Color? = null
) {
    val hasValue = value != "0"
    val bgColor = if (hasValue && accentColor != null) accentColor.copy(alpha = 0.08f)
                  else MaterialTheme.colorScheme.surface
    val valueColor = if (hasValue && accentColor != null) accentColor
                     else MaterialTheme.colorScheme.onPrimaryContainer
    ElevatedCard(
        modifier = modifier,
        shape = RoundedCornerShape(12.dp),
        colors = CardDefaults.elevatedCardColors(containerColor = bgColor),
        elevation = CardDefaults.elevatedCardElevation(defaultElevation = 1.dp)
    ) {
        Column(
            modifier = Modifier
                .fillMaxWidth()
                .padding(horizontal = 12.dp, vertical = 10.dp),
            horizontalAlignment = Alignment.CenterHorizontally
        ) {
            Text(
                value,
                style = MaterialTheme.typography.headlineSmall,
                fontWeight = FontWeight.Bold,
                color = valueColor
            )
            Text(
                label,
                style = MaterialTheme.typography.labelSmall,
                color = MaterialTheme.colorScheme.onSurfaceVariant
            )
        }
    }
}

@Composable
private fun QuickActionCard(
    icon: ImageVector,
    label: String,
    color: Color,
    modifier: Modifier = Modifier,
    isPrimary: Boolean = false,
    onClick: () -> Unit
) {
    if (isPrimary) {
        Card(
            onClick = onClick,
            modifier = modifier.height(92.dp),
            shape = RoundedCornerShape(14.dp),
            colors = CardDefaults.cardColors(
                containerColor = color.copy(alpha = 0.08f)
            )
        ) {
            Column(
                modifier = Modifier
                    .fillMaxSize()
                    .padding(12.dp),
                verticalArrangement = Arrangement.Center,
                horizontalAlignment = Alignment.CenterHorizontally
            ) {
                Box(
                    modifier = Modifier
                        .size(36.dp)
                        .clip(RoundedCornerShape(10.dp))
                        .background(color.copy(alpha = 0.18f)),
                    contentAlignment = Alignment.Center
                ) {
                    Icon(icon, contentDescription = label,
                        tint = color, modifier = Modifier.size(20.dp))
                }
                Spacer(Modifier.height(8.dp))
                Text(label,
                    style = MaterialTheme.typography.labelMedium,
                    fontWeight = FontWeight.SemiBold,
                    color = MaterialTheme.colorScheme.onSurface)
            }
        }
    } else {
        OutlinedCard(
            onClick = onClick,
            modifier = modifier.height(92.dp),
            shape = RoundedCornerShape(14.dp),
            colors = CardDefaults.outlinedCardColors(
                containerColor = MaterialTheme.colorScheme.surface
            ),
            border = CardDefaults.outlinedCardBorder()
        ) {
            Column(
                modifier = Modifier
                    .fillMaxSize()
                    .padding(12.dp),
                verticalArrangement = Arrangement.Center,
                horizontalAlignment = Alignment.CenterHorizontally
            ) {
                Box(
                    modifier = Modifier
                        .size(36.dp)
                        .clip(RoundedCornerShape(10.dp))
                        .background(color.copy(alpha = 0.1f)),
                    contentAlignment = Alignment.Center
                ) {
                    Icon(icon, contentDescription = label,
                        tint = color, modifier = Modifier.size(20.dp))
                }
                Spacer(Modifier.height(8.dp))
                Text(label,
                    style = MaterialTheme.typography.labelMedium,
                    fontWeight = FontWeight.Medium,
                    color = MaterialTheme.colorScheme.onSurface)
            }
        }
    }
}

@OptIn(ExperimentalMaterial3Api::class)
@Composable
private fun CompactActionItem(
    icon: ImageVector,
    label: String,
    modifier: Modifier = Modifier,
    badgeCount: Int = 0,
    onClick: () -> Unit
) {
    Column(
        modifier = modifier
            .clip(RoundedCornerShape(10.dp))
            .clickable(onClick = onClick)
            .padding(vertical = 10.dp),
        horizontalAlignment = Alignment.CenterHorizontally
    ) {
        if (badgeCount > 0) {
            BadgedBox(
                badge = {
                    Badge { Text(badgeCount.toString()) }
                }
            ) {
                Icon(
                    icon, contentDescription = label,
                    tint = MaterialTheme.colorScheme.onSurfaceVariant,
                    modifier = Modifier.size(22.dp)
                )
            }
        } else {
            Icon(
                icon, contentDescription = label,
                tint = MaterialTheme.colorScheme.onSurfaceVariant,
                modifier = Modifier.size(22.dp)
            )
        }
        Spacer(Modifier.height(6.dp))
        Text(
            label,
            style = MaterialTheme.typography.labelSmall,
            color = MaterialTheme.colorScheme.onSurfaceVariant,
            maxLines = 2,
            textAlign = androidx.compose.ui.text.style.TextAlign.Center,
            overflow = androidx.compose.ui.text.style.TextOverflow.Ellipsis
        )
    }
}

@Composable
private fun EmptyState(
    title: String,
    subtitle: String,
    icon: ImageVector,
    modifier: Modifier = Modifier
) {
    Row(
        modifier = modifier
            .fillMaxWidth()
            .padding(vertical = 24.dp),
        verticalAlignment = Alignment.CenterVertically,
        horizontalArrangement = Arrangement.Center
    ) {
        Box(
            modifier = Modifier
                .size(44.dp)
                .clip(CircleShape)
                .background(BrandGreenSurface),
            contentAlignment = Alignment.Center
        ) {
            Icon(icon, contentDescription = null,
                modifier = Modifier.size(22.dp), tint = BrandGreen)
        }
        Spacer(Modifier.width(14.dp))
        Column(verticalArrangement = Arrangement.spacedBy(6.dp)) {
            Text(title,
                style = MaterialTheme.typography.titleSmall,
                fontWeight = FontWeight.SemiBold,
                color = Neutral800)
            Text(subtitle,
                style = MaterialTheme.typography.bodySmall,
                color = Neutral500,
                lineHeight = 18.sp)
        }
    }
}
