package com.chartlite.app.ui.screens

import android.Manifest
import android.content.pm.PackageManager
import android.os.Build
import androidx.activity.compose.rememberLauncherForActivityResult
import androidx.activity.result.contract.ActivityResultContracts
import androidx.compose.foundation.layout.*
import androidx.compose.foundation.rememberScrollState
import androidx.compose.foundation.verticalScroll
import androidx.compose.material.icons.Icons
import androidx.compose.material.icons.automirrored.filled.ArrowBack
import androidx.compose.material.icons.filled.Bluetooth
import androidx.compose.material.icons.filled.Check
import androidx.compose.material.icons.filled.People
import androidx.compose.material.icons.filled.PersonSearch
import androidx.compose.material.icons.automirrored.filled.Send
import androidx.compose.material.icons.filled.SelectAll
import androidx.compose.material.icons.filled.Sync
import androidx.compose.material.icons.filled.Wifi
import androidx.compose.material3.*
import androidx.compose.runtime.*
import androidx.compose.ui.Alignment
import androidx.compose.ui.Modifier
import androidx.compose.ui.platform.LocalContext
import androidx.compose.ui.res.stringResource
import androidx.compose.ui.text.font.FontWeight
import androidx.compose.ui.text.style.TextAlign
import androidx.compose.ui.unit.dp
import androidx.core.content.ContextCompat
import com.chartlite.app.App
import com.chartlite.app.R
import com.chartlite.app.patientid.PatientIdGenerator
import com.chartlite.app.sync.SyncState
import kotlinx.coroutines.launch

@OptIn(ExperimentalMaterial3Api::class)
@Composable
fun SyncScreen(onBack: () -> Unit) {
    val context = LocalContext.current
    val app = context.applicationContext as App
    val syncEngine = app.syncEngine
    val scope = rememberCoroutineScope()

    val state by syncEngine.state.collectAsState()
    val discoveredDevices by syncEngine.discoveredDevices.collectAsState()
    val syncResult by syncEngine.syncResult.collectAsState()
    val errorMessage by syncEngine.errorMessage.collectAsState()
    val pendingConnection by syncEngine.pendingConnection.collectAsState()
    val connectedPeers by syncEngine.connectedEndpoints.collectAsState()
    val pendingCrossFacility by syncEngine.pendingCrossFacilityPayload.collectAsState()
    val crossFacilityResult by syncEngine.crossFacilityResult.collectAsState()
    val isMultiStation = app.appConfig.isMultiStation

    // ── Cross-facility mode state ──
    var isCrossFacilityMode by remember { mutableStateOf(false) }
    var crossFacilityPatientId by remember { mutableStateOf("") }
    var crossFacilityPatientName by remember { mutableStateOf<String?>(null) }
    var crossFacilityPatientError by remember { mutableStateOf<String?>(null) }
    var crossFacilitySelectedPatientIds by remember { mutableStateOf<List<String>>(emptyList()) }
    var sendAllPatients by remember { mutableStateOf(true) }
    var totalPatientCount by remember { mutableStateOf(0) }

    // Load total patient count for "Send All" display
    LaunchedEffect(Unit) {
        totalPatientCount = app.patientRepository.getAll().size
    }

    // ── Runtime permissions for Nearby Connections ──
    val requiredPermissions = remember {
        buildList {
            add(Manifest.permission.ACCESS_FINE_LOCATION)
            if (Build.VERSION.SDK_INT >= Build.VERSION_CODES.S) {
                add(Manifest.permission.BLUETOOTH_ADVERTISE)
                add(Manifest.permission.BLUETOOTH_CONNECT)
                add(Manifest.permission.BLUETOOTH_SCAN)
            }
            if (Build.VERSION.SDK_INT >= Build.VERSION_CODES.TIRAMISU) {
                add(Manifest.permission.NEARBY_WIFI_DEVICES)
            }
        }.toTypedArray()
    }

    var hasPermissions by remember {
        mutableStateOf(
            requiredPermissions.all {
                ContextCompat.checkSelfPermission(context, it) == PackageManager.PERMISSION_GRANTED
            }
        )
    }

    val permissionLauncher = rememberLauncherForActivityResult(
        ActivityResultContracts.RequestMultiplePermissions()
    ) { grants ->
        hasPermissions = grants.values.all { it }
        if (hasPermissions) {
            syncEngine.startDiscovery()
        }
    }

    DisposableEffect(Unit) {
        onDispose {
            syncEngine.stopDiscovery()
        }
    }

    // ── Pending connection verification dialog ──
    pendingConnection?.let { pending ->
        AlertDialog(
            onDismissRequest = { syncEngine.rejectPendingConnection() },
            title = { Text(stringResource(R.string.sync_verify_connection)) },
            text = {
                Column(verticalArrangement = Arrangement.spacedBy(12.dp)) {
                    Text(stringResource(R.string.sync_device_wants_to_connect, pending.deviceName))
                    Text(
                        stringResource(R.string.sync_verify_code_matches),
                        style = MaterialTheme.typography.bodySmall,
                        color = MaterialTheme.colorScheme.onSurfaceVariant
                    )
                    Text(
                        pending.authenticationDigits,
                        style = MaterialTheme.typography.headlineMedium,
                        fontWeight = FontWeight.Bold,
                        textAlign = TextAlign.Center,
                        modifier = Modifier.fillMaxWidth()
                    )
                }
            },
            confirmButton = {
                Button(onClick = { syncEngine.acceptPendingConnection() }) {
                    Text(stringResource(R.string.sync_accept))
                }
            },
            dismissButton = {
                OutlinedButton(onClick = { syncEngine.rejectPendingConnection() }) {
                    Text(stringResource(R.string.sync_reject))
                }
            }
        )
    }

    // ── Cross-facility inbound confirmation dialog ──
    if (state == SyncState.AWAITING_CROSS_FACILITY_CONFIRMATION) {
        pendingCrossFacility?.let { payload ->
            AlertDialog(
                onDismissRequest = { syncEngine.rejectCrossFacilitySync() },
                title = { Text(stringResource(R.string.sync_incoming_patient_data)) },
                text = {
                    Column(verticalArrangement = Arrangement.spacedBy(8.dp)) {
                        Text(
                            stringResource(R.string.sync_from_format, payload.sourceFacilityName),
                            style = MaterialTheme.typography.titleSmall,
                            fontWeight = FontWeight.Bold
                        )
                        Text(
                            stringResource(R.string.sync_facility_id_format, payload.sourceFacilityId),
                            style = MaterialTheme.typography.bodySmall,
                            color = MaterialTheme.colorScheme.onSurfaceVariant
                        )
                        HorizontalDivider(modifier = Modifier.padding(vertical = 4.dp))
                        Text(
                            stringResource(R.string.sync_payload_summary, payload.patients.size, payload.encounters.size, payload.visits.size),
                            style = MaterialTheme.typography.bodyMedium
                        )
                        payload.targetPatientIds.forEach { pid ->
                            Text(
                                stringResource(R.string.sync_patient_format, pid),
                                style = MaterialTheme.typography.bodySmall,
                                color = MaterialTheme.colorScheme.onSurfaceVariant
                            )
                        }
                        HorizontalDivider(modifier = Modifier.padding(vertical = 4.dp))
                        Text(
                            stringResource(R.string.sync_merge_note),
                            style = MaterialTheme.typography.bodySmall,
                            color = MaterialTheme.colorScheme.onSurfaceVariant
                        )
                    }
                },
                confirmButton = {
                    Button(onClick = {
                        scope.launch { syncEngine.acceptCrossFacilitySync() }
                    }) {
                        Text(stringResource(R.string.sync_accept_merge))
                    }
                },
                dismissButton = {
                    OutlinedButton(onClick = { syncEngine.rejectCrossFacilitySync() }) {
                        Text(stringResource(R.string.sync_reject))
                    }
                }
            )
        }
    }

    Scaffold(
        topBar = {
            TopAppBar(
                title = { Text(stringResource(R.string.sync_devices)) },
                navigationIcon = {
                    IconButton(onClick = {
                        syncEngine.reset()
                        onBack()
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
                .padding(16.dp)
                .verticalScroll(rememberScrollState()),
            horizontalAlignment = Alignment.CenterHorizontally,
            verticalArrangement = Arrangement.spacedBy(16.dp)
        ) {
            // Status card
            Card(
                modifier = Modifier.fillMaxWidth(),
                colors = CardDefaults.cardColors(
                    containerColor = MaterialTheme.colorScheme.secondaryContainer
                )
            ) {
                Column(
                    modifier = Modifier.padding(16.dp),
                    horizontalAlignment = Alignment.CenterHorizontally
                ) {
                    Row(verticalAlignment = Alignment.CenterVertically) {
                        Icon(Icons.Default.Bluetooth, contentDescription = null,
                            modifier = Modifier.size(20.dp))
                        Spacer(Modifier.width(4.dp))
                        Icon(Icons.Default.Wifi, contentDescription = null,
                            modifier = Modifier.size(20.dp))
                        Spacer(Modifier.width(8.dp))
                        Text(stringResource(R.string.sync_peer_to_peer),
                            style = MaterialTheme.typography.titleMedium,
                            fontWeight = FontWeight.Bold)
                    }
                    Spacer(Modifier.height(8.dp))
                    Text(
                        stringResource(R.string.sync_peer_to_peer_desc),
                        style = MaterialTheme.typography.bodySmall,
                        textAlign = TextAlign.Center,
                        color = MaterialTheme.colorScheme.onSecondaryContainer
                    )
                }
            }

            // ── Mode selector: Same Facility / Cross-Facility ──
            SingleChoiceSegmentedButtonRow(modifier = Modifier.fillMaxWidth()) {
                SegmentedButton(
                    selected = !isCrossFacilityMode,
                    onClick = {
                        isCrossFacilityMode = false
                        if (state != SyncState.IDLE) syncEngine.reset()
                    },
                    shape = SegmentedButtonDefaults.itemShape(index = 0, count = 2)
                ) {
                    Text(stringResource(R.string.sync_same_facility))
                }
                SegmentedButton(
                    selected = isCrossFacilityMode,
                    onClick = {
                        isCrossFacilityMode = true
                        if (state != SyncState.IDLE) syncEngine.reset()
                    },
                    shape = SegmentedButtonDefaults.itemShape(index = 1, count = 2)
                ) {
                    Text(stringResource(R.string.sync_cross_facility))
                }
            }

            // ── Continuous sync status (multi-station mode) — only in same-facility ──
            if (isMultiStation && !isCrossFacilityMode) {
                Card(
                    modifier = Modifier.fillMaxWidth(),
                    colors = CardDefaults.cardColors(
                        containerColor = if (connectedPeers.isNotEmpty())
                            MaterialTheme.colorScheme.primaryContainer
                        else
                            MaterialTheme.colorScheme.surfaceVariant
                    )
                ) {
                    Column(modifier = Modifier.padding(16.dp)) {
                        Row(verticalAlignment = Alignment.CenterVertically) {
                            Icon(
                                Icons.Default.Sync,
                                contentDescription = null,
                                tint = if (connectedPeers.isNotEmpty())
                                    MaterialTheme.colorScheme.primary
                                else
                                    MaterialTheme.colorScheme.onSurfaceVariant
                            )
                            Spacer(Modifier.width(8.dp))
                            Text(
                                stringResource(R.string.sync_continuous),
                                style = MaterialTheme.typography.titleMedium,
                                fontWeight = FontWeight.Bold
                            )
                        }
                        Spacer(Modifier.height(8.dp))
                        if (connectedPeers.isNotEmpty()) {
                            Text(
                                stringResource(R.string.sync_connected_devices, connectedPeers.size),
                                style = MaterialTheme.typography.bodySmall,
                                color = MaterialTheme.colorScheme.onPrimaryContainer
                            )
                            Spacer(Modifier.height(8.dp))
                            syncResult?.let { result ->
                                val total = result.patientsSent + result.encountersSent + result.visitsSent +
                                    result.patientsReceived + result.encountersReceived + result.visitsReceived
                                val syncedText = stringResource(R.string.sync_records_synced_format, total)
                                val mergedText = if (result.conflicts > 0) stringResource(R.string.sync_records_merged_format, result.conflicts) else ""
                                Text(
                                    syncedText + mergedText,
                                    style = MaterialTheme.typography.labelSmall,
                                    color = MaterialTheme.colorScheme.onPrimaryContainer.copy(alpha = 0.7f)
                                )
                            }
                        } else {
                            Text(
                                stringResource(R.string.sync_searching_clinic_devices),
                                style = MaterialTheme.typography.bodySmall,
                                color = MaterialTheme.colorScheme.onSurfaceVariant
                            )
                            Spacer(Modifier.height(8.dp))
                            LinearProgressIndicator(modifier = Modifier.fillMaxWidth())
                        }
                        Spacer(Modifier.height(12.dp))
                        Row(horizontalArrangement = Arrangement.spacedBy(8.dp)) {
                            OutlinedButton(onClick = {
                                if (connectedPeers.isNotEmpty()) {
                                    com.chartlite.app.sync.ContinuousSyncService.stop(context)
                                } else {
                                    com.chartlite.app.sync.ContinuousSyncService.start(context)
                                }
                            }) {
                                Text(if (connectedPeers.isNotEmpty()) stringResource(R.string.sync_stop) else stringResource(R.string.sync_restart))
                            }
                        }
                    }
                }

                HorizontalDivider(modifier = Modifier.padding(vertical = 4.dp))
                Text(
                    stringResource(R.string.sync_manual),
                    style = MaterialTheme.typography.labelMedium,
                    color = MaterialTheme.colorScheme.onSurfaceVariant,
                    modifier = Modifier.fillMaxWidth()
                )
            }

            // ── Cross-facility: patient selection (shown when IDLE) ──
            val syncInvalidPatientIdMsg = stringResource(R.string.sync_invalid_patient_id)
            val syncPatientAlreadyAddedMsg = stringResource(R.string.sync_patient_already_added)
            val syncPatientNotFoundLocalMsg = stringResource(R.string.sync_patient_not_found_local)
            val syncPatientNotFoundMsg = stringResource(R.string.sync_patient_not_found)
            if (isCrossFacilityMode && state == SyncState.IDLE) {
                CrossFacilityPatientPicker(
                    patientIdInput = crossFacilityPatientId,
                    onPatientIdChange = { input ->
                        crossFacilityPatientId = input
                        crossFacilityPatientError = null
                        crossFacilityPatientName = null
                    },
                    patientName = crossFacilityPatientName,
                    errorMessage = crossFacilityPatientError,
                    selectedPatientIds = crossFacilitySelectedPatientIds,
                    sendAllPatients = sendAllPatients,
                    totalPatientCount = totalPatientCount,
                    onToggleSendAll = { enabled ->
                        sendAllPatients = enabled
                        if (enabled) {
                            // Clear individual selections when switching to "send all"
                            crossFacilitySelectedPatientIds = emptyList()
                            crossFacilityPatientId = ""
                            crossFacilityPatientName = null
                            crossFacilityPatientError = null
                        }
                    },
                    onAddPatient = {
                        val normalized = PatientIdGenerator.normalize(crossFacilityPatientId)
                        if (!PatientIdGenerator.isValid(normalized)) {
                            crossFacilityPatientError = syncInvalidPatientIdMsg
                            return@CrossFacilityPatientPicker
                        }
                        if (crossFacilitySelectedPatientIds.contains(normalized)) {
                            crossFacilityPatientError = syncPatientAlreadyAddedMsg
                            return@CrossFacilityPatientPicker
                        }
                        scope.launch {
                            val patient = app.patientRepository.getById(normalized)
                            if (patient == null) {
                                crossFacilityPatientError = syncPatientNotFoundLocalMsg
                            } else {
                                crossFacilitySelectedPatientIds = crossFacilitySelectedPatientIds + normalized
                                crossFacilityPatientId = ""
                                crossFacilityPatientName = null
                                crossFacilityPatientError = null
                            }
                        }
                    },
                    onRemovePatient = { id ->
                        crossFacilitySelectedPatientIds = crossFacilitySelectedPatientIds - id
                    },
                    onLookup = {
                        val normalized = PatientIdGenerator.normalize(crossFacilityPatientId)
                        if (PatientIdGenerator.isValid(normalized)) {
                            scope.launch {
                                val patient = app.patientRepository.getById(normalized)
                                crossFacilityPatientName = patient?.let { "${it.firstName} ${it.lastName}" }
                                crossFacilityPatientError = if (patient == null) syncPatientNotFoundMsg else null
                            }
                        } else {
                            crossFacilityPatientError = syncInvalidPatientIdMsg
                        }
                    }
                )
            }

            // ── Main state machine ──
            when (state) {
                SyncState.IDLE -> {
                    if (isCrossFacilityMode) {
                        // Cross-facility: discover after selecting patients
                        val canSend = sendAllPatients || crossFacilitySelectedPatientIds.isNotEmpty()
                        val sendCount = if (sendAllPatients) totalPatientCount else crossFacilitySelectedPatientIds.size
                        Button(
                            onClick = {
                                scope.launch {
                                    // Tell the engine to send cross-facility data on connection
                                    syncEngine.sendOnConnect = com.chartlite.app.sync.SyncEngine.SendOnConnect.CROSS_FACILITY
                                    syncEngine.crossFacilityOutboundPatientIds = if (sendAllPatients) {
                                        // Load all patient IDs
                                        app.patientRepository.getAll().map { it.id }
                                    } else {
                                        crossFacilitySelectedPatientIds
                                    }
                                    if (hasPermissions) {
                                        syncEngine.startDiscovery()
                                    } else {
                                        permissionLauncher.launch(requiredPermissions)
                                    }
                                }
                            },
                            modifier = Modifier.fillMaxWidth().height(56.dp),
                            enabled = canSend
                        ) {
                            Icon(Icons.AutoMirrored.Filled.Send, contentDescription = "Send")
                            Spacer(Modifier.width(8.dp))
                            Text(
                                if (sendAllPatients)
                                    stringResource(R.string.sync_send_all_format, totalPatientCount)
                                else
                                    stringResource(R.string.sync_send_patients_format, crossFacilitySelectedPatientIds.size),
                                style = MaterialTheme.typography.titleMedium
                            )
                        }
                        Text(
                            if (sendAllPatients)
                                stringResource(R.string.sync_send_all_hint)
                            else
                                stringResource(R.string.sync_select_patients_hint),
                            style = MaterialTheme.typography.bodySmall,
                            textAlign = TextAlign.Center,
                            color = MaterialTheme.colorScheme.onSurfaceVariant
                        )
                    } else {
                        // Same-facility: existing behavior
                        Button(
                            onClick = {
                                // Tell the engine to send same-facility data on connection
                                syncEngine.sendOnConnect = com.chartlite.app.sync.SyncEngine.SendOnConnect.SAME_FACILITY
                                if (hasPermissions) {
                                    syncEngine.startDiscovery()
                                } else {
                                    permissionLauncher.launch(requiredPermissions)
                                }
                            },
                            modifier = Modifier.fillMaxWidth().height(56.dp)
                        ) {
                            Icon(Icons.Default.Sync, contentDescription = "Sync")
                            Spacer(Modifier.width(8.dp))
                            Text(stringResource(R.string.sync_find_nearby_devices),
                                style = MaterialTheme.typography.titleMedium)
                        }

                        Text(
                            stringResource(R.string.sync_both_devices_hint),
                            style = MaterialTheme.typography.bodySmall,
                            textAlign = TextAlign.Center,
                            color = MaterialTheme.colorScheme.onSurfaceVariant
                        )
                    }
                }

                SyncState.DISCOVERING -> {
                    // Searching animation
                    CircularProgressIndicator(modifier = Modifier.size(48.dp))
                    Text(stringResource(R.string.sync_searching),
                        style = MaterialTheme.typography.bodyLarge)

                    if (discoveredDevices.isEmpty()) {
                        Text(
                            stringResource(R.string.sync_other_device_searching),
                            style = MaterialTheme.typography.bodySmall,
                            color = MaterialTheme.colorScheme.onSurfaceVariant
                        )
                    }

                    // Discovered devices list
                    discoveredDevices.forEach { device ->
                        Card(
                            onClick = {
                                syncEngine.connectToDevice(device)
                            },
                            modifier = Modifier.fillMaxWidth()
                        ) {
                            Row(
                                modifier = Modifier.padding(16.dp),
                                verticalAlignment = Alignment.CenterVertically
                            ) {
                                Icon(Icons.Default.Bluetooth, contentDescription = null,
                                    tint = MaterialTheme.colorScheme.primary)
                                Spacer(Modifier.width(12.dp))
                                Column(modifier = Modifier.weight(1f)) {
                                    Text(device.name,
                                        style = MaterialTheme.typography.bodyLarge,
                                        fontWeight = FontWeight.Medium)
                                    Text(
                                        if (isCrossFacilityMode) stringResource(R.string.sync_tap_to_send)
                                        else stringResource(R.string.sync_tap_to_connect),
                                        style = MaterialTheme.typography.bodySmall,
                                        color = MaterialTheme.colorScheme.onSurfaceVariant
                                    )
                                }
                            }
                        }
                    }

                    // Cancel button
                    OutlinedButton(onClick = { syncEngine.stopDiscovery() }) {
                        Text(stringResource(R.string.cancel))
                    }
                }

                SyncState.CONNECTING -> {
                    CircularProgressIndicator(modifier = Modifier.size(48.dp))
                    Text(stringResource(R.string.sync_connecting), style = MaterialTheme.typography.bodyLarge)
                }

                SyncState.AWAITING_CROSS_FACILITY_CONFIRMATION -> {
                    // The dialog is shown above; show a waiting indicator in the main area
                    CircularProgressIndicator(modifier = Modifier.size(48.dp))
                    Text(stringResource(R.string.sync_waiting_confirmation),
                        style = MaterialTheme.typography.bodyLarge)
                    Text(
                        stringResource(R.string.sync_review_dialog),
                        style = MaterialTheme.typography.bodySmall,
                        color = MaterialTheme.colorScheme.onSurfaceVariant
                    )
                }

                SyncState.SYNCING -> {
                    CircularProgressIndicator(modifier = Modifier.size(48.dp))
                    Text(
                        if (isCrossFacilityMode) stringResource(R.string.sync_sending_patient_data) else stringResource(R.string.sync_syncing_data),
                        style = MaterialTheme.typography.bodyLarge
                    )
                    Text(stringResource(R.string.sync_keep_devices_close),
                        style = MaterialTheme.typography.bodySmall,
                        color = MaterialTheme.colorScheme.onSurfaceVariant)

                    // Send-on-connect is now handled by SyncEngine.onConnectionResult
                    // using the sendOnConnect intent set before discovery. This avoids
                    // the race where a UI LaunchedEffect could fire sendSyncData() before
                    // an incoming cross-facility payload has been processed.
                }

                SyncState.COMPLETED -> {
                    // Success
                    Icon(Icons.Default.Check, contentDescription = "Success",
                        modifier = Modifier.size(64.dp),
                        tint = MaterialTheme.colorScheme.primary)

                    Text(stringResource(R.string.sync_complete),
                        style = MaterialTheme.typography.headlineSmall,
                        fontWeight = FontWeight.Bold)

                    // Cross-facility result card
                    crossFacilityResult?.let { cfResult ->
                        Card(modifier = Modifier.fillMaxWidth()) {
                            Column(
                                modifier = Modifier.padding(16.dp),
                                verticalArrangement = Arrangement.spacedBy(8.dp)
                            ) {
                                Text(
                                    stringResource(R.string.sync_cross_facility_transfer),
                                    style = MaterialTheme.typography.titleSmall,
                                    fontWeight = FontWeight.Bold,
                                    color = MaterialTheme.colorScheme.primary
                                )
                                SyncResultRow(stringResource(R.string.sync_from_label), cfResult.sourceFacilityName)
                                SyncResultRow(stringResource(R.string.sync_patients_label), "${cfResult.patientsReceived}")
                                SyncResultRow(stringResource(R.string.sync_encounters_label), "${cfResult.encountersReceived}")
                                if (cfResult.visitsReceived > 0) {
                                    SyncResultRow(stringResource(R.string.sync_visits_label), "${cfResult.visitsReceived}")
                                }
                                SyncResultRow(stringResource(R.string.sync_duration_label), stringResource(R.string.sync_duration_format, cfResult.durationMs))
                            }
                        }
                    }

                    // Same-facility result card
                    syncResult?.let { result ->
                        if (crossFacilityResult == null) {
                            Card(modifier = Modifier.fillMaxWidth()) {
                                Column(
                                    modifier = Modifier.padding(16.dp),
                                    verticalArrangement = Arrangement.spacedBy(8.dp)
                                ) {
                                    SyncResultRow(stringResource(R.string.sync_patients_sent), "${result.patientsSent}")
                                    SyncResultRow(stringResource(R.string.sync_encounters_sent), "${result.encountersSent}")
                                    if (result.visitsSent > 0) SyncResultRow(stringResource(R.string.sync_visits_sent), "${result.visitsSent}")
                                    SyncResultRow(stringResource(R.string.sync_patients_received), "${result.patientsReceived}")
                                    SyncResultRow(stringResource(R.string.sync_encounters_received), "${result.encountersReceived}")
                                    if (result.visitsReceived > 0) SyncResultRow(stringResource(R.string.sync_visits_received), "${result.visitsReceived}")
                                    if (result.conflicts > 0) {
                                        SyncResultRow(stringResource(R.string.sync_records_merged_label), "${result.conflicts}")
                                    }
                                }
                            }
                        }
                    }

                    // Done navigates back
                    Button(onClick = {
                        syncEngine.reset()
                        onBack()
                    }) {
                        Text(stringResource(R.string.done))
                    }
                }

                SyncState.ERROR -> {
                    // Error state
                    Card(
                        modifier = Modifier.fillMaxWidth(),
                        colors = CardDefaults.cardColors(
                            containerColor = MaterialTheme.colorScheme.errorContainer
                        )
                    ) {
                        Column(modifier = Modifier.padding(16.dp)) {
                            Text(stringResource(R.string.sync_error_title),
                                style = MaterialTheme.typography.titleMedium,
                                color = MaterialTheme.colorScheme.onErrorContainer)
                            Spacer(Modifier.height(8.dp))
                            Text(
                                errorMessage ?: stringResource(R.string.sync_unknown_error),
                                style = MaterialTheme.typography.bodyMedium,
                                color = MaterialTheme.colorScheme.onErrorContainer
                            )
                        }
                    }

                    Row(horizontalArrangement = Arrangement.spacedBy(8.dp)) {
                        Button(onClick = {
                            syncEngine.reset()
                            syncEngine.startDiscovery()
                        }) {
                            Text(stringResource(R.string.sync_retry))
                        }
                        OutlinedButton(onClick = {
                            syncEngine.reset()
                            onBack()
                        }) {
                            Text(stringResource(R.string.sync_go_back))
                        }
                    }
                }
            }
        }
    }
}

// ── Cross-facility patient picker ──

@Composable
private fun CrossFacilityPatientPicker(
    patientIdInput: String,
    onPatientIdChange: (String) -> Unit,
    patientName: String?,
    errorMessage: String?,
    selectedPatientIds: List<String>,
    sendAllPatients: Boolean,
    totalPatientCount: Int,
    onToggleSendAll: (Boolean) -> Unit,
    onAddPatient: () -> Unit,
    onRemovePatient: (String) -> Unit,
    onLookup: () -> Unit
) {
    Card(
        modifier = Modifier.fillMaxWidth(),
        colors = CardDefaults.cardColors(
            containerColor = MaterialTheme.colorScheme.surfaceVariant
        )
    ) {
        Column(
            modifier = Modifier.padding(16.dp),
            verticalArrangement = Arrangement.spacedBy(12.dp)
        ) {
            Row(verticalAlignment = Alignment.CenterVertically) {
                Icon(
                    Icons.Default.PersonSearch,
                    contentDescription = null,
                    tint = MaterialTheme.colorScheme.primary
                )
                Spacer(Modifier.width(8.dp))
                Text(
                    stringResource(R.string.sync_select_patients_to_share),
                    style = MaterialTheme.typography.titleMedium,
                    fontWeight = FontWeight.Bold
                )
            }

            // ── Send All Patients toggle ──
            Card(
                modifier = Modifier.fillMaxWidth(),
                colors = CardDefaults.cardColors(
                    containerColor = if (sendAllPatients)
                        MaterialTheme.colorScheme.primaryContainer
                    else
                        MaterialTheme.colorScheme.surface
                )
            ) {
                Row(
                    modifier = Modifier
                        .fillMaxWidth()
                        .padding(horizontal = 12.dp, vertical = 8.dp),
                    verticalAlignment = Alignment.CenterVertically
                ) {
                    Icon(
                        Icons.Default.People,
                        contentDescription = null,
                        tint = if (sendAllPatients)
                            MaterialTheme.colorScheme.primary
                        else
                            MaterialTheme.colorScheme.onSurfaceVariant,
                        modifier = Modifier.size(20.dp)
                    )
                    Spacer(Modifier.width(8.dp))
                    Column(modifier = Modifier.weight(1f)) {
                        Text(
                            stringResource(R.string.sync_send_all_patients),
                            style = MaterialTheme.typography.titleSmall,
                            fontWeight = FontWeight.Medium
                        )
                        Text(
                            stringResource(R.string.sync_send_all_patients_desc, totalPatientCount),
                            style = MaterialTheme.typography.bodySmall,
                            color = MaterialTheme.colorScheme.onSurfaceVariant
                        )
                    }
                    Switch(
                        checked = sendAllPatients,
                        onCheckedChange = onToggleSendAll
                    )
                }
            }

            // ── Individual patient selection (only when not sending all) ──
            if (!sendAllPatients) {
                HorizontalDivider()

                Text(
                    stringResource(R.string.sync_or_select_individual),
                    style = MaterialTheme.typography.bodySmall,
                    color = MaterialTheme.colorScheme.onSurfaceVariant
                )

                // Patient ID input
                OutlinedTextField(
                    value = patientIdInput,
                    onValueChange = onPatientIdChange,
                    label = { Text(stringResource(R.string.sync_patient_id_label)) },
                    singleLine = true,
                    isError = errorMessage != null,
                    supportingText = {
                        when {
                            errorMessage != null -> Text(errorMessage)
                            patientName != null -> Text(
                                patientName,
                                color = MaterialTheme.colorScheme.primary
                            )
                        }
                    },
                    modifier = Modifier.fillMaxWidth()
                )

                // Lookup + Add buttons
                Row(horizontalArrangement = Arrangement.spacedBy(8.dp)) {
                    OutlinedButton(
                        onClick = onLookup,
                        enabled = patientIdInput.isNotBlank()
                    ) {
                        Text(stringResource(R.string.sync_look_up))
                    }
                    Button(
                        onClick = onAddPatient,
                        enabled = patientIdInput.isNotBlank()
                    ) {
                        Text(stringResource(R.string.sync_add_patient))
                    }
                }

                // Selected patients list
                if (selectedPatientIds.isNotEmpty()) {
                    HorizontalDivider()
                    Text(
                        stringResource(R.string.sync_patients_selected_format, selectedPatientIds.size),
                        style = MaterialTheme.typography.labelMedium,
                        fontWeight = FontWeight.Medium
                    )
                    selectedPatientIds.forEach { id ->
                        Row(
                            modifier = Modifier.fillMaxWidth(),
                            verticalAlignment = Alignment.CenterVertically,
                            horizontalArrangement = Arrangement.SpaceBetween
                        ) {
                            Text(
                                id,
                                style = MaterialTheme.typography.bodyMedium,
                                fontWeight = FontWeight.Medium
                            )
                            TextButton(onClick = { onRemovePatient(id) }) {
                                Text(stringResource(R.string.sync_remove), color = MaterialTheme.colorScheme.error)
                            }
                        }
                    }
                }
            }
        }
    }
}

@Composable
private fun SyncResultRow(label: String, value: String) {
    Row(
        modifier = Modifier.fillMaxWidth(),
        horizontalArrangement = Arrangement.SpaceBetween
    ) {
        Text(label, style = MaterialTheme.typography.bodyMedium,
            color = MaterialTheme.colorScheme.onSurfaceVariant)
        Text(value, style = MaterialTheme.typography.bodyMedium,
            fontWeight = FontWeight.Medium)
    }
}
