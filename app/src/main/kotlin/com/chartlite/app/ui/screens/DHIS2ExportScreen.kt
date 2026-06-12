package com.chartlite.app.ui.screens

import android.widget.Toast
import androidx.compose.foundation.background
import androidx.compose.foundation.layout.*
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
import androidx.compose.ui.text.input.PasswordVisualTransformation
import androidx.compose.ui.platform.LocalContext
import androidx.compose.ui.res.stringResource
import androidx.compose.ui.text.font.FontFamily
import androidx.compose.ui.text.font.FontWeight
import androidx.compose.ui.unit.dp
import com.chartlite.app.App
import com.chartlite.app.R
import com.chartlite.app.integration.DHIS2Client
import com.chartlite.app.integration.DHIS2Config
import com.chartlite.app.integration.DHIS2Mapper
import com.chartlite.app.ui.theme.*
import kotlinx.coroutines.launch
import java.time.LocalDate
import java.time.format.DateTimeFormatter

/**
 * Full DHIS2 export screen — replaces the placeholder dialog in FacilityDashboardScreen.
 *
 * Features:
 * - Configure DHIS2 server connection
 * - Test connectivity
 * - Preview data payload
 * - Push aggregate data to DHIS2
 */
@OptIn(ExperimentalMaterial3Api::class)
@Composable
fun DHIS2ExportScreen(onBack: () -> Unit) {
    val context = LocalContext.current
    val app = context.applicationContext as App
    val scope = rememberCoroutineScope()

    // Config state
    var serverUrl by remember { mutableStateOf(app.appConfig.dhis2ServerUrl) }
    var username by remember { mutableStateOf(app.appConfig.dhis2Username) }
    var password by remember { mutableStateOf(app.appConfig.dhis2Password) }
    var orgUnitId by remember { mutableStateOf(app.appConfig.dhis2OrgUnit) }

    // UI state
    var showErrors by remember { mutableStateOf(false) }
    var connectionStatus by remember { mutableStateOf<String?>(null) }
    var isConnecting by remember { mutableStateOf(false) }
    var isPushing by remember { mutableStateOf(false) }
    var pushResult by remember { mutableStateOf<String?>(null) }
    var showPreview by remember { mutableStateOf(false) }
    var previewJson by remember { mutableStateOf("") }
    var showConfig by remember { mutableStateOf(!app.appConfig.dhis2ServerUrl.isNotBlank()) }

    val period = remember { DateTimeFormatter.ofPattern("yyyyMM").format(LocalDate.now()) }

    // Load data for export — hoist so Preview + Push share the same data
    var encounterCount by remember { mutableIntStateOf(0) }
    var labOrderCount by remember { mutableIntStateOf(0) }
    var referralCount by remember { mutableIntStateOf(0) }
    var immunizationCount by remember { mutableIntStateOf(0) }
    var patientCount by remember { mutableIntStateOf(0) }

    // Cached data loaded once, shared between Preview and Push
    var cachedEncounters by remember { mutableStateOf<List<com.chartlite.app.database.entity.EncounterEntity>>(emptyList()) }
    var cachedLabOrders by remember { mutableStateOf<List<com.chartlite.app.database.entity.LabOrderEntity>>(emptyList()) }
    var cachedReferrals by remember { mutableStateOf<List<com.chartlite.app.database.entity.ReferralEntity>>(emptyList()) }

    LaunchedEffect(Unit) {
        // Load by date range for current month instead of getAll()
        val now = System.currentTimeMillis()
        val monthStart = java.time.LocalDate.now().withDayOfMonth(1)
            .atStartOfDay(java.time.ZoneId.systemDefault()).toInstant().toEpochMilli()
        cachedEncounters = app.encounterRepository.getByDateRange(monthStart, now)
        cachedLabOrders = app.labOrderRepository.getPending()
        cachedReferrals = app.referralRepository.getPending(app.appConfig.facilityId)
        encounterCount = cachedEncounters.size
        patientCount = app.patientRepository.getCount()
        labOrderCount = cachedLabOrders.size
        referralCount = cachedReferrals.size
    }

    fun buildConfig() = DHIS2Config(
        serverUrl = serverUrl,
        username = username,
        password = password,
        orgUnitId = orgUnitId
    )

    val connectedString = stringResource(R.string.connected)
    val connectionFailedFormat = stringResource(R.string.connection_failed_format)
    val exportSuccessFormat = stringResource(R.string.export_success_format)
    val exportFailedFormat = stringResource(R.string.export_failed_format)
    val configSavedString = stringResource(R.string.configuration_saved)

    Scaffold(
        topBar = {
            TopAppBar(
                title = {
                    Column {
                        Text(stringResource(R.string.dhis2_export))
                        Text(stringResource(R.string.dhis2_subtitle),
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
        Column(
            modifier = Modifier
                .fillMaxSize()
                .padding(padding)
                .verticalScroll(rememberScrollState())
                .padding(16.dp),
            verticalArrangement = Arrangement.spacedBy(16.dp)
        ) {
            // ── Data Summary Card ──
            Card {
                Column(modifier = Modifier.padding(16.dp)) {
                    Row(verticalAlignment = Alignment.CenterVertically) {
                        Icon(Icons.Default.Assessment, contentDescription = null, tint = BrandGreen)
                        Spacer(Modifier.width(8.dp))
                        Text(stringResource(R.string.export_summary), style = MaterialTheme.typography.titleMedium, fontWeight = FontWeight.SemiBold)
                    }
                    Spacer(Modifier.height(12.dp))
                    Text(stringResource(R.string.period_format, period), style = MaterialTheme.typography.bodyMedium)
                    Spacer(Modifier.height(8.dp))
                    Row(Modifier.fillMaxWidth(), horizontalArrangement = Arrangement.SpaceEvenly) {
                        SummaryChip(stringResource(R.string.encounters), "$encounterCount")
                        SummaryChip(stringResource(R.string.patients), "$patientCount")
                        SummaryChip(stringResource(R.string.lab_orders_label), "$labOrderCount")
                        SummaryChip(stringResource(R.string.referrals), "$referralCount")
                    }
                }
            }

            // ── Server Configuration ──
            Card {
                Column(modifier = Modifier.padding(16.dp)) {
                    Row(
                        modifier = Modifier.fillMaxWidth(),
                        horizontalArrangement = Arrangement.SpaceBetween,
                        verticalAlignment = Alignment.CenterVertically
                    ) {
                        Row(verticalAlignment = Alignment.CenterVertically) {
                            Icon(Icons.Default.Settings, contentDescription = null, tint = InfoBlue)
                            Spacer(Modifier.width(8.dp))
                            Text(stringResource(R.string.server_configuration), style = MaterialTheme.typography.titleMedium, fontWeight = FontWeight.SemiBold)
                        }
                        TextButton(onClick = { showConfig = !showConfig }) {
                            Text(if (showConfig) stringResource(R.string.hide) else stringResource(R.string.edit))
                        }
                    }

                    if (showConfig) {
                        Spacer(Modifier.height(8.dp))
                        OutlinedTextField(
                            value = serverUrl,
                            onValueChange = { serverUrl = it },
                            label = { Text(stringResource(R.string.server_url)) },
                            placeholder = { Text(stringResource(R.string.server_url_placeholder)) },
                            modifier = Modifier.fillMaxWidth(),
                            singleLine = true,
                            isError = showErrors && (serverUrl.isBlank() || !serverUrl.startsWith("http")),
                            supportingText = if (showErrors && serverUrl.isBlank()) {{ Text(stringResource(R.string.required)) }}
                                else if (showErrors && !serverUrl.startsWith("http")) {{ Text(stringResource(R.string.must_be_valid_url)) }}
                                else null
                        )
                        Spacer(Modifier.height(8.dp))
                        OutlinedTextField(
                            value = orgUnitId,
                            onValueChange = { orgUnitId = it },
                            label = { Text(stringResource(R.string.organisation_unit_id)) },
                            placeholder = { Text(stringResource(R.string.org_unit_placeholder)) },
                            modifier = Modifier.fillMaxWidth(),
                            singleLine = true,
                            isError = showErrors && orgUnitId.isBlank(),
                            supportingText = if (showErrors && orgUnitId.isBlank()) {{ Text(stringResource(R.string.required)) }} else null
                        )
                        Spacer(Modifier.height(8.dp))
                        Row(Modifier.fillMaxWidth(), horizontalArrangement = Arrangement.spacedBy(8.dp)) {
                            OutlinedTextField(
                                value = username,
                                onValueChange = { username = it },
                                label = { Text(stringResource(R.string.username)) },
                                modifier = Modifier.weight(1f),
                                singleLine = true
                            )
                            OutlinedTextField(
                                value = password,
                                onValueChange = { password = it },
                                label = { Text(stringResource(R.string.password)) },
                                modifier = Modifier.weight(1f),
                                singleLine = true,
                                visualTransformation = PasswordVisualTransformation()
                            )
                        }
                        Spacer(Modifier.height(12.dp))
                        Row(horizontalArrangement = Arrangement.spacedBy(8.dp)) {
                            Button(
                                onClick = {
                                    if (serverUrl.isBlank() || !serverUrl.startsWith("http") || orgUnitId.isBlank()) {
                                        showErrors = true; return@Button
                                    }
                                    showErrors = false
                                    app.appConfig.dhis2ServerUrl = serverUrl
                                    app.appConfig.dhis2Username = username
                                    app.appConfig.dhis2Password = password
                                    app.appConfig.dhis2OrgUnit = orgUnitId
                                    Toast.makeText(context, configSavedString, Toast.LENGTH_SHORT).show()
                                }
                            ) {
                                Icon(Icons.Default.Save, contentDescription = stringResource(R.string.save), modifier = Modifier.size(18.dp))
                                Spacer(Modifier.width(4.dp))
                                Text(stringResource(R.string.save))
                            }
                            OutlinedButton(
                                onClick = {
                                    isConnecting = true
                                    connectionStatus = null
                                    scope.launch {
                                        val client = DHIS2Client(buildConfig())
                                        val result = client.testConnection()
                                        connectionStatus = when (result) {
                                            is DHIS2Client.DHIS2Result.Success -> connectedString
                                            is DHIS2Client.DHIS2Result.Error -> String.format(connectionFailedFormat, result.message)
                                        }
                                        isConnecting = false
                                    }
                                },
                                enabled = !isConnecting && serverUrl.isNotBlank()
                            ) {
                                if (isConnecting) {
                                    CircularProgressIndicator(modifier = Modifier.size(18.dp), strokeWidth = 2.dp)
                                } else {
                                    Icon(Icons.Default.Wifi, contentDescription = stringResource(R.string.test_connection), modifier = Modifier.size(18.dp))
                                }
                                Spacer(Modifier.width(4.dp))
                                Text(stringResource(R.string.test_connection))
                            }
                        }
                        connectionStatus?.let { status ->
                            Spacer(Modifier.height(8.dp))
                            val isSuccess = status == connectedString
                            Surface(
                                color = if (isSuccess) BrandGreenSurface else AlertRedSurface,
                                shape = RoundedCornerShape(8.dp)
                            ) {
                                Row(
                                    modifier = Modifier.padding(12.dp),
                                    verticalAlignment = Alignment.CenterVertically
                                ) {
                                    Icon(
                                        if (isSuccess) Icons.Default.CheckCircle else Icons.Default.Error,
                                        contentDescription = null,
                                        tint = if (isSuccess) BrandGreen else AlertRed,
                                        modifier = Modifier.size(20.dp)
                                    )
                                    Spacer(Modifier.width(8.dp))
                                    Text(status, style = MaterialTheme.typography.bodySmall)
                                }
                            }
                        }
                    } else if (serverUrl.isNotBlank()) {
                        Spacer(Modifier.height(4.dp))
                        Text(stringResource(R.string.server_label_format, serverUrl), style = MaterialTheme.typography.bodySmall, color = Neutral600)
                        Text(stringResource(R.string.org_unit_label_format, orgUnitId), style = MaterialTheme.typography.bodySmall, color = Neutral600)
                    }
                }
            }

            // ── Action Buttons ──
            Card {
                Column(modifier = Modifier.padding(16.dp)) {
                    Row(verticalAlignment = Alignment.CenterVertically) {
                        Icon(Icons.Default.CloudUpload, contentDescription = null, tint = InfoBlue)
                        Spacer(Modifier.width(8.dp))
                        Text(stringResource(R.string.export_actions), style = MaterialTheme.typography.titleMedium, fontWeight = FontWeight.SemiBold)
                    }
                    Spacer(Modifier.height(12.dp))
                    Row(
                        modifier = Modifier.fillMaxWidth(),
                        horizontalArrangement = Arrangement.spacedBy(8.dp)
                    ) {
                        Button(
                            onClick = {
                                scope.launch {
                                    val dvs = DHIS2Mapper.buildMonthlyReport(
                                        config = buildConfig(),
                                        period = period,
                                        encounters = cachedEncounters,
                                        labOrders = cachedLabOrders,
                                        referrals = cachedReferrals,
                                        immunizations = emptyList(),
                                        stockItems = emptyList(),
                                        patientCount = patientCount
                                    )
                                    previewJson = DHIS2Mapper.toJson(dvs)
                                    showPreview = true
                                }
                            },
                            modifier = Modifier.weight(1f)
                        ) {
                            Icon(Icons.Default.Visibility, contentDescription = stringResource(R.string.preview), modifier = Modifier.size(18.dp))
                            Spacer(Modifier.width(4.dp))
                            Text(stringResource(R.string.preview))
                        }
                        Button(
                            onClick = {
                                isPushing = true
                                pushResult = null
                                scope.launch {
                                    val dvs = DHIS2Mapper.buildMonthlyReport(
                                        config = buildConfig(),
                                        period = period,
                                        encounters = cachedEncounters,
                                        labOrders = cachedLabOrders,
                                        referrals = cachedReferrals,
                                        immunizations = emptyList(),
                                        stockItems = emptyList(),
                                        patientCount = patientCount
                                    )
                                    val client = DHIS2Client(buildConfig())
                                    val result = client.pushDataValueSet(dvs)
                                    pushResult = when (result) {
                                        is DHIS2Client.DHIS2Result.Success -> {
                                            val ic = result.importCount
                                            String.format(exportSuccessFormat, ic?.imported ?: 0, ic?.updated ?: 0, ic?.ignored ?: 0)
                                        }
                                        is DHIS2Client.DHIS2Result.Error -> String.format(exportFailedFormat, result.message)
                                    }
                                    isPushing = false
                                }
                            },
                            modifier = Modifier.weight(1f),
                            enabled = !isPushing && serverUrl.isNotBlank(),
                            colors = ButtonDefaults.buttonColors(containerColor = BrandGreen)
                        ) {
                            if (isPushing) {
                                CircularProgressIndicator(modifier = Modifier.size(18.dp), strokeWidth = 2.dp, color = MaterialTheme.colorScheme.onPrimary)
                            } else {
                                Icon(Icons.Default.CloudUpload, contentDescription = stringResource(R.string.push_to_dhis2), modifier = Modifier.size(18.dp))
                            }
                            Spacer(Modifier.width(4.dp))
                            Text(stringResource(R.string.push_to_dhis2))
                        }
                    }

                    pushResult?.let { result ->
                        Spacer(Modifier.height(12.dp))
                        val isSuccess = result.startsWith("Success")
                        Surface(
                            color = if (isSuccess) BrandGreenSurface else AlertRedSurface,
                            shape = RoundedCornerShape(8.dp)
                        ) {
                            Row(
                                modifier = Modifier.padding(12.dp),
                                verticalAlignment = Alignment.CenterVertically
                            ) {
                                Icon(
                                    if (isSuccess) Icons.Default.CheckCircle else Icons.Default.Error,
                                    contentDescription = null,
                                    tint = if (isSuccess) BrandGreen else AlertRed,
                                    modifier = Modifier.size(20.dp)
                                )
                                Spacer(Modifier.width(8.dp))
                                Text(result, style = MaterialTheme.typography.bodySmall)
                            }
                        }
                    }
                }
            }

            // ── Info Card ──
            Card(colors = CardDefaults.cardColors(containerColor = Neutral100)) {
                Column(modifier = Modifier.padding(16.dp)) {
                    Text(stringResource(R.string.about_dhis2_integration), style = MaterialTheme.typography.titleSmall, fontWeight = FontWeight.SemiBold)
                    Spacer(Modifier.height(8.dp))
                    Text(
                        stringResource(R.string.dhis2_description),
                        style = MaterialTheme.typography.bodySmall,
                        color = Neutral600
                    )
                    Spacer(Modifier.height(4.dp))
                    Text(
                        stringResource(R.string.dhis2_supported),
                        style = MaterialTheme.typography.labelSmall,
                        color = Neutral500
                    )
                }
            }
        }

        // ── Preview Dialog ──
        if (showPreview) {
            AlertDialog(
                onDismissRequest = { showPreview = false },
                title = { Text(stringResource(R.string.dhis2_payload_preview), fontWeight = FontWeight.Bold) },
                text = {
                    Column(Modifier.verticalScroll(rememberScrollState())) {
                        Card(colors = CardDefaults.cardColors(containerColor = Neutral100)) {
                            Text(
                                previewJson,
                                modifier = Modifier.padding(12.dp),
                                style = MaterialTheme.typography.labelSmall,
                                fontFamily = FontFamily.Monospace
                            )
                        }
                    }
                },
                confirmButton = {
                    TextButton(onClick = { showPreview = false }) { Text(stringResource(R.string.close)) }
                }
            )
        }
    }
}

@Composable
private fun SummaryChip(label: String, value: String) {
    Column(horizontalAlignment = Alignment.CenterHorizontally) {
        Text(value, style = MaterialTheme.typography.titleMedium, fontWeight = FontWeight.Bold, color = BrandGreen)
        Text(label, style = MaterialTheme.typography.labelSmall, color = Neutral600)
    }
}
