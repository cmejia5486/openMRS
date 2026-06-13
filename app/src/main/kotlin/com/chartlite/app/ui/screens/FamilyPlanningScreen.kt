package com.chartlite.app.ui.screens

import androidx.compose.foundation.layout.*
import androidx.compose.foundation.lazy.LazyColumn
import androidx.compose.foundation.lazy.items
import androidx.compose.foundation.shape.RoundedCornerShape
import androidx.compose.material.icons.Icons
import androidx.compose.material.icons.automirrored.filled.ArrowBack
import androidx.compose.material.icons.filled.Add
import androidx.compose.material.icons.filled.FamilyRestroom
import androidx.compose.material3.*
import androidx.compose.runtime.*
import androidx.compose.ui.Alignment
import androidx.compose.ui.Modifier
import androidx.compose.ui.platform.LocalContext
import androidx.compose.ui.text.font.FontWeight
import androidx.compose.ui.unit.dp
import com.chartlite.app.App
import com.chartlite.app.auth.AuditLogger
import androidx.compose.ui.res.stringResource
import com.chartlite.app.R
import com.chartlite.app.database.entity.FPVisitEntity
import kotlinx.coroutines.launch
import java.text.SimpleDateFormat
import java.util.Date
import java.util.Locale

enum class FPMethod(val displayName: String) {
    COC("Combined Oral Contraceptive"),
    POP("Progestogen-Only Pill"),
    INJECTABLE("Injectable (DMPA/NET-EN)"),
    IMPLANT("Implant (Implanon/Jadelle)"),
    IUD("Intrauterine Device"),
    CONDOM("Condom (Male/Female)"),
    NATURAL("Natural Family Planning"),
    STERILIZATION("Sterilization"),
    NONE("None/Counseling Only")
}

@OptIn(ExperimentalMaterial3Api::class)
@Composable
fun FamilyPlanningScreen(
    patientId: String,
    onBack: () -> Unit
) {
    val context = LocalContext.current
    val app = context.applicationContext as App
    val scope = rememberCoroutineScope()

    var fpVisits by remember { mutableStateOf<List<FPVisitEntity>>(emptyList()) }
    var activeMethod by remember { mutableStateOf<FPVisitEntity?>(null) }
    var isLoading by remember { mutableStateOf(true) }
    var showAddDialog by remember { mutableStateOf(false) }

    LaunchedEffect(patientId) {
        fpVisits = app.fpRepository.getByPatient(patientId)
        activeMethod = app.fpRepository.getActiveMethod(patientId)
        isLoading = false
    }

    Scaffold(
        topBar = {
            TopAppBar(
                title = { Text(stringResource(R.string.family_planning)) },
                navigationIcon = {
                    IconButton(onClick = onBack) { Icon(Icons.AutoMirrored.Filled.ArrowBack, stringResource(R.string.back)) }
                }
            )
        },
        floatingActionButton = {
            FloatingActionButton(onClick = { showAddDialog = true }) { Icon(Icons.Default.Add, stringResource(R.string.new_visit)) }
        }
    ) { padding ->
        if (isLoading) {
            Box(Modifier.fillMaxSize().padding(padding), contentAlignment = Alignment.Center) { CircularProgressIndicator() }
        } else {
            LazyColumn(
                modifier = Modifier.fillMaxSize().padding(padding),
                contentPadding = PaddingValues(16.dp),
                verticalArrangement = Arrangement.spacedBy(12.dp)
            ) {
                // Current method card
                item {
                    Card(
                        modifier = Modifier.fillMaxWidth(),
                        shape = RoundedCornerShape(12.dp),
                        colors = CardDefaults.cardColors(containerColor = MaterialTheme.colorScheme.primaryContainer)
                    ) {
                        Column(Modifier.padding(16.dp)) {
                            Text(stringResource(R.string.current_method), style = MaterialTheme.typography.labelMedium)
                            Text(
                                activeMethod?.let {
                                    FPMethod.entries.find { m -> m.name == it.method }?.displayName ?: it.method
                                } ?: stringResource(R.string.none_recorded),
                                fontWeight = FontWeight.Bold,
                                style = MaterialTheme.typography.titleMedium
                            )
                            activeMethod?.nextFollowUpDate?.let {
                                val dateFormat = SimpleDateFormat("dd MMM yyyy", Locale.getDefault())
                                val isOverdue = it <= System.currentTimeMillis()
                                Text(
                                    if (isOverdue) stringResource(R.string.next_follow_up_overdue_format, dateFormat.format(Date(it)))
                                    else stringResource(R.string.next_follow_up_format, dateFormat.format(Date(it))),
                                    color = if (isOverdue) MaterialTheme.colorScheme.error else MaterialTheme.colorScheme.onPrimaryContainer
                                )
                            }
                        }
                    }
                }

                if (fpVisits.isEmpty()) {
                    item {
                        Box(Modifier.fillMaxWidth().padding(32.dp), contentAlignment = Alignment.Center) {
                            Column(horizontalAlignment = Alignment.CenterHorizontally) {
                                Icon(Icons.Default.FamilyRestroom, null, Modifier.size(48.dp), tint = MaterialTheme.colorScheme.outline)
                                Spacer(Modifier.height(8.dp))
                                Text(stringResource(R.string.no_fp_visits), style = MaterialTheme.typography.bodyMedium, color = MaterialTheme.colorScheme.outline)
                            }
                        }
                    }
                }

                items(fpVisits, key = { it.id }) { visit ->
                    FPVisitCard(visit)
                }
            }
        }
    }

    if (showAddDialog) {
        RecordFPVisitDialog(
            onDismiss = { showAddDialog = false },
            onConfirm = { method, counselingNotes, commodityDispensed, quantity ->
                scope.launch {
                    val userId = app.sessionManager.currentSession?.userId ?: "system"
                    app.fpRepository.recordVisit(
                        patientId = patientId, method = method,
                        providerId = userId, facilityId = app.appConfig.facilityId,
                        counselingNotes = counselingNotes, commodityDispensed = commodityDispensed,
                        quantity = quantity
                    )
                    app.auditLogger.log("RECORD_FP_VISIT", "FP_VISIT", patientId, AuditLogger.buildDetails("method" to method))
                    fpVisits = app.fpRepository.getByPatient(patientId)
                    activeMethod = app.fpRepository.getActiveMethod(patientId)
                    showAddDialog = false
                }
            }
        )
    }
}

@Composable
private fun FPVisitCard(visit: FPVisitEntity) {
    val dateFormat = remember { SimpleDateFormat("dd MMM yyyy", Locale.getDefault()) }
    Card(modifier = Modifier.fillMaxWidth(), shape = RoundedCornerShape(12.dp)) {
        Column(Modifier.padding(16.dp)) {
            Row(Modifier.fillMaxWidth(), horizontalArrangement = Arrangement.SpaceBetween) {
                Text(dateFormat.format(Date(visit.createdAt)), fontWeight = FontWeight.Bold)
                Surface(
                    color = MaterialTheme.colorScheme.secondaryContainer,
                    shape = RoundedCornerShape(8.dp)
                ) {
                    Text(visit.method.replace("_", " "), style = MaterialTheme.typography.labelSmall,
                        modifier = Modifier.padding(horizontal = 12.dp, vertical = 6.dp))
                }
            }
            visit.counselingNotes?.let { Text(stringResource(R.string.notes_format, it), style = MaterialTheme.typography.bodySmall) }
            visit.commodityDispensed?.let { Text(stringResource(R.string.dispensed_visit_format, it, (visit.quantity ?: "?").toString()), style = MaterialTheme.typography.bodySmall) }
            visit.sideEffects?.let { Text(stringResource(R.string.side_effects_format, it), style = MaterialTheme.typography.bodySmall, color = MaterialTheme.colorScheme.error) }
        }
    }
}

@Composable
private fun RecordFPVisitDialog(
    onDismiss: () -> Unit,
    onConfirm: (method: String, counselingNotes: String?, commodityDispensed: String?, quantity: Int?) -> Unit
) {
    var selectedMethod by remember { mutableStateOf("") }
    var counselingNotes by remember { mutableStateOf("") }
    var commodity by remember { mutableStateOf("") }
    var quantity by remember { mutableStateOf("") }
    var showErrors by remember { mutableStateOf(false) }

    AlertDialog(
        onDismissRequest = onDismiss,
        title = { Text(stringResource(R.string.record_fp_visit)) },
        text = {
            Column(verticalArrangement = Arrangement.spacedBy(8.dp)) {
                Text(
                    stringResource(R.string.method) + if (showErrors && selectedMethod.isBlank()) " (${stringResource(R.string.required)})" else "",
                    fontWeight = FontWeight.Medium,
                    color = if (showErrors && selectedMethod.isBlank()) MaterialTheme.colorScheme.error else MaterialTheme.colorScheme.onSurface
                )
                FPMethod.entries.chunked(3).forEach { row ->
                    Row(horizontalArrangement = Arrangement.spacedBy(4.dp)) {
                        row.forEach { m ->
                            FilterChip(
                                selected = selectedMethod == m.name,
                                onClick = { selectedMethod = m.name },
                                label = { Text(m.name, style = MaterialTheme.typography.labelSmall) }
                            )
                        }
                    }
                }
                OutlinedTextField(value = counselingNotes, onValueChange = { counselingNotes = it }, label = { Text(stringResource(R.string.counseling_notes)) }, modifier = Modifier.fillMaxWidth(), minLines = 2)
                OutlinedTextField(value = commodity, onValueChange = { commodity = it }, label = { Text(stringResource(R.string.commodity_dispensed)) }, modifier = Modifier.fillMaxWidth())
                OutlinedTextField(value = quantity, onValueChange = { quantity = it.filter { c -> c.isDigit() } }, label = { Text(stringResource(R.string.quantity)) }, modifier = Modifier.fillMaxWidth())
            }
        },
        confirmButton = {
            Button(
                onClick = {
                    if (selectedMethod.isBlank()) { showErrors = true; return@Button }
                    showErrors = false
                    onConfirm(selectedMethod, counselingNotes.ifBlank { null }, commodity.ifBlank { null }, quantity.toIntOrNull())
                }
            ) { Text(stringResource(R.string.record)) }
        },
        dismissButton = { TextButton(onClick = onDismiss) { Text(stringResource(R.string.cancel)) } }
    )
}
