package com.chartlite.app.ui.screens

import androidx.compose.foundation.layout.*
import androidx.compose.foundation.lazy.LazyColumn
import androidx.compose.foundation.lazy.items
import androidx.compose.foundation.shape.RoundedCornerShape
import androidx.compose.material.icons.Icons
import androidx.compose.material.icons.automirrored.filled.ArrowBack
import androidx.compose.material.icons.filled.Add
import androidx.compose.material.icons.filled.Vaccines
import androidx.compose.material3.*
import androidx.compose.runtime.*
import androidx.compose.ui.Alignment
import androidx.compose.ui.Modifier
import androidx.compose.ui.platform.LocalContext
import androidx.compose.ui.res.stringResource
import androidx.compose.ui.text.font.FontWeight
import androidx.compose.ui.unit.dp
import com.chartlite.app.App
import com.chartlite.app.R
import com.chartlite.app.auth.AuditLogger
import com.chartlite.app.database.entity.ImmunizationEntity
import kotlinx.coroutines.launch
import java.text.SimpleDateFormat
import java.util.Date
import java.util.Locale

@OptIn(ExperimentalMaterial3Api::class)
@Composable
fun ImmunizationScreen(
    patientId: String,
    onBack: () -> Unit
) {
    val context = LocalContext.current
    val app = context.applicationContext as App
    val scope = rememberCoroutineScope()

    var immunizations by remember { mutableStateOf<List<ImmunizationEntity>>(emptyList()) }
    var isLoading by remember { mutableStateOf(true) }
    var showAddDialog by remember { mutableStateOf(false) }

    LaunchedEffect(patientId) {
        immunizations = app.immunizationRepository.getByPatient(patientId)
        isLoading = false
    }

    Scaffold(
        topBar = {
            TopAppBar(
                title = { Text(stringResource(R.string.immunization_record)) },
                navigationIcon = {
                    IconButton(onClick = onBack) { Icon(Icons.AutoMirrored.Filled.ArrowBack, stringResource(R.string.back)) }
                }
            )
        },
        floatingActionButton = {
            FloatingActionButton(onClick = { showAddDialog = true }) {
                Icon(Icons.Default.Add, stringResource(R.string.record_immunization))
            }
        }
    ) { padding ->
        if (isLoading) {
            Box(Modifier.fillMaxSize().padding(padding), contentAlignment = Alignment.Center) { CircularProgressIndicator() }
        } else if (immunizations.isEmpty()) {
            Box(Modifier.fillMaxSize().padding(padding), contentAlignment = Alignment.Center) {
                Column(horizontalAlignment = Alignment.CenterHorizontally) {
                    Icon(Icons.Default.Vaccines, null, Modifier.size(64.dp), tint = MaterialTheme.colorScheme.outline)
                    Spacer(Modifier.height(16.dp))
                    Text(stringResource(R.string.no_immunizations_recorded), style = MaterialTheme.typography.titleMedium)
                    Text(stringResource(R.string.tap_plus_record_vaccination), style = MaterialTheme.typography.bodyMedium, color = MaterialTheme.colorScheme.outline)
                }
            }
        } else {
            LazyColumn(
                modifier = Modifier.fillMaxSize().padding(padding),
                contentPadding = PaddingValues(16.dp),
                verticalArrangement = Arrangement.spacedBy(12.dp)
            ) {
                items(immunizations, key = { it.id }) { imm ->
                    ImmunizationCard(imm)
                }
            }
        }
    }

    if (showAddDialog) {
        RecordImmunizationDialog(
            onDismiss = { showAddDialog = false },
            onConfirm = { vaccineCode, vaccineName, doseNumber, site, batchNumber ->
                scope.launch {
                    val userId = app.sessionManager.currentSession?.userId ?: "system"
                    app.immunizationRepository.recordImmunization(
                        patientId = patientId, vaccineCode = vaccineCode,
                        vaccineName = vaccineName, doseNumber = doseNumber,
                        administeredBy = userId, facilityId = app.appConfig.facilityId,
                        batchNumber = batchNumber, site = site
                    )
                    app.auditLogger.log("RECORD_IMMUNIZATION", "IMMUNIZATION", patientId,
                        AuditLogger.buildDetails("vaccine" to vaccineCode, "dose" to doseNumber))
                    immunizations = app.immunizationRepository.getByPatient(patientId)
                    showAddDialog = false
                }
            }
        )
    }
}

@Composable
private fun ImmunizationCard(immunization: ImmunizationEntity) {
    val dateFormat = remember { SimpleDateFormat("dd MMM yyyy", Locale.getDefault()) }
    val isOverdue = immunization.nextDoseDueDate != null &&
            immunization.nextDoseDueDate <= System.currentTimeMillis()

    Card(modifier = Modifier.fillMaxWidth(), shape = RoundedCornerShape(12.dp)) {
        Column(Modifier.padding(16.dp)) {
            Row(Modifier.fillMaxWidth(), horizontalArrangement = Arrangement.SpaceBetween) {
                Text(immunization.vaccineName, fontWeight = FontWeight.Bold)
                Surface(
                    color = MaterialTheme.colorScheme.secondaryContainer,
                    shape = RoundedCornerShape(8.dp)
                ) {
                    Text(stringResource(R.string.dose_format, immunization.doseNumber), style = MaterialTheme.typography.labelSmall,
                        modifier = Modifier.padding(horizontal = 12.dp, vertical = 6.dp))
                }
            }
            Text(stringResource(R.string.code_format, immunization.vaccineCode), style = MaterialTheme.typography.bodySmall, color = MaterialTheme.colorScheme.outline)
            Text(stringResource(R.string.given_format, dateFormat.format(Date(immunization.administeredAt))), style = MaterialTheme.typography.bodySmall)
            immunization.site?.let { Text(stringResource(R.string.site_format, it), style = MaterialTheme.typography.bodySmall) }
            immunization.batchNumber?.let { Text(stringResource(R.string.batch_label_format, it), style = MaterialTheme.typography.bodySmall) }
            immunization.nextDoseDueDate?.let {
                Spacer(Modifier.height(4.dp))
                val dateStr = dateFormat.format(Date(it))
                Text(
                    if (isOverdue) stringResource(R.string.next_dose_overdue_format, dateStr)
                    else stringResource(R.string.next_dose_format, dateStr),
                    style = MaterialTheme.typography.bodySmall,
                    fontWeight = if (isOverdue) FontWeight.Bold else FontWeight.Normal,
                    color = if (isOverdue) MaterialTheme.colorScheme.error else MaterialTheme.colorScheme.outline
                )
            }
        }
    }
}

@Composable
private fun RecordImmunizationDialog(
    onDismiss: () -> Unit,
    onConfirm: (vaccineCode: String, vaccineName: String, doseNumber: Int, site: String?, batchNumber: String?) -> Unit
) {
    var vaccineCode by remember { mutableStateOf("") }
    var vaccineName by remember { mutableStateOf("") }
    var doseNumber by remember { mutableStateOf("1") }
    var site by remember { mutableStateOf("") }
    var batchNumber by remember { mutableStateOf("") }

    // Common EPI vaccines for quick selection
    val commonVaccines = listOf(
        "BCG" to "BCG (Tuberculosis)",
        "OPV" to "Oral Polio Vaccine",
        "PENTA" to "Pentavalent (DPT-HepB-Hib)",
        "PCV" to "Pneumococcal Conjugate",
        "ROTA" to "Rotavirus",
        "MEASLES" to "Measles/MR",
        "YELLOW_FEVER" to "Yellow Fever",
        "HPV" to "HPV Vaccine",
        "TT" to "Tetanus Toxoid",
        "COVID" to "COVID-19"
    )

    AlertDialog(
        onDismissRequest = onDismiss,
        title = { Text(stringResource(R.string.record_immunization)) },
        text = {
            Column(verticalArrangement = Arrangement.spacedBy(8.dp)) {
                Text(stringResource(R.string.quick_select), fontWeight = FontWeight.Medium, style = MaterialTheme.typography.bodySmall)
                Row(horizontalArrangement = Arrangement.spacedBy(4.dp), modifier = Modifier.fillMaxWidth()) {
                    commonVaccines.take(5).forEach { (code, name) ->
                        FilterChip(
                            selected = vaccineCode == code,
                            onClick = { vaccineCode = code; vaccineName = name },
                            label = { Text(code, style = MaterialTheme.typography.labelSmall) }
                        )
                    }
                }
                Row(horizontalArrangement = Arrangement.spacedBy(4.dp), modifier = Modifier.fillMaxWidth()) {
                    commonVaccines.drop(5).forEach { (code, name) ->
                        FilterChip(
                            selected = vaccineCode == code,
                            onClick = { vaccineCode = code; vaccineName = name },
                            label = { Text(code, style = MaterialTheme.typography.labelSmall) }
                        )
                    }
                }
                OutlinedTextField(value = vaccineCode, onValueChange = { vaccineCode = it }, label = { Text(stringResource(R.string.vaccine_code)) }, modifier = Modifier.fillMaxWidth())
                OutlinedTextField(value = vaccineName, onValueChange = { vaccineName = it }, label = { Text(stringResource(R.string.vaccine_name)) }, modifier = Modifier.fillMaxWidth())
                OutlinedTextField(value = doseNumber, onValueChange = { doseNumber = it.filter { c -> c.isDigit() } }, label = { Text(stringResource(R.string.dose_number)) }, modifier = Modifier.fillMaxWidth())
                OutlinedTextField(value = site, onValueChange = { site = it }, label = { Text(stringResource(R.string.site_optional)) }, modifier = Modifier.fillMaxWidth())
                OutlinedTextField(value = batchNumber, onValueChange = { batchNumber = it }, label = { Text(stringResource(R.string.batch_optional)) }, modifier = Modifier.fillMaxWidth())
            }
        },
        confirmButton = {
            Button(
                onClick = { onConfirm(vaccineCode, vaccineName, doseNumber.toIntOrNull() ?: 1, site.ifBlank { null }, batchNumber.ifBlank { null }) },
                enabled = vaccineCode.isNotBlank() && vaccineName.isNotBlank()
            ) { Text(stringResource(R.string.record)) }
        },
        dismissButton = { TextButton(onClick = onDismiss) { Text(stringResource(R.string.cancel)) } }
    )
}
