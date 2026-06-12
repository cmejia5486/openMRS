package com.chartlite.app.ui.screens

import androidx.compose.foundation.background
import androidx.compose.foundation.layout.*
import androidx.compose.foundation.layout.heightIn
import androidx.compose.foundation.lazy.LazyColumn
import androidx.compose.foundation.lazy.itemsIndexed
import androidx.compose.foundation.shape.RoundedCornerShape
import androidx.compose.material.icons.Icons
import androidx.compose.material.icons.automirrored.filled.ArrowBack
import androidx.compose.material.icons.filled.CheckCircle
import androidx.compose.material.icons.filled.LocalPharmacy
import androidx.compose.material3.*
import androidx.compose.runtime.*
import androidx.compose.ui.Alignment
import androidx.compose.ui.Modifier
import androidx.compose.ui.draw.clip
import androidx.compose.ui.graphics.Color
import androidx.compose.ui.platform.LocalContext
import androidx.compose.ui.text.font.FontWeight
import androidx.compose.ui.unit.dp
import androidx.compose.ui.unit.sp
import com.chartlite.app.App
import com.chartlite.app.database.entity.PatientEntity
import com.chartlite.app.database.entity.VisitEntity
import com.chartlite.app.model.Medication
import com.chartlite.app.ui.theme.*
import com.google.gson.Gson
import com.google.gson.reflect.TypeToken
import kotlinx.coroutines.launch
import androidx.compose.ui.res.stringResource
import com.chartlite.app.R

@OptIn(ExperimentalMaterial3Api::class)
@Composable
fun PharmacyScreen(
    visitId: String,
    onComplete: () -> Unit,
    onBack: () -> Unit
) {
    val context = LocalContext.current
    val app = context.applicationContext as App
    val scope = rememberCoroutineScope()
    val gson = remember { Gson() }

    var visit by remember { mutableStateOf<VisitEntity?>(null) }
    var patient by remember { mutableStateOf<PatientEntity?>(null) }
    var medications by remember { mutableStateOf<List<Medication>>(emptyList()) }
    var isLoading by remember { mutableStateOf(true) }
    var isSaving by remember { mutableStateOf(false) }
    var errorMessage by remember { mutableStateOf<String?>(null) }

    // Track dispense status per medication: index -> status string
    val dispenseStatus = remember { mutableStateMapOf<Int, String>() }
    var showConfirmDialog by remember { mutableStateOf(false) }
    val failedToLoadVisitMsg = stringResource(R.string.failed_to_load_visit)
    val failedToSaveMsg = stringResource(R.string.failed_to_save)

    // Load visit, encounter, patient data
    LaunchedEffect(visitId) {
        try {
            val loadedVisit = app.visitRepository.getById(visitId)
            visit = loadedVisit

            if (loadedVisit != null) {
                // Load patient info
                patient = app.patientRepository.getById(loadedVisit.patientId)

                // Load consultation encounter medications
                val consultId = loadedVisit.consultEncounterId
                if (consultId != null) {
                    val encounter = app.encounterRepository.getById(consultId)
                    if (encounter != null) {
                        val medsType = object : TypeToken<List<Medication>>() {}.type
                        val parsedMeds: List<Medication> = try {
                            gson.fromJson(encounter.medications, medsType) ?: emptyList()
                        } catch (_: Exception) {
                            emptyList()
                        }
                        medications = parsedMeds
                    }
                }
            }
        } catch (e: Exception) {
            errorMessage = failedToLoadVisitMsg
        } finally {
            isLoading = false
        }
    }

    // Confirm dispensing dialog
    if (showConfirmDialog) {
        AlertDialog(
            onDismissRequest = { showConfirmDialog = false },
            title = { Text(stringResource(R.string.complete_dispensing_title)) },
            text = {
                val pending = medications.indices.count { (dispenseStatus[it] ?: "Pending") == "Pending" }
                if (pending > 0) {
                    Text(stringResource(R.string.pending_meds_format, pending))
                } else {
                    Text(stringResource(R.string.finalize_dispensing))
                }
            },
            confirmButton = {
                TextButton(onClick = {
                    showConfirmDialog = false
                    if (isSaving) return@TextButton
                    isSaving = true
                    scope.launch {
                        try {
                            val notes = medications.mapIndexed { index, med ->
                                mapOf(
                                    "medication" to med.name,
                                    "formularyCode" to med.formularyCode,
                                    "status" to (dispenseStatus[index] ?: "Pending")
                                )
                            }
                            val notesJson = gson.toJson(notes)
                            app.visitRepository.savePharmacyNotes(visitId, notesJson)
                            app.visitRepository.completeVisit(
                                visitId = visitId,
                                providerId = app.sessionManager.currentSession?.userId
                                    ?: app.appConfig.providerId
                            )
                            onComplete()
                        } catch (e: Exception) {
                            errorMessage = failedToSaveMsg
                            isSaving = false
                        }
                    }
                }) {
                    Text(stringResource(R.string.complete))
                }
            },
            dismissButton = {
                TextButton(onClick = { showConfirmDialog = false }) {
                    Text(stringResource(R.string.cancel))
                }
            }
        )
    }

    Scaffold(
        topBar = {
            TopAppBar(
                title = { Text(stringResource(R.string.pharmacy)) },
                navigationIcon = {
                    IconButton(onClick = onBack) {
                        Icon(Icons.AutoMirrored.Filled.ArrowBack, contentDescription = stringResource(R.string.back))
                    }
                },
                colors = TopAppBarDefaults.topAppBarColors(
                    containerColor = MaterialTheme.colorScheme.surface
                )
            )
        },
        containerColor = MaterialTheme.colorScheme.surfaceContainerLow
    ) { padding ->
        if (isLoading) {
            Box(
                modifier = Modifier
                    .fillMaxSize()
                    .padding(padding),
                contentAlignment = Alignment.Center
            ) {
                CircularProgressIndicator(color = BrandGreen)
            }
            return@Scaffold
        }

        if (visit == null) {
            Box(
                modifier = Modifier
                    .fillMaxSize()
                    .padding(padding),
                contentAlignment = Alignment.Center
            ) {
                Text(
                    errorMessage ?: stringResource(R.string.visit_not_found),
                    style = MaterialTheme.typography.bodyLarge,
                    color = Neutral600
                )
            }
            return@Scaffold
        }

        LazyColumn(
            modifier = Modifier
                .fillMaxSize()
                .padding(padding),
            contentPadding = PaddingValues(horizontal = 20.dp, vertical = 16.dp),
            verticalArrangement = Arrangement.spacedBy(12.dp)
        ) {
            // Patient info card
            item(key = "patient_info") {
                Card(
                    modifier = Modifier.fillMaxWidth(),
                    shape = RoundedCornerShape(14.dp),
                    colors = CardDefaults.cardColors(containerColor = MaterialTheme.colorScheme.surface),
                    elevation = CardDefaults.cardElevation(defaultElevation = 1.dp)
                ) {
                    Row(
                        modifier = Modifier
                            .fillMaxWidth()
                            .padding(16.dp),
                        verticalAlignment = Alignment.CenterVertically,
                        horizontalArrangement = Arrangement.spacedBy(12.dp)
                    ) {
                        Box(
                            modifier = Modifier
                                .size(44.dp)
                                .clip(RoundedCornerShape(12.dp))
                                .background(BrandGreenSurface),
                            contentAlignment = Alignment.Center
                        ) {
                            Icon(
                                Icons.Default.LocalPharmacy,
                                contentDescription = null,
                                tint = BrandGreen,
                                modifier = Modifier.size(24.dp)
                            )
                        }
                        Column(modifier = Modifier.weight(1f)) {
                            Text(
                                text = patient?.let { "${it.firstName} ${it.lastName}" } ?: stringResource(R.string.patient_id),
                                style = MaterialTheme.typography.titleMedium,
                                fontWeight = FontWeight.SemiBold,
                                color = Neutral900
                            )
                            Text(
                                text = "ID: ${visit?.patientId ?: "—"}",
                                style = MaterialTheme.typography.bodySmall,
                                color = Neutral500
                            )
                        }
                    }
                }
            }

            // Medications header
            item(key = "meds_header") {
                Text(
                    stringResource(R.string.prescribed_medications_header),
                    style = MaterialTheme.typography.labelMedium,
                    color = Neutral500,
                    letterSpacing = 1.5.sp,
                    modifier = Modifier.padding(top = 4.dp)
                )
            }

            if (medications.isEmpty()) {
                item(key = "no_meds") {
                    Card(
                        modifier = Modifier.fillMaxWidth(),
                        shape = RoundedCornerShape(14.dp),
                        colors = CardDefaults.cardColors(containerColor = MaterialTheme.colorScheme.surface)
                    ) {
                        Column(
                            modifier = Modifier
                                .fillMaxWidth()
                                .padding(32.dp),
                            horizontalAlignment = Alignment.CenterHorizontally
                        ) {
                            Text(
                                stringResource(R.string.no_medications_prescribed),
                                style = MaterialTheme.typography.bodyLarge,
                                color = Neutral600
                            )
                            Spacer(Modifier.height(4.dp))
                            Text(
                                stringResource(R.string.no_prescriptions_consultation),
                                style = MaterialTheme.typography.bodySmall,
                                color = Neutral400
                            )
                        }
                    }
                }
            }

            // Medication cards
            itemsIndexed(medications, key = { index, med -> "med_$index" }) { index, med ->
                MedicationDispenseCard(
                    medication = med,
                    status = dispenseStatus[index],
                    onStatusChange = { newStatus ->
                        dispenseStatus[index] = newStatus
                    }
                )
            }

            // Complete dispensing button
            item(key = "complete_button") {
                Spacer(Modifier.height(8.dp))
                Button(
                    onClick = { showConfirmDialog = true },
                    enabled = !isSaving,
                    modifier = Modifier
                        .fillMaxWidth()
                        .height(52.dp),
                    shape = RoundedCornerShape(14.dp),
                    colors = ButtonDefaults.buttonColors(
                        containerColor = BrandGreen,
                        contentColor = Color.White
                    )
                ) {
                    if (isSaving) {
                        CircularProgressIndicator(
                            modifier = Modifier.size(20.dp),
                            color = Color.White,
                            strokeWidth = 2.dp
                        )
                    } else {
                        Icon(
                            Icons.Default.CheckCircle,
                            contentDescription = null,
                            modifier = Modifier.size(20.dp)
                        )
                        Spacer(Modifier.width(8.dp))
                        Text(
                            stringResource(R.string.complete_dispensing),
                            style = MaterialTheme.typography.titleMedium,
                            fontWeight = FontWeight.SemiBold
                        )
                    }
                }

                // Error message
                errorMessage?.let { err ->
                    Spacer(Modifier.height(8.dp))
                    Card(
                        colors = CardDefaults.cardColors(
                            containerColor = AlertRedSurface
                        ),
                        shape = RoundedCornerShape(10.dp)
                    ) {
                        Text(
                            err,
                            modifier = Modifier.padding(12.dp),
                            color = AlertRed,
                            style = MaterialTheme.typography.bodySmall
                        )
                    }
                }

                Spacer(Modifier.height(24.dp))
            }
        }
    }
}

@OptIn(ExperimentalMaterial3Api::class)
@Composable
private fun MedicationDispenseCard(
    medication: Medication,
    status: String?,
    onStatusChange: (String) -> Unit
) {
    Card(
        modifier = Modifier.fillMaxWidth(),
        shape = RoundedCornerShape(14.dp),
        colors = CardDefaults.cardColors(containerColor = MaterialTheme.colorScheme.surface),
        elevation = CardDefaults.cardElevation(defaultElevation = 1.dp)
    ) {
        Column(
            modifier = Modifier
                .fillMaxWidth()
                .padding(16.dp)
        ) {
            // Medication name + formulary code
            Row(
                modifier = Modifier.fillMaxWidth(),
                horizontalArrangement = Arrangement.SpaceBetween,
                verticalAlignment = Alignment.CenterVertically
            ) {
                Text(
                    text = medication.name,
                    style = MaterialTheme.typography.titleMedium,
                    fontWeight = FontWeight.Bold,
                    color = Neutral900,
                    modifier = Modifier.weight(1f)
                )
                if (medication.formularyCode.isNotBlank()) {
                    Surface(
                        shape = RoundedCornerShape(6.dp),
                        color = Neutral100
                    ) {
                        Text(
                            text = medication.formularyCode,
                            style = MaterialTheme.typography.labelSmall,
                            color = Neutral600,
                            modifier = Modifier.padding(horizontal = 8.dp, vertical = 4.dp)
                        )
                    }
                }
            }

            Spacer(Modifier.height(8.dp))

            // Dose + frequency + duration
            val doseText = buildString {
                medication.dose?.let { append("${it}") }
                medication.unit?.let { append(" $it") }
                medication.frequency?.let { append(" - $it") }
                medication.duration?.let { append(" for $it days") }
            }.trim()
            if (doseText.isNotEmpty()) {
                Text(
                    text = doseText,
                    style = MaterialTheme.typography.bodyMedium,
                    color = Neutral700
                )
                Spacer(Modifier.height(6.dp))
            }

            // Route badge
            medication.route?.let { route ->
                Surface(
                    shape = RoundedCornerShape(6.dp),
                    color = InfoBlueSurface
                ) {
                    Text(
                        text = route.uppercase(),
                        style = MaterialTheme.typography.labelSmall,
                        fontWeight = FontWeight.Medium,
                        color = InfoBlue,
                        modifier = Modifier.padding(horizontal = 8.dp, vertical = 4.dp)
                    )
                }
                Spacer(Modifier.height(12.dp))
            }

            // Dispense status chips — 10dp spacing for gloved clinical use
            Row(
                modifier = Modifier.fillMaxWidth(),
                horizontalArrangement = Arrangement.spacedBy(10.dp)
            ) {
                DispenseChip(
                    label = "Dispensed",
                    selected = status == "Dispensed",
                    selectedColor = BrandGreen,
                    onClick = {
                        onStatusChange(if (status == "Dispensed") "" else "Dispensed")
                    },
                    modifier = Modifier.weight(1f)
                )
                DispenseChip(
                    label = "Out of Stock",
                    selected = status == "Out of Stock",
                    selectedColor = AlertRed,
                    onClick = {
                        onStatusChange(if (status == "Out of Stock") "" else "Out of Stock")
                    },
                    modifier = Modifier.weight(1f)
                )
                DispenseChip(
                    label = "Substituted",
                    selected = status == "Substituted",
                    selectedColor = WarningAmber,
                    onClick = {
                        onStatusChange(if (status == "Substituted") "" else "Substituted")
                    },
                    modifier = Modifier.weight(1f)
                )
            }
        }
    }
}

@OptIn(ExperimentalMaterial3Api::class)
@Composable
private fun DispenseChip(
    label: String,
    selected: Boolean,
    selectedColor: Color,
    onClick: () -> Unit,
    modifier: Modifier = Modifier
) {
    FilterChip(
        selected = selected,
        onClick = onClick,
        modifier = modifier.heightIn(min = 44.dp),
        label = {
            Text(
                text = label,
                style = MaterialTheme.typography.labelMedium,
                fontWeight = if (selected) FontWeight.SemiBold else FontWeight.Normal
            )
        },
        colors = FilterChipDefaults.filterChipColors(
            selectedContainerColor = selectedColor.copy(alpha = 0.15f),
            selectedLabelColor = selectedColor
        ),
        border = FilterChipDefaults.filterChipBorder(
            borderColor = Neutral300,
            selectedBorderColor = selectedColor,
            enabled = true,
            selected = selected
        )
    )
}
