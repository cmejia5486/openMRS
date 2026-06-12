package com.lyecdevelopers.worklist.presentation.patient

import androidx.compose.animation.AnimatedVisibility
import androidx.compose.animation.Crossfade
import androidx.compose.foundation.layout.Arrangement
import androidx.compose.foundation.layout.Box
import androidx.compose.foundation.layout.Column
import androidx.compose.foundation.layout.FlowRow
import androidx.compose.foundation.layout.Spacer
import androidx.compose.foundation.layout.fillMaxSize
import androidx.compose.foundation.layout.fillMaxWidth
import androidx.compose.foundation.layout.height
import androidx.compose.foundation.layout.padding
import androidx.compose.foundation.lazy.LazyColumn
import androidx.compose.foundation.lazy.items
import androidx.compose.foundation.shape.RoundedCornerShape
import androidx.compose.material.icons.Icons
import androidx.compose.material.icons.filled.Add
import androidx.compose.material.icons.filled.Close
import androidx.compose.material.icons.filled.Info
import androidx.compose.material.icons.filled.MoreVert
import androidx.compose.material.icons.outlined.MonitorHeart
import androidx.compose.material3.DropdownMenu
import androidx.compose.material3.DropdownMenuItem
import androidx.compose.material3.ExperimentalMaterial3Api
import androidx.compose.material3.ExtendedFloatingActionButton
import androidx.compose.material3.FloatingActionButton
import androidx.compose.material3.HorizontalDivider
import androidx.compose.material3.Icon
import androidx.compose.material3.IconButton
import androidx.compose.material3.MaterialTheme
import androidx.compose.material3.Scaffold
import androidx.compose.material3.Text
import androidx.compose.material3.TopAppBar
import androidx.compose.runtime.Composable
import androidx.compose.runtime.LaunchedEffect
import androidx.compose.runtime.collectAsState
import androidx.compose.runtime.getValue
import androidx.compose.runtime.mutableStateOf
import androidx.compose.runtime.remember
import androidx.compose.runtime.setValue
import androidx.compose.ui.Alignment
import androidx.compose.ui.Modifier
import androidx.compose.ui.draw.shadow
import androidx.compose.ui.graphics.vector.ImageVector
import androidx.compose.ui.unit.dp
import androidx.hilt.navigation.compose.hiltViewModel
import androidx.navigation.NavController
import com.lyecdevelopers.core.data.local.entity.PatientEntity
import com.lyecdevelopers.core.data.local.entity.VitalsEntity
import com.lyecdevelopers.core.model.VisitWithDetails
import com.lyecdevelopers.core.ui.components.BaseScreen
import com.lyecdevelopers.core.ui.components.EmptyStateView
import com.lyecdevelopers.worklist.presentation.visit.VisitCard
import com.lyecdevelopers.worklist.presentation.visit.VisitDetailsDialog
import com.lyecdevelopers.worklist.presentation.worklist.StartVisitDialog
import com.lyecdevelopers.worklist.presentation.worklist.WorklistViewModel
import com.lyecdevelopers.worklist.presentation.worklist.event.WorklistEvent
import java.time.LocalDate
import java.time.Period


@OptIn(ExperimentalMaterial3Api::class)
@Composable
fun PatientDetailsScreen(
    onStartEncounter: (PatientEntity?, Any?) -> Unit,
    viewModel: WorklistViewModel = hiltViewModel(),
    navController: NavController,
) {
    var isLoading by remember { mutableStateOf(false) }
    val state by viewModel.uiState.collectAsState()

    var selectedVisit by remember { mutableStateOf<VisitWithDetails?>(null) }
    var fabExpanded by remember { mutableStateOf(false) }

    var isStartVisitDialogVisible by remember { mutableStateOf(false) }
    var showRecordDialog by remember { mutableStateOf(false) }

    var optionsExpanded by remember { mutableStateOf(false) }
    val eligibleOptions = listOf("Eligible")


    LaunchedEffect(state.mostRecentVisit) {
        state.mostRecentVisit?.visit?.id?.let { visitId ->
            viewModel.getVitalsByVisit(visitId)
        }
    }

    LaunchedEffect(state.isLoading) {
        isLoading = state.isLoading
    }

    val patientVisits = remember(state.visits, state.selectedPatient?.id) {
        state.visits?.filter { it.visit.patientId == state.selectedPatient?.id }
    }


    // ✅ Show Vitals Dialog
    if (showRecordDialog) {
        RecordVitalDialog(
            patient = state.selectedPatient ?: return,
            onDismissRequest = { showRecordDialog = false },
            onSave = { vitals ->
                viewModel.onEvent(WorklistEvent.OnVitalsChanged(vitals))
                viewModel.onEvent(WorklistEvent.SaveVitals)
                showRecordDialog = false
            })
    }

    BaseScreen(
        uiEventFlow = viewModel.uiEvent,
        navController = navController,
        showLoading = { loading -> isLoading = loading },
        isLoading = isLoading,
    ) {
        Scaffold(topBar = {
            TopAppBar(title = { Text("Patient Details") }, actions = {
                IconButton(onClick = { optionsExpanded = true }) {
                    Icon(
                        imageVector = Icons.Default.MoreVert,
                        contentDescription = "More Options"
                    )
                }
                DropdownMenu(
                    expanded = optionsExpanded, onDismissRequest = { optionsExpanded = false }) {
                    eligibleOptions.forEach { option ->
                        DropdownMenuItem(text = { Text(option) }, onClick = {
                            optionsExpanded = false
                            viewModel.onEvent(
                                WorklistEvent.OnMarkPatientEligible(state.selectedPatient?.id)
                            )
                        })
                    }

                    HorizontalDivider()

                    DropdownMenuItem(text = { Text("Sync Now") }, onClick = {
                        optionsExpanded = false
                        viewModel.onEvent(
                            WorklistEvent.OnSyncPatientNow(state.selectedPatient?.id)
                        )
                    })
                }
            })



        }, floatingActionButton = {
            Box(contentAlignment = Alignment.BottomEnd) {
                Column(
                    verticalArrangement = Arrangement.spacedBy(12.dp),
                    horizontalAlignment = Alignment.End,
                    modifier = Modifier.padding(bottom = 72.dp)
                ) {
                    AnimatedVisibility(visible = fabExpanded) {
                        SmallFabButton(
                            icon = Icons.Outlined.MonitorHeart,
                            label = "New Vitals",
                            onClick = {
                                fabExpanded = false
                                showRecordDialog = true
                            },
                        )
                    }

                    AnimatedVisibility(visible = fabExpanded) {
                        SmallFabButton(
                            icon = Icons.Default.Info,
                            label = "New Encounter",
                            onClick = {
                                fabExpanded = false
                                onStartEncounter(state.selectedPatient, null)
                            },
                        )
                    }

                    AnimatedVisibility(visible = fabExpanded) {
                        SmallFabButton(
                            icon = Icons.Default.Add,
                            label = "New Visit",
                            onClick = {
                                fabExpanded = false
                                isStartVisitDialogVisible = true
                            },
                        )
                    }
                }

                FloatingActionButton(
                    onClick = { fabExpanded = !fabExpanded },
                    containerColor = MaterialTheme.colorScheme.primary
                ) {
                    Crossfade(
                        targetState = fabExpanded, label = "FAB Icon Crossfade"
                    ) { expanded ->
                        Icon(
                            imageVector = if (expanded) Icons.Default.Close else Icons.Default.Add,
                            contentDescription = if (expanded) "Close" else "Add"
                        )
                    }
                }
            }
        }
        ) { padding ->
            LazyColumn(
                contentPadding = padding,
                modifier = Modifier
                    .fillMaxSize()
                    .padding(16.dp),
                verticalArrangement = Arrangement.spacedBy(16.dp)
            ) {
                // ───────────── Patient Info ─────────────
                item {
                    val patient = state.selectedPatient

                    if (patient != null) {
                        val age = calculateAge(patient.dateOfBirth)
                        val ageText = if (age >= 0) "$age years" else "Unknown age"
                        val demographics = "$ageText • ${patient.gender}"

                        Column(verticalArrangement = Arrangement.spacedBy(8.dp)) {
                            Text(
                                text = "${patient.firstName} ${patient.lastName}",
                                style = MaterialTheme.typography.titleMedium
                            )
                            Text(demographics, style = MaterialTheme.typography.bodyMedium)

                            if (state.vitals != null) {
                                Column(verticalArrangement = Arrangement.spacedBy(4.dp)) {
                                    Text(
                                        text = "Latest Vitals",
                                        style = MaterialTheme.typography.titleMedium
                                    )
                                    HorizontalDivider()
                                    VitalsInfo(vitals = state.vitalsEntity)
                                }
                            } else {
                                EmptyStateView("No vitals recorded.")
                            }
                        }
                    } else {
                        EmptyStateView("No patient selected.")
                    }
                }

                // ───────────── Current Visit ─────────────
                item {
                    state.mostRecentVisit?.let { visit ->
                        Column(
                            modifier = Modifier
                                .fillMaxWidth()
                                .padding(vertical = 8.dp)
                        ) {
                            Text(
                                text = "Current Visit",
                                style = MaterialTheme.typography.titleMedium
                            )
                            HorizontalDivider(Modifier.padding(vertical = 8.dp))
                            VisitCard(
                                visit = visit,
                                isCurrent = true,
                                onClick = { selectedVisit = visit }
                            )
                        }
                    } ?: run {
                        Column(
                            modifier = Modifier
                                .fillMaxWidth()
                                .padding(vertical = 8.dp)
                        ) {
                            Text(
                                text = "Current Visit",
                                style = MaterialTheme.typography.titleMedium
                            )
                            HorizontalDivider(Modifier.padding(vertical = 8.dp))
                            EmptyStateView(
                                message = "No active visit found."
                            )
                        }
                    }
                }

                // ───────────── Visit History ─────────────
                if (!patientVisits.isNullOrEmpty()) {
                    item {
                        Text(
                            text = "Visit History", style = MaterialTheme.typography.titleMedium
                        )
                        HorizontalDivider(Modifier.padding(vertical = 8.dp))
                    }

                    items(
                        items = patientVisits, key = { it.visit.id }) { visit ->
                        VisitCard(
                            visit = visit, onClick = { selectedVisit = visit })
                    }
                } else {
                    item {
                        Column {
                            Text(
                                text = "Visit History", style = MaterialTheme.typography.titleMedium
                            )
                            HorizontalDivider(Modifier.padding(vertical = 8.dp))
                            EmptyStateView(
                                message = "No previous visits found for this patient."
                            )
                        }
                    }
                }


                // ───────────── Encounters ─────────────
                item {
                    Text("Encounters", style = MaterialTheme.typography.titleMedium)
                    HorizontalDivider()
                }

                if (state.encounters.isNotEmpty()) {
                    item {
                        EncounterSection(
                            title = "Current Encounter", encounters = state.encounters
                        )
                    }
                } else {
                    item {
                        Column {
                            EmptyStateView("No encounters available.")
                            Spacer(Modifier.height(8.dp))
                        }
                    }
                }
            }

            selectedVisit?.let {
                VisitDetailsDialog(
                    visit = it, onDismiss = { selectedVisit = null })
            }
        }

        // ───────────── Start Visit Dialog ─────────────
        StartVisitDialog(
            isVisible = isStartVisitDialogVisible,
            onDismissRequest = { isStartVisitDialogVisible = false },
            viewModel = viewModel
        )
    }
}


@Composable
fun VitalsInfo(vitals: VitalsEntity?) {
    Column {
        Spacer(modifier = Modifier.height(4.dp))

        FlowRow(
            horizontalArrangement = Arrangement.spacedBy(12.dp),
            verticalArrangement = Arrangement.spacedBy(8.dp),
            modifier = Modifier.fillMaxWidth()
        ) {
            if (vitals?.bloodPressureSystolic != null && vitals.bloodPressureDiastolic != null) {
                Text(
                    "BP: ${vitals.bloodPressureSystolic}/${vitals.bloodPressureDiastolic} mmHg",
                    style = MaterialTheme.typography.bodySmall
                )
            }

            vitals?.heartRate?.let {
                Text(
                    "HR: $it bpm",
                    style = MaterialTheme.typography.bodySmall
                )
            }

            vitals?.temperature?.let {
                Text(
                    "Temp: $it °C",
                    style = MaterialTheme.typography.bodySmall
                )
            }

            vitals?.respirationRate?.let {
                Text(
                    "RR: $it breaths/min",
                    style = MaterialTheme.typography.bodySmall
                )
            }

            vitals?.spo2?.let {
                Text(
                    "SpO₂: $it%",
                    style = MaterialTheme.typography.bodySmall
                )
            }

            vitals?.weight?.let {
                Text(
                    "Weight: $it kg",
                    style = MaterialTheme.typography.bodySmall
                )
            }

            vitals?.height?.let {
                Text(
                    "Height: $it cm",
                    style = MaterialTheme.typography.bodySmall
                )
            }

            vitals?.bmi?.let {
                Text(
                    "BMI: $it",
                    style = MaterialTheme.typography.bodySmall
                )
            }

            vitals?.muac?.let {
                Text(
                    "MUAC: $it cm",
                    style = MaterialTheme.typography.bodySmall
                )
            }
        }

        vitals?.notes?.takeIf { it.isNotBlank() }?.let { notes ->
            Spacer(modifier = Modifier.height(8.dp))
            Text(
                "Notes: $notes",
                style = MaterialTheme.typography.bodySmall
            )
        }
    }
}


@Composable
fun SmallFabButton(
    icon: ImageVector,
    label: String,
    onClick: () -> Unit,
) {
    ExtendedFloatingActionButton(
        onClick = onClick,
        icon = { Icon(icon, contentDescription = null) },
        text = { Text(label) },
        containerColor = MaterialTheme.colorScheme.secondaryContainer,
        contentColor = MaterialTheme.colorScheme.onSecondaryContainer,
        modifier = Modifier.shadow(4.dp, RoundedCornerShape(16.dp))
    )
}

fun calculateAge(dateOfBirth: String): Int {
    return try {
        val dob = LocalDate.parse(dateOfBirth)
        val today = LocalDate.now()
        Period.between(dob, today).years
    } catch (_: Exception) {
        -1 // fallback if parsing fails
    }
}


