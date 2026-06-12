package com.lyecdevelopers.sync.presentation

// Sync module
import androidx.compose.animation.animateContentSize
import androidx.compose.animation.core.animateIntAsState
import androidx.compose.foundation.layout.Arrangement
import androidx.compose.foundation.layout.Column
import androidx.compose.foundation.layout.ColumnScope
import androidx.compose.foundation.layout.Row
import androidx.compose.foundation.layout.Spacer
import androidx.compose.foundation.layout.fillMaxSize
import androidx.compose.foundation.layout.fillMaxWidth
import androidx.compose.foundation.layout.height
import androidx.compose.foundation.layout.padding
import androidx.compose.foundation.layout.size
import androidx.compose.foundation.layout.width
import androidx.compose.foundation.lazy.LazyColumn
import androidx.compose.foundation.shape.RoundedCornerShape
import androidx.compose.material.icons.Icons
import androidx.compose.material.icons.filled.Autorenew
import androidx.compose.material.icons.filled.CheckCircle
import androidx.compose.material.icons.filled.Description
import androidx.compose.material.icons.filled.Download
import androidx.compose.material.icons.filled.ErrorOutline
import androidx.compose.material.icons.filled.Groups
import androidx.compose.material.icons.filled.HowToReg
import androidx.compose.material.icons.filled.People
import androidx.compose.material.icons.filled.Person
import androidx.compose.material.icons.filled.PersonSearch
import androidx.compose.material.icons.filled.Schedule
import androidx.compose.material.icons.filled.Sync
import androidx.compose.material3.AlertDialog
import androidx.compose.material3.Button
import androidx.compose.material3.ExperimentalMaterial3Api
import androidx.compose.material3.HorizontalDivider
import androidx.compose.material3.Icon
import androidx.compose.material3.MaterialTheme
import androidx.compose.material3.ModalBottomSheet
import androidx.compose.material3.Scaffold
import androidx.compose.material3.Surface
import androidx.compose.material3.Switch
import androidx.compose.material3.Text
import androidx.compose.material3.TextButton
import androidx.compose.material3.rememberModalBottomSheetState
import androidx.compose.runtime.Composable
import androidx.compose.runtime.LaunchedEffect
import androidx.compose.runtime.collectAsState
import androidx.compose.runtime.getValue
import androidx.compose.runtime.mutableStateOf
import androidx.compose.runtime.remember
import androidx.compose.runtime.saveable.rememberSaveable
import androidx.compose.runtime.setValue
import androidx.compose.ui.Alignment
import androidx.compose.ui.Modifier
import androidx.compose.ui.graphics.vector.ImageVector
import androidx.compose.ui.text.font.FontWeight
import androidx.compose.ui.unit.dp
import androidx.hilt.navigation.compose.hiltViewModel
import com.lyecdevelopers.core.model.cohort.IndicatorRepository
import com.lyecdevelopers.core.ui.components.BaseScreen
import com.lyecdevelopers.sync.presentation.event.SyncEvent
import com.lyecdevelopers.sync.presentation.forms.DownloadFormsScreen
import com.lyecdevelopers.sync.presentation.patients.PatientFilterSectionContent


@OptIn(ExperimentalMaterial3Api::class)
@Composable
fun SyncScreen(
    onBack: () -> Unit = {},
) {
    val viewModel: SyncViewModel = hiltViewModel()
    val uiState by viewModel.uiState.collectAsState()

    val sheetState = rememberModalBottomSheetState(skipPartiallyExpanded = true)
    var isSheetVisible by rememberSaveable { mutableStateOf(false) }
    var showPatientFilterDialog by rememberSaveable { mutableStateOf(false) }
    var isLoading by remember { mutableStateOf(false) }

    if (isSheetVisible) {
        ModalBottomSheet(
            onDismissRequest = { isSheetVisible = false }, sheetState = sheetState
        ) {
            DownloadFormsScreen(
                viewModel = viewModel, onDownloadSelected = { isSheetVisible = false })
        }
    }
    LaunchedEffect(uiState.isLoading) {
        isLoading = uiState.isLoading
    }

    BaseScreen(
        uiEventFlow = viewModel.uiEvent,
        showLoading = { loading -> isLoading = loading },
        isLoading = isLoading,
    ) {
        Scaffold { padding ->
            LazyColumn(
                contentPadding = padding,
                modifier = Modifier
                    .fillMaxSize()
                    .padding(horizontal = 16.dp, vertical = 12.dp),
                verticalArrangement = Arrangement.spacedBy(24.dp)
            ) {
                item {
                    SyncSection(title = "Sync Status") {
                        Surface(
                            tonalElevation = 1.dp, shape = RoundedCornerShape(12.dp),
                            modifier = Modifier.fillMaxWidth()
                        ) {
                            Column(modifier = Modifier.padding(16.dp)) {

                                StatusRow(
                                    icon = Icons.Filled.Schedule,
                                    label = "Last Sync:",
                                    value = uiState.lastSyncTime
                                )

                                StatusRow(
                                    icon = Icons.Filled.CheckCircle,
                                    label = "Status:",
                                    value = uiState.lastSyncStatus
                                )

                                StatusRow(
                                    icon = Icons.Filled.Person,
                                    label = "Synced By:",
                                    value = uiState.lastSyncBy
                                )

                                uiState.lastSyncError?.let {
                                    Spacer(Modifier.height(12.dp))
                                    Row(verticalAlignment = Alignment.CenterVertically) {
                                        Icon(
                                            imageVector = Icons.Filled.ErrorOutline,
                                            contentDescription = null,
                                            tint = MaterialTheme.colorScheme.error
                                        )
                                        Spacer(Modifier.width(8.dp))
                                        Text(
                                            text = "Last Error: $it",
                                            color = MaterialTheme.colorScheme.error,
                                            style = MaterialTheme.typography.bodyMedium
                                        )
                                    }
                                }

                                Spacer(Modifier.height(16.dp))

                                Button(
                                    onClick = { viewModel.onEvent(SyncEvent.SyncNow) },
                                    modifier = Modifier.fillMaxWidth()
                                ) {
                                    Icon(Icons.Filled.Sync, contentDescription = null)
                                    Spacer(Modifier.width(8.dp))
                                    Text("Sync Now")
                                }
                            }
                        }
                    }
                }

                item {
                    SyncSection(title = "Data Summary") {
                        Surface(
                            tonalElevation = 1.dp, shape = RoundedCornerShape(12.dp),
                            modifier = Modifier.fillMaxWidth()
                        ) {
                            Column(
                                modifier = Modifier
                                    .padding(16.dp)
                                    .animateContentSize()
                            ) {
                                // Saved Section
                                Text(
                                    text = "Saved",
                                    style = MaterialTheme.typography.titleMedium.copy(fontWeight = FontWeight.Bold),
                                    modifier = Modifier.padding(bottom = 8.dp)
                                )

                                SummaryRow(
                                    icon = Icons.Default.Description,
                                    label = "Available Forms:",
                                    count = uiState.formCount
                                )
                                SummaryRow(
                                    icon = Icons.Default.HowToReg,
                                    label = "Patients Saved:",
                                    count = uiState.patientCount
                                )
                                SummaryRow(
                                    icon = Icons.Default.CheckCircle,
                                    label = "Encounters Saved:",
                                    count = uiState.encounterCount
                                )

                                HorizontalDivider(modifier = Modifier.padding(vertical = 12.dp))

                                // Synced Section
                                Text(
                                    text = "Synced",
                                    style = MaterialTheme.typography.titleMedium.copy(fontWeight = FontWeight.Bold),
                                    modifier = Modifier.padding(bottom = 8.dp)
                                )

                                SummaryRow(
                                    icon = Icons.Default.Groups,
                                    label = "Patients Synced:",
                                    count = uiState.syncedPatientCount
                                )
                                SummaryRow(
                                    icon = Icons.Default.CheckCircle,
                                    label = "Encounters Synced:",
                                    count = uiState.syncedEncounterCount
                                )
                            }
                        }
                    }
                }



                item {
                    SyncSection(title = "Auto Sync") {
                        Surface(
                            tonalElevation = 1.dp,
                            shape = RoundedCornerShape(12.dp),
                            modifier = Modifier.fillMaxWidth()
                        ) {
                            Column(modifier = Modifier.padding(16.dp)) {
                                Row(
                                    verticalAlignment = Alignment.CenterVertically,
                                    modifier = Modifier.fillMaxWidth()
                                ) {
                                    Icon(
                                        imageVector = Icons.Default.Autorenew,
                                        contentDescription = null,
                                        tint = MaterialTheme.colorScheme.primary
                                    )
                                    Spacer(Modifier.width(8.dp))
                                    Text(
                                        "Enable Auto-Sync",
                                        style = MaterialTheme.typography.titleMedium.copy(fontWeight = FontWeight.SemiBold)
                                    )
                                    Spacer(Modifier.weight(1f))
                                    Switch(
                                        checked = uiState.autoSyncEnabled,
                                        onCheckedChange = { isChecked ->
                                            viewModel.onEvent(SyncEvent.ToggleAutoSync(isChecked))
                                        })
                                }

                                if (uiState.autoSyncEnabled) {
                                    Spacer(Modifier.height(8.dp))
                                    Text(
                                        "Interval: ${uiState.autoSyncInterval} hours",
                                        style = MaterialTheme.typography.bodyMedium.copy(color = MaterialTheme.colorScheme.onSurfaceVariant)
                                    )
                                }
                            }
                        }
                    }
                }

                item {
                    SyncSection(title = "Manual Download") {
                        Surface(
                            tonalElevation = 1.dp, shape = RoundedCornerShape(12.dp),
                            modifier = Modifier.fillMaxWidth()
                        ) {
                            Column(modifier = Modifier.padding(16.dp)) {

                                Row(verticalAlignment = Alignment.CenterVertically) {
                                    Icon(
                                        imageVector = Icons.Default.Description,
                                        contentDescription = null,
                                        tint = MaterialTheme.colorScheme.primary
                                    )
                                    Spacer(Modifier.width(8.dp))
                                    Text(
                                        "Download Forms",
                                        style = MaterialTheme.typography.titleMedium
                                    )
                                }

                                Spacer(Modifier.height(8.dp))

                                Button(
                                    onClick = { isSheetVisible = true },
                                    modifier = Modifier.fillMaxWidth()
                                ) {
                                    Icon(Icons.Default.Download, contentDescription = null)
                                    Spacer(Modifier.width(8.dp))
                                    Text("Download Forms")
                                }

                                HorizontalDivider(modifier = Modifier.padding(vertical = 16.dp))

                                Row(verticalAlignment = Alignment.CenterVertically) {
                                    Icon(
                                        imageVector = Icons.Default.People,
                                        contentDescription = null,
                                        tint = MaterialTheme.colorScheme.primary
                                    )
                                    Spacer(Modifier.width(8.dp))
                                    Text(
                                        "Download Patients",
                                        style = MaterialTheme.typography.titleMedium
                                    )
                                }

                                Spacer(Modifier.height(8.dp))

                                Button(
                                    onClick = { showPatientFilterDialog = true },
                                    modifier = Modifier.fillMaxWidth()
                                ) {
                                    Icon(Icons.Default.PersonSearch, contentDescription = null)
                                    Spacer(Modifier.width(8.dp))
                                    Text("Download Patients")
                                }
                            }
                        }
                    }
                }

            }
        }
    }

    if (showPatientFilterDialog) {
        AlertDialog(onDismissRequest = { showPatientFilterDialog = false }, confirmButton = {
            TextButton(
                onClick = {
                    viewModel.onEvent(SyncEvent.ApplyFilters)
                    showPatientFilterDialog = false
                }) { Text("Apply") }
        }, dismissButton = {
            TextButton(onClick = { showPatientFilterDialog = false }) {
                Text("Cancel")
            }
        }, text = {
            PatientFilterSectionContent(
                cohortOptions = uiState.cohorts,
                selectedCohort = uiState.selectedCohort,
                onSelectedCohortChanged = {
                    viewModel.onEvent(SyncEvent.SelectedCohortChanged(it))
                },
                indicatorOptions = buildList {
                    addAll(IndicatorRepository.reportIndicators)
                    addAll(uiState.encounterTypes)
                    addAll(uiState.orderTypes)

                },
                selectedIndicator = uiState.selectedIndicator,
                onIndicatorSelected = {
                    viewModel.onEvent(SyncEvent.IndicatorSelected(it))
                },
                availableParameters = uiState.availableParameters,
                selectedParameters = uiState.selectedParameters,
                highlightedAvailable = uiState.highlightedAvailable,
                highlightedSelected = uiState.highlightedSelected,
                onHighlightAvailableToggle = {
                    viewModel.onEvent(SyncEvent.ToggleHighlightAvailable(it))
                },
                onHighlightSelectedToggle = {
                    viewModel.onEvent(SyncEvent.ToggleHighlightSelected(it))
                },
                onMoveRight = { viewModel.onEvent(SyncEvent.MoveRight) },
                onMoveLeft = { viewModel.onEvent(SyncEvent.MoveLeft) },
            )

        })
    }
}


@Composable
fun SyncSection(
    title: String,
    content: @Composable ColumnScope.() -> Unit,
) {
    Column(
        modifier = Modifier
            .fillMaxWidth()
            .padding(16.dp),
        verticalArrangement = Arrangement.spacedBy(8.dp)
    ) {
        Text(
            text = title,
            style = MaterialTheme.typography.titleMedium,
            modifier = Modifier.padding(bottom = 8.dp)
        )
        content()
    }
}


@Composable
fun SummaryRow(
    icon: ImageVector,
    label: String,
    count: Int?,
) {
    Row(
        verticalAlignment = Alignment.CenterVertically,
        horizontalArrangement = Arrangement.SpaceBetween,
        modifier = Modifier
            .fillMaxWidth()
            .padding(vertical = 4.dp)
    ) {
        Row(verticalAlignment = Alignment.CenterVertically) {
            Icon(
                imageVector = icon,
                contentDescription = null,
                tint = MaterialTheme.colorScheme.primary,
                modifier = Modifier.size(20.dp)
            )
            Spacer(modifier = Modifier.width(8.dp))
            Text(label)
        }

        AnimatedCount(count)
    }
}

@Composable
fun AnimatedCount(count: Int?) {
    val animatedCount by animateIntAsState(
        targetValue = count ?: 0, label = "AnimatedCount"
    )
    Text(
        text = if (count == null) "--" else "$animatedCount",
        style = MaterialTheme.typography.bodyLarge
    )
}

@Composable
fun StatusRow(
    icon: ImageVector,
    label: String,
    value: String,
) {
    Row(
        verticalAlignment = Alignment.CenterVertically,
        horizontalArrangement = Arrangement.SpaceBetween,
        modifier = Modifier
            .fillMaxWidth()
            .padding(vertical = 4.dp)
    ) {
        Row(verticalAlignment = Alignment.CenterVertically) {
            Icon(
                imageVector = icon,
                contentDescription = null,
                tint = MaterialTheme.colorScheme.primary,
                modifier = Modifier.size(20.dp)
            )
            Spacer(Modifier.width(8.dp))
            Text(label)
        }
        Text(value)
    }
}


