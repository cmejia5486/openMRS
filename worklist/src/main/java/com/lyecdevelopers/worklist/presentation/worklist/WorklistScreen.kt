package com.lyecdevelopers.worklist.presentation.worklist

import androidx.compose.foundation.layout.Arrangement
import androidx.compose.foundation.layout.Column
import androidx.compose.foundation.layout.fillMaxSize
import androidx.compose.foundation.layout.padding
import androidx.compose.foundation.lazy.LazyColumn
import androidx.compose.foundation.lazy.items
import androidx.compose.material.icons.Icons
import androidx.compose.material.icons.filled.Add
import androidx.compose.material3.ExperimentalMaterial3Api
import androidx.compose.material3.FloatingActionButton
import androidx.compose.material3.Icon
import androidx.compose.material3.MaterialTheme
import androidx.compose.material3.Scaffold
import androidx.compose.runtime.Composable
import androidx.compose.runtime.LaunchedEffect
import androidx.compose.runtime.collectAsState
import androidx.compose.runtime.getValue
import androidx.compose.runtime.mutableStateOf
import androidx.compose.runtime.remember
import androidx.compose.runtime.setValue
import androidx.compose.ui.Modifier
import androidx.compose.ui.unit.dp
import androidx.hilt.navigation.compose.hiltViewModel
import com.lyecdevelopers.core.data.local.entity.PatientEntity
import com.lyecdevelopers.core.ui.components.BaseScreen
import com.lyecdevelopers.core.ui.components.EmptyStateView

@OptIn(ExperimentalMaterial3Api::class)
@Composable
fun WorklistScreen(
    onPatientClick: (PatientEntity) -> Unit,
    onRegisterPatient: () -> Unit,
    modifier: Modifier = Modifier,
    viewModel: WorklistViewModel = hiltViewModel(),
) {
    val uiState by viewModel.uiState.collectAsState()
    var isStartVisitDialogVisible by remember { mutableStateOf(false) }

    var isLoading by remember { mutableStateOf(false) }

    LaunchedEffect(uiState.isLoading) {
        isLoading = uiState.isLoading
    }

    BaseScreen(
        uiEventFlow = viewModel.uiEvent,
        showLoading = { loading -> isLoading = loading },
        isLoading = isLoading,
    ) {
        Scaffold(
            floatingActionButton = {
                FloatingActionButton(
                    onClick = onRegisterPatient,
                    containerColor = MaterialTheme.colorScheme.primary,
                    contentColor = MaterialTheme.colorScheme.onPrimary
                ) {
                    Icon(
                        imageVector = Icons.Default.Add, contentDescription = "Register Patient"
                    )
                }
            }) { padding ->
            LazyColumn(
                contentPadding = padding,
                modifier = modifier
                    .fillMaxSize()
                    .padding(horizontal = 16.dp, vertical = 8.dp),
                verticalArrangement = Arrangement.spacedBy(16.dp)
            ) {
                // Static header
                item {
                    WorklistSummary(patients = uiState.patients)
                }

                if (uiState.patients.isEmpty()) {
                    item {
                        Column(
                            modifier = Modifier
                                .fillMaxSize()
                                .padding(16.dp)
                        ) {
                            EmptyStateView(message = "No patients found.")
                        }
                    }
                } else {
                    items(uiState.patients, key = { it.id }) { patient ->
                        PatientCard(
                            allVisits = uiState.visits!!,
                            patient = patient,
                            onStartVisit = {
                                isStartVisitDialogVisible = true
                            },
                            onViewDetails = { onPatientClick(patient) })
                    }
                }
            }


        }


        StartVisitDialog(
            isVisible = isStartVisitDialogVisible,
            onDismissRequest = { isStartVisitDialogVisible = false },
            viewModel = viewModel
        )

    }


}







