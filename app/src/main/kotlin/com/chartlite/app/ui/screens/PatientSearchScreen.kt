package com.chartlite.app.ui.screens

import androidx.compose.foundation.layout.*
import androidx.compose.foundation.lazy.LazyColumn
import androidx.compose.foundation.lazy.items
import androidx.compose.material.icons.Icons
import androidx.compose.material.icons.automirrored.filled.ArrowBack
import androidx.compose.material.icons.filled.PersonAdd
import androidx.compose.material.icons.filled.Search
import androidx.compose.material3.*
import androidx.compose.runtime.*
import androidx.compose.runtime.saveable.rememberSaveable
import androidx.compose.ui.Alignment
import androidx.compose.ui.Modifier
import androidx.compose.ui.platform.LocalContext
import androidx.compose.ui.text.font.FontWeight
import androidx.compose.ui.text.input.ImeAction
import androidx.compose.foundation.text.KeyboardOptions
import androidx.compose.ui.unit.dp
import com.chartlite.app.App
import androidx.compose.ui.res.stringResource
import com.chartlite.app.R
import com.chartlite.app.database.entity.PatientEntity
import kotlinx.coroutines.delay
import kotlinx.coroutines.launch

@OptIn(ExperimentalMaterial3Api::class)
@Composable
fun PatientSearchScreen(
    onPatientSelected: (String) -> Unit,
    onCheckIn: ((String) -> Unit)? = null,
    onBack: () -> Unit
) {
    val context = LocalContext.current
    val app = context.applicationContext as App
    val scope = rememberCoroutineScope()

    var query by rememberSaveable { mutableStateOf("") }
    var results by remember { mutableStateOf<List<PatientEntity>>(emptyList()) }
    var searched by rememberSaveable { mutableStateOf(false) }
    var isLoading by remember { mutableStateOf(true) }

    // Load recent patients on first open
    LaunchedEffect(Unit) {
        results = app.patientRepository.getRecent()
        isLoading = false
    }

    // Debounced search — 300ms delay to avoid excessive queries
    LaunchedEffect(query) {
        if (query.isBlank()) {
            searched = false
            isLoading = true
            results = app.patientRepository.getRecent()
            isLoading = false
            return@LaunchedEffect
        }
        isLoading = true
        delay(300L)
        results = app.patientRepository.search(query)
        searched = true
        isLoading = false
    }

    Scaffold(
        topBar = {
            TopAppBar(
                title = { Text(stringResource(R.string.find_patient)) },
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
                .imePadding()
                .padding(16.dp)
        ) {
            OutlinedTextField(
                value = query,
                onValueChange = { query = it },
                label = { Text(stringResource(R.string.search_by_id_name_phone)) },
                leadingIcon = { Icon(Icons.Default.Search, contentDescription = "Search") },
                modifier = Modifier.fillMaxWidth(),
                singleLine = true,
                keyboardOptions = KeyboardOptions(imeAction = ImeAction.Search)
            )

            Spacer(Modifier.height(12.dp))

            if (isLoading) {
                Box(Modifier.fillMaxWidth().padding(vertical = 24.dp),
                    contentAlignment = Alignment.Center) {
                    CircularProgressIndicator(modifier = Modifier.size(32.dp))
                }
            } else {
                if (!searched) {
                    Text(stringResource(R.string.recent_patients), style = MaterialTheme.typography.titleSmall,
                        modifier = Modifier.padding(bottom = 8.dp))
                    if (results.isEmpty()) {
                        Text(
                            stringResource(R.string.no_patients_registered),
                            style = MaterialTheme.typography.bodyMedium,
                            color = MaterialTheme.colorScheme.onSurfaceVariant,
                            modifier = Modifier.padding(vertical = 16.dp)
                        )
                    }
                } else if (results.isEmpty()) {
                    Text(stringResource(R.string.no_patients_found_format, query),
                        style = MaterialTheme.typography.bodyMedium,
                        color = MaterialTheme.colorScheme.onSurfaceVariant,
                        modifier = Modifier.padding(vertical = 16.dp))
                }

                LazyColumn(verticalArrangement = Arrangement.spacedBy(8.dp)) {
                    items(results, key = { it.id }) { patient ->
                        PatientCard(
                            patient = patient,
                            onClick = { onPatientSelected(patient.id) },
                            onCheckIn = onCheckIn?.let { cb -> { cb(patient.id) } }
                        )
                    }
                }
            }
        }
    }
}

@Composable
fun PatientCard(
    patient: PatientEntity,
    onClick: () -> Unit,
    onCheckIn: (() -> Unit)? = null
) {
    Card(
        onClick = onClick,
        modifier = Modifier.fillMaxWidth()
    ) {
        Row(
            modifier = Modifier.padding(12.dp).fillMaxWidth(),
            horizontalArrangement = Arrangement.SpaceBetween,
            verticalAlignment = Alignment.CenterVertically
        ) {
            Column(modifier = Modifier.weight(1f)) {
                Text(
                    "${patient.firstName} ${patient.lastName}",
                    style = MaterialTheme.typography.titleMedium,
                    fontWeight = FontWeight.Bold
                )
                Text(
                    patient.id,
                    style = MaterialTheme.typography.bodyMedium,
                    color = MaterialTheme.colorScheme.primary
                )
            }
            Column(horizontalAlignment = Alignment.End) {
                patient.ageYears?.let {
                    Text("${it}y", style = MaterialTheme.typography.bodySmall)
                }
                Text(patient.gender.replaceFirstChar { it.uppercase() },
                    style = MaterialTheme.typography.bodySmall)
            }
            if (onCheckIn != null) {
                Spacer(Modifier.width(8.dp))
                FilledTonalIconButton(onClick = onCheckIn) {
                    Icon(Icons.Default.PersonAdd, contentDescription = "Check In",
                        modifier = Modifier.size(20.dp))
                }
            }
        }
    }
}
