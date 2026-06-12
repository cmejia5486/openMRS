package com.chartlite.app.ui.screens

import androidx.compose.foundation.layout.*
import androidx.compose.foundation.lazy.LazyColumn
import androidx.compose.foundation.lazy.items
import androidx.compose.foundation.shape.RoundedCornerShape
import androidx.compose.material.icons.Icons
import androidx.compose.material.icons.automirrored.filled.ArrowBack
import androidx.compose.material.icons.filled.Add
import androidx.compose.material.icons.filled.ChildCare
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
import com.chartlite.app.database.entity.GrowthMeasurementEntity
import com.chartlite.app.database.repository.GrowthRepository
import kotlinx.coroutines.launch
import java.text.SimpleDateFormat
import java.util.Date
import java.util.Locale

@OptIn(ExperimentalMaterial3Api::class)
@Composable
fun GrowthChartScreen(
    patientId: String,
    onBack: () -> Unit
) {
    val context = LocalContext.current
    val app = context.applicationContext as App
    val scope = rememberCoroutineScope()

    var measurements by remember { mutableStateOf<List<GrowthMeasurementEntity>>(emptyList()) }
    var isLoading by remember { mutableStateOf(true) }
    var showAddDialog by remember { mutableStateOf(false) }

    LaunchedEffect(patientId) {
        measurements = app.growthRepository.getByPatient(patientId)
        isLoading = false
    }

    Scaffold(
        topBar = {
            TopAppBar(
                title = { Text(stringResource(R.string.growth_chart)) },
                navigationIcon = {
                    IconButton(onClick = onBack) { Icon(Icons.AutoMirrored.Filled.ArrowBack, stringResource(R.string.back)) }
                }
            )
        },
        floatingActionButton = {
            FloatingActionButton(onClick = { showAddDialog = true }) { Icon(Icons.Default.Add, "Add Measurement") }
        }
    ) { padding ->
        if (isLoading) {
            Box(Modifier.fillMaxSize().padding(padding), contentAlignment = Alignment.Center) { CircularProgressIndicator() }
        } else if (measurements.isEmpty()) {
            Box(Modifier.fillMaxSize().padding(padding), contentAlignment = Alignment.Center) {
                Column(horizontalAlignment = Alignment.CenterHorizontally) {
                    Icon(Icons.Default.ChildCare, null, Modifier.size(64.dp), tint = MaterialTheme.colorScheme.outline)
                    Spacer(Modifier.height(16.dp))
                    Text(stringResource(R.string.no_growth_measurements), style = MaterialTheme.typography.titleMedium)
                    Text(stringResource(R.string.tap_plus_record_weight), style = MaterialTheme.typography.bodyMedium, color = MaterialTheme.colorScheme.outline)
                }
            }
        } else {
            LazyColumn(
                modifier = Modifier.fillMaxSize().padding(padding),
                contentPadding = PaddingValues(16.dp),
                verticalArrangement = Arrangement.spacedBy(12.dp)
            ) {
                // Latest Z-score summary
                measurements.firstOrNull()?.let { latest ->
                    item { ZScoreSummaryCard(latest) }
                }

                items(measurements, key = { it.id }) { m ->
                    GrowthMeasurementCard(m)
                }
            }
        }
    }

    if (showAddDialog) {
        AddMeasurementDialog(
            onDismiss = { showAddDialog = false },
            onConfirm = { weight, height, headCirc, muac, ageMonths ->
                scope.launch {
                    val userId = app.sessionManager.currentSession?.userId ?: "system"
                    app.growthRepository.recordMeasurement(
                        patientId = patientId, measuredBy = userId,
                        weight = weight, height = height,
                        headCircumference = headCirc, muac = muac,
                        ageInMonths = ageMonths
                    )
                    app.auditLogger.log("RECORD_GROWTH", "GROWTH", patientId,
                        AuditLogger.buildDetails("weight" to weight, "height" to height))
                    measurements = app.growthRepository.getByPatient(patientId)
                    showAddDialog = false
                }
            }
        )
    }
}

@Composable
private fun ZScoreSummaryCard(measurement: GrowthMeasurementEntity) {
    Card(
        modifier = Modifier.fillMaxWidth(),
        shape = RoundedCornerShape(12.dp),
        colors = CardDefaults.cardColors(
            containerColor = when {
                measurement.weightForAgeZ != null && measurement.weightForAgeZ <= GrowthRepository.Z_SEVERE_MALNUTRITION ->
                    MaterialTheme.colorScheme.errorContainer
                measurement.weightForAgeZ != null && measurement.weightForAgeZ <= GrowthRepository.Z_MODERATE_MALNUTRITION ->
                    MaterialTheme.colorScheme.tertiaryContainer
                else -> MaterialTheme.colorScheme.primaryContainer
            }
        )
    ) {
        Column(Modifier.padding(16.dp)) {
            Text(stringResource(R.string.latest_z_scores), style = MaterialTheme.typography.labelMedium)
            Spacer(Modifier.height(8.dp))
            Row(Modifier.fillMaxWidth(), horizontalArrangement = Arrangement.SpaceEvenly) {
                measurement.weightForAgeZ?.let { ZScoreChip("WAZ", it) }
                measurement.heightForAgeZ?.let { ZScoreChip("HAZ", it) }
                measurement.bmiForAgeZ?.let { ZScoreChip("BAZ", it) }
            }
            if (measurement.weightForAgeZ != null && measurement.weightForAgeZ <= GrowthRepository.Z_MODERATE_MALNUTRITION) {
                Spacer(Modifier.height(8.dp))
                Text(
                    if (measurement.weightForAgeZ <= GrowthRepository.Z_SEVERE_MALNUTRITION) stringResource(R.string.severe_malnutrition_referral)
                    else stringResource(R.string.moderate_malnutrition_support),
                    color = MaterialTheme.colorScheme.error,
                    fontWeight = FontWeight.Bold,
                    style = MaterialTheme.typography.bodySmall
                )
            }
        }
    }
}

@Composable
private fun ZScoreChip(label: String, zScore: Float) {
    val color = when {
        zScore <= GrowthRepository.Z_SEVERE_MALNUTRITION -> MaterialTheme.colorScheme.error
        zScore <= GrowthRepository.Z_MODERATE_MALNUTRITION -> MaterialTheme.colorScheme.tertiary
        zScore >= GrowthRepository.Z_OBESE -> MaterialTheme.colorScheme.error
        zScore >= GrowthRepository.Z_OVERWEIGHT -> MaterialTheme.colorScheme.tertiary
        else -> MaterialTheme.colorScheme.primary
    }
    Column(horizontalAlignment = Alignment.CenterHorizontally) {
        Text(label, style = MaterialTheme.typography.labelSmall)
        Text(
            String.format("%.1f", zScore),
            fontWeight = FontWeight.Bold,
            color = color,
            style = MaterialTheme.typography.titleMedium
        )
    }
}

@Composable
private fun GrowthMeasurementCard(measurement: GrowthMeasurementEntity) {
    val dateFormat = remember { SimpleDateFormat("dd MMM yyyy", Locale.getDefault()) }
    Card(modifier = Modifier.fillMaxWidth(), shape = RoundedCornerShape(12.dp)) {
        Column(Modifier.padding(16.dp)) {
            Text(dateFormat.format(Date(measurement.measuredAt)), fontWeight = FontWeight.Bold)
            Spacer(Modifier.height(8.dp))
            Row(Modifier.fillMaxWidth(), horizontalArrangement = Arrangement.SpaceEvenly) {
                measurement.weight?.let { MeasurementItem("Weight", "${String.format("%.1f", it)} kg") }
                measurement.height?.let { MeasurementItem("Height", "${String.format("%.1f", it)} cm") }
                measurement.muac?.let { MeasurementItem("MUAC", "${String.format("%.1f", it)} cm") }
                measurement.headCircumference?.let { MeasurementItem("Head", "${String.format("%.1f", it)} cm") }
            }
        }
    }
}

@Composable
private fun MeasurementItem(label: String, value: String) {
    Column(horizontalAlignment = Alignment.CenterHorizontally) {
        Text(label, style = MaterialTheme.typography.labelSmall, color = MaterialTheme.colorScheme.outline)
        Text(value, fontWeight = FontWeight.SemiBold)
    }
}

@Composable
private fun AddMeasurementDialog(
    onDismiss: () -> Unit,
    onConfirm: (weight: Float?, height: Float?, headCirc: Float?, muac: Float?, ageMonths: Int?) -> Unit
) {
    var weight by remember { mutableStateOf("") }
    var height by remember { mutableStateOf("") }
    var headCirc by remember { mutableStateOf("") }
    var muac by remember { mutableStateOf("") }
    var ageMonths by remember { mutableStateOf("") }
    var showErrors by remember { mutableStateOf(false) }

    AlertDialog(
        onDismissRequest = onDismiss,
        title = { Text(stringResource(R.string.record_growth_measurement)) },
        text = {
            Column(verticalArrangement = Arrangement.spacedBy(8.dp)) {
                OutlinedTextField(value = weight, onValueChange = { weight = it }, label = { Text(stringResource(R.string.weight_kg)) }, modifier = Modifier.fillMaxWidth(),
                    isError = showErrors && weight.isBlank(),
                    supportingText = if (showErrors && weight.isBlank()) {{ Text("Required") }} else null)
                OutlinedTextField(value = height, onValueChange = { height = it }, label = { Text(stringResource(R.string.height_cm)) }, modifier = Modifier.fillMaxWidth())
                OutlinedTextField(value = headCirc, onValueChange = { headCirc = it }, label = { Text(stringResource(R.string.head_circumference_cm)) }, modifier = Modifier.fillMaxWidth())
                OutlinedTextField(value = muac, onValueChange = { muac = it }, label = { Text(stringResource(R.string.muac_cm)) }, modifier = Modifier.fillMaxWidth())
                OutlinedTextField(value = ageMonths, onValueChange = { ageMonths = it.filter { c -> c.isDigit() } }, label = { Text(stringResource(R.string.age_months_zscore)) }, modifier = Modifier.fillMaxWidth())
            }
        },
        confirmButton = {
            Button(
                onClick = {
                    if (weight.isBlank()) { showErrors = true; return@Button }
                    showErrors = false
                    onConfirm(
                        weight.toFloatOrNull(), height.toFloatOrNull(),
                        headCirc.toFloatOrNull(), muac.toFloatOrNull(),
                        ageMonths.toIntOrNull()
                    )
                }
            ) { Text(stringResource(R.string.record)) }
        },
        dismissButton = { TextButton(onClick = onDismiss) { Text(stringResource(R.string.cancel)) } }
    )
}
