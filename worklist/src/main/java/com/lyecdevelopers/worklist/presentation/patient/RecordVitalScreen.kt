package com.lyecdevelopers.worklist.presentation.patient

import android.annotation.SuppressLint
import androidx.compose.foundation.background
import androidx.compose.foundation.layout.Arrangement
import androidx.compose.foundation.layout.Column
import androidx.compose.foundation.layout.Row
import androidx.compose.foundation.layout.Spacer
import androidx.compose.foundation.layout.fillMaxWidth
import androidx.compose.foundation.layout.height
import androidx.compose.foundation.layout.padding
import androidx.compose.foundation.layout.size
import androidx.compose.foundation.layout.width
import androidx.compose.foundation.rememberScrollState
import androidx.compose.foundation.shape.RoundedCornerShape
import androidx.compose.foundation.verticalScroll
import androidx.compose.material.icons.Icons
import androidx.compose.material.icons.filled.Air
import androidx.compose.material.icons.filled.Bloodtype
import androidx.compose.material.icons.filled.Favorite
import androidx.compose.material.icons.filled.Height
import androidx.compose.material.icons.filled.MonitorWeight
import androidx.compose.material.icons.filled.Straighten
import androidx.compose.material.icons.filled.Thermostat
import androidx.compose.material3.Button
import androidx.compose.material3.ExperimentalMaterial3Api
import androidx.compose.material3.Icon
import androidx.compose.material3.MaterialTheme
import androidx.compose.material3.Surface
import androidx.compose.material3.Text
import androidx.compose.material3.TextButton
import androidx.compose.material3.TextField
import androidx.compose.runtime.Composable
import androidx.compose.runtime.LaunchedEffect
import androidx.compose.runtime.collectAsState
import androidx.compose.runtime.getValue
import androidx.compose.runtime.mutableStateOf
import androidx.compose.runtime.remember
import androidx.compose.runtime.setValue
import androidx.compose.ui.Alignment
import androidx.compose.ui.Modifier
import androidx.compose.ui.graphics.Color
import androidx.compose.ui.graphics.vector.ImageVector
import androidx.compose.ui.text.font.FontWeight
import androidx.compose.ui.unit.dp
import androidx.compose.ui.unit.sp
import androidx.compose.ui.window.Dialog
import androidx.hilt.navigation.compose.hiltViewModel
import com.lyecdevelopers.core.data.local.entity.PatientEntity
import com.lyecdevelopers.worklist.domain.model.Vitals
import com.lyecdevelopers.worklist.presentation.worklist.WorklistViewModel

@OptIn(ExperimentalMaterial3Api::class)
@Composable
fun RecordVitalDialog(
    patient: PatientEntity,
    onDismissRequest: () -> Unit,
    onSave: (Vitals) -> Unit,
) {
    val viewModel: WorklistViewModel = hiltViewModel()
    val state by viewModel.uiState.collectAsState()

    val vitals = state.vitals ?: Vitals()

    LaunchedEffect(vitals.weight, vitals.height) {
        val bmi = calculateBmi(vitals.weight, vitals.height)
        viewModel.updateVitals(vitals.copy(bmi = bmi))
    }

    var showValidationError by remember { mutableStateOf(false) }

    Dialog(onDismissRequest = onDismissRequest) {
        Surface(
            shape = RoundedCornerShape(16.dp),
            tonalElevation = 4.dp,
            modifier = Modifier
                .fillMaxWidth()
                .padding(16.dp)
        ) {
            Column(
                modifier = Modifier
                    .padding(16.dp)
                    .verticalScroll(rememberScrollState())
            ) {
                Text(
                    "Record Vitals", style = MaterialTheme.typography.titleLarge
                )

                Spacer(modifier = Modifier.height(16.dp))

                // Your form fields
                RowPair(
                    label = "Temperature",
                    unit = "°C",
                    value = vitals.temperature,
                    onValueChange = { viewModel.updateVitals(vitals.copy(temperature = it)) },
                    icon = Icons.Default.Thermostat
                )

                RowPairTwoFields(
                    label = "Blood Pressure",
                    unit = "mmHg",
                    first = vitals.bloodPressureSystolic,
                    second = vitals.bloodPressureDiastolic,
                    onFirstChange = { viewModel.updateVitals(vitals.copy(bloodPressureSystolic = it)) },
                    onSecondChange = { viewModel.updateVitals(vitals.copy(bloodPressureDiastolic = it)) },
                    icon = Icons.Default.Favorite
                )

                RowPair(
                    label = "Heart rate",
                    unit = "beats/min",
                    value = vitals.heartRate,
                    onValueChange = { viewModel.updateVitals(vitals.copy(heartRate = it)) },
                    icon = Icons.Default.Favorite
                )

                RowPair(
                    label = "Respiration rate",
                    unit = "breaths/min",
                    value = vitals.respirationRate,
                    onValueChange = { viewModel.updateVitals(vitals.copy(respirationRate = it)) },
                    icon = Icons.Default.Air
                )

                RowPair(
                    label = "SpO₂",
                    unit = "%",
                    value = vitals.spo2,
                    onValueChange = { viewModel.updateVitals(vitals.copy(spo2 = it)) },
                    icon = Icons.Default.Bloodtype
                )

                Spacer(modifier = Modifier.height(12.dp))

                Text("Notes", fontSize = 14.sp, fontWeight = FontWeight.Medium)
                TextField(
                    value = vitals.notes,
                    onValueChange = { viewModel.updateVitals(vitals.copy(notes = it)) },
                    modifier = Modifier
                        .fillMaxWidth()
                        .height(100.dp),
                    placeholder = { Text("Type any additional notes here") })

                Spacer(modifier = Modifier.height(24.dp))

                SectionHeader("Record biometrics")

                RowPair(
                    label = "Weight",
                    unit = "kg",
                    value = vitals.weight,
                    onValueChange = { viewModel.updateVitals(vitals.copy(weight = it)) },
                    icon = Icons.Default.MonitorWeight
                )

                RowPair(
                    label = "Height",
                    unit = "cm",
                    value = vitals.height,
                    onValueChange = { viewModel.updateVitals(vitals.copy(height = it)) },
                    icon = Icons.Default.Height
                )

                Row(
                    verticalAlignment = Alignment.CenterVertically,
                    modifier = Modifier
                        .fillMaxWidth()
                        .padding(vertical = 6.dp)
                ) {
                    Column(modifier = Modifier.weight(1f)) {
                        Text("BMI (auto)", fontSize = 14.sp)
                        TextField(
                            value = vitals.bmi,
                            onValueChange = {},
                            readOnly = true,
                            modifier = Modifier.fillMaxWidth(),
                            placeholder = { Text("---") },
                            singleLine = true
                        )
                    }
                    Spacer(modifier = Modifier.width(8.dp))
                    Text("kg/m²", fontSize = 12.sp)
                }

                RowPair(
                    label = "MUAC",
                    unit = "cm",
                    value = vitals.muac,
                    onValueChange = { viewModel.updateVitals(vitals.copy(muac = it)) },
                    icon = Icons.Default.Straighten
                )

                if (showValidationError) {
                    Text(
                        text = "Temperature, Weight, and Height must not be empty.",
                        color = MaterialTheme.colorScheme.error,
                        modifier = Modifier.padding(top = 8.dp)
                    )
                }

                Spacer(modifier = Modifier.height(24.dp))

                Row(
                    horizontalArrangement = Arrangement.End, modifier = Modifier.fillMaxWidth()
                ) {
                    TextButton(onClick = onDismissRequest) {
                        Text("Cancel")
                    }
                    Spacer(modifier = Modifier.width(8.dp))
                    Button(
                        onClick = {
                            if (vitals.temperature.isNotBlank() && vitals.weight.isNotBlank() && vitals.height.isNotBlank()) {
                                showValidationError = false
                                onSave(vitals)
                            } else {
                                showValidationError = true
                            }
                        }) {
                        Text("Save")
                    }
                }
            }
        }
    }
}


@Composable
fun MuacRow(muac: String, onValueChange: (String) -> Unit) {
    val (label, colour) = remember(muac) {
        val value = muac.toFloatOrNull()
        when {
            value == null -> "" to Color.Transparent
            value < 19f -> "Red < 19.0cm" to Color.Red
            value in 19f..22f -> "Yellow 19.0–22.0cm" to Color.Yellow
            value > 22f -> "Green > 22.0cm" to Color.Green
            else -> "" to Color.Transparent
        }
    }

    Column(
        modifier = Modifier
            .fillMaxWidth()
            .padding(vertical = 6.dp)
    ) {
        Text("MUAC", fontSize = 14.sp)
        Row(
            verticalAlignment = Alignment.CenterVertically,
            modifier = Modifier.fillMaxWidth()
        ) {
            TextField(
                value = muac,
                onValueChange = onValueChange,
                placeholder = { Text("---") },
                modifier = Modifier.weight(1f),
                singleLine = true
            )
            Spacer(modifier = Modifier.width(8.dp))
            Text("cm", fontSize = 12.sp)
            if (label.isNotEmpty()) {
                Spacer(modifier = Modifier.width(8.dp))
                Text(
                    text = label,
                    color = MaterialTheme.colorScheme.onBackground,
                    modifier = Modifier
                        .background(colour, RoundedCornerShape(4.dp))
                        .padding(horizontal = 6.dp, vertical = 2.dp)
                )
            }
        }
    }
}

@Composable
fun SectionHeader(title: String) {
    Text(
        text = title,
        fontSize = 18.sp,
        fontWeight = FontWeight.SemiBold,
        modifier = Modifier.padding(vertical = 12.dp)
    )
}

@Composable
fun RowPair(
    label: String,
    unit: String,
    value: String,
    onValueChange: (String) -> Unit,
    icon: ImageVector? = null,
) {
    Row(
        verticalAlignment = Alignment.CenterVertically,
        modifier = Modifier
            .fillMaxWidth()
            .padding(vertical = 6.dp)
    ) {
        if (icon != null) {
            Icon(
                imageVector = icon,
                contentDescription = "$label icon",
                modifier = Modifier.size(20.dp)
            )
            Spacer(modifier = Modifier.width(8.dp))
        }

        Column(modifier = Modifier.weight(1f)) {
            Text(label, fontSize = 14.sp)
            TextField(
                value = value,
                onValueChange = onValueChange,
                placeholder = { Text("---") }, singleLine = true, modifier = Modifier.fillMaxWidth()
            )
        }

        Spacer(modifier = Modifier.width(8.dp))
        Text(unit, fontSize = 12.sp)
    }
}


@Composable
fun RowPairTwoFields(
    label: String,
    unit: String,
    first: String,
    second: String,
    onFirstChange: (String) -> Unit,
    onSecondChange: (String) -> Unit,
    icon: ImageVector? = null,
) {
    Column(
        modifier = Modifier
            .fillMaxWidth()
            .padding(vertical = 6.dp)
    ) {
        Row(verticalAlignment = Alignment.CenterVertically) {
            if (icon != null) {
                Icon(
                    imageVector = icon,
                    contentDescription = "$label icon",
                    modifier = Modifier.size(20.dp),
                    tint = MaterialTheme.colorScheme.primary
                )
                Spacer(modifier = Modifier.width(8.dp))
            }
            Text(label, fontSize = 14.sp)
        }
        Spacer(modifier = Modifier.height(4.dp))
        Row(
            verticalAlignment = Alignment.CenterVertically, modifier = Modifier.fillMaxWidth()
        ) {
            TextField(
                value = first,
                onValueChange = onFirstChange,
                placeholder = { Text("---") },
                singleLine = true,
                modifier = Modifier.weight(1f)
            )
            Spacer(modifier = Modifier.width(8.dp))
            Text(unit, fontSize = 12.sp, modifier = Modifier.align(Alignment.CenterVertically))
            Spacer(modifier = Modifier.width(8.dp))
            TextField(
                value = second,
                onValueChange = onSecondChange,
                placeholder = { Text("---") },
                singleLine = true,
                modifier = Modifier.weight(1f)
            )
            Spacer(modifier = Modifier.width(8.dp))
            Text(unit, fontSize = 12.sp, modifier = Modifier.align(Alignment.CenterVertically))
        }
    }
}


@SuppressLint("DefaultLocale")
fun calculateBmi(weightStr: String, heightStr: String): String {
    return try {
        val weight = weightStr.toDouble()
        val heightCm = heightStr.toDouble()
        val heightM = heightCm / 100
        val bmi = weight / (heightM * heightM)
        String.format("%.1f", bmi)
    } catch (e: Exception) {
        ""
    }
}
