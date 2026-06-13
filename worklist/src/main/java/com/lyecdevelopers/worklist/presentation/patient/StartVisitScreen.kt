package com.lyecdevelopers.worklist.presentation.patient

import android.app.DatePickerDialog
import android.app.TimePickerDialog
import androidx.compose.foundation.clickable
import androidx.compose.foundation.layout.Arrangement
import androidx.compose.foundation.layout.Column
import androidx.compose.foundation.layout.Row
import androidx.compose.foundation.layout.Spacer
import androidx.compose.foundation.layout.fillMaxSize
import androidx.compose.foundation.layout.fillMaxWidth
import androidx.compose.foundation.layout.height
import androidx.compose.foundation.layout.padding
import androidx.compose.foundation.layout.width
import androidx.compose.material.icons.Icons
import androidx.compose.material.icons.filled.ArrowDropDown
import androidx.compose.material.icons.filled.DateRange
import androidx.compose.material3.ButtonDefaults
import androidx.compose.material3.DropdownMenuItem
import androidx.compose.material3.ExperimentalMaterial3Api
import androidx.compose.material3.ExposedDropdownMenuBox
import androidx.compose.material3.Icon
import androidx.compose.material3.MaterialTheme
import androidx.compose.material3.OutlinedButton
import androidx.compose.material3.RadioButton
import androidx.compose.material3.Text
import androidx.compose.material3.TextField
import androidx.compose.runtime.Composable
import androidx.compose.runtime.collectAsState
import androidx.compose.runtime.getValue
import androidx.compose.runtime.remember
import androidx.compose.ui.Alignment
import androidx.compose.ui.Modifier
import androidx.compose.ui.graphics.Color
import androidx.compose.ui.platform.LocalContext
import androidx.compose.ui.unit.dp
import androidx.hilt.navigation.compose.hiltViewModel
import com.lyecdevelopers.core.ui.components.BaseScreen
import com.lyecdevelopers.worklist.presentation.worklist.WorklistViewModel
import com.lyecdevelopers.worklist.presentation.worklist.event.WorklistEvent
import java.text.SimpleDateFormat
import java.util.Calendar
import java.util.Locale


@OptIn(ExperimentalMaterial3Api::class)
@Composable
fun StartVisitScreen(
    viewModel: WorklistViewModel = hiltViewModel(),
) {
    val context = LocalContext.current
    val uiState by viewModel.uiState.collectAsState()
    val calendar = remember { Calendar.getInstance() }

    BaseScreen(
        uiEventFlow = viewModel.uiEvent,
        isLoading = uiState.isLoading,
        showLoading = {/*handled by uiState*/ }) {
        Column(
            modifier = Modifier
                .fillMaxSize()
                .padding(16.dp)
        ) {

            Text(
                "Start a Visit",
                style = MaterialTheme.typography.headlineSmall,
                modifier = Modifier.padding(bottom = 16.dp)
            )

            Text("The visit is", style = MaterialTheme.typography.bodyMedium)
            Row(
                horizontalArrangement = Arrangement.spacedBy(8.dp),
                modifier = Modifier
                    .fillMaxWidth()
                    .padding(vertical = 8.dp)
            ) {
                uiState.visitStatuses.forEach { status ->
                    OutlinedButton(
                        onClick = {
                            viewModel.onEvent(WorklistEvent.OnVisitStatusChanged(status))
                        }, colors = ButtonDefaults.outlinedButtonColors(
                            containerColor = if (uiState.visitStatus == status) Color(0xFFDDEEFF) else Color.Transparent
                        )
                    ) {
                        Text(
                            status,
                            color = if (uiState.visitStatus == status) Color.Blue else Color.Black
                        )
                    }
                }
            }

            if (uiState.visitStatus != "New") {
                Spacer(Modifier.height(16.dp))
                Text("Visit start date", style = MaterialTheme.typography.bodyMedium)

                Row(
                    horizontalArrangement = Arrangement.spacedBy(8.dp),
                    verticalAlignment = Alignment.CenterVertically
                ) {
                    OutlinedButton(
                        onClick = {
                            DatePickerDialog(
                                context,
                                { _, year, month, dayOfMonth ->
                                    calendar.set(year, month, dayOfMonth)
                                    val newDate =
                                        SimpleDateFormat("dd/MM/yyyy", Locale.getDefault()).format(
                                            calendar.time
                                        )
                                    viewModel.onEvent(WorklistEvent.OnStartDateChanged(newDate))
                                },
                                calendar.get(Calendar.YEAR),
                                calendar.get(Calendar.MONTH),
                                calendar.get(Calendar.DAY_OF_MONTH)
                            ).show()
                        }) {
                        Icon(Icons.Default.DateRange, contentDescription = null)
                        Spacer(Modifier.width(4.dp))
                        Text(uiState.startDate)
                    }

                    OutlinedButton(
                        onClick = {
                            TimePickerDialog(
                                context,
                                { _, hourOfDay, minute ->
                                    calendar.set(Calendar.HOUR_OF_DAY, hourOfDay)
                                    calendar.set(Calendar.MINUTE, minute)
                                    val isAfternoon = hourOfDay >= 12
                                    val newAmPm = if (isAfternoon) "PM" else "AM"
                                    val hr12 = when {
                                        hourOfDay == 0 -> 12
                                        hourOfDay > 12 -> hourOfDay - 12
                                        else -> hourOfDay
                                    }
                                    val newTime = "%02d:%02d".format(hr12, minute)
                                    viewModel.onEvent(WorklistEvent.OnStartTimeChanged(newTime))
                                    viewModel.onEvent(WorklistEvent.OnAmPmChanged(newAmPm))
                                },
                                calendar.get(Calendar.HOUR_OF_DAY),
                                calendar.get(Calendar.MINUTE),
                                false
                            ).show()
                        }) {
                        Text(uiState.startTime)
                    }

                    ExposedDropdownMenuBox(
                        expanded = uiState.amPmMenuExpanded, onExpandedChange = {
                            viewModel.onEvent(WorklistEvent.OnAmPmMenuExpandedChanged(!uiState.amPmMenuExpanded))
                        }) {
                        TextField(
                            value = uiState.amPm,
                            onValueChange = {},
                            readOnly = true,
                            trailingIcon = {
                                Icon(Icons.Default.ArrowDropDown, contentDescription = null)
                            },
                            modifier = Modifier
                                .menuAnchor()
                                .width(80.dp)
                        )
                        ExposedDropdownMenu(
                            expanded = uiState.amPmMenuExpanded, onDismissRequest = {
                                viewModel.onEvent(WorklistEvent.OnAmPmMenuExpandedChanged(false))
                            }) {
                            listOf("AM", "PM").forEach { option ->
                                DropdownMenuItem(text = { Text(option) }, onClick = {
                                    viewModel.onEvent(WorklistEvent.OnAmPmChanged(option))
                                    viewModel.onEvent(WorklistEvent.OnAmPmMenuExpandedChanged(false))
                                })
                            }
                        }
                    }
                }
            }

            Spacer(Modifier.height(16.dp))
            Text("Visit location", style = MaterialTheme.typography.bodyMedium)

            ExposedDropdownMenuBox(
                expanded = uiState.locationMenuExpanded, onExpandedChange = {
                    viewModel.onEvent(WorklistEvent.OnLocationMenuExpandedChanged(!uiState.locationMenuExpanded))
                }) {
                TextField(
                    value = uiState.visitLocation,
                    onValueChange = {},
                    readOnly = true,
                    label = { Text("Select a location") },
                    trailingIcon = { Icon(Icons.Default.ArrowDropDown, null) },
                    modifier = Modifier
                        .menuAnchor()
                        .fillMaxWidth()
                )

                ExposedDropdownMenu(
                    expanded = uiState.locationMenuExpanded, onDismissRequest = {
                        viewModel.onEvent(WorklistEvent.OnLocationMenuExpandedChanged(false))
                    }) {
                    uiState.visitLocations.forEach { location ->
                        DropdownMenuItem(text = { Text(location) }, onClick = {
                            viewModel.onEvent(WorklistEvent.OnVisitLocationChanged(location))
                            viewModel.onEvent(WorklistEvent.OnLocationMenuExpandedChanged(false))
                        })
                    }
                }
            }

            Spacer(Modifier.height(16.dp))
            Text("Visit type", style = MaterialTheme.typography.bodyMedium)
            uiState.visitTypes.forEach { type ->
                Row(
                    verticalAlignment = Alignment.CenterVertically,
                    modifier = Modifier
                        .fillMaxWidth()
                        .clickable {
                            viewModel.onEvent(WorklistEvent.OnVisitTypeChanged(type))
                        }
                        .padding(vertical = 8.dp)) {
                    RadioButton(
                        selected = uiState.visitType == type,
                        onClick = { viewModel.onEvent(WorklistEvent.OnVisitTypeChanged(type)) })
                    Text(type, modifier = Modifier.padding(start = 8.dp))
                }
            }

            Spacer(Modifier.weight(1f))

        }
    }
}


