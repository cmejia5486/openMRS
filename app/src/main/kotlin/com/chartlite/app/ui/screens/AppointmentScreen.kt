package com.chartlite.app.ui.screens

import androidx.compose.foundation.layout.*
import androidx.compose.foundation.lazy.LazyColumn
import androidx.compose.foundation.lazy.LazyRow
import androidx.compose.foundation.lazy.items
import androidx.compose.foundation.shape.RoundedCornerShape
import androidx.compose.material.icons.Icons
import androidx.compose.material.icons.automirrored.filled.ArrowBack
import androidx.compose.material.icons.filled.Add
import androidx.compose.material.icons.filled.CalendarMonth
import androidx.compose.material.icons.filled.NavigateBefore
import androidx.compose.material.icons.filled.NavigateNext
import androidx.compose.material3.*
import androidx.compose.runtime.*
import androidx.compose.ui.Alignment
import androidx.compose.ui.Modifier
import androidx.compose.ui.platform.LocalContext
import androidx.compose.ui.text.font.FontWeight
import androidx.compose.ui.unit.dp
import com.chartlite.app.App
import com.chartlite.app.auth.AuditLogger
import com.chartlite.app.database.entity.AppointmentEntity
import com.chartlite.app.model.AppointmentStatus
import com.chartlite.app.model.AppointmentType
import kotlinx.coroutines.launch
import java.text.SimpleDateFormat
import androidx.compose.ui.res.stringResource
import com.chartlite.app.R
import java.util.*

@OptIn(ExperimentalMaterial3Api::class)
@Composable
fun AppointmentScreen(
    onBack: () -> Unit
) {
    val context = LocalContext.current
    val app = context.applicationContext as App
    val scope = rememberCoroutineScope()
    val facilityId = app.appConfig.facilityId

    var selectedDate by remember { mutableStateOf(todayStartMillis()) }
    var appointments by remember { mutableStateOf<List<AppointmentEntity>>(emptyList()) }
    var isLoading by remember { mutableStateOf(true) }
    var showCreateDialog by remember { mutableStateOf(false) }

    val dateFormat = remember { SimpleDateFormat("EEEE, dd MMMM yyyy", Locale.getDefault()) }

    fun loadAppointments() {
        scope.launch {
            isLoading = true
            appointments = app.appointmentRepository.getByDate(facilityId, selectedDate)
            isLoading = false
        }
    }

    LaunchedEffect(selectedDate) { loadAppointments() }

    Scaffold(
        topBar = {
            TopAppBar(
                title = { Text(stringResource(R.string.appointments)) },
                navigationIcon = {
                    IconButton(onClick = onBack) {
                        Icon(Icons.AutoMirrored.Filled.ArrowBack, stringResource(R.string.back))
                    }
                }
            )
        },
        floatingActionButton = {
            FloatingActionButton(onClick = { showCreateDialog = true }) {
                Icon(Icons.Default.Add, stringResource(R.string.new_appointment))
            }
        }
    ) { padding ->
        Column(
            modifier = Modifier.fillMaxSize().padding(padding)
        ) {
            // Date navigation
            Card(
                modifier = Modifier.fillMaxWidth().padding(horizontal = 16.dp, vertical = 8.dp),
                shape = RoundedCornerShape(12.dp)
            ) {
                Row(
                    modifier = Modifier.fillMaxWidth().padding(8.dp),
                    horizontalArrangement = Arrangement.SpaceBetween,
                    verticalAlignment = Alignment.CenterVertically
                ) {
                    IconButton(onClick = {
                        val cal = Calendar.getInstance().apply { timeInMillis = selectedDate; add(Calendar.DAY_OF_MONTH, -1) }
                        selectedDate = cal.timeInMillis
                    }) {
                        Icon(Icons.Default.NavigateBefore, stringResource(R.string.previous_day))
                    }
                    Column(horizontalAlignment = Alignment.CenterHorizontally) {
                        Text(
                            dateFormat.format(Date(selectedDate)),
                            fontWeight = FontWeight.Bold
                        )
                        Text(
                            stringResource(R.string.appointments_count_format, appointments.size),
                            style = MaterialTheme.typography.bodySmall,
                            color = MaterialTheme.colorScheme.outline
                        )
                    }
                    IconButton(onClick = {
                        val cal = Calendar.getInstance().apply { timeInMillis = selectedDate; add(Calendar.DAY_OF_MONTH, 1) }
                        selectedDate = cal.timeInMillis
                    }) {
                        Icon(Icons.Default.NavigateNext, stringResource(R.string.next_day))
                    }
                }
            }

            // Appointment list
            if (isLoading) {
                Box(Modifier.fillMaxSize(), contentAlignment = Alignment.Center) {
                    CircularProgressIndicator()
                }
            } else if (appointments.isEmpty()) {
                Box(Modifier.fillMaxSize(), contentAlignment = Alignment.Center) {
                    Column(horizontalAlignment = Alignment.CenterHorizontally) {
                        Icon(
                            Icons.Default.CalendarMonth,
                            contentDescription = null,
                            modifier = Modifier.size(64.dp),
                            tint = MaterialTheme.colorScheme.outline
                        )
                        Spacer(Modifier.height(16.dp))
                        Text(stringResource(R.string.no_appointments), style = MaterialTheme.typography.titleMedium)
                        Text(
                            stringResource(R.string.tap_plus_schedule),
                            style = MaterialTheme.typography.bodyMedium,
                            color = MaterialTheme.colorScheme.outline
                        )
                    }
                }
            } else {
                LazyColumn(
                    contentPadding = PaddingValues(16.dp),
                    verticalArrangement = Arrangement.spacedBy(12.dp)
                ) {
                    items(appointments, key = { it.id }) { appt ->
                        AppointmentCard(
                            appointment = appt,
                            onStatusUpdate = { newStatus ->
                                scope.launch {
                                    when (newStatus) {
                                        AppointmentStatus.CHECKED_IN.name ->
                                            app.appointmentRepository.checkIn(appt.id)
                                        AppointmentStatus.IN_PROGRESS.name ->
                                            app.appointmentRepository.startVisit(appt.id)
                                        AppointmentStatus.COMPLETED.name ->
                                            app.appointmentRepository.complete(appt.id)
                                        AppointmentStatus.NO_SHOW.name ->
                                            app.appointmentRepository.markNoShow(appt.id)
                                        AppointmentStatus.CANCELLED.name ->
                                            app.appointmentRepository.cancel(appt.id)
                                    }
                                    app.auditLogger.log(
                                        action = "UPDATE_APPOINTMENT",
                                        targetType = "APPOINTMENT",
                                        targetId = appt.id,
                                        details = AuditLogger.buildDetails("newStatus" to newStatus)
                                    )
                                    loadAppointments()
                                }
                            }
                        )
                    }
                }
            }
        }
    }

    val patientIdNotFoundMsg = stringResource(R.string.patient_id_not_found)
    if (showCreateDialog) {
        CreateAppointmentDialog(
            onDismiss = { showCreateDialog = false },
            onConfirm = { patientId, type, scheduledTime, durationMinutes, notes ->
                scope.launch {
                    try {
                        val userId = app.sessionManager.currentSession?.userId ?: "system"
                        app.appointmentRepository.schedule(
                            patientId = patientId,
                            facilityId = facilityId,
                            scheduledDate = selectedDate,
                            type = type,
                            createdBy = userId,
                            scheduledTime = scheduledTime,
                            durationMinutes = durationMinutes,
                            notes = notes
                        )
                        app.auditLogger.log(
                            action = "CREATE_APPOINTMENT",
                            targetType = "APPOINTMENT",
                            details = AuditLogger.buildDetails("patientId" to patientId, "type" to type, "date" to selectedDate)
                        )
                        loadAppointments()
                        showCreateDialog = false
                    } catch (e: IllegalArgumentException) {
                        android.widget.Toast.makeText(context, patientIdNotFoundMsg, android.widget.Toast.LENGTH_SHORT).show()
                    }
                }
            }
        )
    }
}

@Composable
private fun AppointmentCard(
    appointment: AppointmentEntity,
    onStatusUpdate: (String) -> Unit
) {
    val statusColor = when (appointment.status) {
        AppointmentStatus.SCHEDULED.name -> MaterialTheme.colorScheme.primary
        AppointmentStatus.CHECKED_IN.name -> MaterialTheme.colorScheme.tertiary
        AppointmentStatus.IN_PROGRESS.name -> MaterialTheme.colorScheme.secondary
        AppointmentStatus.COMPLETED.name -> MaterialTheme.colorScheme.outline
        AppointmentStatus.NO_SHOW.name -> MaterialTheme.colorScheme.error
        AppointmentStatus.CANCELLED.name -> MaterialTheme.colorScheme.error
        else -> MaterialTheme.colorScheme.outline
    }

    Card(
        modifier = Modifier.fillMaxWidth(),
        shape = RoundedCornerShape(12.dp)
    ) {
        Column(Modifier.padding(16.dp)) {
            Row(
                modifier = Modifier.fillMaxWidth(),
                horizontalArrangement = Arrangement.SpaceBetween,
                verticalAlignment = Alignment.CenterVertically
            ) {
                Column(Modifier.weight(1f)) {
                    Text(
                        appointment.scheduledTime ?: stringResource(R.string.walk_in),
                        fontWeight = FontWeight.Bold,
                        style = MaterialTheme.typography.titleMedium
                    )
                    Text(
                        appointment.type.replace("_", " "),
                        style = MaterialTheme.typography.bodyMedium
                    )
                }
                Surface(
                    color = statusColor.copy(alpha = 0.12f),
                    shape = RoundedCornerShape(8.dp)
                ) {
                    Text(
                        appointment.status.replace("_", " "),
                        color = statusColor,
                        style = MaterialTheme.typography.labelSmall,
                        modifier = Modifier.padding(horizontal = 12.dp, vertical = 6.dp)
                    )
                }
            }

            Spacer(Modifier.height(4.dp))
            Text(
                stringResource(R.string.patient_short_format, appointment.patientId.take(8)),
                style = MaterialTheme.typography.bodySmall,
                color = MaterialTheme.colorScheme.outline
            )
            Text(
                stringResource(R.string.duration_min_format, appointment.durationMinutes),
                style = MaterialTheme.typography.bodySmall,
                color = MaterialTheme.colorScheme.outline
            )

            appointment.notes?.let {
                Spacer(Modifier.height(4.dp))
                Text(it, style = MaterialTheme.typography.bodySmall)
            }

            // Action buttons based on status
            val activeStatus = appointment.status
            if (activeStatus == AppointmentStatus.SCHEDULED.name ||
                activeStatus == AppointmentStatus.CHECKED_IN.name ||
                activeStatus == AppointmentStatus.IN_PROGRESS.name) {
                Spacer(Modifier.height(8.dp))
                Row(horizontalArrangement = Arrangement.spacedBy(8.dp)) {
                    when (activeStatus) {
                        AppointmentStatus.SCHEDULED.name -> {
                            Button(
                                onClick = { onStatusUpdate(AppointmentStatus.CHECKED_IN.name) },
                                modifier = Modifier.weight(1f)
                            ) { Text(stringResource(R.string.check_in)) }
                            OutlinedButton(
                                onClick = { onStatusUpdate(AppointmentStatus.NO_SHOW.name) }
                            ) { Text(stringResource(R.string.no_show)) }
                        }
                        AppointmentStatus.CHECKED_IN.name -> {
                            Button(
                                onClick = { onStatusUpdate(AppointmentStatus.IN_PROGRESS.name) },
                                modifier = Modifier.weight(1f)
                            ) { Text(stringResource(R.string.start_visit)) }
                        }
                        AppointmentStatus.IN_PROGRESS.name -> {
                            Button(
                                onClick = { onStatusUpdate(AppointmentStatus.COMPLETED.name) },
                                modifier = Modifier.weight(1f)
                            ) { Text(stringResource(R.string.complete)) }
                        }
                    }
                    if (activeStatus != AppointmentStatus.IN_PROGRESS.name) {
                        OutlinedButton(
                            onClick = { onStatusUpdate(AppointmentStatus.CANCELLED.name) },
                            colors = ButtonDefaults.outlinedButtonColors(
                                contentColor = MaterialTheme.colorScheme.error
                            )
                        ) { Text(stringResource(R.string.cancel)) }
                    }
                }
            }
        }
    }
}

@Composable
private fun CreateAppointmentDialog(
    onDismiss: () -> Unit,
    onConfirm: (patientId: String, type: String, scheduledTime: String?, durationMinutes: Int, notes: String?) -> Unit
) {
    var patientId by remember { mutableStateOf("") }
    var type by remember { mutableStateOf(AppointmentType.NEW_VISIT.name) }
    var scheduledTime by remember { mutableStateOf("") }
    var durationMinutes by remember { mutableStateOf("30") }
    var notes by remember { mutableStateOf("") }
    var showErrors by remember { mutableStateOf(false) }

    AlertDialog(
        onDismissRequest = onDismiss,
        title = { Text(stringResource(R.string.schedule_appointment)) },
        text = {
            Column(verticalArrangement = Arrangement.spacedBy(12.dp)) {
                OutlinedTextField(
                    value = patientId,
                    onValueChange = { patientId = it },
                    label = { Text(stringResource(R.string.patient_id)) },
                    modifier = Modifier.fillMaxWidth(),
                    isError = showErrors && patientId.isBlank(),
                    supportingText = if (showErrors && patientId.isBlank()) {{ Text(stringResource(R.string.required)) }} else null
                )

                Text("Type", fontWeight = FontWeight.Medium)
                LazyRow(horizontalArrangement = Arrangement.spacedBy(8.dp)) {
                    items(AppointmentType.entries.toList()) { t ->
                        FilterChip(
                            selected = type == t.name,
                            onClick = { type = t.name },
                            label = { Text(t.name.replace("_", " "), style = MaterialTheme.typography.labelSmall) }
                        )
                    }
                }

                OutlinedTextField(
                    value = scheduledTime,
                    onValueChange = { scheduledTime = it },
                    label = { Text(stringResource(R.string.time_optional)) },
                    modifier = Modifier.fillMaxWidth()
                )

                OutlinedTextField(
                    value = durationMinutes,
                    onValueChange = { durationMinutes = it.filter { c -> c.isDigit() } },
                    label = { Text(stringResource(R.string.duration_minutes)) },
                    modifier = Modifier.fillMaxWidth()
                )

                OutlinedTextField(
                    value = notes,
                    onValueChange = { notes = it },
                    label = { Text(stringResource(R.string.notes_optional)) },
                    modifier = Modifier.fillMaxWidth(),
                    minLines = 2
                )
            }
        },
        confirmButton = {
            Button(
                onClick = {
                    if (patientId.isBlank()) { showErrors = true; return@Button }
                    showErrors = false
                    onConfirm(
                        patientId,
                        type,
                        scheduledTime.ifBlank { null },
                        durationMinutes.toIntOrNull() ?: 30,
                        notes.ifBlank { null }
                    )
                }
            ) { Text(stringResource(R.string.schedule)) }
        },
        dismissButton = {
            TextButton(onClick = onDismiss) { Text(stringResource(R.string.cancel)) }
        }
    )
}

private fun todayStartMillis(): Long {
    val cal = Calendar.getInstance()
    cal.set(Calendar.HOUR_OF_DAY, 0)
    cal.set(Calendar.MINUTE, 0)
    cal.set(Calendar.SECOND, 0)
    cal.set(Calendar.MILLISECOND, 0)
    return cal.timeInMillis
}
