package com.chartlite.app.ui.screens

import android.Manifest
import android.content.pm.PackageManager
import androidx.activity.compose.rememberLauncherForActivityResult
import androidx.activity.result.contract.ActivityResultContracts
import androidx.compose.foundation.layout.*
import androidx.compose.foundation.lazy.LazyColumn
import androidx.compose.foundation.lazy.items
import androidx.compose.foundation.shape.RoundedCornerShape
import androidx.compose.material.icons.Icons
import androidx.compose.material.icons.automirrored.filled.ArrowBack
import androidx.compose.material.icons.automirrored.filled.Send
import androidx.compose.material.icons.filled.*
import androidx.compose.material3.*
import androidx.compose.runtime.*
import androidx.compose.ui.Alignment
import androidx.compose.ui.Modifier
import androidx.compose.ui.platform.LocalContext
import androidx.compose.ui.text.font.FontWeight
import androidx.compose.ui.unit.dp
import androidx.core.content.ContextCompat
import com.chartlite.app.App
import com.chartlite.app.sms.*
import kotlinx.coroutines.launch
import java.text.SimpleDateFormat
import java.util.Date
import java.util.Locale
import androidx.compose.ui.res.stringResource
import com.chartlite.app.R

@OptIn(ExperimentalMaterial3Api::class)
@Composable
fun AppointmentReminderScreen(
    onBack: () -> Unit
) {
    val context = LocalContext.current
    val app = context.applicationContext as App
    val scope = rememberCoroutineScope()
    val dateFormat = remember { SimpleDateFormat("dd MMM yyyy HH:mm", Locale.getDefault()) }

    var pendingReminders by remember { mutableStateOf<List<ReminderCandidate>>(emptyList()) }
    var sameDayReminders by remember { mutableStateOf<List<ReminderCandidate>>(emptyList()) }
    var missedFollowUps by remember { mutableStateOf<List<ReminderCandidate>>(emptyList()) }
    var isLoading by remember { mutableStateOf(true) }
    var isSending by remember { mutableStateOf(false) }
    var batchResult by remember { mutableStateOf<BatchResult?>(null) }
    var selectedTab by remember { mutableIntStateOf(0) }
    var showSendAllDialog by remember { mutableStateOf(false) }

    // SMS permission handling — request at point of use
    val hasTwilio = app.appConfig.twilioAccountSid.isNotBlank()
    var hasSmsPermission by remember {
        mutableStateOf(
            hasTwilio || ContextCompat.checkSelfPermission(
                context, Manifest.permission.SEND_SMS
            ) == PackageManager.PERMISSION_GRANTED
        )
    }
    var pendingSendAction by remember { mutableStateOf<(() -> Unit)?>(null) }
    val smsPermissionLauncher = rememberLauncherForActivityResult(
        ActivityResultContracts.RequestPermission()
    ) { granted ->
        hasSmsPermission = granted || hasTwilio
        if (granted || hasTwilio) {
            pendingSendAction?.invoke()
        }
        pendingSendAction = null
    }

    /** Ensure SMS permission before executing [action]. */
    fun requireSmsPermission(action: () -> Unit) {
        if (hasSmsPermission) {
            action()
        } else {
            pendingSendAction = action
            smsPermissionLauncher.launch(Manifest.permission.SEND_SMS)
        }
    }

    LaunchedEffect(Unit) {
        val reminder = app.appointmentReminder
        pendingReminders = reminder.getPendingReminders()
        sameDayReminders = reminder.getSameDayReminders()
        missedFollowUps = reminder.getMissedAppointmentFollowUps()
        isLoading = false
    }

    // Confirm "Send All" dialog
    val totalPending = pendingReminders.size + sameDayReminders.size
    if (showSendAllDialog) {
        AlertDialog(
            onDismissRequest = { showSendAllDialog = false },
            title = { Text(stringResource(R.string.send_all_reminders)) },
            text = { Text(stringResource(R.string.send_all_reminders_body, totalPending)) },
            confirmButton = {
                TextButton(onClick = {
                    showSendAllDialog = false
                    requireSmsPermission {
                        scope.launch {
                            isSending = true
                            batchResult = app.appointmentReminder.sendAllPending()
                            pendingReminders = app.appointmentReminder.getPendingReminders()
                            sameDayReminders = app.appointmentReminder.getSameDayReminders()
                            isSending = false
                        }
                    }
                }) {
                    Text(stringResource(R.string.send_all))
                }
            },
            dismissButton = {
                TextButton(onClick = { showSendAllDialog = false }) {
                    Text(stringResource(R.string.cancel))
                }
            }
        )
    }

    Scaffold(
        topBar = {
            TopAppBar(
                title = { Text(stringResource(R.string.sms_reminders)) },
                navigationIcon = {
                    IconButton(onClick = onBack) { Icon(Icons.AutoMirrored.Filled.ArrowBack, stringResource(R.string.back)) }
                },
                actions = {
                    if (totalPending > 0) {
                        Button(
                            onClick = { showSendAllDialog = true },
                            enabled = !isSending,
                            modifier = Modifier.padding(end = 8.dp)
                        ) {
                            if (isSending) {
                                CircularProgressIndicator(modifier = Modifier.size(16.dp), strokeWidth = 2.dp)
                                Spacer(Modifier.width(8.dp))
                            }
                            Icon(Icons.AutoMirrored.Filled.Send, contentDescription = stringResource(R.string.send_all), Modifier.size(16.dp))
                            Spacer(Modifier.width(4.dp))
                            Text(stringResource(R.string.send_all_count_format, totalPending))
                        }
                    }
                }
            )
        }
    ) { padding ->
        Column(Modifier.padding(padding)) {
            // SMS permission warning banner
            if (!hasSmsPermission) {
                Surface(
                    color = MaterialTheme.colorScheme.errorContainer,
                    modifier = Modifier.fillMaxWidth()
                ) {
                    Row(
                        modifier = Modifier.padding(12.dp),
                        verticalAlignment = Alignment.CenterVertically
                    ) {
                        Icon(Icons.Default.Warning, null, tint = MaterialTheme.colorScheme.error)
                        Spacer(Modifier.width(8.dp))
                        Column(Modifier.weight(1f)) {
                            Text(stringResource(R.string.sms_permission_required), fontWeight = FontWeight.Bold,
                                color = MaterialTheme.colorScheme.onErrorContainer)
                            Text(stringResource(R.string.grant_sms_permission),
                                style = MaterialTheme.typography.bodySmall,
                                color = MaterialTheme.colorScheme.onErrorContainer)
                        }
                        TextButton(onClick = { smsPermissionLauncher.launch(Manifest.permission.SEND_SMS) }) {
                            Text(stringResource(R.string.grant))
                        }
                    }
                }
            }

            // Batch result banner
            batchResult?.let { result ->
                Card(
                    modifier = Modifier.fillMaxWidth().padding(16.dp),
                    shape = RoundedCornerShape(12.dp),
                    colors = CardDefaults.cardColors(
                        containerColor = if (result.failed == 0)
                            MaterialTheme.colorScheme.primaryContainer
                        else MaterialTheme.colorScheme.errorContainer
                    )
                ) {
                    Row(
                        Modifier.padding(16.dp).fillMaxWidth(),
                        horizontalArrangement = Arrangement.SpaceBetween,
                        verticalAlignment = Alignment.CenterVertically
                    ) {
                        Column {
                            Text(stringResource(R.string.batch_send_complete), fontWeight = FontWeight.Bold)
                            Text(stringResource(R.string.batch_result_format, result.sent, result.failed, result.total))
                        }
                        IconButton(onClick = { batchResult = null }) {
                            Icon(Icons.Default.Close, stringResource(R.string.close))
                        }
                    }
                }
            }

            // Tabs
            PrimaryTabRow(selectedTabIndex = selectedTab) {
                Tab(selected = selectedTab == 0, onClick = { selectedTab = 0 }) {
                    Row(Modifier.padding(12.dp), verticalAlignment = Alignment.CenterVertically) {
                        Text(stringResource(R.string.tomorrow))
                        if (pendingReminders.isNotEmpty()) {
                            Spacer(Modifier.width(4.dp))
                            Badge { Text("${pendingReminders.size}") }
                        }
                    }
                }
                Tab(selected = selectedTab == 1, onClick = { selectedTab = 1 }) {
                    Row(Modifier.padding(12.dp), verticalAlignment = Alignment.CenterVertically) {
                        Text(stringResource(R.string.today))
                        if (sameDayReminders.isNotEmpty()) {
                            Spacer(Modifier.width(4.dp))
                            Badge { Text("${sameDayReminders.size}") }
                        }
                    }
                }
                Tab(selected = selectedTab == 2, onClick = { selectedTab = 2 }) {
                    Row(Modifier.padding(12.dp), verticalAlignment = Alignment.CenterVertically) {
                        Text(stringResource(R.string.missed))
                        if (missedFollowUps.isNotEmpty()) {
                            Spacer(Modifier.width(4.dp))
                            Badge { Text("${missedFollowUps.size}") }
                        }
                    }
                }
            }

            if (isLoading) {
                Box(Modifier.fillMaxSize(), contentAlignment = Alignment.Center) { CircularProgressIndicator() }
            } else {
                val currentList = when (selectedTab) {
                    0 -> pendingReminders
                    1 -> sameDayReminders
                    2 -> missedFollowUps
                    else -> emptyList()
                }

                if (currentList.isEmpty()) {
                    Box(Modifier.fillMaxSize(), contentAlignment = Alignment.Center) {
                        Column(horizontalAlignment = Alignment.CenterHorizontally) {
                            Icon(Icons.Default.NotificationsOff, contentDescription = null, modifier = Modifier.size(64.dp), tint = MaterialTheme.colorScheme.outline)
                            Spacer(Modifier.height(16.dp))
                            Text(
                                when (selectedTab) {
                                    0 -> stringResource(R.string.no_reminders_tomorrow)
                                    1 -> stringResource(R.string.no_same_day_reminders)
                                    else -> stringResource(R.string.no_missed_appointments)
                                },
                                style = MaterialTheme.typography.titleMedium
                            )
                        }
                    }
                } else {
                    LazyColumn(
                        contentPadding = PaddingValues(16.dp),
                        verticalArrangement = Arrangement.spacedBy(12.dp)
                    ) {
                        items(currentList, key = { it.appointment.id }) { candidate ->
                            ReminderCard(
                                candidate = candidate,
                                dateFormat = dateFormat,
                                message = app.appointmentReminder.buildMessage(candidate),
                                onSend = {
                                    requireSmsPermission {
                                        scope.launch {
                                            isSending = true
                                            app.appointmentReminder.sendReminder(candidate)
                                            // Refresh
                                            pendingReminders = app.appointmentReminder.getPendingReminders()
                                            sameDayReminders = app.appointmentReminder.getSameDayReminders()
                                            missedFollowUps = app.appointmentReminder.getMissedAppointmentFollowUps()
                                            isSending = false
                                        }
                                    }
                                },
                                isSending = isSending
                            )
                        }
                    }
                }
            }
        }
    }
}

@Composable
private fun ReminderCard(
    candidate: ReminderCandidate,
    dateFormat: SimpleDateFormat,
    message: String,
    onSend: () -> Unit,
    isSending: Boolean
) {
    val typeColor = when (candidate.messageType) {
        ReminderType.DAY_BEFORE -> MaterialTheme.colorScheme.primaryContainer
        ReminderType.SAME_DAY -> MaterialTheme.colorScheme.tertiaryContainer
        ReminderType.MISSED -> MaterialTheme.colorScheme.errorContainer
    }

    Card(
        modifier = Modifier.fillMaxWidth(),
        shape = RoundedCornerShape(12.dp),
        colors = CardDefaults.cardColors(containerColor = typeColor)
    ) {
        Column(Modifier.padding(16.dp)) {
            Row(
                Modifier.fillMaxWidth(),
                horizontalArrangement = Arrangement.SpaceBetween,
                verticalAlignment = Alignment.CenterVertically
            ) {
                Column(Modifier.weight(1f)) {
                    Text("${candidate.patient.firstName} ${candidate.patient.lastName}", fontWeight = FontWeight.Bold)
                    Text(
                        candidate.patient.phoneNumber ?: "",
                        style = MaterialTheme.typography.bodySmall,
                        color = MaterialTheme.colorScheme.outline
                    )
                }
                AssistChip(
                    onClick = { /* Read-only type indicator */ },
                    label = { Text(candidate.appointment.type, style = MaterialTheme.typography.labelSmall) }
                )
            }

            Spacer(Modifier.height(8.dp))
            Text(
                stringResource(R.string.date_colon_format, dateFormat.format(Date(candidate.appointment.scheduledDate))),
                style = MaterialTheme.typography.bodySmall
            )

            // Preview message
            Spacer(Modifier.height(8.dp))
            Card(
                modifier = Modifier.fillMaxWidth(),
                shape = RoundedCornerShape(8.dp),
                colors = CardDefaults.cardColors(containerColor = MaterialTheme.colorScheme.surface)
            ) {
                Text(
                    message,
                    style = MaterialTheme.typography.bodySmall,
                    modifier = Modifier.padding(12.dp)
                )
            }

            Spacer(Modifier.height(8.dp))
            Button(
                onClick = onSend,
                enabled = !isSending,
                modifier = Modifier.align(Alignment.End)
            ) {
                Icon(Icons.AutoMirrored.Filled.Send, contentDescription = stringResource(R.string.send_sms), Modifier.size(16.dp))
                Spacer(Modifier.width(4.dp))
                Text(stringResource(R.string.send_sms))
            }
        }
    }
}
