package com.chartlite.app.ui.screens

import androidx.compose.foundation.clickable
import androidx.compose.foundation.layout.*
import androidx.compose.foundation.lazy.LazyColumn
import androidx.compose.foundation.lazy.items
import androidx.compose.foundation.shape.RoundedCornerShape
import androidx.compose.material.icons.Icons
import androidx.compose.material.icons.automirrored.filled.ArrowBack
import androidx.compose.material.icons.automirrored.filled.Send
import androidx.compose.material3.*
import androidx.compose.runtime.*
import androidx.compose.ui.Alignment
import androidx.compose.ui.Modifier
import androidx.compose.ui.platform.LocalContext
import androidx.compose.ui.text.font.FontWeight
import androidx.compose.ui.text.style.TextOverflow
import androidx.compose.ui.unit.dp
import com.chartlite.app.App
import com.chartlite.app.auth.AuditLogger
import com.chartlite.app.database.entity.ReferralEntity
import com.chartlite.app.model.ReferralStatus
import com.chartlite.app.model.ReferralUrgency
import androidx.compose.ui.res.stringResource
import com.chartlite.app.R
import com.chartlite.app.model.normalizeReferralValue
import kotlinx.coroutines.launch
import java.text.SimpleDateFormat
import java.util.Date
import java.util.Locale

@OptIn(ExperimentalMaterial3Api::class)
@Composable
fun ReferralScreen(
    onPatientSelected: (String) -> Unit = {},
    onBack: () -> Unit
) {
    val context = LocalContext.current
    val app = context.applicationContext as App
    val scope = rememberCoroutineScope()

    var referrals by remember { mutableStateOf<List<ReferralEntity>>(emptyList()) }
    var patientNames by remember { mutableStateOf<Map<String, String>>(emptyMap()) }
    var isLoading by remember { mutableStateOf(true) }
    var filterStatus by remember { mutableStateOf<String?>(null) }

    fun loadReferrals() {
        scope.launch {
            isLoading = true
            val list = if (filterStatus == ReferralStatus.PENDING.name) {
                app.referralRepository.getPending(app.appConfig.facilityId)
            } else {
                app.referralRepository.getByFacility(app.appConfig.facilityId)
            }
            referrals = list

            // Look up patient names for all unique patient IDs
            val ids = list.map { it.patientId }.distinct()
            val names = mutableMapOf<String, String>()
            for (id in ids) {
                val patient = app.database.patientDao().getById(id)
                if (patient != null) {
                    val name = listOfNotNull(patient.firstName, patient.lastName)
                        .joinToString(" ")
                        .ifEmpty { null }
                    names[id] = name ?: id.take(8)
                } else {
                    names[id] = id.take(8)
                }
            }
            patientNames = names
            isLoading = false
        }
    }

    LaunchedEffect(filterStatus) { loadReferrals() }

    Scaffold(
        topBar = {
            TopAppBar(
                title = { Text(stringResource(R.string.referrals)) },
                navigationIcon = {
                    IconButton(onClick = onBack) {
                        Icon(Icons.AutoMirrored.Filled.ArrowBack, stringResource(R.string.back))
                    }
                }
            )
        }
    ) { padding ->
        Column(
            modifier = Modifier.fillMaxSize().padding(padding)
        ) {
            // Status filter chips
            Row(
                modifier = Modifier.fillMaxWidth()
                    .padding(horizontal = 16.dp, vertical = 8.dp),
                horizontalArrangement = Arrangement.spacedBy(8.dp)
            ) {
                FilterChip(
                    selected = filterStatus == null,
                    onClick = { filterStatus = null },
                    label = { Text(stringResource(R.string.all)) }
                )
                FilterChip(
                    selected = filterStatus == ReferralStatus.PENDING.name,
                    onClick = { filterStatus = ReferralStatus.PENDING.name },
                    label = { Text(stringResource(R.string.pending)) }
                )
            }

            if (isLoading) {
                Box(Modifier.fillMaxSize(), contentAlignment = Alignment.Center) {
                    CircularProgressIndicator()
                }
            } else if (referrals.isEmpty()) {
                Box(Modifier.fillMaxSize(), contentAlignment = Alignment.Center) {
                    Column(horizontalAlignment = Alignment.CenterHorizontally) {
                        Icon(
                            Icons.AutoMirrored.Filled.Send,
                            contentDescription = null,
                            modifier = Modifier.size(64.dp),
                            tint = MaterialTheme.colorScheme.outline
                        )
                        Spacer(Modifier.height(16.dp))
                        Text(stringResource(R.string.no_referrals), style = MaterialTheme.typography.titleMedium)
                        Text(
                            stringResource(R.string.referrals_created_during_encounters),
                            style = MaterialTheme.typography.bodyMedium,
                            color = MaterialTheme.colorScheme.outline
                        )
                    }
                }
            } else {
                LazyColumn(
                    contentPadding = PaddingValues(16.dp),
                    verticalArrangement = Arrangement.spacedBy(10.dp)
                ) {
                    items(referrals, key = { it.id }) { referral ->
                        ReferralCard(
                            referral = referral,
                            patientName = patientNames[referral.patientId] ?: referral.patientId.take(8),
                            onPatientClick = { onPatientSelected(referral.patientId) },
                            onStatusUpdate = { newStatus ->
                                scope.launch {
                                    app.referralRepository.updateStatus(referral.id, newStatus)
                                    app.auditLogger.log(
                                        action = "UPDATE_REFERRAL",
                                        targetType = "REFERRAL",
                                        targetId = referral.id,
                                        details = AuditLogger.buildDetails("newStatus" to newStatus)
                                    )
                                    loadReferrals()
                                }
                            }
                        )
                    }
                }
            }
        }
    }
}

@Composable
private fun ReferralCard(
    referral: ReferralEntity,
    patientName: String,
    onPatientClick: () -> Unit,
    onStatusUpdate: (String) -> Unit
) {
    val dateFormat = remember { SimpleDateFormat("dd MMM yyyy", Locale.getDefault()) }
    val destinationLabel = remember(referral.toFacility) {
        normalizeReferralValue(referral.toFacility)
    }
    val departmentLabel = remember(referral.toDepartment) {
        normalizeReferralValue(referral.toDepartment)
    }
    val reasonLabel = remember(referral.reason) {
        normalizeReferralValue(referral.reason) ?: "Clinical referral"
    }

    val toLine = listOfNotNull(destinationLabel, departmentLabel)
        .joinToString(" · ")
        .ifEmpty { "Unspecified destination" }

    val statusColor = when (referral.status) {
        ReferralStatus.PENDING.name -> MaterialTheme.colorScheme.primary
        ReferralStatus.ACCEPTED.name -> MaterialTheme.colorScheme.tertiary
        ReferralStatus.COMPLETED.name -> MaterialTheme.colorScheme.secondary
        ReferralStatus.CANCELLED.name -> MaterialTheme.colorScheme.error
        else -> MaterialTheme.colorScheme.outline
    }

    val urgencyColor = when (referral.urgency) {
        ReferralUrgency.EMERGENCY.name -> MaterialTheme.colorScheme.error
        ReferralUrgency.URGENT.name -> MaterialTheme.colorScheme.tertiary
        else -> MaterialTheme.colorScheme.outline
    }

    OutlinedCard(
        modifier = Modifier.fillMaxWidth(),
        shape = RoundedCornerShape(12.dp)
    ) {
        Column(Modifier.padding(14.dp)) {
            // ── Row 1: Patient name (clickable) + date ──
            Row(
                modifier = Modifier.fillMaxWidth(),
                horizontalArrangement = Arrangement.SpaceBetween,
                verticalAlignment = Alignment.CenterVertically
            ) {
                Text(
                    patientName,
                    modifier = Modifier
                        .clickable(onClick = onPatientClick)
                        .weight(1f),
                    style = MaterialTheme.typography.titleSmall,
                    fontWeight = FontWeight.SemiBold,
                    color = MaterialTheme.colorScheme.primary,
                    maxLines = 1,
                    overflow = TextOverflow.Ellipsis
                )
                Text(
                    dateFormat.format(Date(referral.referredAt)),
                    style = MaterialTheme.typography.labelSmall,
                    color = MaterialTheme.colorScheme.onSurfaceVariant
                )
            }

            Spacer(Modifier.height(4.dp))

            // ── Row 2: To destination + reason ──
            Text(
                "→ $toLine",
                style = MaterialTheme.typography.bodyMedium
            )
            Text(
                reasonLabel,
                style = MaterialTheme.typography.bodySmall,
                color = MaterialTheme.colorScheme.onSurfaceVariant
            )

            Spacer(Modifier.height(6.dp))

            // ── Row 3: Status + Urgency badges ──
            Row(
                horizontalArrangement = Arrangement.spacedBy(6.dp),
                verticalAlignment = Alignment.CenterVertically
            ) {
                Surface(
                    color = statusColor.copy(alpha = 0.12f),
                    shape = RoundedCornerShape(4.dp)
                ) {
                    Text(
                        referral.status,
                        modifier = Modifier.padding(horizontal = 8.dp, vertical = 2.dp),
                        style = MaterialTheme.typography.labelSmall,
                        fontWeight = FontWeight.SemiBold,
                        color = statusColor
                    )
                }
                if (referral.urgency != ReferralUrgency.ROUTINE.name) {
                    Surface(
                        color = urgencyColor.copy(alpha = 0.12f),
                        shape = RoundedCornerShape(4.dp)
                    ) {
                        Text(
                            referral.urgency,
                            modifier = Modifier.padding(horizontal = 8.dp, vertical = 2.dp),
                            style = MaterialTheme.typography.labelSmall,
                            fontWeight = FontWeight.SemiBold,
                            color = urgencyColor
                        )
                    }
                }
                referral.timeframeDays?.let { days ->
                    Surface(
                        color = MaterialTheme.colorScheme.outlineVariant.copy(alpha = 0.3f),
                        shape = RoundedCornerShape(4.dp)
                    ) {
                        Text(
                            if (days == 0) stringResource(R.string.today_uppercase) else stringResource(R.string.within_days_format, days),
                            modifier = Modifier.padding(horizontal = 8.dp, vertical = 2.dp),
                            style = MaterialTheme.typography.labelSmall,
                            fontWeight = FontWeight.SemiBold,
                            color = MaterialTheme.colorScheme.onSurfaceVariant
                        )
                    }
                }
            }

            // ── Patient instructions ──
            referral.patientInstructions?.let { instructions ->
                Spacer(Modifier.height(6.dp))
                Text(
                    instructions,
                    style = MaterialTheme.typography.bodySmall,
                    color = MaterialTheme.colorScheme.onSurfaceVariant
                )
            }

            // ── SMS sent to patient ──
            referral.smsText?.let { sms ->
                Spacer(Modifier.height(8.dp))
                Surface(
                    color = MaterialTheme.colorScheme.surfaceVariant.copy(alpha = 0.5f),
                    shape = RoundedCornerShape(6.dp)
                ) {
                    Row(
                        modifier = Modifier.padding(horizontal = 10.dp, vertical = 6.dp),
                        horizontalArrangement = Arrangement.spacedBy(6.dp),
                        verticalAlignment = Alignment.Top
                    ) {
                        Icon(
                            Icons.AutoMirrored.Filled.Send,
                            contentDescription = null,
                            modifier = Modifier.size(14.dp),
                            tint = MaterialTheme.colorScheme.onSurfaceVariant
                        )
                        Column {
                            Text(
                                stringResource(R.string.sms_sent_to_patient),
                                style = MaterialTheme.typography.labelSmall,
                                fontWeight = FontWeight.SemiBold,
                                color = MaterialTheme.colorScheme.onSurfaceVariant
                            )
                            Text(
                                sms,
                                style = MaterialTheme.typography.bodySmall,
                                color = MaterialTheme.colorScheme.onSurfaceVariant
                            )
                        }
                    }
                }
            }

            // Action buttons for pending referrals
            if (referral.status == ReferralStatus.PENDING.name) {
                Spacer(Modifier.height(10.dp))
                Row(horizontalArrangement = Arrangement.spacedBy(8.dp)) {
                    Button(
                        onClick = { onStatusUpdate(ReferralStatus.ACCEPTED.name) },
                        modifier = Modifier.weight(1f)
                    ) { Text(stringResource(R.string.accept)) }
                    OutlinedButton(
                        onClick = { onStatusUpdate(ReferralStatus.CANCELLED.name) },
                        colors = ButtonDefaults.outlinedButtonColors(
                            contentColor = MaterialTheme.colorScheme.error
                        )
                    ) { Text(stringResource(R.string.cancel)) }
                }
            } else if (referral.status == ReferralStatus.ACCEPTED.name) {
                Spacer(Modifier.height(10.dp))
                Button(
                    onClick = { onStatusUpdate(ReferralStatus.COMPLETED.name) },
                    modifier = Modifier.fillMaxWidth()
                ) { Text(stringResource(R.string.mark_completed)) }
            }
        }
    }
}
