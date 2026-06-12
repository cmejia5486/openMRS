package com.chartlite.app.ui.screens

import android.util.Log
import android.widget.Toast
import androidx.compose.foundation.BorderStroke
import androidx.compose.foundation.Canvas
import androidx.compose.foundation.background
import androidx.compose.foundation.clickable
import androidx.compose.foundation.layout.*
import androidx.compose.foundation.lazy.LazyColumn
import androidx.compose.foundation.lazy.LazyRow
import androidx.compose.foundation.lazy.items
import androidx.compose.foundation.lazy.itemsIndexed
import androidx.compose.foundation.shape.CircleShape
import androidx.compose.foundation.shape.RoundedCornerShape
import androidx.compose.material.icons.Icons
import androidx.compose.material.icons.automirrored.filled.ArrowBack
import androidx.compose.material.icons.filled.*
import androidx.compose.material3.*
import androidx.compose.runtime.*
import androidx.compose.ui.Alignment
import androidx.compose.ui.Modifier
import androidx.compose.ui.draw.clip
import androidx.compose.ui.geometry.Offset
import androidx.compose.ui.graphics.Brush
import androidx.compose.ui.graphics.Color
import androidx.compose.ui.graphics.Path
import androidx.compose.ui.graphics.drawscope.Fill
import androidx.compose.ui.graphics.drawscope.Stroke
import androidx.compose.ui.graphics.vector.ImageVector
import androidx.compose.ui.platform.LocalClipboardManager
import androidx.compose.ui.platform.LocalContext
import androidx.compose.ui.res.stringResource
import androidx.compose.ui.text.AnnotatedString
import androidx.compose.ui.text.font.FontFamily
import androidx.compose.ui.text.font.FontWeight
import androidx.compose.ui.unit.dp
import androidx.compose.ui.unit.sp
import com.chartlite.app.App
import com.chartlite.app.R
import com.chartlite.app.database.entity.EncounterEntity
import com.chartlite.app.database.entity.PatientEntity
import com.chartlite.app.database.entity.effectiveEncounterTimeMillis
import com.chartlite.app.model.VitalSigns
import com.chartlite.app.ui.components.EncounterCard
import com.chartlite.app.ui.theme.*
import com.google.gson.Gson
import kotlinx.coroutines.launch
import java.text.SimpleDateFormat
import java.util.Date
import java.util.Locale

/**
 * Patient Summary Dashboard — comprehensive single-screen patient overview.
 */
@OptIn(ExperimentalMaterial3Api::class)
@Composable
fun PatientSummaryScreen(
    patientId: String,
    onEncounterSelected: (String) -> Unit,
    onNewEncounter: () -> Unit,
    onViewTimeline: () -> Unit,
    onViewImmunizations: () -> Unit,
    onViewGrowthChart: () -> Unit,
    onViewSMSHistory: () -> Unit,
    onBack: () -> Unit
) {
    val context = LocalContext.current
    val app = context.applicationContext as App
    val scope = rememberCoroutineScope()
    val gson = remember { Gson() }
    val dateFormat = remember { SimpleDateFormat("dd MMM yyyy", Locale.getDefault()) }
    val clipboardManager = LocalClipboardManager.current

    var patient by remember { mutableStateOf<PatientEntity?>(null) }
    var encounters by remember { mutableStateOf<List<EncounterEntity>>(emptyList()) }
    var smsLogs by remember { mutableStateOf<List<com.chartlite.app.database.entity.SmsLogEntity>>(emptyList()) }
    var isLoading by remember { mutableStateOf(true) }

    LaunchedEffect(patientId) {
        patient = app.patientRepository.getById(patientId)
        encounters = app.encounterRepository.getByPatientId(patientId)
        smsLogs = try { app.smsLogRepository.getByPatientId(patientId) } catch (_: Exception) { emptyList() }
        isLoading = false
    }

    Scaffold(
        topBar = {
            TopAppBar(
                title = { Text(patient?.let { "${it.firstName} ${it.lastName}" } ?: stringResource(R.string.patient_summary)) },
                navigationIcon = {
                    IconButton(onClick = onBack) { Icon(Icons.AutoMirrored.Filled.ArrowBack, stringResource(R.string.back)) }
                }
            )
        },
        floatingActionButton = {
            ExtendedFloatingActionButton(
                onClick = onNewEncounter,
                containerColor = BrandGreen,
                contentColor = Color.White,
                icon = { Icon(Icons.Default.Add, null) },
                text = { Text(stringResource(R.string.new_encounter)) }
            )
        }
    ) { padding ->
        if (isLoading) {
            Box(Modifier.fillMaxSize().padding(padding), contentAlignment = Alignment.Center) {
                CircularProgressIndicator()
            }
        } else if (patient == null) {
            Box(Modifier.fillMaxSize().padding(padding), contentAlignment = Alignment.Center) {
                Text(stringResource(R.string.patient_not_found), style = MaterialTheme.typography.titleMedium)
            }
        } else {
            val pat = patient ?: return@Scaffold
            val vitalHistory = remember(encounters) { extractVitalHistory(encounters, gson) }
            val diagnosisSummary = remember(encounters) { extractDiagnosisSummary(encounters) }
            val medicationSummary = remember(encounters) { extractMedicationSummary(encounters) }
            val allergies = remember(encounters, pat) { extractAllergies(encounters, pat, gson) }

            LazyColumn(
                modifier = Modifier.fillMaxSize().padding(padding),
                contentPadding = PaddingValues(16.dp),
                verticalArrangement = Arrangement.spacedBy(16.dp)
            ) {
                // ── Patient Header Card (Gradient) ──
                item {
                    Surface(
                        modifier = Modifier.fillMaxWidth(),
                        shape = RoundedCornerShape(20.dp),
                        shadowElevation = 2.dp
                    ) {
                        Box(
                            modifier = Modifier
                                .fillMaxWidth()
                                .background(
                                    Brush.horizontalGradient(listOf(BrandGreen, BrandGreenDark)),
                                    shape = RoundedCornerShape(20.dp)
                                )
                        ) {
                            Column(Modifier.padding(20.dp)) {
                                Row(verticalAlignment = Alignment.CenterVertically) {
                                    // Avatar
                                    Box(
                                        modifier = Modifier
                                            .size(56.dp)
                                            .clip(CircleShape)
                                            .background(Color.White.copy(alpha = 0.2f)),
                                        contentAlignment = Alignment.Center
                                    ) {
                                        Text(
                                            pat.firstName.firstOrNull()?.uppercase() ?: "?",
                                            color = Color.White,
                                            fontWeight = FontWeight.Bold,
                                            style = MaterialTheme.typography.headlineSmall
                                        )
                                    }
                                    Spacer(Modifier.width(16.dp))
                                    Column(Modifier.weight(1f)) {
                                        Text(
                                            "${pat.firstName} ${pat.lastName}",
                                            fontWeight = FontWeight.Bold,
                                            style = MaterialTheme.typography.headlineSmall,
                                            color = Color.White
                                        )
                                        Spacer(Modifier.height(2.dp))
                                        Text(
                                            buildString {
                                                append("${pat.ageYears ?: "?"}y")
                                                append("  \u00B7  ")
                                                append(pat.gender.replaceFirstChar { it.uppercase() })
                                            },
                                            style = MaterialTheme.typography.bodyMedium,
                                            color = Color.White.copy(alpha = 0.85f)
                                        )
                                        Spacer(Modifier.height(4.dp))
                                        // Patient ID — tappable to copy
                                        Row(
                                            verticalAlignment = Alignment.CenterVertically,
                                            modifier = Modifier.clickable {
                                                clipboardManager.setText(AnnotatedString(pat.id))
                                                Toast.makeText(context, "ID copied", Toast.LENGTH_SHORT).show()
                                            }
                                        ) {
                                            Icon(
                                                Icons.Default.ContentCopy,
                                                contentDescription = "Copy ID",
                                                modifier = Modifier.size(12.dp),
                                                tint = Color.White.copy(alpha = 0.6f)
                                            )
                                            Spacer(Modifier.width(4.dp))
                                            Text(
                                                pat.id,
                                                style = MaterialTheme.typography.labelMedium,
                                                fontFamily = FontFamily.Monospace,
                                                color = Color.White.copy(alpha = 0.7f),
                                                letterSpacing = 2.sp
                                            )
                                        }
                                    }
                                }

                                Spacer(Modifier.height(16.dp))

                                // Stats row — icon pills
                                Row(
                                    Modifier.fillMaxWidth(),
                                    horizontalArrangement = Arrangement.spacedBy(8.dp)
                                ) {
                                    StatPill(
                                        icon = Icons.Default.CalendarToday,
                                        value = "${encounters.size}",
                                        label = stringResource(R.string.visits_label),
                                        modifier = Modifier.weight(1f)
                                    )
                                    StatPill(
                                        icon = Icons.Default.MedicalServices,
                                        value = "${diagnosisSummary.size}",
                                        label = stringResource(R.string.conditions_label),
                                        modifier = Modifier.weight(1f)
                                    )
                                    StatPill(
                                        icon = Icons.Default.Medication,
                                        value = "${medicationSummary.size}",
                                        label = "Active Meds",
                                        modifier = Modifier.weight(1f)
                                    )
                                }

                                if (!pat.phoneNumber.isNullOrBlank()) {
                                    Spacer(Modifier.height(10.dp))
                                    Row(verticalAlignment = Alignment.CenterVertically) {
                                        Icon(Icons.Default.Phone, null, Modifier.size(12.dp), tint = Color.White.copy(alpha = 0.6f))
                                        Spacer(Modifier.width(4.dp))
                                        Text(pat.phoneNumber!!, style = MaterialTheme.typography.bodySmall, color = Color.White.copy(alpha = 0.7f))
                                    }
                                }
                            }
                        }
                    }
                }

                // ── Quick Actions ──
                item {
                    LazyRow(horizontalArrangement = Arrangement.spacedBy(8.dp)) {
                        item {
                            AssistChip(
                                onClick = onViewTimeline,
                                label = { Text(stringResource(R.string.timeline)) },
                                leadingIcon = { Icon(Icons.Default.Timeline, null, Modifier.size(16.dp)) },
                                colors = AssistChipDefaults.assistChipColors(
                                    containerColor = BrandGreenSurface,
                                    labelColor = BrandGreenDark,
                                    leadingIconContentColor = BrandGreen
                                ),
                                border = AssistChipDefaults.assistChipBorder(enabled = true, borderColor = BrandGreen.copy(alpha = 0.3f))
                            )
                        }
                        item {
                            AssistChip(
                                onClick = onViewImmunizations,
                                label = { Text(stringResource(R.string.immunizations)) },
                                leadingIcon = { Icon(Icons.Default.Vaccines, null, Modifier.size(16.dp)) },
                                colors = AssistChipDefaults.assistChipColors(
                                    containerColor = BrandGreenSurface,
                                    labelColor = BrandGreenDark,
                                    leadingIconContentColor = BrandGreen
                                ),
                                border = AssistChipDefaults.assistChipBorder(enabled = true, borderColor = BrandGreen.copy(alpha = 0.3f))
                            )
                        }
                        item {
                            AssistChip(
                                onClick = onViewGrowthChart,
                                label = { Text(stringResource(R.string.growth_chart)) },
                                leadingIcon = { Icon(Icons.Default.ChildCare, null, Modifier.size(16.dp)) },
                                colors = AssistChipDefaults.assistChipColors(
                                    containerColor = BrandGreenSurface,
                                    labelColor = BrandGreenDark,
                                    leadingIconContentColor = BrandGreen
                                ),
                                border = AssistChipDefaults.assistChipBorder(enabled = true, borderColor = BrandGreen.copy(alpha = 0.3f))
                            )
                        }
                        item {
                            AssistChip(
                                onClick = onViewSMSHistory,
                                label = { Text(stringResource(R.string.sms_history)) },
                                leadingIcon = { Icon(Icons.Default.Sms, null, Modifier.size(16.dp)) },
                                colors = AssistChipDefaults.assistChipColors(
                                    containerColor = BrandGreenSurface,
                                    labelColor = BrandGreenDark,
                                    leadingIconContentColor = BrandGreen
                                ),
                                border = AssistChipDefaults.assistChipBorder(enabled = true, borderColor = BrandGreen.copy(alpha = 0.3f))
                            )
                        }
                    }
                }

                // ── SMS Health Record ──
                if (smsLogs.isNotEmpty()) {
                    item {
                        Card(
                            Modifier.fillMaxWidth().clickable(onClick = onViewSMSHistory),
                            shape = RoundedCornerShape(12.dp),
                            colors = CardDefaults.cardColors(containerColor = Color.White),
                            elevation = CardDefaults.cardElevation(defaultElevation = 0.5.dp)
                        ) {
                            Column(Modifier.padding(16.dp)) {
                                Row(
                                    Modifier.fillMaxWidth(),
                                    horizontalArrangement = Arrangement.SpaceBetween,
                                    verticalAlignment = Alignment.CenterVertically
                                ) {
                                    Row(verticalAlignment = Alignment.CenterVertically) {
                                        Icon(Icons.Default.Sms, null, Modifier.size(20.dp), tint = BrandGreen)
                                        Spacer(Modifier.width(8.dp))
                                        Text(
                                            stringResource(R.string.sms_history),
                                            style = MaterialTheme.typography.titleSmall,
                                            fontWeight = FontWeight.SemiBold
                                        )
                                    }
                                    Icon(Icons.Default.ChevronRight, null, Modifier.size(20.dp), tint = Neutral400)
                                }
                                Spacer(Modifier.height(8.dp))
                                val sentCount = smsLogs.count { it.status == "SENT" || it.status == "DELIVERED" }
                                val failedCount = smsLogs.count { it.status == "FAILED" }
                                val skippedCount = smsLogs.count { it.status == "SKIPPED" }
                                Row(horizontalArrangement = Arrangement.spacedBy(8.dp)) {
                                    if (sentCount > 0) {
                                        Surface(color = BrandGreenSurface, shape = RoundedCornerShape(6.dp)) {
                                            Text(
                                                "$sentCount sent",
                                                modifier = Modifier.padding(horizontal = 8.dp, vertical = 4.dp),
                                                style = MaterialTheme.typography.labelMedium,
                                                color = BrandGreen,
                                                fontWeight = FontWeight.Medium
                                            )
                                        }
                                    }
                                    if (failedCount > 0) {
                                        Surface(color = AlertRedSurface, shape = RoundedCornerShape(6.dp)) {
                                            Text(
                                                "$failedCount failed",
                                                modifier = Modifier.padding(horizontal = 8.dp, vertical = 4.dp),
                                                style = MaterialTheme.typography.labelMedium,
                                                color = AlertRed,
                                                fontWeight = FontWeight.Medium
                                            )
                                        }
                                    }
                                    if (skippedCount > 0) {
                                        Surface(color = WarningAmberSurface, shape = RoundedCornerShape(6.dp)) {
                                            Text(
                                                "$skippedCount no phone",
                                                modifier = Modifier.padding(horizontal = 8.dp, vertical = 4.dp),
                                                style = MaterialTheme.typography.labelMedium,
                                                color = WarningAmber,
                                                fontWeight = FontWeight.Medium
                                            )
                                        }
                                    }
                                }
                                // Show latest SMS content summary
                                val latest = smsLogs.firstOrNull()
                                if (latest != null) {
                                    Spacer(Modifier.height(6.dp))
                                    val timeFormat = remember { SimpleDateFormat("dd MMM, HH:mm", Locale.getDefault()) }
                                    Text(
                                        "${timeFormat.format(Date(latest.timestamp))} \u2014 ${latest.contentSummary}",
                                        style = MaterialTheme.typography.bodySmall,
                                        color = Neutral500,
                                        maxLines = 2
                                    )
                                }
                            }
                        }
                    }
                }

                // ── Allergies ──
                if (allergies.isNotEmpty()) {
                    item {
                        Card(
                            Modifier.fillMaxWidth(),
                            shape = RoundedCornerShape(12.dp),
                            colors = CardDefaults.cardColors(containerColor = AlertRedSurface)
                        ) {
                            Column(Modifier.padding(16.dp)) {
                                Row(verticalAlignment = Alignment.CenterVertically) {
                                    Icon(Icons.Default.Warning, null, Modifier.size(18.dp), tint = AlertRed)
                                    Spacer(Modifier.width(8.dp))
                                    Text(
                                        stringResource(R.string.allergies),
                                        fontWeight = FontWeight.Bold,
                                        color = AlertRed,
                                        style = MaterialTheme.typography.titleSmall
                                    )
                                }
                                Spacer(Modifier.height(8.dp))
                                // Allergy pills
                                @OptIn(ExperimentalLayoutApi::class)
                                FlowRow(
                                    horizontalArrangement = Arrangement.spacedBy(6.dp),
                                    verticalArrangement = Arrangement.spacedBy(6.dp)
                                ) {
                                    allergies.forEach { allergy ->
                                        Surface(
                                            color = AlertRed.copy(alpha = 0.12f),
                                            shape = RoundedCornerShape(6.dp)
                                        ) {
                                            Text(
                                                allergy,
                                                modifier = Modifier.padding(horizontal = 8.dp, vertical = 4.dp),
                                                style = MaterialTheme.typography.labelMedium,
                                                color = AlertRed,
                                                fontWeight = FontWeight.Medium
                                            )
                                        }
                                    }
                                }
                            }
                        }
                    }
                }

                // ── Active Conditions ──
                item {
                    SectionHeader(Icons.Default.MedicalServices, stringResource(R.string.active_conditions)) {
                        if (diagnosisSummary.isNotEmpty()) {
                            Surface(color = BrandGreenSurface, shape = RoundedCornerShape(10.dp)) {
                                Text(
                                    "${diagnosisSummary.size}",
                                    modifier = Modifier.padding(horizontal = 8.dp, vertical = 2.dp),
                                    style = MaterialTheme.typography.labelSmall,
                                    color = BrandGreen,
                                    fontWeight = FontWeight.Bold
                                )
                            }
                        }
                    }
                }
                if (diagnosisSummary.isNotEmpty()) {
                    item {
                        Card(
                            Modifier.fillMaxWidth(),
                            shape = RoundedCornerShape(12.dp),
                            colors = CardDefaults.cardColors(containerColor = Color.White),
                            elevation = CardDefaults.cardElevation(defaultElevation = 0.5.dp)
                        ) {
                            Column(Modifier.padding(16.dp)) {
                                diagnosisSummary.take(10).forEachIndexed { index, (diagnosis, count) ->
                                    if (index > 0) Spacer(Modifier.height(8.dp))
                                    Row(
                                        Modifier.fillMaxWidth(),
                                        verticalAlignment = Alignment.CenterVertically
                                    ) {
                                        // Frequency indicator dot
                                        val dotColor = when {
                                            count >= 4 -> AlertRed
                                            count >= 2 -> WarningAmber
                                            else -> BrandGreen
                                        }
                                        Box(
                                            Modifier
                                                .size(8.dp)
                                                .clip(CircleShape)
                                                .background(dotColor)
                                        )
                                        Spacer(Modifier.width(10.dp))
                                        Column(Modifier.weight(1f)) {
                                            // Extract ICD-10 code and description
                                            val parts = diagnosis.split(" — ", limit = 2)
                                            if (parts.size == 2) {
                                                Text(
                                                    parts[0],
                                                    style = MaterialTheme.typography.labelSmall,
                                                    fontFamily = FontFamily.Monospace,
                                                    color = Neutral500
                                                )
                                                Text(
                                                    parts[1],
                                                    style = MaterialTheme.typography.bodyMedium
                                                )
                                            } else {
                                                Text(diagnosis, style = MaterialTheme.typography.bodyMedium)
                                            }
                                        }
                                        Surface(
                                            color = BrandGreenSurface,
                                            shape = CircleShape
                                        ) {
                                            Text(
                                                "$count",
                                                modifier = Modifier.padding(horizontal = 8.dp, vertical = 2.dp),
                                                style = MaterialTheme.typography.labelSmall,
                                                fontWeight = FontWeight.Bold,
                                                color = BrandGreen
                                            )
                                        }
                                    }
                                }
                            }
                        }
                    }
                } else {
                    item { EmptyPlaceholder("No conditions recorded yet") }
                }

                // ── Current Medications ──
                item {
                    SectionHeader(Icons.Default.Medication, stringResource(R.string.recent_medications)) {
                        if (medicationSummary.isNotEmpty()) {
                            Surface(color = BrandGreenSurface, shape = RoundedCornerShape(10.dp)) {
                                Text(
                                    "${medicationSummary.size}",
                                    modifier = Modifier.padding(horizontal = 8.dp, vertical = 2.dp),
                                    style = MaterialTheme.typography.labelSmall,
                                    color = BrandGreen,
                                    fontWeight = FontWeight.Bold
                                )
                            }
                        }
                    }
                }
                if (medicationSummary.isNotEmpty()) {
                    item {
                        Card(
                            Modifier.fillMaxWidth(),
                            shape = RoundedCornerShape(12.dp),
                            colors = CardDefaults.cardColors(containerColor = Color.White),
                            elevation = CardDefaults.cardElevation(defaultElevation = 0.5.dp)
                        ) {
                            Column(Modifier.padding(16.dp)) {
                                medicationSummary.take(10).forEachIndexed { index, (medication, count) ->
                                    if (index > 0) Spacer(Modifier.height(8.dp))
                                    Row(
                                        Modifier.fillMaxWidth(),
                                        verticalAlignment = Alignment.CenterVertically
                                    ) {
                                        Icon(
                                            Icons.Default.Medication,
                                            null,
                                            Modifier.size(16.dp),
                                            tint = BrandGreen
                                        )
                                        Spacer(Modifier.width(10.dp))
                                        Text(
                                            medication,
                                            style = MaterialTheme.typography.bodyMedium,
                                            fontWeight = FontWeight.Medium,
                                            modifier = Modifier.weight(1f)
                                        )
                                        Text(
                                            "\u00D7$count",
                                            style = MaterialTheme.typography.labelMedium,
                                            color = Neutral500
                                        )
                                    }
                                }
                            }
                        }
                    }
                } else {
                    item { EmptyPlaceholder("No medications recorded yet") }
                }

                // ── Vital Signs Trending ──
                item {
                    SectionHeader(Icons.Default.MonitorHeart, stringResource(R.string.vital_signs_trend))
                }

                if (vitalHistory.isNotEmpty()) {
                    // Blood Pressure
                    val bpData = vitalHistory.filter { it.systolicBP != null && it.diastolicBP != null }
                    if (bpData.isNotEmpty()) {
                        item {
                            VitalTrendCard(
                                title = stringResource(R.string.blood_pressure),
                                data = bpData.map { Triple(it.date, (it.systolicBP ?: 0).toFloat(), (it.diastolicBP ?: 0).toFloat()) },
                                unit = "mmHg",
                                primaryLabel = "Systolic",
                                secondaryLabel = "Diastolic",
                                primaryColor = Color(0xFFE53935),
                                secondaryColor = Color(0xFF1E88E5),
                                normalRange = 90f..140f,
                                dateFormat = dateFormat
                            )
                        }
                    }

                    // Heart Rate
                    val hrData = vitalHistory.filter { it.pulse != null }
                    if (hrData.isNotEmpty()) {
                        item {
                            VitalTrendCard(
                                title = stringResource(R.string.heart_rate),
                                data = hrData.map { Triple(it.date, (it.pulse ?: 0).toFloat(), 0f) },
                                unit = "bpm",
                                primaryLabel = "HR",
                                primaryColor = Color(0xFFE91E63),
                                normalRange = 60f..100f,
                                dateFormat = dateFormat
                            )
                        }
                    }

                    // Temperature
                    val tempData = vitalHistory.filter { it.temperature != null }
                    if (tempData.isNotEmpty()) {
                        item {
                            VitalTrendCard(
                                title = stringResource(R.string.temperature),
                                data = tempData.map { Triple(it.date, it.temperature ?: 0f, 0f) },
                                unit = "\u00B0C",
                                primaryLabel = "Temp",
                                primaryColor = Color(0xFFFF9800),
                                normalRange = 36.1f..37.2f,
                                dateFormat = dateFormat
                            )
                        }
                    }

                    // Weight
                    val weightData = vitalHistory.filter { it.weight != null }
                    if (weightData.isNotEmpty()) {
                        item {
                            VitalTrendCard(
                                title = stringResource(R.string.weight),
                                data = weightData.map { Triple(it.date, it.weight ?: 0f, 0f) },
                                unit = "kg",
                                primaryLabel = "Weight",
                                primaryColor = Color(0xFF4CAF50),
                                dateFormat = dateFormat
                            )
                        }
                    }

                    // SpO2
                    val spo2Data = vitalHistory.filter { it.oxygenSat != null }
                    if (spo2Data.isNotEmpty()) {
                        item {
                            VitalTrendCard(
                                title = stringResource(R.string.oxygen_saturation),
                                data = spo2Data.map { Triple(it.date, (it.oxygenSat ?: 0).toFloat(), 0f) },
                                unit = "%",
                                primaryLabel = "SpO2",
                                primaryColor = Color(0xFF2196F3),
                                normalRange = 95f..100f,
                                dateFormat = dateFormat
                            )
                        }
                    }
                } else {
                    item { EmptyPlaceholder("No vitals recorded yet") }
                }

                // ── Recent Encounters ──
                item {
                    SectionHeader(Icons.Default.History, stringResource(R.string.recent_encounters_section)) {
                        if (encounters.isNotEmpty()) {
                            Surface(color = BrandGreenSurface, shape = RoundedCornerShape(10.dp)) {
                                Text(
                                    "${encounters.size}",
                                    modifier = Modifier.padding(horizontal = 8.dp, vertical = 2.dp),
                                    style = MaterialTheme.typography.labelSmall,
                                    color = BrandGreen,
                                    fontWeight = FontWeight.Bold
                                )
                            }
                        }
                    }
                }
                if (encounters.isNotEmpty()) {
                    itemsIndexed(encounters.take(10), key = { _, e -> e.id }) { index, encounter ->
                        Column {
                            // Timeline connector between cards
                            if (index > 0) {
                                Box(
                                    Modifier
                                        .padding(start = 20.dp)
                                        .width(2.dp)
                                        .height(8.dp)
                                        .background(BrandGreen.copy(alpha = 0.25f))
                                )
                            }
                            Box {
                                EncounterCard(
                                    encounter = encounter,
                                    onClick = { onEncounterSelected(encounter.id) }
                                )
                                // "Latest" badge on first card
                                if (index == 0) {
                                    Surface(
                                        color = BrandGreenSurface,
                                        shape = RoundedCornerShape(4.dp),
                                        modifier = Modifier
                                            .align(Alignment.TopEnd)
                                            .padding(top = 8.dp, end = 12.dp)
                                    ) {
                                        Text(
                                            "Latest",
                                            modifier = Modifier.padding(horizontal = 8.dp, vertical = 2.dp),
                                            style = MaterialTheme.typography.labelSmall,
                                            color = BrandGreen,
                                            fontWeight = FontWeight.Bold
                                        )
                                    }
                                }
                            }
                        }
                    }
                } else {
                    item { EmptyPlaceholder("No encounters recorded yet") }
                }

                item { Spacer(Modifier.height(80.dp)) } // FAB clearance
            }
        }
    }
}

// ── Private Composables ──

@Composable
private fun SectionHeader(
    icon: ImageVector,
    title: String,
    trailingContent: @Composable (() -> Unit)? = null
) {
    Row(
        modifier = Modifier.fillMaxWidth(),
        verticalAlignment = Alignment.CenterVertically
    ) {
        Icon(icon, null, Modifier.size(20.dp), tint = BrandGreen)
        Spacer(Modifier.width(8.dp))
        Text(
            title,
            style = MaterialTheme.typography.titleMedium,
            fontWeight = FontWeight.SemiBold,
            color = Neutral800
        )
        if (trailingContent != null) {
            Spacer(Modifier.weight(1f))
            trailingContent()
        }
    }
}

@Composable
private fun StatPill(
    icon: ImageVector,
    value: String,
    label: String,
    modifier: Modifier = Modifier
) {
    Surface(
        modifier = modifier,
        color = Color.White.copy(alpha = 0.15f),
        shape = RoundedCornerShape(10.dp)
    ) {
        Column(
            modifier = Modifier.padding(horizontal = 8.dp, vertical = 8.dp),
            horizontalAlignment = Alignment.CenterHorizontally
        ) {
            Icon(icon, null, Modifier.size(16.dp), tint = Color.White)
            Spacer(Modifier.height(4.dp))
            Text(value, fontWeight = FontWeight.Bold, style = MaterialTheme.typography.titleSmall, color = Color.White)
            Text(label, style = MaterialTheme.typography.labelSmall, color = Color.White.copy(alpha = 0.7f))
        }
    }
}

@Composable
private fun EmptyPlaceholder(text: String) {
    Surface(
        modifier = Modifier.fillMaxWidth(),
        shape = RoundedCornerShape(12.dp),
        border = BorderStroke(1.dp, Neutral200)
    ) {
        Text(
            text,
            modifier = Modifier.padding(16.dp),
            style = MaterialTheme.typography.bodySmall,
            color = Neutral400
        )
    }
}

// Keep internal for reuse in other screens
@Composable
internal fun SummarySection(title: String) {
    Text(title, style = MaterialTheme.typography.titleMedium, fontWeight = FontWeight.Bold)
}

@Composable
internal fun VitalTrendCard(
    title: String,
    data: List<Triple<Long, Float, Float>>, // date, primaryValue, secondaryValue
    unit: String,
    primaryLabel: String,
    secondaryLabel: String? = null,
    primaryColor: Color,
    secondaryColor: Color? = null,
    normalRange: ClosedFloatingPointRange<Float>? = null,
    dateFormat: SimpleDateFormat
) {
    val latest = data.lastOrNull()
    val latestValue = latest?.second
    val isNormal = normalRange == null || (latestValue != null && latestValue in normalRange)

    Card(
        Modifier.fillMaxWidth(),
        shape = RoundedCornerShape(12.dp),
        colors = CardDefaults.cardColors(containerColor = Color.White),
        border = BorderStroke(1.dp, Neutral200)
    ) {
        Column(Modifier.padding(16.dp)) {
            // Title row with value and status badge
            Row(
                Modifier.fillMaxWidth(),
                horizontalArrangement = Arrangement.SpaceBetween,
                verticalAlignment = Alignment.CenterVertically
            ) {
                Text(title, fontWeight = FontWeight.Bold, style = MaterialTheme.typography.titleSmall)
                if (latestValue != null) {
                    Row(verticalAlignment = Alignment.CenterVertically) {
                        Text(
                            "${formatVitalValue(latestValue)} $unit",
                            fontWeight = FontWeight.Bold,
                            color = if (isNormal) BrandGreen else AlertRed
                        )
                        Spacer(Modifier.width(6.dp))
                        Surface(
                            color = if (isNormal) BrandGreenSurface else AlertRedSurface,
                            shape = RoundedCornerShape(4.dp)
                        ) {
                            Text(
                                if (isNormal) "Normal" else "Abnormal",
                                modifier = Modifier.padding(horizontal = 6.dp, vertical = 2.dp),
                                style = MaterialTheme.typography.labelSmall,
                                color = if (isNormal) BrandGreen else AlertRed,
                                fontWeight = FontWeight.Medium
                            )
                        }
                    }
                }
            }

            // Chart or single-value display
            if (data.size >= 2) {
                Spacer(Modifier.height(8.dp))
                SparklineChart(
                    data = data,
                    primaryColor = primaryColor,
                    secondaryColor = secondaryColor,
                    normalRange = normalRange,
                    modifier = Modifier.fillMaxWidth().height(56.dp)
                )
                // Legend + date range
                Spacer(Modifier.height(4.dp))
                Row(
                    modifier = Modifier.fillMaxWidth(),
                    horizontalArrangement = Arrangement.SpaceBetween,
                    verticalAlignment = Alignment.CenterVertically
                ) {
                    Row(horizontalArrangement = Arrangement.spacedBy(10.dp)) {
                        LegendItem(primaryLabel, primaryColor)
                        secondaryLabel?.let { secondaryColor?.let { color -> LegendItem(it, color) } }
                    }
                    Text(
                        if (data.size >= 2) "${dateFormat.format(Date(data.first().first))} \u2013 ${dateFormat.format(Date(data.last().first))}" else "",
                        style = MaterialTheme.typography.labelSmall,
                        color = Neutral400
                    )
                }
            }
        }
    }
}

@Composable
internal fun SparklineChart(
    data: List<Triple<Long, Float, Float>>,
    primaryColor: Color,
    secondaryColor: Color?,
    normalRange: ClosedFloatingPointRange<Float>?,
    modifier: Modifier
) {
    if (data.size < 2) return

    val primaryValues = data.map { it.second }
    val secondaryValues = data.map { it.third }.filter { it > 0 }
    val allValues = primaryValues + secondaryValues
    val dataMin = allValues.min()
    val dataMax = allValues.max()
    val effectiveMin = normalRange?.start?.let { minOf(it, dataMin) } ?: dataMin
    val effectiveMax = normalRange?.endInclusive?.let { maxOf(it, dataMax) } ?: dataMax
    val span = (effectiveMax - effectiveMin).coerceAtLeast(1f)
    val padding = span * 0.1f // 10% padding instead of fixed ±5
    val minVal = effectiveMin - padding
    val maxVal = effectiveMax + padding
    val range = (maxVal - minVal).coerceAtLeast(0.1f)

    Canvas(modifier = modifier) {
        val width = size.width
        val height = size.height
        val stepX = width / (data.size - 1).coerceAtLeast(1)

        // Normal range background — subtle
        normalRange?.let { nr ->
            val topY = height - ((nr.endInclusive - minVal) / range * height)
            val bottomY = height - ((nr.start - minVal) / range * height)
            drawRect(
                color = Color(0xFF4CAF50).copy(alpha = 0.06f),
                topLeft = Offset(0f, topY),
                size = androidx.compose.ui.geometry.Size(width, bottomY - topY)
            )
        }

        // Primary line + filled area
        val primaryPath = Path()
        data.forEachIndexed { index, (_, value, _) ->
            val x = index * stepX
            val y = height - ((value - minVal) / range * height)
            if (index == 0) primaryPath.moveTo(x, y) else primaryPath.lineTo(x, y)
        }
        drawPath(primaryPath, primaryColor, style = Stroke(width = 2.5f))

        // Filled area under primary line
        val fillPath = Path().apply {
            addPath(primaryPath)
            lineTo((data.size - 1) * stepX, height)
            lineTo(0f, height)
            close()
        }
        drawPath(fillPath, primaryColor.copy(alpha = 0.05f), style = Fill)

        // Secondary line (e.g., diastolic BP)
        if (secondaryValues.isNotEmpty() && secondaryColor != null) {
            drawSparkline(data.map { it.third }, minVal, range, stepX, height, secondaryColor)
        }

        // Data points
        data.forEachIndexed { index, (_, value, _) ->
            val x = index * stepX
            val y = height - ((value - minVal) / range * height)
            drawCircle(Color.White, radius = 5f, center = Offset(x, y))
            drawCircle(primaryColor, radius = 3.5f, center = Offset(x, y))
        }
    }
}

private fun androidx.compose.ui.graphics.drawscope.DrawScope.drawSparkline(
    values: List<Float>,
    minVal: Float,
    range: Float,
    stepX: Float,
    height: Float,
    color: Color
) {
    if (values.size < 2) return

    val path = Path()
    values.forEachIndexed { index, value ->
        val x = index * stepX
        val y = height - ((value - minVal) / range * height)
        if (index == 0) path.moveTo(x, y) else path.lineTo(x, y)
    }
    drawPath(path, color, style = Stroke(width = 2.5f))
}

@Composable
internal fun LegendItem(label: String, color: Color) {
    Row(verticalAlignment = Alignment.CenterVertically) {
        Box(Modifier.size(10.dp).clip(CircleShape).background(color))
        Spacer(Modifier.width(4.dp))
        Text(label, style = MaterialTheme.typography.bodySmall, color = MaterialTheme.colorScheme.outline)
    }
}

internal fun formatVitalValue(value: Float): String {
    return if (value == value.toLong().toFloat()) value.toLong().toString() else "%.1f".format(value)
}

// ── Data Extraction Helpers ──

data class VitalHistoryPoint(
    val date: Long,
    val systolicBP: Int? = null,
    val diastolicBP: Int? = null,
    val pulse: Int? = null,
    val temperature: Float? = null,
    val weight: Float? = null,
    val oxygenSat: Int? = null
)

internal fun extractVitalHistory(encounters: List<EncounterEntity>, gson: Gson): List<VitalHistoryPoint> {
    return encounters
        .sortedBy { it.effectiveEncounterTimeMillis() ?: Long.MAX_VALUE }
        .mapNotNull { encounter ->
        try {
            val vitals = gson.fromJson(encounter.vitals, VitalSigns::class.java) ?: return@mapNotNull null
            val encounterTimeMillis = encounter.effectiveEncounterTimeMillis() ?: return@mapNotNull null
            VitalHistoryPoint(
                date = encounterTimeMillis,
                systolicBP = vitals.systolicBP,
                diastolicBP = vitals.diastolicBP,
                pulse = vitals.pulse,
                temperature = vitals.temperature,
                weight = vitals.weight,
                oxygenSat = vitals.oxygenSaturation
            )
        } catch (_: Exception) { null }
    }
}

private const val TAG = "PatientSummaryScreen"

internal fun extractDiagnosisSummary(encounters: List<EncounterEntity>): List<Pair<String, Int>> {
    val counts = mutableMapOf<String, Int>()
    val gson = Gson()
    val type = object : com.google.gson.reflect.TypeToken<List<Map<String, Any>>>() {}.type
    encounters.forEach { encounter ->
        if (encounter.diagnoses.isNotBlank() && encounter.diagnoses != "[]") {
            try {
                val diagnoses: List<Map<String, Any>> = gson.fromJson(encounter.diagnoses, type)
                diagnoses.forEach { diag ->
                    val code = diag["icd10Code"]?.toString() ?: ""
                    val desc = diag["description"]?.toString() ?: ""
                    val label = if (code.isNotBlank()) "$code \u2014 $desc" else desc
                    if (label.isNotBlank()) counts[label] = (counts[label] ?: 0) + 1
                }
            } catch (e: Exception) {
                Log.w(TAG, "Failed to parse diagnoses JSON", e)
            }
        }
    }
    return counts.entries.sortedByDescending { it.value }.map { it.key to it.value }
}

internal fun extractMedicationSummary(encounters: List<EncounterEntity>): List<Pair<String, Int>> {
    val counts = mutableMapOf<String, Int>()
    val gson = Gson()
    val type = object : com.google.gson.reflect.TypeToken<List<Map<String, Any>>>() {}.type
    encounters.forEach { encounter ->
        if (encounter.medications.isNotBlank() && encounter.medications != "[]") {
            try {
                val meds: List<Map<String, Any>> = gson.fromJson(encounter.medications, type)
                meds.forEach { med ->
                    val name = med["name"]?.toString() ?: ""
                    if (name.isNotBlank()) counts[name] = (counts[name] ?: 0) + 1
                }
            } catch (e: Exception) {
                Log.w(TAG, "Failed to parse medications JSON", e)
            }
        }
    }
    return counts.entries.sortedByDescending { it.value }.map { it.key to it.value }
}

internal fun extractAllergies(encounters: List<EncounterEntity>, patient: PatientEntity, gson: Gson): List<String> {
    val allergies = mutableSetOf<String>()

    // Include patient-level allergies (clinical safety — these are the authoritative source)
    if (patient.allergies.isNotBlank() && patient.allergies != "[]") {
        try {
            val type = object : com.google.gson.reflect.TypeToken<List<String>>() {}.type
            val list: List<String> = gson.fromJson(patient.allergies, type)
            allergies.addAll(list.filter { it.isNotBlank() })
        } catch (e: Exception) {
            Log.w(TAG, "Failed to parse patient allergies JSON", e)
        }
    }

    // Also include encounter-level allergies (may capture additional ones)
    val allergyType = object : com.google.gson.reflect.TypeToken<List<String>>() {}.type
    encounters.forEach { encounter ->
        if (encounter.allergies.isNotBlank() && encounter.allergies != "[]") {
            try {
                val list: List<String> = gson.fromJson(encounter.allergies, allergyType)
                allergies.addAll(list.filter { it.isNotBlank() })
            } catch (e: Exception) {
                Log.w(TAG, "Failed to parse encounter allergies JSON", e)
            }
        }
    }
    return allergies.toList().sorted()
}
