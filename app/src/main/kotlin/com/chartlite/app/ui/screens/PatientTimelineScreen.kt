package com.chartlite.app.ui.screens

import androidx.compose.foundation.background
import androidx.compose.foundation.layout.*
import androidx.compose.foundation.lazy.LazyColumn
import androidx.compose.foundation.lazy.items
import androidx.compose.foundation.shape.CircleShape
import androidx.compose.foundation.shape.RoundedCornerShape
import androidx.compose.foundation.text.KeyboardOptions
import androidx.compose.material.icons.Icons
import androidx.compose.material.icons.automirrored.filled.ArrowBack
import androidx.compose.material.icons.filled.*
import androidx.compose.material3.*
import androidx.compose.runtime.*
import androidx.compose.ui.Alignment
import androidx.compose.ui.Modifier
import androidx.compose.ui.draw.clip
import androidx.compose.ui.graphics.Color
import androidx.compose.ui.platform.LocalContext
import androidx.compose.ui.text.font.FontWeight
import androidx.compose.ui.text.input.KeyboardType
import androidx.compose.ui.text.input.PasswordVisualTransformation
import androidx.compose.ui.text.style.TextOverflow
import androidx.compose.ui.unit.dp
import com.chartlite.app.App
import com.chartlite.app.database.entity.EncounterEntity
import com.chartlite.app.database.entity.ImmunizationEntity
import com.chartlite.app.database.entity.PatientEntity
import com.chartlite.app.database.entity.ReferralEntity
import com.chartlite.app.database.entity.effectiveEncounterTimeMillis
import com.chartlite.app.database.entity.normalizedReferralOrNull
import com.chartlite.app.model.CDSSAlert
import com.chartlite.app.model.Diagnosis
import com.chartlite.app.model.Medication
import com.chartlite.app.model.VitalSigns
import com.chartlite.app.ui.theme.*
import com.google.gson.Gson
import com.google.gson.reflect.TypeToken
import kotlinx.coroutines.Dispatchers
import kotlinx.coroutines.async
import kotlinx.coroutines.coroutineScope
import kotlinx.coroutines.launch
import java.time.Instant
import java.time.ZoneId
import java.time.format.DateTimeFormatter
import java.time.temporal.ChronoUnit
import androidx.compose.ui.res.stringResource
import com.chartlite.app.R
import java.text.SimpleDateFormat
import java.util.Date
import java.util.Locale

@OptIn(ExperimentalMaterial3Api::class)
@Composable
fun PatientTimelineScreen(
    patientId: String,
    onNewEncounter: () -> Unit,
    onCheckIn: ((String) -> Unit)? = null,
    onEncounterSelected: (String) -> Unit,
    onViewSMSHistory: (() -> Unit)? = null,
    onBack: () -> Unit
) {
    val context = LocalContext.current
    val app = context.applicationContext as App
    val gson = remember { Gson() }
    val dateFormat = remember { SimpleDateFormat("dd MMM yyyy", Locale.getDefault()) }

    val scope = rememberCoroutineScope()
    var patient by remember { mutableStateOf<PatientEntity?>(null) }
    var encounters by remember { mutableStateOf<List<EncounterEntity>>(emptyList()) }
    var referrals by remember { mutableStateOf<List<ReferralEntity>>(emptyList()) }
    var immunizations by remember { mutableStateOf<List<ImmunizationEntity>>(emptyList()) }
    var isLoading by remember { mutableStateOf(true) }
    var alreadyCheckedIn by remember { mutableStateOf(false) }
    var showPinDialog by remember { mutableStateOf(false) }
    var showEditPatientSheet by remember { mutableStateOf(false) }

    LaunchedEffect(patientId) {
        // Run all DB queries in parallel — saves 50-200ms on Galaxy A03 vs sequential
        coroutineScope {
            val patientDef = async(Dispatchers.IO) { app.patientRepository.getById(patientId) }
            val encountersDef = async(Dispatchers.IO) { app.encounterRepository.getByPatientId(patientId) }
            val referralsDef = async(Dispatchers.IO) {
                try { app.referralRepository.getByPatient(patientId) } catch (_: Exception) { emptyList() }
            }
            val immunizationsDef = async(Dispatchers.IO) {
                try { app.immunizationRepository.getByPatient(patientId) } catch (_: Exception) { emptyList() }
            }
            val checkedInDef = if (onCheckIn != null) {
                async(Dispatchers.IO) { app.visitRepository.getTodayVisitForPatient(patientId) != null }
            } else null

            patient = patientDef.await()
            encounters = encountersDef.await()
            referrals = referralsDef.await()
            immunizations = immunizationsDef.await()
            alreadyCheckedIn = checkedInDef?.await() ?: false
        }
        isLoading = false
    }

    Scaffold(
        topBar = {
            TopAppBar(
                title = {
                    Column {
                        Text(
                            patient?.let { "${it.firstName} ${it.lastName}" } ?: stringResource(R.string.patient_id),
                            maxLines = 1,
                            overflow = TextOverflow.Ellipsis
                        )
                        Text(
                            patientId,
                            style = MaterialTheme.typography.labelMedium,
                            color = MaterialTheme.colorScheme.onSurfaceVariant
                        )
                    }
                },
                navigationIcon = {
                    IconButton(onClick = onBack) {
                        Icon(Icons.AutoMirrored.Filled.ArrowBack, contentDescription = stringResource(R.string.back))
                    }
                },
                actions = {
                    // Edit patient button
                    IconButton(onClick = { showEditPatientSheet = true }) {
                        Icon(Icons.Default.Edit, contentDescription = stringResource(R.string.edit))
                    }
                }
            )
        },
        floatingActionButton = {
            if (onCheckIn != null) {
                ExtendedFloatingActionButton(
                    onClick = { if (!alreadyCheckedIn) onCheckIn(patientId) },
                    icon = { Icon(
                        if (alreadyCheckedIn) Icons.Default.CheckCircle else Icons.Default.PersonAdd,
                        contentDescription = if (alreadyCheckedIn) stringResource(R.string.already_checked_in) else stringResource(R.string.check_in)
                    ) },
                    text = { Text(if (alreadyCheckedIn) stringResource(R.string.already_checked_in) else stringResource(R.string.check_in)) },
                    containerColor = if (alreadyCheckedIn)
                        MaterialTheme.colorScheme.surfaceVariant
                    else
                        MaterialTheme.colorScheme.primaryContainer
                )
            } else {
                ExtendedFloatingActionButton(
                    onClick = onNewEncounter,
                    icon = { Icon(Icons.Default.Add, contentDescription = stringResource(R.string.new_encounter)) },
                    text = { Text(stringResource(R.string.new_encounter)) }
                )
            }
        }
    ) { padding ->
        if (isLoading) {
            Box(Modifier.fillMaxSize().padding(padding), contentAlignment = Alignment.Center) {
                CircularProgressIndicator()
            }
            return@Scaffold
        }

        // Derived data from encounters
        val diagnosisSummary = remember(encounters) { extractDiagnosisSummary(encounters) }
        val medicationSummary = remember(encounters) { extractMedicationSummary(encounters) }
        val allergies = remember(encounters, patient) {
            patient?.let { extractAllergies(encounters, it, gson) } ?: emptyList()
        }
        val vitalHistory = remember(encounters) { extractVitalHistory(encounters, gson) }

        // Follow-up schedule: compute future follow-up dates from encounters
        val upcomingFollowUps = remember(encounters) {
            val now = System.currentTimeMillis()
            encounters
                .filter { it.followUpDays != null && it.followUpDays!! > 0 }
                .mapNotNull { enc ->
                    val encTime = enc.effectiveEncounterTimeMillis() ?: return@mapNotNull null
                    val dueMs = encTime + (enc.followUpDays!! * 86_400_000L)
                    Triple(enc.followUpReason ?: "Follow-up", dueMs, encTime)
                }
                .sortedBy { it.second }
                .take(5)
        }

        // CDSS alerts from latest encounter
        val latestCdssAlerts = remember(encounters) {
            encounters.firstOrNull()?.cdssAlerts?.let { json ->
                try {
                    gson.fromJson<List<CDSSAlert>>(json, object : TypeToken<List<CDSSAlert>>() {}.type)
                        ?.filter { !(encounters.firstOrNull()?.cdssAcknowledged ?: false) }
                } catch (_: Exception) { null }
            } ?: emptyList()
        }

        // Split diagnoses into chronic (≥2 encounters) and acute
        val (chronicDx, acuteDx) = remember(diagnosisSummary) {
            val chronic = diagnosisSummary.filter { it.second >= 2 }
            val acute = diagnosisSummary.filter { it.second < 2 }
            chronic to acute
        }

        LazyColumn(
            modifier = Modifier
                .fillMaxSize()
                .padding(padding)
                .padding(horizontal = 16.dp),
            verticalArrangement = Arrangement.spacedBy(12.dp),
            contentPadding = PaddingValues(vertical = 12.dp)
        ) {
            // ── Patient Info Card — clean white card ──
            patient?.let { p ->
                item(key = "patient_info") {
                    Card(
                        modifier = Modifier.fillMaxWidth(),
                        shape = RoundedCornerShape(16.dp),
                        colors = CardDefaults.cardColors(containerColor = MaterialTheme.colorScheme.surface),
                        elevation = CardDefaults.cardElevation(defaultElevation = 1.dp)
                    ) {
                        Column(modifier = Modifier.padding(16.dp)) {
                            Row(verticalAlignment = Alignment.CenterVertically) {
                                // Avatar
                                Box(
                                    modifier = Modifier
                                        .size(52.dp)
                                        .clip(CircleShape)
                                        .background(BrandGreen),
                                    contentAlignment = Alignment.Center
                                ) {
                                    Text(
                                        p.firstName.firstOrNull()?.uppercase() ?: "?",
                                        color = Color.White,
                                        fontWeight = FontWeight.Bold,
                                        style = MaterialTheme.typography.headlineSmall
                                    )
                                }
                                Spacer(Modifier.width(14.dp))
                                Column(modifier = Modifier.weight(1f)) {
                                    Text(
                                        "${p.firstName} ${p.lastName}",
                                        fontWeight = FontWeight.Bold,
                                        style = MaterialTheme.typography.titleLarge
                                    )
                                    Row(
                                        horizontalArrangement = Arrangement.spacedBy(12.dp),
                                        verticalAlignment = Alignment.CenterVertically
                                    ) {
                                        val ageText = "${p.ageYears ?: "?"}y"
                                        val sexText = p.gender.replaceFirstChar { it.uppercase() }
                                        Text(
                                            "$ageText · $sexText",
                                            style = MaterialTheme.typography.bodyMedium,
                                            color = Neutral600
                                        )
                                    }
                                    // ID with copy hint
                                    Text(
                                        "ID: ${p.id}",
                                        style = MaterialTheme.typography.bodySmall,
                                        color = Neutral500
                                    )
                                }
                            }

                            Spacer(Modifier.height(12.dp))

                            // Stats row
                            Row(
                                modifier = Modifier.fillMaxWidth(),
                                horizontalArrangement = Arrangement.SpaceEvenly
                            ) {
                                val registeredDateLabel = remember(p.createdAt) {
                                    p.createdAt.takeIf { it > 0L }?.let { dateFormat.format(Date(it)) } ?: "—"
                                }
                                QuickStat(value = "${encounters.size}", label = stringResource(R.string.visits_label))
                                QuickStat(value = "${diagnosisSummary.size}", label = stringResource(R.string.conditions_label))
                                QuickStat(value = "${medicationSummary.size}", label = stringResource(R.string.active_meds_label))
                                QuickStat(value = registeredDateLabel, label = stringResource(R.string.registered))
                            }

                            // Phone + PIN row
                            if (!p.phoneNumber.isNullOrBlank()) {
                                Spacer(Modifier.height(10.dp))
                                HorizontalDivider(color = Neutral200)
                                Spacer(Modifier.height(8.dp))
                                Row(verticalAlignment = Alignment.CenterVertically) {
                                    Icon(Icons.Default.Phone, null, Modifier.size(16.dp), tint = Neutral500)
                                    Spacer(Modifier.width(6.dp))
                                    Text(
                                        p.phoneNumber!!,
                                        style = MaterialTheme.typography.bodyMedium,
                                        modifier = Modifier.weight(1f)
                                    )
                                    TextButton(
                                        onClick = { showPinDialog = true },
                                        contentPadding = PaddingValues(horizontal = 8.dp, vertical = 0.dp)
                                    ) {
                                        Icon(Icons.Default.Lock, null, Modifier.size(14.dp))
                                        Spacer(Modifier.width(4.dp))
                                        Text(
                                            if (p.pin.isNullOrBlank()) stringResource(R.string.set_sms_pin)
                                            else stringResource(R.string.change_sms_pin),
                                            style = MaterialTheme.typography.labelSmall
                                        )
                                    }
                                }
                            }
                        }
                    }
                }

                // ── Allergy Banner ──
                if (allergies.isNotEmpty()) {
                    item(key = "allergy_banner") {
                        Card(
                            modifier = Modifier.fillMaxWidth(),
                            shape = RoundedCornerShape(12.dp),
                            colors = CardDefaults.cardColors(
                                containerColor = MaterialTheme.colorScheme.errorContainer
                            )
                        ) {
                            Row(
                                modifier = Modifier.padding(12.dp),
                                verticalAlignment = Alignment.CenterVertically,
                                horizontalArrangement = Arrangement.spacedBy(8.dp)
                            ) {
                                Icon(
                                    Icons.Default.Warning,
                                    contentDescription = stringResource(R.string.known_allergies_label),
                                    tint = MaterialTheme.colorScheme.error,
                                    modifier = Modifier.size(20.dp)
                                )
                                Text(
                                    stringResource(R.string.allergies_format, allergies.joinToString(", ")),
                                    style = MaterialTheme.typography.titleSmall,
                                    fontWeight = FontWeight.Bold,
                                    color = MaterialTheme.colorScheme.onErrorContainer
                                )
                            }
                        }
                    }
                }

                // ── Quick Action Chips ──
                item(key = "quick_actions") {
                    Row(
                        modifier = Modifier.fillMaxWidth(),
                        horizontalArrangement = Arrangement.spacedBy(8.dp)
                    ) {
                        if (onViewSMSHistory != null) {
                            AssistChip(
                                onClick = onViewSMSHistory,
                                label = { Text(stringResource(R.string.sms_history)) },
                                leadingIcon = { Icon(Icons.Default.Sms, null, Modifier.size(16.dp)) }
                            )
                        }
                        if (!p.phoneNumber.isNullOrBlank()) {
                            AssistChip(
                                onClick = { showPinDialog = true },
                                label = {
                                    Text(
                                        if (p.pin.isNullOrBlank()) stringResource(R.string.set_sms_pin)
                                        else stringResource(R.string.change_sms_pin)
                                    )
                                },
                                leadingIcon = { Icon(Icons.Default.Lock, null, Modifier.size(16.dp)) }
                            )
                        }
                    }
                }
            }

            // ── Upcoming Follow-ups ──
            if (upcomingFollowUps.isNotEmpty()) {
                item(key = "followup_section") {
                    SummarySection(stringResource(R.string.upcoming_follow_ups))
                }
                item(key = "followup_card") {
                    val now = System.currentTimeMillis()
                    Card(
                        Modifier.fillMaxWidth(),
                        shape = RoundedCornerShape(12.dp),
                        elevation = CardDefaults.cardElevation(defaultElevation = 0.5.dp)
                    ) {
                        Column(Modifier.padding(16.dp)) {
                            upcomingFollowUps.forEach { (reason, dueMs, visitMs) ->
                                val overdue = dueMs < now
                                val dueStr = dateFormat.format(Date(dueMs))
                                val visitStr = dateFormat.format(Date(visitMs))
                                Row(
                                    Modifier.fillMaxWidth().padding(vertical = 4.dp),
                                    verticalAlignment = Alignment.CenterVertically
                                ) {
                                    Icon(
                                        Icons.Default.Event,
                                        contentDescription = null,
                                        tint = if (overdue) AlertRed else BrandGreen,
                                        modifier = Modifier.size(18.dp)
                                    )
                                    Spacer(Modifier.width(8.dp))
                                    Column(Modifier.weight(1f)) {
                                        Text(
                                            reason,
                                            style = MaterialTheme.typography.bodyMedium,
                                            fontWeight = FontWeight.Medium
                                        )
                                        Text(
                                            stringResource(R.string.from_visit_format, visitStr),
                                            style = MaterialTheme.typography.labelSmall,
                                            color = Neutral500
                                        )
                                    }
                                    if (overdue) {
                                        Surface(
                                            color = AlertRed.copy(alpha = 0.12f),
                                            shape = RoundedCornerShape(4.dp)
                                        ) {
                                            Text(
                                                stringResource(R.string.follow_up_overdue),
                                                modifier = Modifier.padding(horizontal = 6.dp, vertical = 2.dp),
                                                style = MaterialTheme.typography.labelSmall,
                                                fontWeight = FontWeight.Bold,
                                                color = AlertRed
                                            )
                                        }
                                    } else {
                                        Text(
                                            dueStr,
                                            style = MaterialTheme.typography.labelMedium,
                                            color = BrandGreen
                                        )
                                    }
                                }
                            }
                        }
                    }
                }
            }

            // ── CDSS Clinical Alerts ──
            if (latestCdssAlerts.isNotEmpty()) {
                item(key = "cdss_alerts") {
                    SummarySection(stringResource(R.string.clinical_alerts))
                }
                item(key = "cdss_alerts_card") {
                    Card(
                        Modifier.fillMaxWidth(),
                        shape = RoundedCornerShape(12.dp),
                        colors = CardDefaults.cardColors(
                            containerColor = WarningAmber.copy(alpha = 0.08f)
                        )
                    ) {
                        Column(Modifier.padding(16.dp)) {
                            latestCdssAlerts.forEach { alert ->
                                Row(
                                    Modifier.fillMaxWidth().padding(vertical = 3.dp),
                                    verticalAlignment = Alignment.CenterVertically
                                ) {
                                    Icon(
                                        Icons.Default.Warning,
                                        contentDescription = null,
                                        tint = when (alert.severity.name) {
                                            "HIGH" -> AlertRed
                                            "MEDIUM" -> WarningAmber
                                            else -> InfoBlue
                                        },
                                        modifier = Modifier.size(16.dp)
                                    )
                                    Spacer(Modifier.width(8.dp))
                                    Column(Modifier.weight(1f)) {
                                        Text(
                                            alert.message,
                                            style = MaterialTheme.typography.bodySmall,
                                            fontWeight = FontWeight.Medium
                                        )
                                        Text(
                                            alert.category,
                                            style = MaterialTheme.typography.labelSmall,
                                            color = Neutral500
                                        )
                                    }
                                }
                            }
                        }
                    }
                }
            }

            // ── Latest Vitals (compact chips) ──
            if (vitalHistory.isNotEmpty()) {
                item(key = "vitals_section") {
                    SummarySection(stringResource(R.string.vital_signs_trend))
                }

                // Show sparkline trends if enough data, otherwise compact chips
                val bpData = vitalHistory.filter { it.systolicBP != null && it.diastolicBP != null }
                if (bpData.size >= 2) {
                    item(key = "vital_bp") {
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

                val hrData = vitalHistory.filter { it.pulse != null }
                if (hrData.size >= 2) {
                    item(key = "vital_hr") {
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

                val tempData = vitalHistory.filter { it.temperature != null }
                if (tempData.size >= 2) {
                    item(key = "vital_temp") {
                        VitalTrendCard(
                            title = stringResource(R.string.temperature),
                            data = tempData.map { Triple(it.date, it.temperature ?: 0f, 0f) },
                            unit = "\u00b0C",
                            primaryLabel = "Temp",
                            primaryColor = Color(0xFFFF9800),
                            normalRange = 36.1f..37.2f,
                            dateFormat = dateFormat
                        )
                    }
                }

                val weightData = vitalHistory.filter { it.weight != null }
                if (weightData.size >= 2) {
                    item(key = "vital_weight") {
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

                val spo2Data = vitalHistory.filter { it.oxygenSat != null }
                if (spo2Data.size >= 2) {
                    item(key = "vital_spo2") {
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

                // Single-point vitals as compact chips
                if (vitalHistory.size == 1) {
                    item(key = "vital_chips") {
                        val v = vitalHistory.first()
                        Row(
                            modifier = Modifier.fillMaxWidth(),
                            horizontalArrangement = Arrangement.spacedBy(8.dp)
                        ) {
                            v.systolicBP?.let { sys ->
                                VitalChip("BP", "${sys}/${v.diastolicBP ?: "-"}",
                                    if (sys > 140) AlertRed else BrandGreen, Modifier.weight(1f))
                            }
                            v.pulse?.let { hr ->
                                VitalChip("HR", "$hr",
                                    if (hr > 100) WarningAmber else BrandGreen, Modifier.weight(1f))
                            }
                            v.temperature?.let { temp ->
                                VitalChip("Temp", "${"%.1f".format(temp)}\u00b0",
                                    if (temp > 38.0) AlertRed else BrandGreen, Modifier.weight(1f))
                            }
                            v.oxygenSat?.let { spo2 ->
                                VitalChip("SpO2", "$spo2%",
                                    if (spo2 < 95) AlertRed else BrandGreen, Modifier.weight(1f))
                            }
                        }
                    }
                }
            }

            // ── Problem List (chronic + acute) ──
            if (diagnosisSummary.isNotEmpty()) {
                item(key = "conditions_header") {
                    SummarySection(stringResource(R.string.problem_list))
                }
                item(key = "conditions_card") {
                    Card(
                        Modifier.fillMaxWidth(),
                        shape = RoundedCornerShape(12.dp),
                        elevation = CardDefaults.cardElevation(defaultElevation = 0.5.dp)
                    ) {
                        Column(Modifier.padding(16.dp)) {
                            // Chronic conditions first (≥2 encounters)
                            chronicDx.take(8).forEach { (diagnosis, count) ->
                                Row(
                                    Modifier.fillMaxWidth().padding(vertical = 3.dp),
                                    horizontalArrangement = Arrangement.SpaceBetween,
                                    verticalAlignment = Alignment.CenterVertically
                                ) {
                                    Text(diagnosis,
                                        style = MaterialTheme.typography.bodyMedium,
                                        fontWeight = FontWeight.Medium,
                                        modifier = Modifier.weight(1f))
                                    Row(horizontalArrangement = Arrangement.spacedBy(4.dp)) {
                                        Surface(
                                            color = AlertRed.copy(alpha = 0.1f),
                                            shape = RoundedCornerShape(4.dp)
                                        ) {
                                            Text(
                                                stringResource(R.string.chronic),
                                                modifier = Modifier.padding(horizontal = 5.dp, vertical = 1.dp),
                                                style = MaterialTheme.typography.labelSmall,
                                                color = AlertRed
                                            )
                                        }
                                        Badge { Text("$count") }
                                    }
                                }
                            }
                            // Acute / recent diagnoses
                            if (chronicDx.isNotEmpty() && acuteDx.isNotEmpty()) {
                                HorizontalDivider(
                                    modifier = Modifier.padding(vertical = 6.dp),
                                    color = Neutral200
                                )
                            }
                            acuteDx.take(6).forEach { (diagnosis, count) ->
                                Row(
                                    Modifier.fillMaxWidth().padding(vertical = 3.dp),
                                    horizontalArrangement = Arrangement.SpaceBetween,
                                    verticalAlignment = Alignment.CenterVertically
                                ) {
                                    Text(diagnosis,
                                        style = MaterialTheme.typography.bodyMedium,
                                        modifier = Modifier.weight(1f))
                                    Badge(containerColor = Neutral200) { Text("$count") }
                                }
                            }
                        }
                    }
                }
            }

            // ── Current Medications (only if non-empty) ──
            if (medicationSummary.isNotEmpty()) {
                item(key = "medications_header") {
                    SummarySection(stringResource(R.string.recent_medications))
                }
                item(key = "medications_card") {
                    Card(
                        Modifier.fillMaxWidth(),
                        shape = RoundedCornerShape(12.dp),
                        elevation = CardDefaults.cardElevation(defaultElevation = 0.5.dp)
                    ) {
                        Column(Modifier.padding(16.dp)) {
                            medicationSummary.take(8).forEach { (medication, count) ->
                                Row(
                                    Modifier.fillMaxWidth().padding(vertical = 3.dp),
                                    horizontalArrangement = Arrangement.SpaceBetween
                                ) {
                                    Text(medication,
                                        style = MaterialTheme.typography.bodyMedium,
                                        modifier = Modifier.weight(1f))
                                    Text("\u00d7$count",
                                        style = MaterialTheme.typography.bodySmall,
                                        color = Neutral500)
                                }
                            }
                        }
                    }
                }
            }

            // ── Immunization Summary ──
            if (immunizations.isNotEmpty()) {
                item(key = "immunizations_header") {
                    SummarySection(stringResource(R.string.immunizations))
                }
                item(key = "immunizations_card") {
                    val grouped = remember(immunizations) {
                        immunizations
                            .sortedByDescending { it.administeredAt }
                            .groupBy { it.vaccineCode.uppercase() }
                            .entries.toList()
                            .take(10)
                    }
                    Card(
                        Modifier.fillMaxWidth(),
                        shape = RoundedCornerShape(12.dp),
                        elevation = CardDefaults.cardElevation(defaultElevation = 0.5.dp)
                    ) {
                        Column(Modifier.padding(16.dp)) {
                            grouped.forEach { (code, records) ->
                                val latest = records.first()
                                val dateStr = dateFormat.format(Date(latest.administeredAt))
                                val overdue = latest.nextDoseDueDate?.let { it < System.currentTimeMillis() } ?: false
                                Row(
                                    Modifier.fillMaxWidth().padding(vertical = 3.dp),
                                    horizontalArrangement = Arrangement.SpaceBetween,
                                    verticalAlignment = Alignment.CenterVertically
                                ) {
                                    Column(Modifier.weight(1f)) {
                                        Text(
                                            latest.vaccineName.ifBlank { code },
                                            style = MaterialTheme.typography.bodyMedium
                                        )
                                        Text(
                                            "${stringResource(R.string.dose_format, latest.doseNumber)} · $dateStr",
                                            style = MaterialTheme.typography.labelSmall,
                                            color = Neutral500
                                        )
                                    }
                                    if (overdue) {
                                        Surface(
                                            color = AlertRed.copy(alpha = 0.12f),
                                            shape = RoundedCornerShape(4.dp)
                                        ) {
                                            Text(
                                                stringResource(R.string.overdue),
                                                modifier = Modifier.padding(horizontal = 5.dp, vertical = 1.dp),
                                                style = MaterialTheme.typography.labelSmall,
                                                fontWeight = FontWeight.Bold,
                                                color = AlertRed
                                            )
                                        }
                                    }
                                }
                            }
                        }
                    }
                }
            }

            // ── Referral History ──
            if (referrals.isNotEmpty()) {
                item(key = "referrals_header") {
                    SummarySection(stringResource(R.string.referral_history))
                }
                item(key = "referrals_card") {
                    Card(
                        Modifier.fillMaxWidth(),
                        shape = RoundedCornerShape(12.dp),
                        elevation = CardDefaults.cardElevation(defaultElevation = 0.5.dp)
                    ) {
                        Column(Modifier.padding(16.dp)) {
                            referrals.sortedByDescending { it.referredAt }.take(5).forEach { ref ->
                                val dateStr = dateFormat.format(Date(ref.referredAt))
                                val urgencyColor = when (ref.urgency.uppercase()) {
                                    "EMERGENCY" -> AlertRed
                                    "URGENT" -> WarningAmber
                                    else -> BrandGreen
                                }
                                Row(
                                    Modifier.fillMaxWidth().padding(vertical = 4.dp),
                                    verticalAlignment = Alignment.CenterVertically
                                ) {
                                    Surface(
                                        color = urgencyColor.copy(alpha = 0.12f),
                                        shape = RoundedCornerShape(4.dp)
                                    ) {
                                        Text(
                                            ref.urgency.uppercase().take(6),
                                            modifier = Modifier.padding(horizontal = 5.dp, vertical = 2.dp),
                                            style = MaterialTheme.typography.labelSmall,
                                            fontWeight = FontWeight.Bold,
                                            color = urgencyColor
                                        )
                                    }
                                    Spacer(Modifier.width(8.dp))
                                    Column(Modifier.weight(1f)) {
                                        Text(
                                            ref.toFacility,
                                            style = MaterialTheme.typography.bodyMedium,
                                            fontWeight = FontWeight.Medium,
                                            maxLines = 1,
                                            overflow = TextOverflow.Ellipsis
                                        )
                                        Text(
                                            ref.reason,
                                            style = MaterialTheme.typography.bodySmall,
                                            color = Neutral600,
                                            maxLines = 1,
                                            overflow = TextOverflow.Ellipsis
                                        )
                                    }
                                    Text(
                                        dateStr,
                                        style = MaterialTheme.typography.labelSmall,
                                        color = Neutral500
                                    )
                                }
                            }
                        }
                    }
                }
            }

            // ── Encounters List ──
            item(key = "encounters_header") {
                Text(
                    stringResource(R.string.encounters_count_format, encounters.size),
                    style = MaterialTheme.typography.titleMedium,
                    fontWeight = FontWeight.Bold,
                    modifier = Modifier.padding(top = 4.dp)
                )
            }

            if (encounters.isEmpty()) {
                item(key = "empty_state") {
                    Card(
                        Modifier.fillMaxWidth(),
                        shape = RoundedCornerShape(12.dp),
                        colors = CardDefaults.cardColors(containerColor = Neutral50)
                    ) {
                        Column(
                            modifier = Modifier.fillMaxWidth().padding(32.dp),
                            horizontalAlignment = Alignment.CenterHorizontally
                        ) {
                            Icon(
                                Icons.Default.Description,
                                contentDescription = null,
                                modifier = Modifier.size(48.dp),
                                tint = Neutral400
                            )
                            Spacer(Modifier.height(12.dp))
                            Text(
                                stringResource(R.string.no_encounters_recorded_yet),
                                style = MaterialTheme.typography.bodyMedium,
                                color = Neutral500
                            )
                            Spacer(Modifier.height(8.dp))
                            Text(
                                stringResource(R.string.tap_new_encounter_hint),
                                style = MaterialTheme.typography.bodySmall,
                                color = Neutral400
                            )
                        }
                    }
                }
            }

            items(encounters, key = { it.id }) { encounter ->
                EncounterTimelineCard(
                    encounter = encounter,
                    gson = gson,
                    isFirst = encounter == encounters.firstOrNull(),
                    isLast = encounter == encounters.lastOrNull(),
                    onClick = { onEncounterSelected(encounter.id) }
                )
            }

            // Bottom spacing for FAB
            item(key = "bottom_spacer") { Spacer(Modifier.height(80.dp)) }
        }
    }

    // ── SMS PIN Dialog ──
    if (showPinDialog) {
        val p = patient
        if (p != null && !p.phoneNumber.isNullOrBlank()) {
            SmsPinDialog(
                hasExistingPin = !p.pin.isNullOrBlank(),
                onDismiss = { showPinDialog = false },
                onSave = { newPin ->
                    scope.launch {
                        val updated = p.copy(pin = newPin.takeIf { it.isNotBlank() })
                        app.patientRepository.update(updated)
                        patient = updated
                        showPinDialog = false
                    }
                },
                onRemove = if (!p.pin.isNullOrBlank()) {
                    {
                        scope.launch {
                            val updated = p.copy(pin = null)
                            app.patientRepository.update(updated)
                            patient = updated
                            showPinDialog = false
                        }
                    }
                } else null
            )
        }
    }

    // ── Edit Patient Bottom Sheet ──
    if (showEditPatientSheet) {
        patient?.let { p ->
            EditPatientSheet(
                patient = p,
                onDismiss = { showEditPatientSheet = false },
                onSave = { updated ->
                    scope.launch {
                        app.patientRepository.update(updated)
                        patient = updated
                        showEditPatientSheet = false
                    }
                }
            )
        }
    }
}

/**
 * Bottom sheet for editing basic patient info including PIN.
 */
@OptIn(ExperimentalMaterial3Api::class)
@Composable
private fun EditPatientSheet(
    patient: PatientEntity,
    onDismiss: () -> Unit,
    onSave: (PatientEntity) -> Unit
) {
    var firstName by remember { mutableStateOf(patient.firstName) }
    var lastName by remember { mutableStateOf(patient.lastName) }
    var phoneNumber by remember { mutableStateOf(patient.phoneNumber ?: "") }
    var pin by remember { mutableStateOf(patient.pin ?: "") }
    var ageYears by remember { mutableStateOf(patient.ageYears?.toString() ?: "") }

    ModalBottomSheet(onDismissRequest = onDismiss) {
        Column(
            modifier = Modifier
                .fillMaxWidth()
                .padding(horizontal = 24.dp)
                .padding(bottom = 32.dp),
            verticalArrangement = Arrangement.spacedBy(12.dp)
        ) {
            Text(
                stringResource(R.string.edit_patient),
                style = MaterialTheme.typography.titleLarge,
                fontWeight = FontWeight.Bold
            )

            OutlinedTextField(
                value = firstName,
                onValueChange = { firstName = it },
                label = { Text(stringResource(R.string.first_name)) },
                singleLine = true,
                modifier = Modifier.fillMaxWidth()
            )

            OutlinedTextField(
                value = lastName,
                onValueChange = { lastName = it },
                label = { Text(stringResource(R.string.last_name)) },
                singleLine = true,
                modifier = Modifier.fillMaxWidth()
            )

            OutlinedTextField(
                value = ageYears,
                onValueChange = { if (it.length <= 3 && it.all { c -> c.isDigit() }) ageYears = it },
                label = { Text(stringResource(R.string.age_label)) },
                keyboardOptions = KeyboardOptions(keyboardType = KeyboardType.Number),
                singleLine = true,
                modifier = Modifier.fillMaxWidth()
            )

            OutlinedTextField(
                value = phoneNumber,
                onValueChange = { phoneNumber = it },
                label = { Text(stringResource(R.string.phone_label)) },
                keyboardOptions = KeyboardOptions(keyboardType = KeyboardType.Phone),
                singleLine = true,
                modifier = Modifier.fillMaxWidth()
            )

            OutlinedTextField(
                value = pin,
                onValueChange = { if (it.length <= 4 && it.all { c -> c.isDigit() }) pin = it },
                label = { Text(stringResource(R.string.sms_pin_label)) },
                keyboardOptions = KeyboardOptions(keyboardType = KeyboardType.NumberPassword),
                visualTransformation = PasswordVisualTransformation(),
                singleLine = true,
                supportingText = { Text(stringResource(R.string.sms_pin_explanation)) },
                modifier = Modifier.fillMaxWidth()
            )

            Spacer(Modifier.height(4.dp))

            Row(
                modifier = Modifier.fillMaxWidth(),
                horizontalArrangement = Arrangement.spacedBy(12.dp)
            ) {
                OutlinedButton(
                    onClick = onDismiss,
                    modifier = Modifier.weight(1f)
                ) {
                    Text(stringResource(R.string.cancel))
                }
                Button(
                    onClick = {
                        val updated = patient.copy(
                            firstName = firstName.trim(),
                            lastName = lastName.trim(),
                            phoneNumber = phoneNumber.trim().ifBlank { null },
                            pin = pin.trim().ifBlank { null },
                            ageYears = ageYears.toIntOrNull(),
                            updatedAt = System.currentTimeMillis()
                        )
                        onSave(updated)
                    },
                    enabled = firstName.isNotBlank() && lastName.isNotBlank(),
                    modifier = Modifier.weight(1f)
                ) {
                    Text(stringResource(R.string.save))
                }
            }
        }
    }
}

/**
 * Dialog for setting, changing, or removing an SMS privacy PIN.
 */
@Composable
private fun SmsPinDialog(
    hasExistingPin: Boolean,
    onDismiss: () -> Unit,
    onSave: (String) -> Unit,
    onRemove: (() -> Unit)? = null
) {
    var pin by remember { mutableStateOf("") }
    var confirmPin by remember { mutableStateOf("") }
    var showError by remember { mutableStateOf(false) }

    AlertDialog(
        onDismissRequest = onDismiss,
        title = {
            Text(
                if (hasExistingPin) stringResource(R.string.change_sms_pin)
                else stringResource(R.string.set_sms_pin)
            )
        },
        text = {
            Column(verticalArrangement = Arrangement.spacedBy(12.dp)) {
                Text(
                    stringResource(R.string.sms_pin_explanation),
                    style = MaterialTheme.typography.bodySmall,
                    color = MaterialTheme.colorScheme.onSurfaceVariant
                )
                OutlinedTextField(
                    value = pin,
                    onValueChange = { if (it.length <= 4 && it.all { c -> c.isDigit() }) { pin = it; showError = false } },
                    label = { Text(stringResource(R.string.enter_pin)) },
                    keyboardOptions = KeyboardOptions(keyboardType = KeyboardType.NumberPassword),
                    visualTransformation = PasswordVisualTransformation(),
                    singleLine = true,
                    modifier = Modifier.fillMaxWidth()
                )
                OutlinedTextField(
                    value = confirmPin,
                    onValueChange = { if (it.length <= 4 && it.all { c -> c.isDigit() }) { confirmPin = it; showError = false } },
                    label = { Text(stringResource(R.string.confirm_pin)) },
                    keyboardOptions = KeyboardOptions(keyboardType = KeyboardType.NumberPassword),
                    visualTransformation = PasswordVisualTransformation(),
                    singleLine = true,
                    isError = showError,
                    supportingText = if (showError) {{ Text(stringResource(R.string.pins_dont_match)) }} else null,
                    modifier = Modifier.fillMaxWidth()
                )
                if (onRemove != null) {
                    TextButton(
                        onClick = onRemove,
                        colors = ButtonDefaults.textButtonColors(contentColor = MaterialTheme.colorScheme.error)
                    ) {
                        Icon(Icons.Default.DeleteForever, contentDescription = null, modifier = Modifier.size(16.dp))
                        Spacer(Modifier.width(4.dp))
                        Text(stringResource(R.string.remove_sms_pin))
                    }
                }
            }
        },
        confirmButton = {
            TextButton(
                onClick = {
                    if (pin.length == 4 && pin == confirmPin) {
                        onSave(pin)
                    } else {
                        showError = true
                    }
                },
                enabled = pin.length == 4
            ) {
                Text(stringResource(R.string.save))
            }
        },
        dismissButton = {
            TextButton(onClick = onDismiss) {
                Text(stringResource(R.string.cancel))
            }
        }
    )
}

@Composable
private fun QuickStat(value: String, label: String) {
    Column(horizontalAlignment = Alignment.CenterHorizontally) {
        Text(
            value,
            fontWeight = FontWeight.Bold,
            style = MaterialTheme.typography.titleSmall,
            color = BrandGreen
        )
        Text(
            label,
            style = MaterialTheme.typography.labelSmall,
            color = Neutral500
        )
    }
}

@Composable
private fun VitalChip(label: String, value: String, color: Color, modifier: Modifier = Modifier) {
    Surface(
        modifier = modifier,
        color = color.copy(alpha = 0.08f),
        shape = RoundedCornerShape(8.dp)
    ) {
        Column(
            modifier = Modifier.padding(horizontal = 8.dp, vertical = 6.dp),
            horizontalAlignment = Alignment.CenterHorizontally
        ) {
            Text(value,
                style = MaterialTheme.typography.labelMedium,
                fontWeight = FontWeight.Bold, color = color)
            Text(label,
                style = MaterialTheme.typography.labelSmall,
                color = Neutral500)
        }
    }
}

@Composable
private fun EncounterTimelineCard(
    encounter: EncounterEntity,
    gson: Gson,
    isFirst: Boolean,
    isLast: Boolean,
    onClick: () -> Unit
) {
    val displayTimeMillis = remember(encounter.timestamp, encounter.createdAt) {
        encounter.effectiveEncounterTimeMillis()
    }
    val dateStr = remember(displayTimeMillis) {
        displayTimeMillis?.let {
            DateTimeFormatter.ofPattern("dd MMM yyyy, HH:mm")
                .withZone(ZoneId.systemDefault())
                .format(Instant.ofEpochMilli(it))
        } ?: ""
    }
    val diagnoses: List<Diagnosis> = remember(encounter.diagnoses) {
        try {
            gson.fromJson(encounter.diagnoses,
                object : TypeToken<List<Diagnosis>>() {}.type) ?: emptyList()
        } catch (_: Exception) { emptyList() }
    }
    val medications: List<Medication> = remember(encounter.medications) {
        try {
            gson.fromJson(encounter.medications,
                object : TypeToken<List<Medication>>() {}.type) ?: emptyList()
        } catch (_: Exception) { emptyList() }
    }

    Row(modifier = Modifier.fillMaxWidth()) {
        // Timeline connector
        Column(
            horizontalAlignment = Alignment.CenterHorizontally,
            modifier = Modifier.width(24.dp)
        ) {
            if (!isFirst) {
                Box(
                    modifier = Modifier
                        .width(2.dp)
                        .height(8.dp)
                        .background(Neutral300)
                )
            } else {
                Spacer(Modifier.height(8.dp))
            }

            Box(
                modifier = Modifier
                    .size(12.dp)
                    .clip(CircleShape)
                    .background(if (isFirst) BrandGreen else Neutral400)
            )

            if (!isLast) {
                Box(
                    modifier = Modifier
                        .width(2.dp)
                        .weight(1f)
                        .background(Neutral300)
                )
            }
        }

        Spacer(Modifier.width(8.dp))

        // Encounter card
        Card(
            onClick = onClick,
            modifier = Modifier.weight(1f),
            shape = RoundedCornerShape(12.dp),
            elevation = CardDefaults.cardElevation(defaultElevation = 0.5.dp)
        ) {
            Column(modifier = Modifier.padding(12.dp)) {
                Row(
                    modifier = Modifier.fillMaxWidth(),
                    horizontalArrangement = Arrangement.SpaceBetween,
                    verticalAlignment = Alignment.CenterVertically
                ) {
                    Text(dateStr, style = MaterialTheme.typography.labelMedium,
                        color = Neutral600)

                    if (isFirst) {
                        Surface(
                            color = BrandGreenSurface,
                            shape = RoundedCornerShape(4.dp)
                        ) {
                            Text(stringResource(R.string.latest),
                                modifier = Modifier.padding(horizontal = 6.dp, vertical = 2.dp),
                                style = MaterialTheme.typography.labelSmall,
                                fontWeight = FontWeight.Bold,
                                color = BrandGreenDark)
                        }
                    }
                }

                if (diagnoses.isNotEmpty()) {
                    Spacer(Modifier.height(4.dp))
                    Text("Dx: ${diagnoses.joinToString(", ") { it.description }}",
                        style = MaterialTheme.typography.bodyMedium,
                        fontWeight = FontWeight.Medium,
                        maxLines = 2,
                        overflow = TextOverflow.Ellipsis)
                }

                if (medications.isNotEmpty()) {
                    Spacer(Modifier.height(2.dp))
                    Text("Rx: ${medications.joinToString(", ") { "${it.name} ${it.dose ?: ""}${it.unit ?: ""}" }}",
                        style = MaterialTheme.typography.bodySmall,
                        color = Neutral600,
                        maxLines = 2,
                        overflow = TextOverflow.Ellipsis)
                }

                // Status badges
                val hasBadges = encounter.smsStatus != null || encounter.normalizedReferralOrNull() != null
                if (hasBadges) {
                    Spacer(Modifier.height(6.dp))
                    Row(horizontalArrangement = Arrangement.spacedBy(8.dp)) {
                        encounter.smsStatus?.let { status ->
                            val statusColor = when (status) {
                                "SENT", "DELIVERED" -> BrandGreen
                                "FAILED" -> AlertRed
                                else -> Neutral500
                            }
                            Row(verticalAlignment = Alignment.CenterVertically) {
                                Icon(Icons.Default.Sms, contentDescription = null,
                                    tint = statusColor, modifier = Modifier.size(12.dp))
                                Spacer(Modifier.width(2.dp))
                                Text(status, style = MaterialTheme.typography.labelSmall, color = statusColor)
                            }
                        }
                        encounter.normalizedReferralOrNull()?.let {
                            Row(verticalAlignment = Alignment.CenterVertically) {
                                Icon(Icons.Default.LocalHospital, contentDescription = null,
                                    tint = InfoBlue, modifier = Modifier.size(12.dp))
                                Spacer(Modifier.width(2.dp))
                                Text(stringResource(R.string.referred), style = MaterialTheme.typography.labelSmall, color = InfoBlue)
                            }
                        }
                    }
                }
            }
        }
    }
}
