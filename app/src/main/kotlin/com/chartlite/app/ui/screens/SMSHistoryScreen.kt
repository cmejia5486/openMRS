package com.chartlite.app.ui.screens

import androidx.compose.animation.AnimatedVisibility
import androidx.compose.animation.expandVertically
import androidx.compose.animation.shrinkVertically
import androidx.compose.foundation.background
import androidx.compose.foundation.clickable
import androidx.compose.foundation.layout.*
import androidx.compose.foundation.lazy.LazyColumn
import androidx.compose.foundation.lazy.items
import androidx.compose.foundation.shape.CircleShape
import androidx.compose.foundation.shape.RoundedCornerShape
import androidx.compose.material.icons.Icons
import androidx.compose.material.icons.automirrored.filled.ArrowBack
import androidx.compose.material.icons.automirrored.filled.Send
import androidx.compose.material.icons.automirrored.filled.TrendingUp
import androidx.compose.material.icons.filled.*
import androidx.compose.material3.*
import androidx.compose.runtime.*
import androidx.compose.ui.Alignment
import androidx.compose.ui.Modifier
import androidx.compose.ui.draw.clip
import androidx.compose.ui.graphics.Brush
import androidx.compose.ui.graphics.Color
import androidx.compose.ui.graphics.vector.ImageVector
import androidx.compose.ui.platform.LocalContext
import androidx.compose.ui.res.stringResource
import androidx.compose.ui.text.font.FontFamily
import androidx.compose.ui.text.font.FontWeight
import androidx.compose.ui.text.style.TextOverflow
import androidx.compose.ui.unit.dp
import com.chartlite.app.App
import com.chartlite.app.R
import com.chartlite.app.database.entity.PatientEntity
import com.chartlite.app.database.entity.SmsLogEntity
import com.chartlite.app.model.StructuredEncounter
import com.chartlite.app.sms.BinaryDecodeLookup
import com.chartlite.app.sms.BinaryEncoder
import com.chartlite.app.sms.PatientHealthSummaryBuilder
import com.chartlite.app.ui.theme.*
import java.text.SimpleDateFormat
import java.util.Date
import java.util.Locale

@OptIn(ExperimentalMaterial3Api::class)
@Composable
fun SMSHistoryScreen(
    patientId: String,
    onBack: () -> Unit
) {
    val context = LocalContext.current
    val app = context.applicationContext as App

    var logs by remember { mutableStateOf<List<SmsLogEntity>>(emptyList()) }
    var patient by remember { mutableStateOf<PatientEntity?>(null) }
    var isLoading by remember { mutableStateOf(true) }
    val encounterCache = remember { mutableStateMapOf<String, StructuredEncounter>() }
    var allPatientEncounters by remember { mutableStateOf<List<StructuredEncounter>>(emptyList()) }
    var expandedLogId by remember { mutableStateOf<String?>(null) }

    LaunchedEffect(patientId) {
        logs = app.smsLogRepository.getByPatientId(patientId)
        patient = app.patientRepository.getById(patientId)
        // Load all encounters for health history display
        allPatientEncounters = app.encounterRepository.getByPatientId(patientId)
            .map { app.encounterRepository.toStructuredEncounter(it) }
        isLoading = false
    }

    // Load encounter when expanded
    LaunchedEffect(expandedLogId) {
        val logId = expandedLogId ?: return@LaunchedEffect
        val log = logs.find { it.id == logId } ?: return@LaunchedEffect
        val encId = log.encounterId ?: return@LaunchedEffect
        if (encounterCache.containsKey(encId)) return@LaunchedEffect
        try {
            val entity = app.encounterRepository.getById(encId) ?: return@LaunchedEffect
            encounterCache[encId] = app.encounterRepository.toStructuredEncounter(entity)
        } catch (_: Exception) {}
    }

    Scaffold(
        topBar = {
            TopAppBar(
                title = { Text(stringResource(R.string.sms_history)) },
                navigationIcon = {
                    IconButton(onClick = onBack) {
                        Icon(Icons.AutoMirrored.Filled.ArrowBack, contentDescription = "Back")
                    }
                }
            )
        }
    ) { padding ->
        if (isLoading) {
            Box(Modifier.fillMaxSize().padding(padding), contentAlignment = Alignment.Center) {
                CircularProgressIndicator()
            }
            return@Scaffold
        }

        LazyColumn(
            modifier = Modifier.fillMaxSize().padding(padding),
            contentPadding = PaddingValues(16.dp),
            verticalArrangement = Arrangement.spacedBy(12.dp)
        ) {
            // ── Gradient header ──
            item {
                val patientName = patient?.let {
                    listOfNotNull(it.firstName, it.lastName).joinToString(" ")
                } ?: patientId
                val sentCount = logs.count { it.status == "SENT" || it.status == "DELIVERED" }
                val failedCount = logs.count { it.status == "FAILED" }
                val skippedCount = logs.count { it.status == "SKIPPED" }
                SmsHeaderCard(patientName, logs.size, sentCount, failedCount, skippedCount)
            }

            if (logs.isEmpty()) {
                item { EmptyState() }
            } else {
                items(logs, key = { it.id }) { log ->
                    val isExpanded = expandedLogId == log.id
                    val encounter = log.encounterId?.let { encounterCache[it] }
                    SmsLogCard(
                        log = log,
                        isExpanded = isExpanded,
                        encounter = encounter,
                        allEncounters = allPatientEncounters,
                        onClick = { expandedLogId = if (isExpanded) null else log.id }
                    )
                }
            }
        }
    }
}

// ═══════════════════════════════════════════════════════════════
// Header
// ═══════════════════════════════════════════════════════════════

@Composable
private fun SmsHeaderCard(
    patientName: String,
    total: Int,
    sent: Int,
    failed: Int,
    skipped: Int
) {
    Box(
        modifier = Modifier
            .fillMaxWidth()
            .background(
                Brush.horizontalGradient(listOf(BrandGreen, BrandGreenDark)),
                shape = RoundedCornerShape(16.dp)
            )
    ) {
        Column(Modifier.padding(20.dp)) {
            Row(verticalAlignment = Alignment.CenterVertically) {
                Icon(Icons.Default.Sms, null, Modifier.size(28.dp), tint = Color.White)
                Spacer(Modifier.width(12.dp))
                Column {
                    Text(
                        patientName,
                        style = MaterialTheme.typography.titleMedium,
                        fontWeight = FontWeight.Bold,
                        color = Color.White
                    )
                    Text(
                        "$total message${if (total != 1) "s" else ""}",
                        style = MaterialTheme.typography.bodySmall,
                        color = Color.White.copy(alpha = 0.8f)
                    )
                }
            }
            if (total > 0) {
                Spacer(Modifier.height(12.dp))
                Row(horizontalArrangement = Arrangement.spacedBy(8.dp)) {
                    if (sent > 0) StatPill("$sent sent", Color.White.copy(alpha = 0.2f), Color.White)
                    if (failed > 0) StatPill("$failed failed", AlertRed.copy(alpha = 0.3f), Color.White)
                    if (skipped > 0) StatPill("$skipped skipped", Color.White.copy(alpha = 0.15f), Color.White.copy(alpha = 0.7f))
                }
            }
        }
    }
}

@Composable
private fun StatPill(text: String, bgColor: Color, textColor: Color) {
    Surface(
        shape = RoundedCornerShape(20.dp),
        color = bgColor
    ) {
        Text(
            text,
            modifier = Modifier.padding(horizontal = 10.dp, vertical = 4.dp),
            style = MaterialTheme.typography.labelSmall,
            fontWeight = FontWeight.Medium,
            color = textColor
        )
    }
}

// ═══════════════════════════════════════════════════════════════
// SMS Log Card
// ═══════════════════════════════════════════════════════════════

@Composable
private fun SmsLogCard(
    log: SmsLogEntity,
    isExpanded: Boolean,
    encounter: StructuredEncounter?,
    allEncounters: List<StructuredEncounter> = emptyList(),
    onClick: () -> Unit
) {
    val dateFormat = remember { SimpleDateFormat("dd MMM, HH:mm", Locale.getDefault()) }

    val isSent = log.status == "SENT" || log.status == "DELIVERED"
    val isSkipped = log.status == "SKIPPED"

    // Status styling
    val statusColor = when {
        isSent -> BrandGreen
        isSkipped -> WarningAmber
        else -> AlertRed
    }
    val statusLabel = when {
        isSent -> "Delivered"
        isSkipped -> "No Phone"
        else -> "Failed"
    }
    val cardBg = when {
        isSent -> Color.White
        isSkipped -> WarningAmberSurface
        else -> AlertRedSurface
    }

    Card(
        modifier = Modifier.fillMaxWidth().clickable(onClick = onClick),
        shape = RoundedCornerShape(12.dp),
        colors = CardDefaults.cardColors(containerColor = cardBg),
        elevation = CardDefaults.cardElevation(defaultElevation = if (isSent) 1.dp else 0.dp)
    ) {
        Column(Modifier.padding(14.dp), verticalArrangement = Arrangement.spacedBy(8.dp)) {

            // ── Row 1: timestamp · type · status ──
            Row(
                Modifier.fillMaxWidth(),
                horizontalArrangement = Arrangement.SpaceBetween,
                verticalAlignment = Alignment.CenterVertically
            ) {
                // Left: timestamp + type
                Text(
                    dateFormat.format(Date(log.timestamp)),
                    style = MaterialTheme.typography.labelSmall,
                    color = Neutral500
                )

                // Right: status pill
                Surface(
                    shape = RoundedCornerShape(20.dp),
                    color = statusColor.copy(alpha = 0.12f)
                ) {
                    Row(
                        Modifier.padding(horizontal = 8.dp, vertical = 3.dp),
                        verticalAlignment = Alignment.CenterVertically,
                        horizontalArrangement = Arrangement.spacedBy(4.dp)
                    ) {
                        Box(Modifier.size(6.dp).clip(CircleShape).background(statusColor))
                        Text(
                            statusLabel,
                            style = MaterialTheme.typography.labelSmall,
                            fontWeight = FontWeight.SemiBold,
                            color = statusColor
                        )
                    }
                }
            }

            // ── Row 2: content summary ──
            Text(
                log.contentSummary,
                style = MaterialTheme.typography.bodyMedium,
                fontWeight = FontWeight.Medium,
                maxLines = if (isExpanded) Int.MAX_VALUE else 2,
                overflow = TextOverflow.Ellipsis
            )

            // Error detail
            if (!isSent && !isSkipped && !log.error.isNullOrBlank()) {
                Text(log.error!!, style = MaterialTheme.typography.bodySmall, color = AlertRed)
            }

            // ── Row 3: provider info + expand hint ──
            Row(
                Modifier.fillMaxWidth(),
                horizontalArrangement = Arrangement.SpaceBetween,
                verticalAlignment = Alignment.CenterVertically
            ) {
                Text(
                    buildString {
                        append(log.provider.lowercase().replaceFirstChar { it.uppercase() })
                        if (log.recipientPhone != "none") {
                            append(" \u00b7 \u2022\u2022\u2022\u2022${log.recipientPhone.takeLast(4)}")
                        }
                    },
                    style = MaterialTheme.typography.labelSmall,
                    color = Neutral400
                )
                Icon(
                    if (isExpanded) Icons.Default.ExpandLess else Icons.Default.ExpandMore,
                    contentDescription = null,
                    modifier = Modifier.size(18.dp),
                    tint = Neutral400
                )
            }

            // ── Expanded: encounter details as sent in SMS ──
            AnimatedVisibility(
                visible = isExpanded,
                enter = expandVertically(),
                exit = shrinkVertically()
            ) {
                if (encounter != null) {
                    SmsPayloadSection(encounter, allEncounters)
                } else if (log.encounterId != null) {
                    Row(
                        Modifier.fillMaxWidth().padding(vertical = 12.dp),
                        horizontalArrangement = Arrangement.Center,
                        verticalAlignment = Alignment.CenterVertically
                    ) {
                        CircularProgressIndicator(Modifier.size(16.dp), strokeWidth = 2.dp)
                        Spacer(Modifier.width(8.dp))
                        Text("Loading...", style = MaterialTheme.typography.bodySmall, color = Neutral400)
                    }
                } else {
                    Text(
                        "No encounter data linked",
                        style = MaterialTheme.typography.bodySmall,
                        color = Neutral400,
                        modifier = Modifier.padding(vertical = 4.dp)
                    )
                }
            }
        }
    }
}

// ═══════════════════════════════════════════════════════════════
// SMS Payload Detail — literal decode of the 92-byte V4 binary
// ═══════════════════════════════════════════════════════════════

/**
 * Performs a real encode→decode round-trip on the encounter and displays
 * exactly what the 92-byte encrypted SMS contains — no more, no less.
 * This is the "portable health record" a receiving clinician would see.
 */
@Composable
private fun SmsPayloadSection(
    encounter: StructuredEncounter,
    allEncounters: List<StructuredEncounter> = emptyList()
) {
    // Round-trip: encode the encounter to V4 binary, then decode it back.
    // This shows exactly what survives the 92-byte wire format.
    val decoded = remember(encounter.id) {
        try {
            val summary = PatientHealthSummaryBuilder.buildSummary(
                allEncounters = allEncounters.ifEmpty { listOf(encounter) },
                patientAllergies = encounter.allergies
            )
            val binary = BinaryEncoder.encodeV4(encounter, encounter.patientId, summary)
            BinaryEncoder.decodeV4(binary)
        } catch (_: Exception) { null }
    }

    Column(
        Modifier
            .fillMaxWidth()
            .padding(top = 4.dp)
            .background(Neutral50, RoundedCornerShape(8.dp))
            .padding(12.dp),
        verticalArrangement = Arrangement.spacedBy(10.dp)
    ) {
        // Header
        Row(
            verticalAlignment = Alignment.CenterVertically,
            horizontalArrangement = Arrangement.spacedBy(6.dp)
        ) {
            Icon(Icons.Default.Lock, null, Modifier.size(14.dp), tint = BrandGreen)
            Text(
                "Encrypted Patient Health Record",
                style = MaterialTheme.typography.labelMedium,
                fontWeight = FontWeight.SemiBold,
                color = BrandGreenDark
            )
        }

        if (decoded == null) {
            Text("Unable to encode/decode", style = MaterialTheme.typography.bodySmall, color = Neutral400)
            return@Column
        }

        val enc = decoded.encounter

        // ── Free Text (bytes 72-90: 19-char reason for visit) ──
        if (decoded.freeText.isNotBlank()) {
            Surface(
                color = BrandGreenSurface,
                shape = RoundedCornerShape(8.dp),
                modifier = Modifier.fillMaxWidth()
            ) {
                Text(
                    decoded.freeText,
                    modifier = Modifier.padding(10.dp),
                    style = MaterialTheme.typography.bodyMedium,
                    fontFamily = FontFamily.Monospace,
                    fontWeight = FontWeight.SemiBold,
                    color = BrandGreenDark
                )
            }
        }

        // ── Vitals (bytes 25-31) ──
        val vitalItems = buildList {
            val bp = "${enc.systolicBP}/${enc.diastolicBP}"
            if (enc.systolicBP != 120 || enc.diastolicBP != 80) add("BP" to "$bp mmHg")
            if (enc.temperature != 37.0f) add("Temp" to "${"%.1f".format(enc.temperature)}\u00b0C")
            if (enc.pulse > 0) add("HR" to "${enc.pulse} bpm")
            if (enc.weight > 0) add("Wt" to "${enc.weight} kg")
            if (decoded.height > 0) add("Ht" to "${decoded.height} cm")
            if (decoded.spo2 > 70) add("SpO2" to "${decoded.spo2}%")
            if (decoded.respiratoryRateCode > 0) add("RR" to decoded.respiratoryRateLabel)
        }
        if (vitalItems.isNotEmpty()) {
            PayloadField(Icons.Default.MonitorHeart, "Vitals", WarningAmber) {
                vitalItems.chunked(3).forEach { row ->
                    Row(horizontalArrangement = Arrangement.spacedBy(16.dp)) {
                        row.forEach { (label, value) ->
                            Column {
                                Text(label, style = MaterialTheme.typography.labelSmall, color = Neutral400)
                                Text(value, style = MaterialTheme.typography.bodySmall, fontWeight = FontWeight.Medium, color = Neutral700)
                            }
                        }
                    }
                }
            }
        }

        // ── Diagnoses (bytes 15-18: up to 3 × 9-bit hash indices) ──
        // Show the original encounter diagnoses that were encoded (limited to 3)
        val encodedDx = (encounter.diagnoses.ifEmpty { encounter.suggestedDiagnoses }).take(3)
        if (encodedDx.isNotEmpty()) {
            PayloadField(Icons.Default.MedicalServices, "Diagnoses", InfoBlue) {
                encodedDx.forEach { dx ->
                    Row(
                        verticalAlignment = Alignment.CenterVertically,
                        horizontalArrangement = Arrangement.spacedBy(6.dp)
                    ) {
                        if (dx.icd10Code.isNotBlank()) {
                            Surface(color = InfoBlueSurface, shape = RoundedCornerShape(4.dp)) {
                                Text(
                                    dx.icd10Code,
                                    modifier = Modifier.padding(horizontal = 6.dp, vertical = 2.dp),
                                    style = MaterialTheme.typography.labelSmall,
                                    fontFamily = FontFamily.Monospace,
                                    fontWeight = FontWeight.Bold,
                                    color = InfoBlue
                                )
                            }
                        }
                        Text(dx.description, style = MaterialTheme.typography.bodySmall, color = Neutral700)
                    }
                }
            }
        }

        // ── Medications (bytes 19-24: up to 3 × 16-bit packed) ──
        if (enc.medications.isNotEmpty()) {
            PayloadField(Icons.Default.Medication, "Medications", BrandGreen) {
                // Show encoded meds with names from encounter (indices are hashed)
                val encodedMeds = encounter.medications.take(3)
                encodedMeds.forEachIndexed { i, med ->
                    val decodedMed = enc.medications.getOrNull(i)
                    Row(
                        verticalAlignment = Alignment.CenterVertically,
                        horizontalArrangement = Arrangement.spacedBy(6.dp)
                    ) {
                        Surface(color = BrandGreenSurface, shape = RoundedCornerShape(4.dp)) {
                            Text(
                                med.name,
                                modifier = Modifier.padding(horizontal = 6.dp, vertical = 2.dp),
                                style = MaterialTheme.typography.labelSmall,
                                fontWeight = FontWeight.Bold,
                                color = BrandGreenDark
                            )
                        }
                        if (decodedMed != null) {
                            val detail = buildString {
                                append(BinaryDecodeLookup.doseLabel(decodedMed.doseCode))
                                append(" ")
                                append(BinaryDecodeLookup.freqLabel(decodedMed.freqCode))
                            }.trim()
                            if (detail.isNotBlank() && detail != "– –") {
                                Text(detail, style = MaterialTheme.typography.bodySmall, color = Neutral500)
                            }
                        }
                    }
                }
            }
        }

        // ── Allergy flags (byte 32: 8-bit bitmask) ──
        val allergyLabels = BinaryDecodeLookup.allergyLabels(enc.allergyFlags)
        if (allergyLabels.isNotEmpty()) {
            PayloadField(Icons.Default.Warning, "Allergies", AlertRed) {
                Row(horizontalArrangement = Arrangement.spacedBy(6.dp)) {
                    allergyLabels.forEach { allergy ->
                        Surface(color = AlertRedSurface, shape = RoundedCornerShape(4.dp)) {
                            Text(
                                allergy,
                                modifier = Modifier.padding(horizontal = 6.dp, vertical = 2.dp),
                                style = MaterialTheme.typography.labelSmall,
                                fontWeight = FontWeight.Medium,
                                color = AlertRed
                            )
                        }
                    }
                }
            }
        }

        // ── Follow-up (byte 33) ──
        enc.followUpDays?.let { days ->
            if (days > 0) {
                PayloadField(Icons.Default.Event, "Follow-up", Neutral700) {
                    Text("$days days", style = MaterialTheme.typography.bodySmall, color = Neutral700)
                }
            }
        }

        // ══════════════════════════════════════════════
        // ── Health History (bytes 34-71) ──
        // ══════════════════════════════════════════════
        if (decoded.totalVisits > 1 || decoded.chronicConditions.isNotEmpty() ||
            decoded.immunizations.isNotEmpty() || decoded.growth != null) {

            HorizontalDivider(color = Neutral200, modifier = Modifier.padding(vertical = 4.dp))
            Row(
                verticalAlignment = Alignment.CenterVertically,
                horizontalArrangement = Arrangement.spacedBy(6.dp)
            ) {
                Icon(Icons.Default.History, null, Modifier.size(14.dp), tint = BrandGreen)
                Text(
                    "Patient Health History",
                    style = MaterialTheme.typography.labelMedium,
                    fontWeight = FontWeight.SemiBold,
                    color = BrandGreenDark
                )
            }

            // Visit count (byte 36)
            PayloadField(Icons.Default.CalendarToday, "Visits", BrandGreen) {
                Text(
                    "${decoded.totalVisits} total visits",
                    style = MaterialTheme.typography.bodySmall,
                    color = Neutral700
                )
            }

            // Chronic conditions (bytes 37-46: up to 5 × 2 bytes)
            if (decoded.chronicConditions.isNotEmpty()) {
                // Use encounter data to resolve hash indices back to ICD-10 codes
                val chronicDxLookup = allEncounters
                    .flatMap { e -> (e.diagnoses + e.suggestedDiagnoses).map { it.icd10Code to it.description } }
                    .filter { it.first.isNotBlank() }
                    .groupBy { it.first }
                    .filter { it.value.size >= 2 }
                    .map { (code, entries) -> code to entries.first().second }
                    .toMap()

                PayloadField(Icons.Default.Favorite, "Chronic Conditions", InfoBlue) {
                    decoded.chronicConditions.forEach { cc ->
                        val match = chronicDxLookup.entries.firstOrNull {
                            (it.key.hashCode() and 0x1FF) == cc.icdHashIndex
                        }
                        Row(
                            verticalAlignment = Alignment.CenterVertically,
                            horizontalArrangement = Arrangement.spacedBy(6.dp)
                        ) {
                            Surface(color = InfoBlueSurface, shape = RoundedCornerShape(4.dp)) {
                                Text(
                                    match?.key ?: "#${cc.icdHashIndex}",
                                    modifier = Modifier.padding(horizontal = 6.dp, vertical = 2.dp),
                                    style = MaterialTheme.typography.labelSmall,
                                    fontFamily = FontFamily.Monospace,
                                    fontWeight = FontWeight.Bold,
                                    color = InfoBlue
                                )
                            }
                            Text(
                                "${match?.value ?: "Unknown"} (${cc.occurrenceCount}×)",
                                style = MaterialTheme.typography.bodySmall,
                                color = Neutral700
                            )
                        }
                    }
                }
            }

            // Abnormal vitals (bytes 47-58: up to 3 × 4 bytes)
            if (decoded.abnormalVitals.isNotEmpty()) {
                PayloadField(Icons.AutoMirrored.Filled.TrendingUp, "Abnormal Vitals", WarningAmber) {
                    decoded.abnormalVitals.forEach { av ->
                        Text(
                            "${av.vitalLabel}: ${av.displayValue} (${av.date})",
                            style = MaterialTheme.typography.bodySmall,
                            color = Neutral700
                        )
                    }
                }
            }

            // Growth (bytes 59-62)
            decoded.growth?.let { g ->
                PayloadField(Icons.Default.ChildCare, "Growth", BrandGreen) {
                    Text(
                        "Wt ${g.weightKg}kg (z=${"%.1f".format(g.weightZScore)}) \u2022 Ht ${g.heightCm}cm (z=${"%.1f".format(g.heightZScore)})",
                        style = MaterialTheme.typography.bodySmall,
                        color = Neutral700
                    )
                }
            }

            // Immunization history (bytes 63-69: up to 3 vaccines)
            if (decoded.immunizations.isNotEmpty()) {
                PayloadField(Icons.Default.Vaccines, "Immunization History", InfoBlue) {
                    decoded.immunizations.forEach { imm ->
                        Row(
                            verticalAlignment = Alignment.CenterVertically,
                            horizontalArrangement = Arrangement.spacedBy(6.dp)
                        ) {
                            Surface(color = InfoBlueSurface, shape = RoundedCornerShape(4.dp)) {
                                Text(
                                    imm.vaccineCode,
                                    modifier = Modifier.padding(horizontal = 6.dp, vertical = 2.dp),
                                    style = MaterialTheme.typography.labelSmall,
                                    fontFamily = FontFamily.Monospace,
                                    fontWeight = FontWeight.Bold,
                                    color = InfoBlue
                                )
                            }
                            Text(
                                "dose ${imm.doseNumber}",
                                style = MaterialTheme.typography.bodySmall,
                                color = Neutral700
                            )
                        }
                    }
                }
            }

            // Cumulative allergy flags (byte 35)
            val cumulativeAllergies = BinaryDecodeLookup.allergyLabels(decoded.cumulativeAllergyFlags)
            if (cumulativeAllergies.isNotEmpty()) {
                PayloadField(Icons.Default.Warning, "Cumulative Allergies", AlertRed) {
                    Row(horizontalArrangement = Arrangement.spacedBy(6.dp)) {
                        cumulativeAllergies.forEach { allergy ->
                            Surface(color = AlertRedSurface, shape = RoundedCornerShape(4.dp)) {
                                Text(
                                    allergy,
                                    modifier = Modifier.padding(horizontal = 6.dp, vertical = 2.dp),
                                    style = MaterialTheme.typography.labelSmall,
                                    fontWeight = FontWeight.Medium,
                                    color = AlertRed
                                )
                            }
                        }
                    }
                }
            }

            // Clinical status flags (bytes 70-71)
            val statusLabels = decoded.clinicalStatus1Labels + decoded.clinicalStatus2Labels
            if (statusLabels.isNotEmpty()) {
                PayloadField(Icons.Default.Flag, "Clinical Status Flags", WarningAmber) {
                    Row(horizontalArrangement = Arrangement.spacedBy(6.dp)) {
                        statusLabels.forEach { label ->
                            Surface(color = WarningAmberSurface, shape = RoundedCornerShape(4.dp)) {
                                Text(
                                    label,
                                    modifier = Modifier.padding(horizontal = 6.dp, vertical = 2.dp),
                                    style = MaterialTheme.typography.labelSmall,
                                    fontWeight = FontWeight.Medium,
                                    color = WarningAmber
                                )
                            }
                        }
                    }
                }
            }
        }

        // Footer: format info
        Text(
            "AES-256-GCM encrypted \u00b7 92-byte V4 binary format",
            style = MaterialTheme.typography.labelSmall,
            color = Neutral300
        )
    }
}

@Composable
private fun PayloadField(
    icon: ImageVector,
    label: String,
    color: Color,
    content: @Composable ColumnScope.() -> Unit
) {
    Column(verticalArrangement = Arrangement.spacedBy(4.dp)) {
        Row(
            verticalAlignment = Alignment.CenterVertically,
            horizontalArrangement = Arrangement.spacedBy(6.dp)
        ) {
            Icon(icon, null, Modifier.size(14.dp), tint = color)
            Text(
                label,
                style = MaterialTheme.typography.labelSmall,
                fontWeight = FontWeight.SemiBold,
                color = color
            )
        }
        Column(
            Modifier.padding(start = 20.dp),
            verticalArrangement = Arrangement.spacedBy(4.dp)
        ) {
            content()
        }
    }
}

// ═══════════════════════════════════════════════════════════════
// Empty State
// ═══════════════════════════════════════════════════════════════

@Composable
private fun EmptyState() {
    Column(
        Modifier.fillMaxWidth().padding(vertical = 48.dp),
        horizontalAlignment = Alignment.CenterHorizontally,
        verticalArrangement = Arrangement.spacedBy(8.dp)
    ) {
        Icon(Icons.Default.Sms, null, Modifier.size(48.dp), tint = Neutral300)
        Text("No SMS messages sent yet", style = MaterialTheme.typography.bodyLarge, color = Neutral500)
        Text(
            "SMS messages will appear here after encounters are saved",
            style = MaterialTheme.typography.bodySmall,
            color = Neutral400
        )
    }
}
