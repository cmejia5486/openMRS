package com.chartlite.app.ui.screens

import android.content.ClipData
import android.content.ClipboardManager
import android.content.Context
import android.widget.Toast
import androidx.compose.animation.animateContentSize
import androidx.compose.foundation.background
import androidx.compose.foundation.clickable
import androidx.compose.foundation.layout.*
import androidx.compose.foundation.rememberScrollState
import androidx.compose.foundation.shape.RoundedCornerShape
import androidx.compose.foundation.verticalScroll
import androidx.compose.material.icons.Icons
import androidx.compose.material.icons.automirrored.filled.ArrowBack
import androidx.compose.material.icons.automirrored.filled.Notes
import androidx.compose.material.icons.automirrored.filled.Send
import androidx.compose.material.icons.filled.*
import androidx.compose.material3.*
import androidx.compose.runtime.*
import androidx.compose.runtime.saveable.rememberSaveable
import androidx.compose.ui.Alignment
import kotlinx.coroutines.launch
import androidx.compose.ui.Modifier
import androidx.compose.ui.draw.clip
import androidx.compose.ui.graphics.Color
import androidx.compose.ui.graphics.vector.ImageVector
import androidx.compose.ui.platform.LocalContext
import androidx.compose.ui.text.font.FontFamily
import androidx.compose.ui.text.font.FontWeight
import androidx.compose.ui.text.style.TextAlign
import androidx.compose.ui.res.stringResource
import androidx.compose.ui.unit.dp
import com.chartlite.app.App
import com.chartlite.app.R
import com.chartlite.app.billing.ClaimEngine
import com.chartlite.app.billing.IntegrationPayloads
import com.chartlite.app.billing.PDFExporter
import com.chartlite.app.billing.SOAPNoteGenerator
import com.chartlite.app.database.entity.EncounterEntity
import com.chartlite.app.database.entity.effectiveEncounterTimeMillis
import com.chartlite.app.database.entity.normalizedReferralOrNull
import com.chartlite.app.model.*
import com.chartlite.app.ui.components.CDSSAlertBanner
import com.chartlite.app.ui.components.MarkdownText
import com.chartlite.app.ui.theme.*
import com.google.gson.Gson
import com.google.gson.reflect.TypeToken
import java.time.Instant
import java.time.ZoneId
import java.time.format.DateTimeFormatter

@OptIn(ExperimentalMaterial3Api::class, ExperimentalLayoutApi::class)
@Composable
fun EncounterReviewScreen(
    encounterId: String,
    onBack: () -> Unit
) {
    val context = LocalContext.current
    val app = context.applicationContext as App
    val gson = remember { Gson() }
    val scope = rememberCoroutineScope()

    var encounter by remember { mutableStateOf<EncounterEntity?>(null) }
    var diagnoses by remember { mutableStateOf<List<Diagnosis>>(emptyList()) }
    var medications by remember { mutableStateOf<List<Medication>>(emptyList()) }
    var vitals by remember { mutableStateOf<VitalSigns?>(null) }
    var allergies by remember { mutableStateOf<List<String>>(emptyList()) }
    var alerts by remember { mutableStateOf<List<CDSSAlert>>(emptyList()) }
    var patientName by remember { mutableStateOf("Patient") }
    // Benchmark-driven categories (2026-03)
    var examFindings by remember { mutableStateOf<List<String>>(emptyList()) }
    var investigations by remember { mutableStateOf<List<Investigation>>(emptyList()) }
    var planItems by remember { mutableStateOf<List<String>>(emptyList()) }
    var immunizationsList by remember { mutableStateOf<List<ExtractedImmunization>>(emptyList()) }
    var socialHistory by remember { mutableStateOf<List<String>>(emptyList()) }
    var suggestedDiagnoses by remember { mutableStateOf<List<Diagnosis>>(emptyList()) }

    LaunchedEffect(encounterId) {
        val enc = app.encounterRepository.getById(encounterId) ?: return@LaunchedEffect
        encounter = enc
        diagnoses = gson.parseListOrEmpty(enc.diagnoses)
        medications = gson.parseListOrEmpty(enc.medications)
        vitals = try {
            enc.vitals?.let { gson.fromJson(it, VitalSigns::class.java) }
        } catch (_: Exception) { null }
        allergies = gson.parseListOrEmpty(enc.allergies)
        alerts = gson.parseListOrEmpty(enc.cdssAlerts)
        examFindings = gson.parseListOrEmpty(enc.examFindings)
        investigations = gson.parseListOrEmpty(enc.investigations)
        planItems = gson.parseListOrEmpty(enc.plan)
        socialHistory = gson.parseListOrEmpty(enc.socialHistory)
        suggestedDiagnoses = gson.parseListOrEmpty(enc.suggestedDiagnoses)
        immunizationsList = gson.parseListOrEmpty(enc.immunizations)

        // Load patient name
        val patient = app.patientRepository.getById(enc.patientId)
        patient?.let { patientName = "${it.firstName} ${it.lastName}" }
    }

    var selectedTab by remember { mutableIntStateOf(0) }
    // v1: Summary + SOAP Note only. Claim Preview hidden for v1 (see ROADMAP.md).
    val tabs = listOf(
        stringResource(R.string.review_tab_summary),
        stringResource(R.string.review_tab_soap_note)
    )

    Scaffold(
        topBar = {
            TopAppBar(
                title = {
                    Column {
                        Text(stringResource(R.string.encounter_review))
                        Text(patientName,
                            style = MaterialTheme.typography.bodySmall,
                            color = MaterialTheme.colorScheme.onSurfaceVariant,
                            maxLines = 1,
                            overflow = androidx.compose.ui.text.style.TextOverflow.Ellipsis)
                    }
                },
                navigationIcon = {
                    IconButton(onClick = onBack) {
                        Icon(Icons.AutoMirrored.Filled.ArrowBack, contentDescription = stringResource(R.string.back))
                    }
                }
            )
        }
    ) { padding ->
        val enc = encounter
        if (enc == null) {
            Box(Modifier.fillMaxSize(), contentAlignment = Alignment.Center) {
                CircularProgressIndicator()
            }
            return@Scaffold
        }

        Column(
            modifier = Modifier
                .fillMaxSize()
                .padding(padding)
        ) {
            // Tab row
            PrimaryTabRow(selectedTabIndex = selectedTab) {
                tabs.forEachIndexed { index, title ->
                    Tab(
                        selected = selectedTab == index,
                        onClick = { selectedTab = index },
                        text = { Text(title) },
                        icon = {
                            when (index) {
                                0 -> Icon(Icons.Default.Summarize, contentDescription = title, modifier = Modifier.size(18.dp))
                                1 -> Icon(Icons.Default.Receipt, contentDescription = title, modifier = Modifier.size(18.dp))
                                2 -> Icon(Icons.Default.Description, contentDescription = title, modifier = Modifier.size(18.dp))
                            }
                        }
                    )
                }
            }

            // Tab content
            when (selectedTab) {
                0 -> SummaryTab(
                    enc, diagnoses, medications, vitals, allergies, alerts, patientName, context,
                    examFindings, investigations, planItems, socialHistory, suggestedDiagnoses, immunizationsList,
                    onConfirmDiagnosis = { dx ->
                        val confirmed = dx.copy(source = "clinician", isPrimary = diagnoses.isEmpty())
                        val newDiagnoses = diagnoses + confirmed
                        val newSuggested = suggestedDiagnoses.filter { it.icd10Code != dx.icd10Code }
                        diagnoses = newDiagnoses
                        suggestedDiagnoses = newSuggested
                        scope.launch {
                            app.encounterRepository.updateDiagnoses(encounterId, newDiagnoses, newSuggested)
                        }
                    }
                )
                // v1: tab 1 = SOAP Note (Claim Preview hidden, see ROADMAP.md)
                1 -> SOAPNoteTab(enc, diagnoses, medications, vitals, allergies, alerts, patientName, context,
                    examFindings, investigations, planItems, socialHistory, suggestedDiagnoses)
            }
        }
    }
}

// ── Tab 0: Summary (original encounter review) ──

@OptIn(ExperimentalLayoutApi::class)
@Composable
private fun SummaryTab(
    enc: EncounterEntity,
    diagnoses: List<Diagnosis>,
    medications: List<Medication>,
    vitals: VitalSigns?,
    allergies: List<String>,
    alerts: List<CDSSAlert>,
    patientName: String,
    context: Context,
    examFindings: List<String> = emptyList(),
    investigations: List<Investigation> = emptyList(),
    planItems: List<String> = emptyList(),
    socialHistory: List<String> = emptyList(),
    suggestedDiagnoses: List<Diagnosis> = emptyList(),
    immunizations: List<ExtractedImmunization> = emptyList(),
    onConfirmDiagnosis: (Diagnosis) -> Unit = {}
) {
    val displayTimeMillis = remember(enc.timestamp, enc.createdAt) {
        enc.effectiveEncounterTimeMillis()
    }
    val referral = remember(
        enc.referralType,
        enc.referralSpecialty,
        enc.referralUrgency,
        enc.referralReason
    ) { enc.normalizedReferralOrNull() }
    val dateStr = remember(displayTimeMillis) {
        displayTimeMillis?.let {
            DateTimeFormatter.ofPattern("dd MMM yyyy, HH:mm")
                .withZone(ZoneId.systemDefault())
                .format(Instant.ofEpochMilli(it))
        } ?: ""
    }
    val unknownDateStr = stringResource(R.string.unknown_date)
    val displayDateStr = remember(dateStr, unknownDateStr) {
        dateStr.ifEmpty { unknownDateStr }
    }

    Column(
        modifier = Modifier
            .fillMaxSize()
            .verticalScroll(rememberScrollState())
            .padding(16.dp),
        verticalArrangement = Arrangement.spacedBy(12.dp)
    ) {
        // Header
        ElevatedCard {
            Column(modifier = Modifier.fillMaxWidth().padding(16.dp)) {
                Row(
                    modifier = Modifier.fillMaxWidth(),
                    horizontalArrangement = Arrangement.SpaceBetween,
                    verticalAlignment = Alignment.CenterVertically
                ) {
                    Column {
                        Text(
                            stringResource(R.string.patient_id_format, enc.patientId),
                            style = MaterialTheme.typography.titleMedium,
                            fontWeight = FontWeight.Bold
                        )
                        Spacer(Modifier.height(2.dp))
                        Text(displayDateStr, style = MaterialTheme.typography.bodySmall,
                            color = MaterialTheme.colorScheme.onSurfaceVariant)
                    }
                    enc.smsStatus?.let { status ->
                        val isSent = status == "SENT" || status == "DELIVERED"
                        val isPending = status == "PENDING" || status == "SENDING"
                        val badgeColor = when {
                            isSent -> MaterialTheme.colorScheme.primaryContainer
                            isPending -> MaterialTheme.colorScheme.secondaryContainer
                            else -> MaterialTheme.colorScheme.errorContainer
                        }
                        val badgeTextColor = when {
                            isSent -> MaterialTheme.colorScheme.onPrimaryContainer
                            isPending -> MaterialTheme.colorScheme.onSecondaryContainer
                            else -> MaterialTheme.colorScheme.onErrorContainer
                        }
                        Surface(
                            color = badgeColor,
                            shape = MaterialTheme.shapes.small
                        ) {
                            Text(
                                when {
                                    isSent -> stringResource(R.string.sms_sent)
                                    isPending -> stringResource(R.string.sms_pending)
                                    else -> stringResource(R.string.sms_failed)
                                },
                                modifier = Modifier.padding(horizontal = 8.dp, vertical = 4.dp),
                                style = MaterialTheme.typography.labelSmall,
                                color = badgeTextColor
                            )
                        }
                    }
                }

                // SMS details row
                enc.smsStatus?.let { status ->
                    val isSent = status == "SENT" || status == "DELIVERED"
                    val isPending = status == "PENDING" || status == "SENDING"
                    Spacer(Modifier.height(10.dp))
                    HorizontalDivider()
                    Spacer(Modifier.height(10.dp))
                    Row(
                        modifier = Modifier.fillMaxWidth(),
                        verticalAlignment = Alignment.CenterVertically,
                        horizontalArrangement = Arrangement.spacedBy(8.dp)
                    ) {
                        Icon(
                            when {
                                isSent -> Icons.AutoMirrored.Filled.Send
                                isPending -> Icons.Default.Schedule
                                else -> Icons.Default.Error
                            },
                            contentDescription = "SMS",
                            modifier = Modifier.size(16.dp),
                            tint = when {
                                isSent -> MaterialTheme.colorScheme.primary
                                isPending -> MaterialTheme.colorScheme.secondary
                                else -> MaterialTheme.colorScheme.error
                            }
                        )
                        Text(
                            when {
                                isSent -> stringResource(R.string.sms_sent_description)
                                isPending -> stringResource(R.string.sms_pending_description)
                                else -> stringResource(R.string.sms_failed_description)
                            },
                            style = MaterialTheme.typography.bodySmall,
                            color = MaterialTheme.colorScheme.onSurfaceVariant,
                            modifier = Modifier.weight(1f)
                        )
                    }
                }
            }
        }

        // CDSS Alerts
        if (alerts.isNotEmpty()) {
            alerts.forEach { alert ->
                CDSSAlertBanner(alert = alert)
            }
        }

        // Confirmed Diagnoses (hide 0% confidence)
        val visibleDiagnoses = diagnoses.filter { it.confidence > 0f }
        if (visibleDiagnoses.isNotEmpty()) {
            SectionCard(icon = Icons.Default.MedicalServices, title = stringResource(R.string.diagnoses)) {
                visibleDiagnoses.forEach { dx ->
                    Row(
                        modifier = Modifier.fillMaxWidth().padding(vertical = 4.dp),
                        horizontalArrangement = Arrangement.SpaceBetween,
                        verticalAlignment = Alignment.CenterVertically
                    ) {
                        Column(modifier = Modifier.weight(1f)) {
                            Text(dx.description,
                                style = MaterialTheme.typography.bodyLarge,
                                fontWeight = if (dx.isPrimary) FontWeight.Bold else FontWeight.Normal)
                            Text(dx.icd10Code,
                                style = MaterialTheme.typography.bodySmall,
                                color = MaterialTheme.colorScheme.onSurfaceVariant)
                        }
                        ConfidenceBadge(dx.confidence)
                    }
                }
            }
        }

        // Suggested Diagnoses (hide 0% confidence)
        val visibleSuggested = suggestedDiagnoses.filter { it.confidence > 0f }
        if (visibleSuggested.isNotEmpty()) {
            SectionCard(icon = Icons.Default.Lightbulb, title = stringResource(R.string.suggested_diagnoses)) {
                Text(
                    stringResource(R.string.suggested_diagnoses_hint),
                    style = MaterialTheme.typography.bodySmall,
                    color = MaterialTheme.colorScheme.onSurfaceVariant
                )
                Spacer(Modifier.height(8.dp))
                visibleSuggested.forEach { dx ->
                    Row(
                        modifier = Modifier.fillMaxWidth().padding(vertical = 4.dp),
                        horizontalArrangement = Arrangement.SpaceBetween,
                        verticalAlignment = Alignment.CenterVertically
                    ) {
                        Column(modifier = Modifier.weight(1f)) {
                            Text(dx.description,
                                style = MaterialTheme.typography.bodyLarge,
                                fontWeight = FontWeight.Normal)
                            Row(verticalAlignment = Alignment.CenterVertically) {
                                Text(dx.icd10Code,
                                    style = MaterialTheme.typography.bodySmall,
                                    color = MaterialTheme.colorScheme.onSurfaceVariant)
                                Spacer(Modifier.width(8.dp))
                                val isLlm = dx.source == "llm"
                                Surface(
                                    color = (if (isLlm) WarningAmber else BrandGreen).copy(alpha = 0.15f),
                                    shape = RoundedCornerShape(4.dp)
                                ) {
                                    Text(
                                        if (isLlm) "AI" else stringResource(R.string.suggested_label),
                                        modifier = Modifier.padding(horizontal = 6.dp, vertical = 2.dp),
                                        style = MaterialTheme.typography.labelSmall,
                                        color = if (isLlm) WarningAmber else BrandGreen
                                    )
                                }
                            }
                        }
                        IconButton(onClick = { onConfirmDiagnosis(dx) }) {
                            Icon(
                                Icons.Default.AddCircle,
                                contentDescription = stringResource(R.string.add_diagnosis),
                                tint = MaterialTheme.colorScheme.primary
                            )
                        }
                    }
                }
            }
        }

        // Exam Findings (LLM's best category — 88% precision)
        if (examFindings.isNotEmpty()) {
            SectionCard(icon = Icons.Default.Visibility, title = stringResource(R.string.exam_findings)) {
                examFindings.forEach { finding ->
                    Text("• $finding",
                        style = MaterialTheme.typography.bodyMedium,
                        modifier = Modifier.padding(vertical = 2.dp))
                }
            }
        }

        // Investigations
        if (investigations.isNotEmpty()) {
            SectionCard(icon = Icons.Default.Science, title = stringResource(R.string.investigations)) {
                investigations.forEach { inv ->
                    Row(
                        modifier = Modifier.fillMaxWidth().padding(vertical = 4.dp),
                        horizontalArrangement = Arrangement.SpaceBetween,
                        verticalAlignment = Alignment.CenterVertically
                    ) {
                        Column(modifier = Modifier.weight(1f)) {
                            Text(inv.test,
                                style = MaterialTheme.typography.bodyLarge,
                                fontWeight = FontWeight.Medium)
                            inv.result?.let {
                                Text(it,
                                    style = MaterialTheme.typography.bodySmall,
                                    color = MaterialTheme.colorScheme.onSurfaceVariant)
                            } ?: Text(stringResource(R.string.ordered),
                                style = MaterialTheme.typography.bodySmall,
                                color = MaterialTheme.colorScheme.onSurfaceVariant,
                                fontWeight = FontWeight.Light)
                        }
                    }
                }
            }
        }

        // Clinical Plan
        if (planItems.isNotEmpty()) {
            SectionCard(icon = Icons.Default.Checklist, title = stringResource(R.string.clinical_plan)) {
                planItems.forEach { item ->
                    Text("• $item",
                        style = MaterialTheme.typography.bodyMedium,
                        modifier = Modifier.padding(vertical = 2.dp))
                }
            }
        }

        // Medications + Pharmacy Card
        if (medications.isNotEmpty()) {
            SectionCard(icon = Icons.Default.Medication, title = stringResource(R.string.medications)) {
                medications.forEach { med ->
                    Row(
                        modifier = Modifier.fillMaxWidth().padding(vertical = 4.dp),
                        horizontalArrangement = Arrangement.SpaceBetween,
                        verticalAlignment = Alignment.CenterVertically
                    ) {
                        Column(modifier = Modifier.weight(1f)) {
                            Text(med.name,
                                style = MaterialTheme.typography.bodyLarge,
                                fontWeight = FontWeight.Medium)
                            val dosageStr = buildString {
                                med.dose?.let { append(formatDose(it)) }
                                med.unit?.let { append(it) }
                                med.frequency?.let { append(" $it") }
                                med.duration?.let { append(" x ${it}d") }
                                med.route?.let { append(" ($it)") }
                            }
                            if (dosageStr.isNotBlank()) {
                                Text(dosageStr,
                                    style = MaterialTheme.typography.bodyMedium,
                                    color = MaterialTheme.colorScheme.onSurfaceVariant)
                            }
                        }
                        ConfidenceBadge(med.confidence)
                    }
                }

                Spacer(Modifier.height(8.dp))
                HorizontalDivider()
                Spacer(Modifier.height(8.dp))

                // Send to Pharmacy card
                PharmacyOrderCard(medications = medications)
            }
        }

        // Immunizations
        if (immunizations.isNotEmpty()) {
            SectionCard(icon = Icons.Default.Vaccines, title = stringResource(R.string.immunizations)) {
                immunizations.forEach { imm ->
                    Row(
                        modifier = Modifier.fillMaxWidth().padding(vertical = 4.dp),
                        horizontalArrangement = Arrangement.SpaceBetween,
                        verticalAlignment = Alignment.CenterVertically
                    ) {
                        Text(
                            imm.vaccineName.ifBlank { imm.vaccineCode },
                            style = MaterialTheme.typography.bodyLarge,
                            fontWeight = FontWeight.Medium,
                            modifier = Modifier.weight(1f)
                        )
                        Surface(
                            color = MaterialTheme.colorScheme.primaryContainer,
                            shape = RoundedCornerShape(4.dp)
                        ) {
                            Text(
                                stringResource(R.string.dose_format, imm.doseNumber),
                                modifier = Modifier.padding(horizontal = 6.dp, vertical = 2.dp),
                                style = MaterialTheme.typography.labelSmall
                            )
                        }
                    }
                }
            }
        }

        // Vitals
        vitals?.let { v ->
            SectionCard(icon = Icons.Default.MonitorHeart, title = stringResource(R.string.vitals)) {
                val vitalsGrid = listOfNotNull(
                    v.systolicBP?.let { "BP" to "${it}/${v.diastolicBP ?: "-"} mmHg" },
                    v.temperature?.let { "Temp" to "${"%.1f".format(it)}°C" },
                    v.pulse?.let { "Pulse" to "$it bpm" },
                    v.weight?.let { "Weight" to "${"%.1f".format(it)} kg" },
                    v.oxygenSaturation?.let { "SpO2" to "$it%" },
                    v.respiratoryRate?.let { "RR" to "$it /min" },
                    v.height?.let { "Height" to "${"%.0f".format(it)} cm" }
                )
                Row(
                    modifier = Modifier.fillMaxWidth(),
                    horizontalArrangement = Arrangement.spacedBy(8.dp)
                ) {
                    vitalsGrid.chunked(((vitalsGrid.size + 1) / 2).coerceAtLeast(1)).forEach { column ->
                        Column(modifier = Modifier.weight(1f)) {
                            column.forEach { (label, value) ->
                                Row(
                                    modifier = Modifier.fillMaxWidth().padding(vertical = 2.dp),
                                    horizontalArrangement = Arrangement.SpaceBetween
                                ) {
                                    Text(label, style = MaterialTheme.typography.bodyMedium,
                                        color = MaterialTheme.colorScheme.onSurfaceVariant)
                                    Text(value, style = MaterialTheme.typography.titleSmall,
                                        fontWeight = FontWeight.Medium)
                                }
                            }
                        }
                    }
                }
            }
        }

        // Allergies
        if (allergies.isNotEmpty()) {
            SectionCard(icon = Icons.Default.Warning, title = stringResource(R.string.allergies)) {
                FlowRow(
                    horizontalArrangement = Arrangement.spacedBy(8.dp),
                    verticalArrangement = Arrangement.spacedBy(4.dp)
                ) {
                    allergies.forEach { allergy ->
                        Surface(
                            shape = MaterialTheme.shapes.small,
                            color = MaterialTheme.colorScheme.errorContainer,
                            modifier = Modifier.padding(vertical = 2.dp)
                        ) {
                            Text(
                                allergy,
                                modifier = Modifier.padding(horizontal = 12.dp, vertical = 6.dp),
                                style = MaterialTheme.typography.labelLarge
                            )
                        }
                    }
                }
            }
        }

        // Follow-up
        enc.followUpDays?.let { days ->
            SectionCard(icon = Icons.Default.CalendarMonth, title = stringResource(R.string.follow_up)) {
                Text(stringResource(R.string.return_in_days_format, days), style = MaterialTheme.typography.bodyLarge)
                enc.followUpReason?.let {
                    Text(it, style = MaterialTheme.typography.bodySmall,
                        color = MaterialTheme.colorScheme.onSurfaceVariant)
                }
            }
        }

        // Referral
        referral?.let { normalizedReferral ->
            SectionCard(icon = Icons.Default.LocalHospital, title = stringResource(R.string.referral)) {
                Text(
                    if (normalizedReferral.specialty != null)
                        stringResource(R.string.refer_to_specialty_format, normalizedReferral.type, normalizedReferral.specialty.orEmpty())
                    else
                        stringResource(R.string.refer_to_format, normalizedReferral.type),
                    style = MaterialTheme.typography.bodyLarge)
                Text(stringResource(R.string.urgency_format, normalizedReferral.urgency),
                    style = MaterialTheme.typography.bodyMedium,
                    fontWeight = FontWeight.Medium,
                    color = when (normalizedReferral.urgency) {
                        "emergency" -> AlertRed
                        "urgent" -> WarningAmber
                        else -> MaterialTheme.colorScheme.onSurface
                    })
            }
        }

        // Social History
        if (socialHistory.isNotEmpty()) {
            SectionCard(icon = Icons.Default.People, title = stringResource(R.string.social_history)) {
                socialHistory.forEach { item ->
                    Text("• $item",
                        style = MaterialTheme.typography.bodyMedium,
                        modifier = Modifier.padding(vertical = 2.dp))
                }
            }
        }

        // Notes / Transcript (collapsed by default — tap to expand)
        val noteText = enc.freeTextNote.ifBlank { enc.transcript }
        if (noteText.isNotBlank()) {
            var showNotes by rememberSaveable { mutableStateOf(false) }
            Card(
                modifier = Modifier
                    .fillMaxWidth()
                    .clickable { showNotes = !showNotes },
                colors = CardDefaults.cardColors(
                    containerColor = MaterialTheme.colorScheme.surfaceVariant.copy(alpha = 0.6f)
                )
            ) {
                Column(modifier = Modifier.padding(16.dp)) {
                    Row(
                        modifier = Modifier.fillMaxWidth(),
                        horizontalArrangement = Arrangement.SpaceBetween,
                        verticalAlignment = Alignment.CenterVertically
                    ) {
                        Row(
                            horizontalArrangement = Arrangement.spacedBy(8.dp),
                            verticalAlignment = Alignment.CenterVertically
                        ) {
                            Icon(Icons.AutoMirrored.Filled.Notes, contentDescription = null, modifier = Modifier.size(20.dp), tint = MaterialTheme.colorScheme.onSurfaceVariant)
                            Text(stringResource(R.string.clinical_notes),
                                style = MaterialTheme.typography.titleSmall,
                                color = MaterialTheme.colorScheme.onSurfaceVariant)
                        }
                        Icon(
                            if (showNotes) Icons.Default.ExpandLess else Icons.Default.ExpandMore,
                            contentDescription = null,
                            tint = MaterialTheme.colorScheme.onSurfaceVariant,
                            modifier = Modifier.size(20.dp)
                        )
                    }
                    if (showNotes) {
                        Spacer(Modifier.height(8.dp))
                        MarkdownText(noteText, style = MaterialTheme.typography.bodyMedium)
                    }
                }
            }
        }

        // Copy & Export buttons
        val summaryCopiedMsg = stringResource(R.string.summary_copied)
        Button(
            onClick = {
                val text = buildSummaryText(enc, diagnoses, medications, vitals, allergies)
                val clipboard = context.getSystemService(Context.CLIPBOARD_SERVICE) as? ClipboardManager
                clipboard?.setPrimaryClip(ClipData.newPlainText("Encounter Summary", text))
                Toast.makeText(context, summaryCopiedMsg, Toast.LENGTH_SHORT).show()
            },
            modifier = Modifier.fillMaxWidth()
        ) {
            Icon(Icons.Default.ContentCopy, contentDescription = null, modifier = Modifier.size(18.dp))
            Spacer(Modifier.width(8.dp))
            Text(stringResource(R.string.copy_summary))
        }

        OutlinedButton(
            onClick = {
                PDFExporter.exportSummaryAndShare(context, enc, diagnoses, medications, vitals, allergies, patientName, enc.patientId)
            },
            modifier = Modifier.fillMaxWidth()
        ) {
            Icon(Icons.Default.PictureAsPdf, contentDescription = null, modifier = Modifier.size(18.dp))
            Spacer(Modifier.width(8.dp))
            Text(stringResource(R.string.export_as_pdf))
        }

        Spacer(Modifier.height(16.dp))
    }
}

private fun buildSummaryText(
    enc: EncounterEntity,
    diagnoses: List<Diagnosis>,
    medications: List<Medication>,
    vitals: VitalSigns?,
    allergies: List<String>
): String = buildString {
    if (diagnoses.isNotEmpty()) {
        appendLine("DIAGNOSES")
        diagnoses.forEach { dx ->
            val primary = if (dx.isPrimary) " [Primary]" else ""
            appendLine("  ${dx.icd10Code} — ${dx.description}$primary")
        }
        appendLine()
    }
    if (medications.isNotEmpty()) {
        appendLine("MEDICATIONS")
        medications.forEach { med ->
            val doseStr = if (med.dose != null) "${med.dose}${med.unit.orEmpty()}" else null
            val detail = listOfNotNull(doseStr, med.route, med.frequency).joinToString(" | ")
            appendLine("  ${med.name}${if (detail.isNotBlank()) " — $detail" else ""}")
        }
        appendLine()
    }
    vitals?.let { v ->
        appendLine("VITAL SIGNS")
        v.systolicBP?.let { s -> v.diastolicBP?.let { d -> appendLine("  BP: $s/$d mmHg") } }
        v.pulse?.let { appendLine("  HR: $it bpm") }
        v.temperature?.let { appendLine("  Temp: $it °C") }
        v.respiratoryRate?.let { appendLine("  RR: $it /min") }
        v.oxygenSaturation?.let { appendLine("  SpO2: $it%") }
        appendLine()
    }
    if (allergies.isNotEmpty()) {
        appendLine("ALLERGIES")
        allergies.forEach { appendLine("  $it") }
        appendLine()
    }
    val noteText = enc.freeTextNote.ifBlank { enc.transcript }
    if (noteText.isNotBlank()) {
        appendLine("CLINICAL NOTES")
        appendLine(noteText.replace(Regex("\\*\\*|^#{1,3}\\s", RegexOption.MULTILINE), ""))
    }
}

// ── Tab 1: Insurance Claim Preview ──

@Composable
private fun ClaimPreviewTab(
    enc: EncounterEntity,
    diagnoses: List<Diagnosis>,
    medications: List<Medication>,
    vitals: VitalSigns?,
    context: Context,
    patientName: String
) {
    val claim837pCopiedMsg = stringResource(R.string.claim_837p_copied)
    val claimCopiedMsg = stringResource(R.string.claim_copied)
    // Generate real claim using facility's configured country
    val app = context.applicationContext as com.chartlite.app.App
    val claim = remember(enc, diagnoses, medications, vitals) {
        ClaimEngine.generateClaim(
            encounterId = enc.id,
            diagnoses = diagnoses,
            medications = medications,
            vitals = vitals,
            hasReferral = enc.normalizedReferralOrNull() != null,
            countryCode = app.appConfig.countryCode
        )
    }

    Column(
        modifier = Modifier
            .fillMaxSize()
            .verticalScroll(rememberScrollState())
            .padding(16.dp),
        verticalArrangement = Arrangement.spacedBy(12.dp)
    ) {
        // Claim header
        Card(
            colors = CardDefaults.cardColors(containerColor = InfoBlueSurface)
        ) {
            Column(modifier = Modifier.padding(16.dp)) {
                Row(
                    modifier = Modifier.fillMaxWidth(),
                    horizontalArrangement = Arrangement.SpaceBetween,
                    verticalAlignment = Alignment.CenterVertically
                ) {
                    Column {
                        Text(stringResource(R.string.insurance_claim_preview),
                            style = MaterialTheme.typography.titleMedium,
                            fontWeight = FontWeight.Bold)
                        Text(stringResource(R.string.claim_id_format, claim.claimId),
                            style = MaterialTheme.typography.bodySmall,
                            color = Neutral600)
                    }
                    Surface(
                        color = InfoBlue.copy(alpha = 0.15f),
                        shape = RoundedCornerShape(8.dp)
                    ) {
                        Text(
                            stringResource(R.string.em_level_format, claim.emLevel),
                            modifier = Modifier.padding(horizontal = 10.dp, vertical = 4.dp),
                            style = MaterialTheme.typography.labelMedium,
                            fontWeight = FontWeight.Bold,
                            color = InfoBlue
                        )
                    }
                }
                Spacer(Modifier.height(8.dp))
                Row(
                    modifier = Modifier.fillMaxWidth(),
                    horizontalArrangement = Arrangement.SpaceBetween
                ) {
                    Column {
                        Text(stringResource(R.string.patient_label), style = MaterialTheme.typography.labelSmall, color = Neutral500)
                        Text(enc.patientId, style = MaterialTheme.typography.bodyMedium, fontWeight = FontWeight.Medium)
                    }
                    Column(horizontalAlignment = Alignment.End) {
                        Text(stringResource(R.string.payer_type), style = MaterialTheme.typography.labelSmall, color = Neutral500)
                        Text(claim.payerType, style = MaterialTheme.typography.bodyMedium, fontWeight = FontWeight.Medium)
                    }
                }
            }
        }

        // ICD-10 Diagnoses section
        Card {
            Column(modifier = Modifier.padding(16.dp)) {
                Row(verticalAlignment = Alignment.CenterVertically) {
                    Icon(Icons.Default.MedicalServices, contentDescription = null,
                        tint = MaterialTheme.colorScheme.primary, modifier = Modifier.size(20.dp))
                    Spacer(Modifier.width(8.dp))
                    Text(stringResource(R.string.icd10_diagnosis_codes),
                        style = MaterialTheme.typography.titleSmall,
                        fontWeight = FontWeight.SemiBold)
                }
                Spacer(Modifier.height(8.dp))

                if (diagnoses.isEmpty()) {
                    Text(stringResource(R.string.no_diagnoses_claim_warning),
                        style = MaterialTheme.typography.bodySmall, color = AlertRed)
                } else {
                    diagnoses.forEachIndexed { index, dx ->
                        Row(
                            modifier = Modifier.fillMaxWidth().padding(vertical = 4.dp),
                            horizontalArrangement = Arrangement.SpaceBetween,
                            verticalAlignment = Alignment.CenterVertically
                        ) {
                            Row(modifier = Modifier.weight(1f), verticalAlignment = Alignment.CenterVertically) {
                                Surface(
                                    color = if (dx.isPrimary) BrandGreen.copy(alpha = 0.12f)
                                            else Neutral200,
                                    shape = RoundedCornerShape(4.dp)
                                ) {
                                    Text(
                                        if (dx.isPrimary) "P" else "${index + 1}",
                                        modifier = Modifier.padding(horizontal = 6.dp, vertical = 2.dp),
                                        style = MaterialTheme.typography.labelSmall,
                                        fontWeight = FontWeight.Bold,
                                        color = if (dx.isPrimary) BrandGreenDark else Neutral700
                                    )
                                }
                                Spacer(Modifier.width(8.dp))
                                Column {
                                    Text(dx.description, style = MaterialTheme.typography.bodyMedium)
                                    Text(dx.icd10Code, style = MaterialTheme.typography.bodySmall,
                                        fontFamily = FontFamily.Monospace, color = Neutral600)
                                }
                            }
                        }
                    }
                }
            }
        }

        // CPT Procedure Codes / Claim Lines
        Card {
            Column(modifier = Modifier.padding(16.dp)) {
                Row(verticalAlignment = Alignment.CenterVertically) {
                    Icon(Icons.Default.Receipt, contentDescription = null,
                        tint = MaterialTheme.colorScheme.primary, modifier = Modifier.size(20.dp))
                    Spacer(Modifier.width(8.dp))
                    Text(stringResource(R.string.cpt_procedure_codes),
                        style = MaterialTheme.typography.titleSmall,
                        fontWeight = FontWeight.SemiBold)
                }
                Spacer(Modifier.height(8.dp))

                // Table header
                Row(
                    modifier = Modifier
                        .fillMaxWidth()
                        .background(Neutral100, RoundedCornerShape(4.dp))
                        .padding(horizontal = 8.dp, vertical = 6.dp)
                ) {
                    Text(stringResource(R.string.cpt_header), modifier = Modifier.width(60.dp),
                        style = MaterialTheme.typography.labelSmall, fontWeight = FontWeight.Bold)
                    Text(stringResource(R.string.description_header), modifier = Modifier.weight(1f),
                        style = MaterialTheme.typography.labelSmall, fontWeight = FontWeight.Bold)
                    Text(stringResource(R.string.zar_header), modifier = Modifier.width(65.dp),
                        style = MaterialTheme.typography.labelSmall, fontWeight = FontWeight.Bold,
                        textAlign = TextAlign.End)
                }

                claim.claimLines.forEach { line ->
                    Row(
                        modifier = Modifier
                            .fillMaxWidth()
                            .padding(horizontal = 8.dp, vertical = 6.dp),
                        verticalAlignment = Alignment.Top
                    ) {
                        Text(
                            line.cptCode + (line.modifier?.let { "-$it" } ?: ""),
                            modifier = Modifier.width(60.dp),
                            style = MaterialTheme.typography.bodySmall,
                            fontFamily = FontFamily.Monospace
                        )
                        Text(line.description, modifier = Modifier.weight(1f),
                            style = MaterialTheme.typography.bodySmall)
                        Text("R${"%.0f".format(line.tariffZAR)}",
                            modifier = Modifier.width(65.dp),
                            style = MaterialTheme.typography.bodySmall,
                            fontWeight = FontWeight.Medium,
                            textAlign = TextAlign.End)
                    }
                    HorizontalDivider(color = Neutral200)
                }

                // Totals
                Spacer(Modifier.height(8.dp))
                Row(
                    modifier = Modifier
                        .fillMaxWidth()
                        .background(BrandGreenSurface, RoundedCornerShape(4.dp))
                        .padding(horizontal = 8.dp, vertical = 8.dp),
                    horizontalArrangement = Arrangement.SpaceBetween
                ) {
                    Text(stringResource(R.string.total_label), style = MaterialTheme.typography.titleSmall, fontWeight = FontWeight.Bold)
                    Column(horizontalAlignment = Alignment.End) {
                        Text("R${"%.2f".format(claim.totalZAR)}",
                            style = MaterialTheme.typography.titleSmall,
                            fontWeight = FontWeight.Bold, color = BrandGreenDark)
                        Text("≈ \$${"%.2f".format(claim.totalUSD)}",
                            style = MaterialTheme.typography.labelSmall,
                            color = Neutral500)
                    }
                }
            }
        }

        // ICD-10 → CPT Mapping explanation
        Card(colors = CardDefaults.cardColors(containerColor = WarningAmberSurface)) {
            Column(modifier = Modifier.padding(16.dp)) {
                Row(verticalAlignment = Alignment.CenterVertically) {
                    Icon(Icons.Default.Info, contentDescription = null,
                        tint = AccentOrange, modifier = Modifier.size(18.dp))
                    Spacer(Modifier.width(8.dp))
                    Text(stringResource(R.string.how_this_works),
                        style = MaterialTheme.typography.titleSmall,
                        fontWeight = FontWeight.SemiBold)
                }
                Spacer(Modifier.height(8.dp))
                Text(
                    stringResource(R.string.claim_mapping_explanation),
                    style = MaterialTheme.typography.bodySmall,
                    color = Neutral700
                )
            }
        }

        // 837P Claim Preview
        var show837P by remember { mutableStateOf(false) }
        Button(
            onClick = { show837P = true },
            modifier = Modifier.fillMaxWidth(),
            enabled = diagnoses.isNotEmpty()
        ) {
            Icon(Icons.AutoMirrored.Filled.Send, contentDescription = stringResource(R.string.send_claim), modifier = Modifier.size(18.dp))
            Spacer(Modifier.width(8.dp))
            Text(stringResource(R.string.preview_837p_submission))
        }

        if (show837P) {
            val payload = remember {
                IntegrationPayloads.build837PClaim(
                    enc = enc, claim = claim, diagnoses = diagnoses,
                    patientName = patientName, providerName = "Dr. " + enc.providerId.take(8)
                )
            }
            AlertDialog(
                onDismissRequest = { show837P = false },
                title = { Text(stringResource(R.string.electronic_claim_837p), fontWeight = FontWeight.Bold) },
                text = {
                    Column(Modifier.verticalScroll(rememberScrollState())) {
                        Card(colors = CardDefaults.cardColors(containerColor = Neutral100)) {
                            Text(
                                payload,
                                modifier = Modifier.padding(12.dp),
                                style = MaterialTheme.typography.labelSmall,
                                fontFamily = FontFamily.Monospace
                            )
                        }
                        Spacer(Modifier.height(8.dp))
                        Text(stringResource(R.string.edi_payload_description),
                            style = MaterialTheme.typography.bodySmall, color = Neutral600)
                    }
                },
                confirmButton = {
                    TextButton(onClick = {
                        val clipboard = context.getSystemService(Context.CLIPBOARD_SERVICE) as? ClipboardManager
                        clipboard?.setPrimaryClip(ClipData.newPlainText("837P Claim", payload))
                        Toast.makeText(context, claim837pCopiedMsg, Toast.LENGTH_SHORT).show()
                    }) { Text(stringResource(R.string.copy)) }
                },
                dismissButton = {
                    TextButton(onClick = { show837P = false }) { Text(stringResource(R.string.close)) }
                }
            )
        }

        // Copy claim text
        OutlinedButton(
            onClick = {
                val claimText = buildClaimText(enc, claim, diagnoses)
                val clipboard = context.getSystemService(Context.CLIPBOARD_SERVICE) as? ClipboardManager
                clipboard?.setPrimaryClip(ClipData.newPlainText("Claim", claimText))
                Toast.makeText(context, claimCopiedMsg, Toast.LENGTH_SHORT).show()
            },
            modifier = Modifier.fillMaxWidth()
        ) {
            Icon(Icons.Default.ContentCopy, contentDescription = stringResource(R.string.copy_claim), modifier = Modifier.size(18.dp))
            Spacer(Modifier.width(8.dp))
            Text(stringResource(R.string.copy_claim_as_text))
        }

        Spacer(Modifier.height(16.dp))
    }
}

// ── Tab 2: SOAP Note ──

@Composable
private fun SOAPNoteTab(
    enc: EncounterEntity,
    diagnoses: List<Diagnosis>,
    medications: List<Medication>,
    vitals: VitalSigns?,
    allergies: List<String>,
    alerts: List<CDSSAlert>,
    patientName: String,
    context: Context,
    examFindings: List<String> = emptyList(),
    investigations: List<Investigation> = emptyList(),
    planItems: List<String> = emptyList(),
    socialHistory: List<String> = emptyList(),
    suggestedDiagnoses: List<Diagnosis> = emptyList()
) {
    val soapNoteCopiedMsg = stringResource(R.string.soap_note_copied)
    val soapNote = remember(enc, diagnoses, medications, vitals, allergies, examFindings, investigations, planItems, socialHistory, suggestedDiagnoses) {
        SOAPNoteGenerator.generate(
            encounter = enc,
            diagnoses = diagnoses,
            medications = medications,
            vitals = vitals,
            allergies = allergies,
            alerts = alerts,
            patientName = patientName,
            providerName = "Dr. " + enc.providerId.take(8),
            examFindings = examFindings,
            investigations = investigations,
            planItems = planItems,
            socialHistory = socialHistory,
            suggestedDiagnoses = suggestedDiagnoses
        )
    }

    Column(
        modifier = Modifier
            .fillMaxSize()
            .verticalScroll(rememberScrollState())
            .padding(16.dp),
        verticalArrangement = Arrangement.spacedBy(12.dp)
    ) {
        // Status card
        Card(colors = CardDefaults.cardColors(containerColor = BrandGreenSurface)) {
            Row(
                modifier = Modifier.fillMaxWidth().padding(16.dp),
                verticalAlignment = Alignment.CenterVertically
            ) {
                Icon(Icons.Default.CheckCircle, contentDescription = null,
                    tint = BrandGreen, modifier = Modifier.size(24.dp))
                Spacer(Modifier.width(12.dp))
                Column(modifier = Modifier.weight(1f)) {
                    Text(stringResource(R.string.soap_note_generated),
                        style = MaterialTheme.typography.titleSmall,
                        fontWeight = FontWeight.Bold, color = BrandGreenDark)
                    Text(stringResource(R.string.soap_note_word_count_format, soapNote.wordCount),
                        style = MaterialTheme.typography.bodySmall, color = Neutral600)
                }
            }
        }

        // S — Subjective
        SOAPSection(
            letter = "S",
            title = stringResource(R.string.subjective),
            color = InfoBlue,
            content = soapNote.subjective
        )

        // O — Objective
        SOAPSection(
            letter = "O",
            title = stringResource(R.string.objective),
            color = BrandGreen,
            content = soapNote.objective
        )

        // A — Assessment
        SOAPSection(
            letter = "A",
            title = stringResource(R.string.assessment),
            color = AccentOrange,
            content = soapNote.assessment
        )

        // P — Plan
        SOAPSection(
            letter = "P",
            title = stringResource(R.string.plan),
            color = AlertRed,
            content = soapNote.plan
        )

        // Action buttons
        Button(
            onClick = {
                val clipboard = context.getSystemService(Context.CLIPBOARD_SERVICE) as? ClipboardManager
                clipboard?.setPrimaryClip(ClipData.newPlainText("SOAP Note", soapNote.fullText))
                Toast.makeText(context, soapNoteCopiedMsg, Toast.LENGTH_SHORT).show()
            },
            modifier = Modifier.fillMaxWidth()
        ) {
            Icon(Icons.Default.ContentCopy, contentDescription = stringResource(R.string.copy_soap_note), modifier = Modifier.size(18.dp))
            Spacer(Modifier.width(8.dp))
            Text(stringResource(R.string.copy_full_soap_note))
        }

        OutlinedButton(
            onClick = {
                PDFExporter.exportAndShare(context, soapNote, patientName, enc.patientId)
            },
            modifier = Modifier.fillMaxWidth()
        ) {
            Icon(Icons.Default.PictureAsPdf, contentDescription = stringResource(R.string.export_pdf), modifier = Modifier.size(18.dp))
            Spacer(Modifier.width(8.dp))
            Text(stringResource(R.string.export_as_pdf))
        }

        // Dynamic AI mode indicator
        AiModeCard(context)

        Spacer(Modifier.height(16.dp))
    }
}

@Composable
private fun SOAPSection(
    letter: String,
    title: String,
    color: Color,
    content: String
) {
    Card(modifier = Modifier.fillMaxWidth()) {
        Column(modifier = Modifier.padding(16.dp)) {
            Row(verticalAlignment = Alignment.CenterVertically) {
                Box(
                    modifier = Modifier
                        .size(32.dp)
                        .clip(RoundedCornerShape(8.dp))
                        .background(color.copy(alpha = 0.12f)),
                    contentAlignment = Alignment.Center
                ) {
                    Text(letter,
                        style = MaterialTheme.typography.titleMedium,
                        fontWeight = FontWeight.Bold,
                        color = color)
                }
                Spacer(Modifier.width(12.dp))
                Text(title,
                    style = MaterialTheme.typography.titleSmall,
                    fontWeight = FontWeight.SemiBold)
            }
            Spacer(Modifier.height(12.dp))
            MarkdownText(content,
                style = MaterialTheme.typography.bodySmall.copy(
                    lineHeight = MaterialTheme.typography.bodyMedium.lineHeight
                ))
        }
    }
}

// ── AI Mode Card ──

@Composable
private fun AiModeCard(context: Context) {
    val app = context.applicationContext as App
    val aiMode = app.appConfig.aiMode
    val tier = remember { com.chartlite.app.ui.components.detectTier(context) }

    val isConnected = tier == com.chartlite.app.ui.components.ConnectivityTier.CONNECTED
    val isCloudMode = aiMode == "cloud" || aiMode == "auto"

    val icon: ImageVector
    val iconTint: Color
    val title: String
    val description: String

    when {
        isConnected && isCloudMode -> {
            icon = Icons.Default.Cloud
            iconTint = BrandGreen
            title = stringResource(R.string.ai_mode_cloud_title)
            description = stringResource(R.string.ai_mode_cloud_desc)
        }
        aiMode == "on_device" -> {
            icon = Icons.Default.PhoneAndroid
            iconTint = WarningAmber
            title = stringResource(R.string.ai_mode_device_title)
            description = stringResource(R.string.ai_mode_device_desc)
        }
        else -> {
            icon = Icons.Default.CloudOff
            iconTint = Neutral600
            title = stringResource(R.string.ai_mode_fallback_title)
            description = stringResource(R.string.ai_mode_fallback_desc)
        }
    }

    Card(colors = CardDefaults.cardColors(containerColor = Neutral100)) {
        Row(
            modifier = Modifier.padding(16.dp),
            verticalAlignment = Alignment.Top
        ) {
            Icon(icon, contentDescription = null,
                tint = iconTint, modifier = Modifier.size(20.dp))
            Spacer(Modifier.width(12.dp))
            Column {
                Text(title,
                    style = MaterialTheme.typography.titleSmall,
                    fontWeight = FontWeight.SemiBold)
                Spacer(Modifier.height(4.dp))
                Text(description,
                    style = MaterialTheme.typography.bodySmall, color = Neutral600)
            }
        }
    }
}

// ── Pharmacy Order Card ──

@Composable
private fun PharmacyOrderCard(medications: List<Medication>) {
    val context = LocalContext.current
    val app = context.applicationContext as App
    var showFHIR by remember { mutableStateOf(false) }
    val claim837pCopiedMsg = stringResource(R.string.claim_837p_copied)
    val claimCopiedMsg = stringResource(R.string.claim_copied)
    val soapNoteCopiedMsg = stringResource(R.string.soap_note_copied)
    val prescriptionCopiedMsg = stringResource(R.string.prescription_copied)
    val fhirPayloadCopiedMsg = stringResource(R.string.fhir_payload_copied)

    Column {
        Row(verticalAlignment = Alignment.CenterVertically) {
            Icon(Icons.Default.LocalPharmacy, contentDescription = null,
                tint = BrandGreen, modifier = Modifier.size(20.dp))
            Spacer(Modifier.width(8.dp))
            Text(stringResource(R.string.pharmacy_order),
                style = MaterialTheme.typography.titleSmall,
                fontWeight = FontWeight.SemiBold)
        }
        Spacer(Modifier.height(8.dp))

        // Medication order list
        medications.forEach { med ->
            Row(
                modifier = Modifier
                    .fillMaxWidth()
                    .background(Neutral50, RoundedCornerShape(6.dp))
                    .padding(8.dp),
                verticalAlignment = Alignment.CenterVertically
            ) {
                Icon(Icons.Default.Medication, contentDescription = null,
                    tint = Neutral500, modifier = Modifier.size(16.dp))
                Spacer(Modifier.width(8.dp))
                Column(modifier = Modifier.weight(1f)) {
                    Text(med.name, style = MaterialTheme.typography.bodyMedium,
                        fontWeight = FontWeight.Medium)
                    val rx = buildString {
                        med.dose?.let { append(formatDose(it)) }
                        med.unit?.let { append(it) }
                        med.frequency?.let { append(" $it") }
                        med.duration?.let { append(" x $it days") }
                        med.route?.let { append(" ($it)") }
                    }
                    Text(rx, style = MaterialTheme.typography.bodySmall, color = Neutral600)
                }
                Icon(Icons.Default.CheckCircle, contentDescription = null,
                    tint = BrandGreen, modifier = Modifier.size(16.dp))
            }
            Spacer(Modifier.height(4.dp))
        }

        Spacer(Modifier.height(8.dp))

        Row(horizontalArrangement = Arrangement.spacedBy(8.dp)) {
            Button(
                onClick = {
                    val rxText = medications.joinToString("\n") { med ->
                        buildString {
                            append("Rx: ${med.name}")
                            med.dose?.let { append(" ${formatDose(it)}") }
                            med.unit?.let { append(it) }
                            med.frequency?.let { append(" $it") }
                            med.duration?.let { append(" x ${it}d") }
                            med.route?.let { append(" ($it)") }
                        }
                    }
                    val clipboard = context.getSystemService(Context.CLIPBOARD_SERVICE) as? ClipboardManager
                    clipboard?.setPrimaryClip(ClipData.newPlainText("Prescription", rxText))
                    Toast.makeText(context, prescriptionCopiedMsg, Toast.LENGTH_SHORT).show()
                },
                modifier = Modifier.weight(1f),
                colors = ButtonDefaults.buttonColors(containerColor = BrandGreen)
            ) {
                Icon(Icons.Default.LocalPharmacy, contentDescription = stringResource(R.string.copy_prescription), modifier = Modifier.size(16.dp))
                Spacer(Modifier.width(4.dp))
                Text(stringResource(R.string.copy_rx), style = MaterialTheme.typography.labelMedium)
            }

            OutlinedButton(
                onClick = { showFHIR = true },
                modifier = Modifier.weight(1f)
            ) {
                Icon(Icons.AutoMirrored.Filled.Send, contentDescription = stringResource(R.string.send_to_pharmacy_icon), modifier = Modifier.size(16.dp))
                Spacer(Modifier.width(4.dp))
                Text(stringResource(R.string.send_to_pharmacy), style = MaterialTheme.typography.labelMedium)
            }
        }

        if (showFHIR) {
            val fhirPayload = remember {
                // We need encounter context — build a minimal version here
                "FHIR R4 MedicationRequest Bundle\n\n" +
                medications.joinToString("\n\n") { med ->
                    buildString {
                        appendLine("MedicationRequest {")
                        appendLine("  medication: \"${med.name}\" (${med.formularyCode})")
                        med.dose?.let { appendLine("  dose: ${formatDose(it)} ${med.unit ?: "mg"}") }
                        med.frequency?.let { appendLine("  timing: $it") }
                        med.duration?.let { appendLine("  supply: $it days") }
                        med.route?.let { appendLine("  route: $it") }
                        appendLine("  status: active, intent: order")
                        append("}")
                    }
                } + "\n\n${medications.size} MedicationRequest resources ready for FHIR endpoint"
            }
            AlertDialog(
                onDismissRequest = { showFHIR = false },
                title = { Text(stringResource(R.string.fhir_medication_request), fontWeight = FontWeight.Bold) },
                text = {
                    Column(Modifier.verticalScroll(rememberScrollState())) {
                        Card(colors = CardDefaults.cardColors(containerColor = Neutral100)) {
                            Text(
                                fhirPayload,
                                modifier = Modifier.padding(12.dp),
                                style = MaterialTheme.typography.labelSmall,
                                fontFamily = FontFamily.Monospace
                            )
                        }
                        Spacer(Modifier.height(8.dp))
                        Text(stringResource(R.string.fhir_payload_description),
                            style = MaterialTheme.typography.bodySmall, color = Neutral600)
                    }
                },
                confirmButton = {
                    TextButton(onClick = {
                        val clipboard = context.getSystemService(Context.CLIPBOARD_SERVICE) as? ClipboardManager
                        clipboard?.setPrimaryClip(ClipData.newPlainText("FHIR Rx", fhirPayload))
                        Toast.makeText(context, fhirPayloadCopiedMsg, Toast.LENGTH_SHORT).show()
                    }) { Text(stringResource(R.string.copy)) }
                },
                dismissButton = {
                    TextButton(onClick = { showFHIR = false }) { Text(stringResource(R.string.close)) }
                }
            )
        }
    }
}

// ── Helper Functions ──

private fun buildClaimText(
    enc: EncounterEntity,
    claim: ClaimEngine.ClaimPreview,
    diagnoses: List<Diagnosis>
): String = buildString {
    appendLine("INSURANCE CLAIM — ${claim.claimId}")
    appendLine("Patient: ${enc.patientId}")
    appendLine("E/M Code: ${claim.emCode} (Level ${claim.emLevel})")
    appendLine()
    appendLine("DIAGNOSES:")
    diagnoses.forEachIndexed { i, dx ->
        appendLine("  ${i + 1}. ${dx.icd10Code} — ${dx.description}")
    }
    appendLine()
    appendLine("PROCEDURES:")
    claim.claimLines.forEach { line ->
        appendLine("  ${line.cptCode} — ${line.description} — R${"%.2f".format(line.tariffZAR)}")
    }
    appendLine()
    appendLine("TOTAL: R${"%.2f".format(claim.totalZAR)} (≈\$${"%.2f".format(claim.totalUSD)})")
}

@Composable
private fun SectionCard(
    icon: ImageVector,
    title: String,
    content: @Composable ColumnScope.() -> Unit
) {
    Card(modifier = Modifier.fillMaxWidth().animateContentSize()) {
        Column(modifier = Modifier.padding(16.dp)) {
            Row(
                verticalAlignment = Alignment.CenterVertically,
                modifier = Modifier.padding(bottom = 8.dp)
            ) {
                Icon(icon, contentDescription = title,
                    modifier = Modifier.size(20.dp),
                    tint = MaterialTheme.colorScheme.primary)
                Spacer(Modifier.width(8.dp))
                Text(title,
                    style = MaterialTheme.typography.titleMedium,
                    fontWeight = FontWeight.SemiBold)
            }
            content()
        }
    }
}

@Composable
private fun ConfidenceBadge(confidence: Float) {
    val color = when {
        confidence >= 0.8f -> BrandGreen
        confidence >= 0.5f -> WarningAmber
        else -> AlertRed
    }
    Surface(
        color = color.copy(alpha = 0.1f),
        shape = RoundedCornerShape(4.dp)
    ) {
        Text(
            "${"%.0f".format(confidence * 100)}%",
            modifier = Modifier.padding(horizontal = 6.dp, vertical = 2.dp),
            style = MaterialTheme.typography.labelSmall,
            color = color,
            fontWeight = FontWeight.Bold
        )
    }
}

/** Format a dose value, keeping decimals only when meaningful (e.g. 500 → "500", 2.5 → "2.5"). */
private fun formatDose(dose: Float): String =
    if (dose % 1.0f == 0f) "${dose.toInt()}" else "%.1f".format(dose)

/** Safely parse a JSON string to a typed list, returning an empty list on null or parse error. */
private inline fun <reified T> Gson.parseListOrEmpty(json: String?): List<T> = try {
    fromJson<List<T>>(json, object : TypeToken<List<T>>() {}.type) ?: emptyList()
} catch (_: Exception) { emptyList() }
