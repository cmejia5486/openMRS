package com.chartlite.app.ui.screens

import android.content.Context
import android.net.Uri
import android.provider.Telephony
import androidx.compose.foundation.clickable
import androidx.compose.foundation.layout.*
import androidx.compose.foundation.rememberScrollState
import androidx.compose.foundation.text.KeyboardOptions
import androidx.compose.foundation.verticalScroll
import androidx.compose.material.icons.Icons
import androidx.compose.material.icons.automirrored.filled.ArrowBack
import androidx.compose.material.icons.filled.Lock
import androidx.compose.material.icons.filled.Sms
import androidx.compose.material3.*
import androidx.compose.runtime.*
import androidx.compose.runtime.saveable.rememberSaveable
import androidx.compose.ui.Alignment
import androidx.compose.ui.Modifier
import androidx.compose.ui.platform.LocalContext
import androidx.compose.ui.text.font.FontWeight
import androidx.compose.ui.text.input.KeyboardType
import androidx.compose.ui.text.input.PasswordVisualTransformation
import androidx.compose.ui.unit.dp
import com.chartlite.app.App
import com.chartlite.app.sms.DecryptResult
import com.chartlite.app.sms.DecodedEncounter
import com.chartlite.app.sms.DecodedEncounterV2
import com.chartlite.app.sms.DecodedEncounterV3
import com.chartlite.app.sms.DecodedEncounterV4
import com.chartlite.app.sms.BinaryDecodeLookup
import com.chartlite.app.sms.SMSEncryption
import com.chartlite.app.sms.DecodedChronicCondition
import com.chartlite.app.sms.DecodedAbnormalVital
import androidx.compose.material.icons.filled.PersonAdd
import androidx.compose.ui.res.stringResource
import com.chartlite.app.R
import com.chartlite.app.ui.theme.*
import kotlinx.coroutines.Dispatchers
import kotlinx.coroutines.launch
import kotlinx.coroutines.withContext
import java.text.SimpleDateFormat
import java.time.format.DateTimeFormatter
import java.util.Date
import java.util.Locale

private data class PendingSMS(
    val sender: String,
    val timestamp: Long,
    val body: String
)

@OptIn(ExperimentalMaterial3Api::class)
@Composable
fun SMSDecryptScreen(
    onRegisterFromSMS: ((patientId: String?, allergies: List<String>, decoded: DecodedEncounterV4?) -> Unit)? = null,
    onBack: () -> Unit
) {
    val context = LocalContext.current
    val app = context.applicationContext as App
    val scope = rememberCoroutineScope()

    // ── SMS permissions — RECEIVE_SMS for broadcast receiver, READ_SMS for inbox scan ──
    var smsPermissionGranted by remember {
        mutableStateOf(
            androidx.core.content.ContextCompat.checkSelfPermission(
                context, android.Manifest.permission.RECEIVE_SMS
            ) == android.content.pm.PackageManager.PERMISSION_GRANTED ||
            androidx.core.content.ContextCompat.checkSelfPermission(
                context, android.Manifest.permission.READ_SMS
            ) == android.content.pm.PackageManager.PERMISSION_GRANTED
        )
    }
    val smsPermissionLauncher = androidx.activity.compose.rememberLauncherForActivityResult(
        androidx.activity.result.contract.ActivityResultContracts.RequestMultiplePermissions()
    ) { results -> smsPermissionGranted = results.values.any { it } }
    LaunchedEffect(Unit) {
        if (!smsPermissionGranted) {
            smsPermissionLauncher.launch(arrayOf(
                android.Manifest.permission.RECEIVE_SMS,
                android.Manifest.permission.READ_SMS
            ))
        }
    }

    // Load pending SMS: first from broadcast receiver store, then scan device inbox as fallback
    val pendingSMS = remember(smsPermissionGranted) {
        val fromReceiver = loadPendingSMS(context)
        if (fromReceiver.isNotEmpty()) {
            fromReceiver
        } else {
            // Fallback: scan SMS inbox for clinical messages (catches SMS received
            // before RECEIVE_SMS permission was granted or broadcast was missed)
            scanSmsInbox(context)
        }
    }

    var phoneNumber by remember { mutableStateOf("") }
    var pin by remember { mutableStateOf("") }
    var showPinField by rememberSaveable { mutableStateOf(false) }
    var smsContent by remember { mutableStateOf("") }
    var selectedSmsIndex by remember { mutableStateOf(-1) }
    var decryptedEncounter by remember { mutableStateOf<DecodedEncounter?>(null) }
    var decryptedV2 by remember { mutableStateOf<DecodedEncounterV2?>(null) }
    var decryptedV3 by remember { mutableStateOf<DecodedEncounterV3?>(null) }
    var decryptedV4 by remember { mutableStateOf<DecodedEncounterV4?>(null) }
    var error by remember { mutableStateOf<String?>(null) }
    var isDecrypting by remember { mutableStateOf(false) }
    var showManualInput by remember { mutableStateOf(false) }

    Scaffold(
        topBar = {
            TopAppBar(
                title = { Text(stringResource(R.string.read_patient_sms)) },
                navigationIcon = {
                    IconButton(onClick = onBack) {
                        Icon(Icons.AutoMirrored.Filled.ArrowBack, stringResource(R.string.back))
                    }
                }
            )
        }
    ) { padding ->
        Column(
            modifier = Modifier
                .fillMaxSize()
                .padding(padding)
                .imePadding()
                .padding(16.dp)
                .verticalScroll(rememberScrollState()),
            verticalArrangement = Arrangement.spacedBy(12.dp)
        ) {
            // Instructions
            Card(
                colors = CardDefaults.cardColors(
                    containerColor = MaterialTheme.colorScheme.secondaryContainer
                )
            ) {
                Row(modifier = Modifier.padding(16.dp)) {
                    Icon(Icons.Default.Sms, contentDescription = "SMS icon",
                        modifier = Modifier.size(24.dp))
                    Spacer(Modifier.width(12.dp))
                    Column {
                        Text(stringResource(R.string.decrypt_clinical_sms),
                            style = MaterialTheme.typography.titleSmall,
                            fontWeight = FontWeight.Bold)
                        Text(stringResource(R.string.sms_decrypt_instruction),
                            style = MaterialTheme.typography.bodySmall)
                    }
                }
            }

            // ── Pending SMS list ──
            if (pendingSMS.isNotEmpty()) {
                Text(stringResource(R.string.received_clinical_sms_count, pendingSMS.size),
                    style = MaterialTheme.typography.titleSmall)

                pendingSMS.forEachIndexed { index, sms ->
                    val dateStr = SimpleDateFormat("dd/MM/yyyy HH:mm", Locale.getDefault())
                        .format(Date(sms.timestamp))
                    val isSelected = selectedSmsIndex == index

                    Card(
                        modifier = Modifier
                            .fillMaxWidth()
                            .clickable {
                                selectedSmsIndex = index
                                smsContent = sms.body
                                phoneNumber = sms.sender  // Auto-fill — sender's phone IS the key
                                error = null
                                decryptedEncounter = null
                                decryptedV2 = null
                                decryptedV3 = null
                                decryptedV4 = null
                            },
                        colors = CardDefaults.cardColors(
                            containerColor = if (isSelected)
                                MaterialTheme.colorScheme.primaryContainer
                            else
                                MaterialTheme.colorScheme.surfaceVariant
                        )
                    ) {
                        Row(
                            modifier = Modifier.padding(12.dp),
                            verticalAlignment = Alignment.CenterVertically
                        ) {
                            RadioButton(
                                selected = isSelected,
                                onClick = {
                                    selectedSmsIndex = index
                                    smsContent = sms.body
                                    phoneNumber = sms.sender
                                    error = null
                                    decryptedEncounter = null
                                    decryptedV2 = null
                                    decryptedV3 = null
                                    decryptedV4 = null
                                }
                            )
                            Spacer(Modifier.width(8.dp))
                            Column {
                                Text(stringResource(R.string.from_sender, sms.sender),
                                    style = MaterialTheme.typography.bodyMedium,
                                    fontWeight = FontWeight.Medium)
                                Text(dateStr,
                                    style = MaterialTheme.typography.bodyMedium,
                                    color = MaterialTheme.colorScheme.onSurfaceVariant)
                            }
                        }
                    }
                }

                HorizontalDivider(modifier = Modifier.padding(vertical = 4.dp))
            } else {
                // No pending SMS
                Card(
                    modifier = Modifier.fillMaxWidth(),
                    colors = CardDefaults.cardColors(
                        containerColor = MaterialTheme.colorScheme.surfaceVariant
                    )
                ) {
                    Column(
                        modifier = Modifier.padding(16.dp),
                        horizontalAlignment = Alignment.CenterHorizontally
                    ) {
                        Text(stringResource(R.string.no_clinical_sms_received),
                            style = MaterialTheme.typography.bodyMedium)
                        Text(stringResource(R.string.sms_auto_appear),
                            style = MaterialTheme.typography.bodySmall,
                            color = MaterialTheme.colorScheme.onSurfaceVariant)
                    }
                }
            }

            // Manual paste option
            TextButton(onClick = { showManualInput = !showManualInput }) {
                Text(if (showManualInput) stringResource(R.string.hide_manual_input) else stringResource(R.string.paste_sms_manually))
            }

            if (showManualInput) {
                OutlinedTextField(
                    value = smsContent,
                    onValueChange = {
                        smsContent = it
                        selectedSmsIndex = -1
                    },
                    label = { Text(stringResource(R.string.paste_encrypted_sms)) },
                    modifier = Modifier.fillMaxWidth().heightIn(min = 80.dp),
                    maxLines = 4
                )
            }

            // ── Credentials ──
            OutlinedTextField(
                value = phoneNumber,
                onValueChange = { phoneNumber = it },
                label = { Text(stringResource(R.string.patient_phone_number)) },
                modifier = Modifier.fillMaxWidth(),
                leadingIcon = { Icon(Icons.Default.Sms, "Phone") },
                keyboardOptions = KeyboardOptions(keyboardType = KeyboardType.Phone),
                singleLine = true
            )

            // Optional PIN for shared-phone privacy
            TextButton(onClick = { showPinField = !showPinField }) {
                Text(if (showPinField) stringResource(R.string.hide_pin_field) else stringResource(R.string.patient_has_pin))
            }

            if (showPinField) {
                OutlinedTextField(
                    value = pin,
                    onValueChange = { if (it.length <= 4) pin = it },
                    label = { Text(stringResource(R.string.optional_pin_4digits)) },
                    modifier = Modifier.fillMaxWidth(),
                    leadingIcon = { Icon(Icons.Default.Lock, "PIN") },
                    keyboardOptions = KeyboardOptions(keyboardType = KeyboardType.NumberPassword),
                    visualTransformation = PasswordVisualTransformation(),
                    singleLine = true
                )
            }

            // Decrypt button
            val decryptionFailedMsg = stringResource(R.string.decryption_failed)
            Button(
                onClick = {
                    isDecrypting = true
                    error = null
                    decryptedV2 = null
                    decryptedV3 = null
                    decryptedV4 = null
                    scope.launch {
                        val result = withContext(Dispatchers.Default) {
                            try {
                                app.smsSender.decryptSMSWithVersion(smsContent.trim(), phoneNumber.trim(), pin.ifBlank { null })
                            } catch (e: Exception) {
                                null
                            }
                        }
                        when (result) {
                            is DecryptResult.V1 -> {
                                decryptedEncounter = result.encounter
                                decryptedV2 = null; decryptedV3 = null; decryptedV4 = null
                            }
                            is DecryptResult.V2 -> {
                                decryptedEncounter = result.data.encounter
                                decryptedV2 = result.data
                                decryptedV3 = null; decryptedV4 = null
                            }
                            is DecryptResult.V3 -> {
                                decryptedEncounter = result.data.encounter
                                decryptedV2 = null; decryptedV4 = null
                                decryptedV3 = result.data
                            }
                            is DecryptResult.V4 -> {
                                decryptedEncounter = result.data.encounter
                                decryptedV2 = null; decryptedV3 = null
                                decryptedV4 = result.data
                            }
                            null -> {
                                error = decryptionFailedMsg
                            }
                        }
                        isDecrypting = false
                    }
                },
                enabled = phoneNumber.isNotBlank() && smsContent.isNotBlank() && !isDecrypting,
                modifier = Modifier.fillMaxWidth()
            ) {
                if (isDecrypting) {
                    CircularProgressIndicator(modifier = Modifier.size(20.dp),
                        color = MaterialTheme.colorScheme.onPrimary)
                } else {
                    Text(stringResource(R.string.decrypt))
                }
            }

            // Error
            error?.let {
                Card(
                    colors = CardDefaults.cardColors(
                        containerColor = MaterialTheme.colorScheme.errorContainer
                    )
                ) {
                    Text(it, modifier = Modifier.padding(16.dp),
                        color = MaterialTheme.colorScheme.onErrorContainer)
                }
            }

            // Decrypted result
            decryptedEncounter?.let { enc ->
                HorizontalDivider()
                Text(stringResource(R.string.decrypted_record), style = MaterialTheme.typography.titleLarge)

                // V3/V4: Show patient ID
                val smsPatientIdDisplay = decryptedV4?.patientId ?: decryptedV3?.patientId
                smsPatientIdDisplay?.let { pid ->
                    Card(
                        modifier = Modifier.fillMaxWidth(),
                        colors = CardDefaults.cardColors(
                            containerColor = MaterialTheme.colorScheme.primaryContainer
                        )
                    ) {
                        Row(
                            modifier = Modifier.padding(16.dp),
                            verticalAlignment = Alignment.CenterVertically
                        ) {
                            Text("Patient ID: ",
                                style = MaterialTheme.typography.bodyMedium,
                                color = MaterialTheme.colorScheme.onPrimaryContainer)
                            Text(pid,
                                style = MaterialTheme.typography.titleMedium,
                                fontWeight = FontWeight.Bold,
                                color = MaterialTheme.colorScheme.onPrimaryContainer)
                        }
                    }
                }

                Card(modifier = Modifier.fillMaxWidth()) {
                    Column(modifier = Modifier.padding(16.dp),
                        verticalArrangement = Arrangement.spacedBy(8.dp)) {

                        DetailRow("Date", enc.date.format(DateTimeFormatter.ISO_LOCAL_DATE))
                        // Only show vitals that were actually recorded — skip encoding defaults.
                        // BinaryEncoder uses 120/80 for null BP and 37.0 for null temp.
                        if (enc.systolicBP != 120 || enc.diastolicBP != 80) {
                            DetailRow("BP", "${enc.systolicBP}/${enc.diastolicBP} mmHg")
                        }
                        if (enc.temperature != 37.0f && enc.temperature > 0f) {
                            DetailRow("Temperature", "${"%.1f".format(enc.temperature)}°C")
                        }
                        if (enc.pulse > 0) DetailRow("Pulse", "${enc.pulse} bpm")
                        if (enc.weight > 0) DetailRow("Weight", "${enc.weight} kg")

                        // V4 expanded vitals
                        decryptedV4?.let { v4 ->
                            if (v4.height > 0) DetailRow("Height", "${v4.height} cm")
                            if (v4.spo2 > 70) DetailRow("SpO2", "${v4.spo2}%")
                            if (v4.respiratoryRateCode > 0) DetailRow("Resp. Rate", v4.respiratoryRateLabel + " /min")
                            if (v4.freeText.isNotBlank()) DetailRow("Note", v4.freeText)
                        }

                        if (enc.medications.isNotEmpty()) {
                            Text("Medications:", fontWeight = FontWeight.Bold,
                                style = MaterialTheme.typography.bodyMedium)
                            enc.medications.forEach { med ->
                                Text("  Drug #${med.drugIndex}, Dose code: ${med.doseCode}, Freq code: ${med.freqCode}",
                                    style = MaterialTheme.typography.bodySmall)
                            }
                        }

                        if (enc.diagnosisIndices.isNotEmpty()) {
                            Text("Diagnoses:", fontWeight = FontWeight.Bold,
                                style = MaterialTheme.typography.bodyMedium)
                            Text("  Indices: ${enc.diagnosisIndices.joinToString(", ")}",
                                style = MaterialTheme.typography.bodySmall)
                        }

                        enc.followUpDays?.let {
                            DetailRow("Follow-up", "$it days")
                        }
                    }
                }

                // ── Health History Section (v2, v3, or v4) ──
                val historyData = decryptedV4?.let { v4 ->
                    HistoryDisplayData(v4.totalVisits, v4.chronicConditions, v4.abnormalVitals, v4.cumulativeAllergyFlags)
                } ?: decryptedV3?.let { v3 ->
                    HistoryDisplayData(v3.totalVisits, v3.chronicConditions, v3.abnormalVitals, v3.cumulativeAllergyFlags)
                } ?: decryptedV2?.let { v2 ->
                    HistoryDisplayData(v2.totalVisits, v2.chronicConditions, v2.abnormalVitals, v2.cumulativeAllergyFlags)
                }

                historyData?.let { hist ->
                    Spacer(Modifier.height(8.dp))
                    Text(stringResource(R.string.patient_health_history),
                        style = MaterialTheme.typography.titleLarge,
                        fontWeight = FontWeight.Bold)
                    Text(stringResource(R.string.total_visits_format, hist.totalVisits),
                        style = MaterialTheme.typography.bodySmall,
                        color = MaterialTheme.colorScheme.onSurfaceVariant)

                    // Chronic conditions
                    if (hist.chronicConditions.isNotEmpty()) {
                        Card(
                            modifier = Modifier.fillMaxWidth(),
                            colors = CardDefaults.cardColors(
                                containerColor = MaterialTheme.colorScheme.errorContainer.copy(alpha = 0.3f)
                            )
                        ) {
                            Column(modifier = Modifier.padding(16.dp),
                                verticalArrangement = Arrangement.spacedBy(6.dp)) {
                                Text(stringResource(R.string.recurring_conditions),
                                    fontWeight = FontWeight.Bold,
                                    style = MaterialTheme.typography.bodyMedium,
                                    color = MaterialTheme.colorScheme.error)
                                hist.chronicConditions.forEach { cc ->
                                    Text("  Code #${cc.icdHashIndex} — seen ${cc.occurrenceCount} times",
                                        style = MaterialTheme.typography.bodySmall)
                                }
                            }
                        }
                    }

                    // Abnormal vitals history
                    if (hist.abnormalVitals.isNotEmpty()) {
                        Card(
                            modifier = Modifier.fillMaxWidth(),
                            colors = CardDefaults.cardColors(
                                containerColor = MaterialTheme.colorScheme.tertiaryContainer.copy(alpha = 0.3f)
                            )
                        ) {
                            Column(modifier = Modifier.padding(16.dp),
                                verticalArrangement = Arrangement.spacedBy(6.dp)) {
                                Text(stringResource(R.string.abnormal_vitals_history),
                                    fontWeight = FontWeight.Bold,
                                    style = MaterialTheme.typography.bodyMedium)
                                hist.abnormalVitals.forEach { av ->
                                    DetailRow(
                                        "${av.vitalLabel} (${av.date.format(java.time.format.DateTimeFormatter.ISO_LOCAL_DATE)})",
                                        av.displayValue
                                    )
                                }
                            }
                        }
                    }

                    // Cumulative allergies
                    val allergyNames = BinaryDecodeLookup.allergyLabels(hist.cumulativeAllergyFlags)

                    if (allergyNames.isNotEmpty()) {
                        Card(
                            modifier = Modifier.fillMaxWidth(),
                            colors = CardDefaults.cardColors(
                                containerColor = MaterialTheme.colorScheme.errorContainer
                            )
                        ) {
                            Column(modifier = Modifier.padding(16.dp)) {
                                Text(stringResource(R.string.known_allergies_label),
                                    fontWeight = FontWeight.Bold,
                                    style = MaterialTheme.typography.bodyMedium,
                                    color = MaterialTheme.colorScheme.onErrorContainer)
                                Text(allergyNames.joinToString(", "),
                                    style = MaterialTheme.typography.bodySmall,
                                    color = MaterialTheme.colorScheme.onErrorContainer)
                            }
                        }
                    }
                }

                // ── V4-specific sections: Growth, Immunizations, Clinical Status ──
                decryptedV4?.let { v4 ->
                    // Growth Summary
                    v4.growth?.let { g ->
                        Card(
                            modifier = Modifier.fillMaxWidth(),
                            colors = CardDefaults.cardColors(
                                containerColor = MaterialTheme.colorScheme.secondaryContainer.copy(alpha = 0.5f)
                            )
                        ) {
                            Column(modifier = Modifier.padding(16.dp),
                                verticalArrangement = Arrangement.spacedBy(6.dp)) {
                                Text("Growth Summary",
                                    fontWeight = FontWeight.Bold,
                                    style = MaterialTheme.typography.bodyMedium)
                                DetailRow("Weight", "${g.weightKg} kg")
                                DetailRow("Height", "${g.heightCm} cm")
                                DetailRow("Weight Z-score", "${"%.1f".format(g.weightZScore)}")
                                DetailRow("Height Z-score", "${"%.1f".format(g.heightZScore)}")
                            }
                        }
                    }

                    // Immunization History
                    if (v4.immunizations.isNotEmpty()) {
                        Card(
                            modifier = Modifier.fillMaxWidth(),
                            colors = CardDefaults.cardColors(
                                containerColor = MaterialTheme.colorScheme.tertiaryContainer.copy(alpha = 0.5f)
                            )
                        ) {
                            Column(modifier = Modifier.padding(16.dp),
                                verticalArrangement = Arrangement.spacedBy(6.dp)) {
                                Text("Immunization History",
                                    fontWeight = FontWeight.Bold,
                                    style = MaterialTheme.typography.bodyMedium)
                                v4.immunizations.forEach { imm ->
                                    DetailRow(imm.vaccineCode, "Dose ${imm.doseNumber}")
                                }
                            }
                        }
                    }

                    // Clinical Status Flags
                    val allFlags = v4.clinicalStatus1Labels + v4.clinicalStatus2Labels
                    if (allFlags.isNotEmpty()) {
                        Card(
                            modifier = Modifier.fillMaxWidth(),
                            colors = CardDefaults.cardColors(
                                containerColor = MaterialTheme.colorScheme.errorContainer.copy(alpha = 0.5f)
                            )
                        ) {
                            Column(modifier = Modifier.padding(16.dp),
                                verticalArrangement = Arrangement.spacedBy(4.dp)) {
                                Text("Clinical Status",
                                    fontWeight = FontWeight.Bold,
                                    style = MaterialTheme.typography.bodyMedium,
                                    color = MaterialTheme.colorScheme.error)
                                allFlags.forEach { flag ->
                                    Text("• $flag",
                                        style = MaterialTheme.typography.bodySmall,
                                        color = MaterialTheme.colorScheme.onErrorContainer)
                                }
                            }
                        }
                    }
                }

                // Register Patient from SMS button
                if (onRegisterFromSMS != null) {
                    Spacer(Modifier.height(16.dp))

                    // Collect decoded allergy names to pre-fill
                    val allergyFlags = decryptedV4?.cumulativeAllergyFlags
                        ?: decryptedV3?.cumulativeAllergyFlags
                        ?: decryptedV2?.cumulativeAllergyFlags
                        ?: decryptedEncounter?.allergyFlags ?: 0
                    val smsPatientId = decryptedV4?.patientId ?: decryptedV3?.patientId
                    val decodedAllergies = BinaryDecodeLookup.allergyLabels(allergyFlags)

                    Button(
                        onClick = { onRegisterFromSMS(smsPatientId, decodedAllergies, decryptedV4) },
                        modifier = Modifier.fillMaxWidth().height(52.dp),
                        shape = MaterialTheme.shapes.medium
                    ) {
                        Icon(Icons.Default.PersonAdd, contentDescription = "Add patient",
                            modifier = Modifier.size(20.dp))
                        Spacer(Modifier.width(8.dp))
                        Text(
                            if (smsPatientId != null) stringResource(R.string.import_patient_format, smsPatientId)
                            else stringResource(R.string.register_patient_from_sms),
                            style = MaterialTheme.typography.titleMedium
                        )
                    }
                }
            }
        }
    }
}

/** Unified history data for display — v2 and v3 share the same fields. */
private data class HistoryDisplayData(
    val totalVisits: Int,
    val chronicConditions: List<DecodedChronicCondition>,
    val abnormalVitals: List<DecodedAbnormalVital>,
    val cumulativeAllergyFlags: Int
)

/** Load pending SMS stored by SMSReceiver. */
private fun loadPendingSMS(context: Context): List<PendingSMS> {
    val prefs = context.getSharedPreferences("pending_sms", Context.MODE_PRIVATE)
    val messages = prefs.getStringSet("messages", emptySet()) ?: emptySet()

    return messages.mapNotNull { entry ->
        val parts = entry.split("|", limit = 3)
        if (parts.size == 3) {
            PendingSMS(
                sender = parts[0],
                timestamp = parts[1].toLongOrNull() ?: 0L,
                body = parts[2]
            )
        } else null
    }.sortedByDescending { it.timestamp }
}

/**
 * Scan the device SMS inbox for clinical messages.
 * Fallback for when the BroadcastReceiver missed messages (e.g., RECEIVE_SMS permission
 * wasn't granted when the SMS arrived). Scans the last 50 received SMS.
 */
private fun scanSmsInbox(context: Context): List<PendingSMS> {
    val hasReadSms = androidx.core.content.ContextCompat.checkSelfPermission(
        context, android.Manifest.permission.READ_SMS
    ) == android.content.pm.PackageManager.PERMISSION_GRANTED
    if (!hasReadSms) return emptyList()

    val results = mutableListOf<PendingSMS>()
    try {
        val cursor = context.contentResolver.query(
            Telephony.Sms.Inbox.CONTENT_URI,
            arrayOf(Telephony.Sms.ADDRESS, Telephony.Sms.DATE, Telephony.Sms.BODY),
            null, null,
            "${Telephony.Sms.DATE} DESC LIMIT 50"
        )
        cursor?.use {
            val addrIdx = it.getColumnIndexOrThrow(Telephony.Sms.ADDRESS)
            val dateIdx = it.getColumnIndexOrThrow(Telephony.Sms.DATE)
            val bodyIdx = it.getColumnIndexOrThrow(Telephony.Sms.BODY)
            while (it.moveToNext()) {
                val body = it.getString(bodyIdx) ?: continue
                if (SMSEncryption.looksLikeClinicalSMS(body)) {
                    results.add(PendingSMS(
                        sender = it.getString(addrIdx) ?: "Unknown",
                        timestamp = it.getLong(dateIdx),
                        body = body
                    ))
                }
            }
        }
    } catch (_: Exception) {
        // ContentResolver query can fail on some devices
    }
    return results
}

@Composable
private fun DetailRow(label: String, value: String) {
    Row(
        modifier = Modifier.fillMaxWidth(),
        horizontalArrangement = Arrangement.SpaceBetween
    ) {
        Text(label, style = MaterialTheme.typography.bodyMedium,
            color = MaterialTheme.colorScheme.onSurfaceVariant)
        Text(value, style = MaterialTheme.typography.bodyMedium,
            fontWeight = FontWeight.Medium)
    }
}
