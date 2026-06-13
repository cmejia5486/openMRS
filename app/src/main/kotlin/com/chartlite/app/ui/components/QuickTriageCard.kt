package com.chartlite.app.ui.components

import androidx.compose.animation.animateContentSize
import androidx.compose.foundation.layout.*
import androidx.compose.foundation.shape.RoundedCornerShape
import androidx.compose.foundation.text.KeyboardOptions
import androidx.compose.material.icons.Icons
import androidx.compose.material.icons.filled.MonitorHeart
import androidx.compose.material3.*
import androidx.compose.runtime.*
import androidx.compose.runtime.saveable.rememberSaveable
import androidx.compose.ui.Alignment
import androidx.compose.ui.Modifier
import androidx.compose.ui.graphics.Color
import androidx.compose.ui.text.font.FontWeight
import androidx.compose.ui.text.input.KeyboardType
import androidx.compose.ui.text.style.TextOverflow
import androidx.compose.ui.unit.dp
import com.chartlite.app.ui.theme.*
import androidx.compose.ui.res.stringResource
import com.chartlite.app.R

/**
 * An expandable card for inline 30-second triage on the HomeScreen.
 *
 * When collapsed it shows the patient name/ID and a "Triage" button.
 * When expanded it reveals a compact vital-signs form with chief complaint
 * and priority selection, plus actions to save or navigate to full triage.
 *
 * @param patientName full name of the patient
 * @param patientId formatted patient ID (e.g. "KFMT-4WRN")
 * @param expanded whether the triage form is visible
 * @param onToggle expand or collapse the card
 * @param onSave callback with captured vitals, chief complaint, and priority
 * @param onFullTriage navigate to the full voice-based triage screen
 */
@OptIn(ExperimentalMaterial3Api::class)
@Composable
fun QuickTriageCard(
    patientName: String,
    patientId: String,
    expanded: Boolean,
    onToggle: () -> Unit,
    onSave: (
        systolic: Int?,
        diastolic: Int?,
        temp: Float?,
        pulse: Int?,
        spo2: Int?,
        weight: Float?,
        chiefComplaint: String,
        priority: Int
    ) -> Unit,
    onFullTriage: () -> Unit,
    modifier: Modifier = Modifier
) {
    // ── Internal form state ──
    var systolicText by remember { mutableStateOf("") }
    var diastolicText by remember { mutableStateOf("") }
    var tempText by remember { mutableStateOf("") }
    var pulseText by remember { mutableStateOf("") }
    var spo2Text by remember { mutableStateOf("") }
    var weightText by remember { mutableStateOf("") }
    var chiefComplaint by remember { mutableStateOf("") }
    var priority by rememberSaveable { mutableIntStateOf(0) }

    Card(
        modifier = modifier
            .fillMaxWidth()
            .animateContentSize(),
        shape = RoundedCornerShape(14.dp),
        colors = CardDefaults.cardColors(containerColor = Color.White),
        elevation = CardDefaults.cardElevation(defaultElevation = 1.dp)
    ) {
        Column(modifier = Modifier.padding(14.dp)) {
            // ── Collapsed header (always visible) ──
            Row(
                modifier = Modifier.fillMaxWidth(),
                verticalAlignment = Alignment.CenterVertically
            ) {
                // Patient info
                Column(modifier = Modifier.weight(1f)) {
                    Text(
                        text = patientName,
                        style = MaterialTheme.typography.titleSmall,
                        fontWeight = FontWeight.SemiBold,
                        maxLines = 1,
                        overflow = TextOverflow.Ellipsis
                    )
                    Text(
                        text = patientId,
                        style = MaterialTheme.typography.bodySmall,
                        color = Neutral500
                    )
                }

                // Triage toggle button
                Button(
                    onClick = onToggle,
                    colors = ButtonDefaults.buttonColors(
                        containerColor = if (expanded) BrandGreenDark else BrandGreen
                    ),
                    shape = RoundedCornerShape(10.dp),
                    contentPadding = PaddingValues(horizontal = 14.dp, vertical = 6.dp)
                ) {
                    Icon(
                        Icons.Default.MonitorHeart,
                        contentDescription = null,
                        modifier = Modifier.size(16.dp)
                    )
                    Spacer(Modifier.width(6.dp))
                    Text(
                        text = stringResource(R.string.triage_button),
                        style = MaterialTheme.typography.labelLarge
                    )
                }
            }

            // ── Expanded form ──
            if (expanded) {
                Spacer(Modifier.height(14.dp))

                HorizontalDivider(color = Neutral200)

                Spacer(Modifier.height(14.dp))

                // Row 1: Blood pressure
                Row(
                    modifier = Modifier.fillMaxWidth(),
                    horizontalArrangement = Arrangement.spacedBy(10.dp)
                ) {
                    VitalField(
                        value = systolicText,
                        onValueChange = { systolicText = it },
                        label = "Systolic",
                        suffix = "mmHg",
                        modifier = Modifier.weight(1f)
                    )
                    VitalField(
                        value = diastolicText,
                        onValueChange = { diastolicText = it },
                        label = "Diastolic",
                        suffix = "mmHg",
                        modifier = Modifier.weight(1f)
                    )
                }

                Spacer(Modifier.height(10.dp))

                // Row 2: Temp + Pulse
                Row(
                    modifier = Modifier.fillMaxWidth(),
                    horizontalArrangement = Arrangement.spacedBy(10.dp)
                ) {
                    VitalField(
                        value = tempText,
                        onValueChange = { tempText = it },
                        label = "Temp",
                        suffix = "\u00B0C",
                        allowDecimal = true,
                        modifier = Modifier.weight(1f)
                    )
                    VitalField(
                        value = pulseText,
                        onValueChange = { pulseText = it },
                        label = "Pulse",
                        suffix = "bpm",
                        modifier = Modifier.weight(1f)
                    )
                }

                Spacer(Modifier.height(10.dp))

                // Row 3: SpO2 + Weight
                Row(
                    modifier = Modifier.fillMaxWidth(),
                    horizontalArrangement = Arrangement.spacedBy(10.dp)
                ) {
                    VitalField(
                        value = spo2Text,
                        onValueChange = { spo2Text = it },
                        label = "SpO2",
                        suffix = "%",
                        modifier = Modifier.weight(1f)
                    )
                    VitalField(
                        value = weightText,
                        onValueChange = { weightText = it },
                        label = "Weight",
                        suffix = "kg",
                        allowDecimal = true,
                        modifier = Modifier.weight(1f)
                    )
                }

                Spacer(Modifier.height(10.dp))

                // Chief complaint (full width)
                OutlinedTextField(
                    value = chiefComplaint,
                    onValueChange = { chiefComplaint = it },
                    label = { Text(stringResource(R.string.chief_complaint_field)) },
                    modifier = Modifier.fillMaxWidth(),
                    singleLine = false,
                    maxLines = 2,
                    shape = RoundedCornerShape(10.dp),
                    colors = OutlinedTextFieldDefaults.colors(
                        focusedBorderColor = BrandGreen,
                        focusedLabelColor = BrandGreen,
                        cursorColor = BrandGreen
                    )
                )

                Spacer(Modifier.height(12.dp))

                // Priority selection chips
                Text(
                    text = stringResource(R.string.priority_label),
                    style = MaterialTheme.typography.labelMedium,
                    color = Neutral600
                )
                Spacer(Modifier.height(6.dp))

                Row(
                    horizontalArrangement = Arrangement.spacedBy(8.dp)
                ) {
                    PriorityChip(
                        label = stringResource(R.string.priority_normal),
                        chipColor = BrandGreen,
                        isSelected = priority == 0,
                        onClick = { priority = 0 }
                    )
                    PriorityChip(
                        label = stringResource(R.string.priority_priority),
                        chipColor = WarningAmber,
                        isSelected = priority == 1,
                        onClick = { priority = 1 }
                    )
                    PriorityChip(
                        label = stringResource(R.string.priority_emergency),
                        chipColor = AlertRed,
                        isSelected = priority == 2,
                        onClick = { priority = 2 }
                    )
                }

                Spacer(Modifier.height(14.dp))

                // Action buttons
                Row(
                    modifier = Modifier.fillMaxWidth(),
                    horizontalArrangement = Arrangement.spacedBy(10.dp),
                    verticalAlignment = Alignment.CenterVertically
                ) {
                    // Save & send
                    Button(
                        onClick = {
                            onSave(
                                systolicText.toIntOrNull(),
                                diastolicText.toIntOrNull(),
                                tempText.toFloatOrNull(),
                                pulseText.toIntOrNull(),
                                spo2Text.toIntOrNull(),
                                weightText.toFloatOrNull(),
                                chiefComplaint,
                                priority
                            )
                        },
                        modifier = Modifier.weight(1f),
                        colors = ButtonDefaults.buttonColors(containerColor = BrandGreen),
                        shape = RoundedCornerShape(10.dp)
                    ) {
                        Text(
                            text = stringResource(R.string.save_send_consultation),
                            style = MaterialTheme.typography.labelLarge,
                            maxLines = 1
                        )
                    }

                    // Full triage navigation
                    TextButton(
                        onClick = onFullTriage,
                        shape = RoundedCornerShape(10.dp)
                    ) {
                        Text(
                            text = stringResource(R.string.full_triage),
                            style = MaterialTheme.typography.labelLarge,
                            color = BrandGreen,
                            fontWeight = FontWeight.Medium
                        )
                    }
                }
            }
        }
    }
}

// ────────────────────────────────────────────────────────────────────────────
// Private helper composables
// ────────────────────────────────────────────────────────────────────────────

/**
 * Compact numeric OutlinedTextField used for vital signs.
 */
@Composable
private fun VitalField(
    value: String,
    onValueChange: (String) -> Unit,
    label: String,
    suffix: String,
    modifier: Modifier = Modifier,
    allowDecimal: Boolean = false
) {
    OutlinedTextField(
        value = value,
        onValueChange = { text ->
            // Allow only valid numeric input
            val filtered = if (allowDecimal) {
                val raw = text.filter { it.isDigit() || it == '.' }
                // Reject if more than one decimal point (e.g., "36.5.2")
                if (raw.count { it == '.' } > 1) value else raw
            } else {
                text.filter { it.isDigit() }
            }
            onValueChange(filtered)
        },
        label = { Text(label) },
        suffix = { Text(suffix, style = MaterialTheme.typography.labelSmall, color = Neutral500) },
        modifier = modifier,
        singleLine = true,
        keyboardOptions = KeyboardOptions(keyboardType = KeyboardType.Number),
        shape = RoundedCornerShape(10.dp),
        colors = OutlinedTextFieldDefaults.colors(
            focusedBorderColor = BrandGreen,
            focusedLabelColor = BrandGreen,
            cursorColor = BrandGreen
        )
    )
}

/**
 * A FilterChip styled for triage priority selection.
 */
@OptIn(ExperimentalMaterial3Api::class)
@Composable
private fun PriorityChip(
    label: String,
    chipColor: Color,
    isSelected: Boolean,
    onClick: () -> Unit
) {
    FilterChip(
        selected = isSelected,
        onClick = onClick,
        label = {
            Text(
                text = label,
                style = MaterialTheme.typography.labelMedium,
                fontWeight = if (isSelected) FontWeight.Bold else FontWeight.Normal
            )
        },
        colors = FilterChipDefaults.filterChipColors(
            containerColor = Neutral100,
            labelColor = Neutral700,
            selectedContainerColor = chipColor,
            selectedLabelColor = Color.White
        ),
        border = FilterChipDefaults.filterChipBorder(
            borderColor = Neutral300,
            selectedBorderColor = chipColor,
            enabled = true,
            selected = isSelected
        ),
        shape = RoundedCornerShape(10.dp)
    )
}
