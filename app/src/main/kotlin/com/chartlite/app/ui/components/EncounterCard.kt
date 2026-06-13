package com.chartlite.app.ui.components

import androidx.compose.foundation.background
import androidx.compose.foundation.layout.*
import androidx.compose.foundation.shape.CircleShape
import androidx.compose.foundation.shape.RoundedCornerShape
import androidx.compose.material.icons.Icons
import androidx.compose.material.icons.filled.*
import androidx.compose.material3.*
import androidx.compose.runtime.Composable
import androidx.compose.runtime.remember
import androidx.compose.ui.Alignment
import androidx.compose.ui.Modifier
import androidx.compose.ui.draw.clip
import androidx.compose.ui.graphics.Color
import androidx.compose.ui.text.font.FontWeight
import androidx.compose.ui.text.style.TextOverflow
import androidx.compose.ui.unit.dp
import com.chartlite.app.database.entity.EncounterEntity
import com.chartlite.app.database.entity.effectiveEncounterTimeMillis
import com.chartlite.app.model.Diagnosis
import com.chartlite.app.model.Medication
import com.chartlite.app.ui.theme.*
import com.google.gson.Gson
import com.google.gson.reflect.TypeToken
import java.time.Instant
import java.time.ZoneId
import java.time.format.DateTimeFormatter

@Composable
fun EncounterCard(
    encounter: EncounterEntity,
    onClick: () -> Unit,
    modifier: Modifier = Modifier
) {
    val gson = remember { Gson() }

    val displayTimeMillis = remember(encounter.timestamp, encounter.createdAt) {
        encounter.effectiveEncounterTimeMillis()
    }
    val dateStr = remember(displayTimeMillis) {
        displayTimeMillis?.let {
            DateTimeFormatter.ofPattern("dd MMM yyyy")
                .withZone(ZoneId.systemDefault())
                .format(Instant.ofEpochMilli(it))
        } ?: "Unknown date"
    }
    val timeStr = remember(displayTimeMillis) {
        displayTimeMillis?.let {
            DateTimeFormatter.ofPattern("HH:mm")
                .withZone(ZoneId.systemDefault())
                .format(Instant.ofEpochMilli(it))
        } ?: "--:--"
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

    Card(
        onClick = onClick,
        modifier = modifier.fillMaxWidth(),
        shape = RoundedCornerShape(14.dp),
        colors = CardDefaults.cardColors(containerColor = Color.White),
        elevation = CardDefaults.cardElevation(defaultElevation = 1.dp)
    ) {
        Column(modifier = Modifier.padding(16.dp)) {
            // Date and time row
            Row(
                modifier = Modifier.fillMaxWidth(),
                horizontalArrangement = Arrangement.SpaceBetween,
                verticalAlignment = Alignment.CenterVertically
            ) {
                Row(verticalAlignment = Alignment.CenterVertically) {
                    Box(
                        modifier = Modifier
                            .size(8.dp)
                            .clip(CircleShape)
                            .background(BrandGreen)
                    )
                    Spacer(Modifier.width(8.dp))
                    Text(dateStr,
                        style = MaterialTheme.typography.titleSmall,
                        fontWeight = FontWeight.SemiBold)
                }
                Text(timeStr,
                    style = MaterialTheme.typography.bodySmall,
                    color = MaterialTheme.colorScheme.onSurfaceVariant)
            }

            Spacer(Modifier.height(10.dp))

            // Diagnoses
            if (diagnoses.isNotEmpty()) {
                Row(verticalAlignment = Alignment.CenterVertically) {
                    Icon(Icons.Default.MedicalServices, contentDescription = "Diagnoses",
                        modifier = Modifier.size(14.dp),
                        tint = Neutral500)
                    Spacer(Modifier.width(6.dp))
                    Text(
                        diagnoses.joinToString(" | ") { it.description },
                        style = MaterialTheme.typography.bodyMedium,
                        fontWeight = FontWeight.Medium,
                        maxLines = 2,
                        overflow = TextOverflow.Ellipsis
                    )
                }
            }

            // Medications
            if (medications.isNotEmpty()) {
                Spacer(Modifier.height(4.dp))
                Row(verticalAlignment = Alignment.CenterVertically) {
                    Icon(Icons.Default.Medication, contentDescription = "Medications",
                        modifier = Modifier.size(14.dp),
                        tint = Neutral500)
                    Spacer(Modifier.width(6.dp))
                    Text(
                        medications.joinToString(", ") { med ->
                            "${med.name}${med.dose?.let { " ${formatDose(it)}${med.unit ?: ""}" } ?: ""}"
                        },
                        style = MaterialTheme.typography.bodySmall,
                        color = MaterialTheme.colorScheme.onSurfaceVariant,
                        maxLines = 1,
                        overflow = TextOverflow.Ellipsis
                    )
                }
            }

            // SMS status badge
            encounter.smsStatus?.let { status ->
                Spacer(Modifier.height(8.dp))
                val (color, label) = when (status) {
                    "SENT" -> BrandGreen to "SMS Sent"
                    "DELIVERED" -> BrandGreen to "SMS Delivered"
                    "FAILED" -> AlertRed to "SMS Failed"
                    else -> Neutral500 to "SMS Pending"
                }
                Surface(
                    color = color.copy(alpha = 0.1f),
                    shape = RoundedCornerShape(6.dp)
                ) {
                    Row(
                        modifier = Modifier.padding(horizontal = 8.dp, vertical = 3.dp),
                        verticalAlignment = Alignment.CenterVertically
                    ) {
                        Icon(
                            if (status == "SENT" || status == "DELIVERED") Icons.Default.CheckCircle
                            else if (status == "FAILED") Icons.Default.Cancel
                            else Icons.Default.Schedule,
                            contentDescription = label,
                            modifier = Modifier.size(12.dp),
                            tint = color
                        )
                        Spacer(Modifier.width(4.dp))
                        Text(label,
                            style = MaterialTheme.typography.labelSmall,
                            color = color,
                            fontWeight = FontWeight.Medium)
                    }
                }
            }
        }
    }
}

/** Format a dose value, keeping decimals only when meaningful (e.g. 500 → "500", 2.5 → "2.5"). */
private fun formatDose(dose: Float): String =
    if (dose % 1.0f == 0f) "${dose.toInt()}" else "%.1f".format(dose)
