package com.chartlite.app.ui.components

import androidx.compose.foundation.background
import androidx.compose.foundation.layout.*
import androidx.compose.foundation.shape.CircleShape
import androidx.compose.foundation.shape.RoundedCornerShape
import androidx.compose.material.icons.Icons
import androidx.compose.material.icons.filled.Flag
import androidx.compose.material3.*
import androidx.compose.runtime.Composable
import androidx.compose.ui.Alignment
import androidx.compose.ui.Modifier
import androidx.compose.ui.draw.clip
import androidx.compose.ui.graphics.Color
import androidx.compose.ui.semantics.contentDescription
import androidx.compose.ui.semantics.semantics
import androidx.compose.ui.text.font.FontWeight
import androidx.compose.ui.text.style.TextOverflow
import androidx.compose.ui.unit.dp
import com.chartlite.app.ui.theme.*

/**
 * A card for displaying a patient in a station queue.
 *
 * Shows the patient name, ID, wait time, priority indicator, and a context
 * line (e.g., chief complaint, vitals summary, or medication count).
 *
 * @param patientName full name of the patient
 * @param patientId formatted patient ID (e.g. "KFMT-4WRN")
 * @param waitMinutes minutes since the patient entered this queue
 * @param priorityLevel 0=normal, 1=priority, 2=emergency
 * @param contextLine secondary info such as chief complaint or vitals summary
 * @param onClick action when the card is tapped
 * @param onMarkPriority optional callback to cycle priority; receives the new level
 */
@Composable
fun QueueCard(
    patientName: String,
    patientId: String,
    waitMinutes: Int,
    priorityLevel: Int,
    contextLine: String,
    onClick: () -> Unit,
    onMarkPriority: ((Int) -> Unit)? = null,
    modifier: Modifier = Modifier
) {
    val priorityColor = when (priorityLevel) {
        2 -> AlertRed
        1 -> WarningAmber
        else -> BrandGreen
    }
    val priorityLabel = when (priorityLevel) {
        2 -> "Emergency"
        1 -> "Priority"
        else -> "Normal"
    }

    val waitColor = when {
        waitMinutes > 60 -> AlertRed
        waitMinutes > 30 -> WarningAmber
        else -> Neutral500
    }

    Card(
        onClick = onClick,
        modifier = modifier.fillMaxWidth(),
        shape = RoundedCornerShape(14.dp),
        colors = CardDefaults.cardColors(containerColor = Color.White),
        elevation = CardDefaults.cardElevation(defaultElevation = 1.dp)
    ) {
        Column(modifier = Modifier.padding(14.dp)) {
            // ── Row 1: Priority dot + patient name + patient ID ──
            Row(
                modifier = Modifier.fillMaxWidth(),
                verticalAlignment = Alignment.CenterVertically
            ) {
                // Priority dot with accessibility label
                Box(
                    modifier = Modifier
                        .size(10.dp)
                        .clip(CircleShape)
                        .background(priorityColor)
                        .semantics { contentDescription = "Priority: $priorityLabel" }
                )

                Spacer(Modifier.width(10.dp))

                // Patient name
                Text(
                    text = patientName,
                    style = MaterialTheme.typography.titleSmall,
                    fontWeight = FontWeight.SemiBold,
                    maxLines = 1,
                    overflow = TextOverflow.Ellipsis,
                    modifier = Modifier.weight(1f)
                )

                Spacer(Modifier.width(8.dp))

                // Patient ID
                Text(
                    text = patientId,
                    style = MaterialTheme.typography.bodySmall,
                    color = Neutral500
                )
            }

            Spacer(Modifier.height(6.dp))

            // ── Row 2: Context line ──
            Text(
                text = contextLine,
                style = MaterialTheme.typography.bodySmall,
                color = Neutral600,
                maxLines = 1,
                overflow = TextOverflow.Ellipsis,
                modifier = Modifier.padding(start = 20.dp)
            )

            Spacer(Modifier.height(8.dp))

            // ── Row 3: Wait time badge + optional priority button ──
            Row(
                modifier = Modifier
                    .fillMaxWidth()
                    .padding(start = 20.dp),
                verticalAlignment = Alignment.CenterVertically
            ) {
                // Wait time badge
                Surface(
                    color = waitColor.copy(alpha = 0.12f),
                    shape = RoundedCornerShape(6.dp)
                ) {
                    Text(
                        text = "$waitMinutes min",
                        modifier = Modifier.padding(horizontal = 8.dp, vertical = 3.dp),
                        style = MaterialTheme.typography.labelSmall,
                        fontWeight = FontWeight.Medium,
                        color = waitColor
                    )
                }

                Spacer(Modifier.weight(1f))

                // Priority toggle button — 48dp minimum for gloved clinical use
                if (onMarkPriority != null) {
                    IconButton(
                        onClick = {
                            val nextLevel = (priorityLevel + 1) % 3
                            onMarkPriority(nextLevel)
                        },
                        modifier = Modifier.size(48.dp)
                    ) {
                        Icon(
                            imageVector = Icons.Default.Flag,
                            contentDescription = when (priorityLevel) {
                                0 -> "Mark as priority"
                                1 -> "Mark as emergency"
                                else -> "Clear priority"
                            },
                            modifier = Modifier.size(22.dp),
                            tint = priorityColor
                        )
                    }
                }
            }
        }
    }
}
