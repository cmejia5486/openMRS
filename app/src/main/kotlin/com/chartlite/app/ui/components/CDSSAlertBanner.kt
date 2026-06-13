package com.chartlite.app.ui.components

import androidx.compose.animation.animateContentSize
import androidx.compose.foundation.background
import androidx.compose.foundation.clickable
import androidx.compose.foundation.layout.*
import androidx.compose.foundation.shape.CircleShape
import androidx.compose.foundation.shape.RoundedCornerShape
import androidx.compose.material.icons.Icons
import androidx.compose.material.icons.filled.*
import androidx.compose.material3.*
import androidx.compose.runtime.*
import androidx.compose.ui.Alignment
import androidx.compose.ui.Modifier
import androidx.compose.ui.draw.clip
import androidx.compose.ui.graphics.Color
import androidx.compose.ui.text.font.FontWeight
import androidx.compose.ui.unit.dp
import androidx.compose.ui.semantics.Role
import androidx.compose.ui.semantics.role
import androidx.compose.ui.semantics.semantics
import androidx.compose.ui.semantics.stateDescription
import com.chartlite.app.model.AlertSeverity
import com.chartlite.app.model.CDSSAlert
import com.chartlite.app.ui.theme.*

@Composable
fun CDSSAlertBanner(
    alert: CDSSAlert,
    modifier: Modifier = Modifier,
    onAcknowledge: (() -> Unit)? = null
) {
    val (backgroundColor, iconColor, textColor, icon) = when (alert.severity) {
        AlertSeverity.CRITICAL -> AlertStyle(
            AlertRedSurface, AlertRed, Color(0xFF7F1D1D), Icons.Default.Error
        )
        AlertSeverity.WARNING -> AlertStyle(
            WarningAmberSurface, WarningAmber, Color(0xFF78350F), Icons.Default.Warning
        )
        AlertSeverity.INFO -> AlertStyle(
            InfoBlueSurface, InfoBlue, Color(0xFF1E3A5F), Icons.Default.Info
        )
    }

    var expanded by remember(alert.message) { mutableStateOf(alert.severity == AlertSeverity.CRITICAL) }

    Surface(
        modifier = modifier
            .fillMaxWidth()
            .animateContentSize()
            .semantics {
                role = Role.Button
                stateDescription = if (expanded) "Expanded" else "Collapsed"
            }
            .clickable(onClickLabel = "Toggle alert details") { expanded = !expanded },
        color = backgroundColor,
        shape = RoundedCornerShape(12.dp),
        tonalElevation = if (alert.severity == AlertSeverity.CRITICAL) 2.dp else 0.dp
    ) {
        Row(
            modifier = Modifier.padding(14.dp),
            verticalAlignment = Alignment.Top
        ) {
            // Severity icon with colored circle
            Box(
                modifier = Modifier
                    .size(48.dp)
                    .clip(CircleShape)
                    .background(iconColor.copy(alpha = 0.15f)),
                contentAlignment = Alignment.Center
            ) {
                Icon(
                    icon, contentDescription = "${alert.severity.name} alert",
                    modifier = Modifier.size(18.dp),
                    tint = iconColor
                )
            }

            Spacer(Modifier.width(12.dp))

            Column(modifier = Modifier.weight(1f)) {
                Row(
                    modifier = Modifier.fillMaxWidth(),
                    horizontalArrangement = Arrangement.SpaceBetween,
                    verticalAlignment = Alignment.CenterVertically
                ) {
                    Text(
                        alert.category,
                        style = MaterialTheme.typography.labelMedium,
                        fontWeight = FontWeight.Bold,
                        color = iconColor
                    )
                    Surface(
                        color = iconColor.copy(alpha = 0.1f),
                        shape = RoundedCornerShape(4.dp)
                    ) {
                        Text(
                            alert.severity.name,
                            modifier = Modifier.padding(horizontal = 6.dp, vertical = 2.dp),
                            style = MaterialTheme.typography.labelSmall,
                            fontWeight = FontWeight.Bold,
                            color = iconColor
                        )
                    }
                }

                Spacer(Modifier.height(4.dp))

                Text(
                    alert.message,
                    style = MaterialTheme.typography.bodyMedium,
                    color = textColor,
                    maxLines = if (expanded) Int.MAX_VALUE else 2
                )

                if (expanded && onAcknowledge != null &&
                    alert.severity in listOf(AlertSeverity.CRITICAL, AlertSeverity.WARNING)
                ) {
                    Spacer(Modifier.height(10.dp))
                    val buttonLabel = if (alert.severity == AlertSeverity.CRITICAL) "Acknowledge Alert" else "Dismiss Warning"
                    Button(
                        onClick = onAcknowledge,
                        colors = ButtonDefaults.buttonColors(containerColor = iconColor),
                        modifier = Modifier.fillMaxWidth(),
                        shape = RoundedCornerShape(8.dp)
                    ) {
                        Icon(Icons.Default.CheckCircle, contentDescription = null, Modifier.size(16.dp))
                        Spacer(Modifier.width(6.dp))
                        Text(buttonLabel)
                    }
                }
            }
        }
    }
}

private data class AlertStyle(
    val backgroundColor: Color,
    val iconColor: Color,
    val textColor: Color,
    val icon: androidx.compose.ui.graphics.vector.ImageVector
)
