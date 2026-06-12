package com.chartlite.app.ui.components

import androidx.compose.foundation.horizontalScroll
import androidx.compose.foundation.layout.*
import androidx.compose.foundation.rememberScrollState
import androidx.compose.foundation.shape.RoundedCornerShape
import androidx.compose.material.icons.Icons
import androidx.compose.material.icons.filled.MedicalServices
import androidx.compose.material.icons.filled.Medication
import androidx.compose.material.icons.filled.MonitorHeart
import androidx.compose.material.icons.filled.PersonAdd
import androidx.compose.material3.*
import androidx.compose.runtime.Composable
import androidx.compose.ui.Alignment
import androidx.compose.ui.Modifier
import androidx.compose.ui.graphics.Color
import androidx.compose.ui.graphics.vector.ImageVector
import androidx.compose.ui.text.font.FontWeight
import androidx.compose.ui.unit.dp
import androidx.compose.ui.unit.sp
import com.chartlite.app.model.ClinicStation
import com.chartlite.app.ui.theme.*

/**
 * Horizontal row of FilterChips for switching between clinic stations.
 * Each chip shows the station icon, display name, and an optional badge
 * with the queue count when patients are waiting.
 */
@OptIn(ExperimentalMaterial3Api::class)
@Composable
fun StationSwitcher(
    stations: List<ClinicStation>,
    activeStation: ClinicStation,
    queueCounts: Map<ClinicStation, Int>,
    onStationSelected: (ClinicStation) -> Unit,
    modifier: Modifier = Modifier
) {
    // Use compact labels when 4+ stations so all fit on screen without scrolling
    val useCompact = stations.size >= 4

    Row(
        modifier = modifier
            .fillMaxWidth()
            .horizontalScroll(rememberScrollState()),
        horizontalArrangement = Arrangement.spacedBy(if (useCompact) 6.dp else 8.dp),
        verticalAlignment = Alignment.CenterVertically
    ) {
        Spacer(Modifier.width(2.dp))

        stations.forEach { station ->
            val isSelected = station == activeStation
            val count = queueCounts[station] ?: 0
            val label = if (useCompact) compactStationName(station) else station.displayName

            FilterChip(
                selected = isSelected,
                onClick = { onStationSelected(station) },
                label = {
                    Row(
                        verticalAlignment = Alignment.CenterVertically,
                        horizontalArrangement = Arrangement.spacedBy(3.dp)
                    ) {
                        Text(
                            text = label,
                            style = if (useCompact) MaterialTheme.typography.labelMedium
                                    else MaterialTheme.typography.labelLarge
                        )
                        if (count > 0) {
                            Surface(
                                shape = RoundedCornerShape(10.dp),
                                color = if (isSelected) Color.White else BrandGreen,
                                modifier = Modifier.defaultMinSize(minWidth = 20.dp)
                            ) {
                                Text(
                                    text = count.toString(),
                                    modifier = Modifier.padding(horizontal = 4.dp, vertical = 1.dp),
                                    style = MaterialTheme.typography.labelSmall,
                                    fontWeight = FontWeight.Bold,
                                    fontSize = 11.sp,
                                    color = if (isSelected) BrandGreenDark else Color.White
                                )
                            }
                        }
                    }
                },
                leadingIcon = {
                    Icon(
                        imageVector = stationIcon(station),
                        contentDescription = station.displayName,
                        modifier = Modifier.size(if (useCompact) 16.dp else 18.dp)
                    )
                },
                colors = FilterChipDefaults.filterChipColors(
                    containerColor = Neutral100,
                    labelColor = Neutral700,
                    iconColor = Neutral500,
                    selectedContainerColor = BrandGreen,
                    selectedLabelColor = Color.White,
                    selectedLeadingIconColor = Color.White
                ),
                border = FilterChipDefaults.filterChipBorder(
                    borderColor = Neutral300,
                    selectedBorderColor = BrandGreenDark,
                    enabled = true,
                    selected = isSelected
                ),
                shape = RoundedCornerShape(if (useCompact) 12.dp else 14.dp)
            )
        }

        Spacer(Modifier.width(2.dp))
    }
}

/**
 * Shorter station names for compact layout when all 4 stations are enabled.
 */
private fun compactStationName(station: ClinicStation): String = when (station) {
    ClinicStation.REGISTRATION -> "Reg"
    ClinicStation.TRIAGE -> "Triage"
    ClinicStation.CONSULTATION -> "Consult"
    ClinicStation.PHARMACY -> "Pharm"
}

/**
 * Returns the Material icon for a given clinic station.
 */
private fun stationIcon(station: ClinicStation): ImageVector = when (station) {
    ClinicStation.REGISTRATION -> Icons.Default.PersonAdd
    ClinicStation.TRIAGE -> Icons.Default.MonitorHeart
    ClinicStation.CONSULTATION -> Icons.Default.MedicalServices
    ClinicStation.PHARMACY -> Icons.Default.Medication
}
