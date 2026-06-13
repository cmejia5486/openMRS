package com.lyecdevelopers.worklist.presentation.visit

import androidx.compose.foundation.layout.Arrangement
import androidx.compose.foundation.layout.Column
import androidx.compose.foundation.layout.Spacer
import androidx.compose.foundation.layout.height
import androidx.compose.foundation.rememberScrollState
import androidx.compose.foundation.verticalScroll
import androidx.compose.material3.AlertDialog
import androidx.compose.material3.MaterialTheme
import androidx.compose.material3.Text
import androidx.compose.material3.TextButton
import androidx.compose.runtime.Composable
import androidx.compose.ui.Modifier
import androidx.compose.ui.unit.dp
import com.lyecdevelopers.core.model.VisitWithDetails

@Composable
fun VisitDetailsDialog(visit: VisitWithDetails, onDismiss: () -> Unit) {
    AlertDialog(
        onDismissRequest = onDismiss,
        confirmButton = {
            TextButton(onClick = onDismiss) {
                Text("Close")
            }
        },
        title = {
            Text("${visit.visit.type} • ${visit.visit.date}")
        },
        text = {
            Column(
                verticalArrangement = Arrangement.spacedBy(12.dp),
                modifier = Modifier.verticalScroll(rememberScrollState())
            ) {
                Text("Status: ${visit.visit.status}", style = MaterialTheme.typography.bodyMedium)
                if (visit.visit.notes?.isNotBlank() == true) {
                    Text("Notes: ${visit.visit.notes}", style = MaterialTheme.typography.bodySmall)
                }

                if (visit.encounters.isNotEmpty()) {
                    Spacer(Modifier.height(8.dp))
                    Text("Encounters", style = MaterialTheme.typography.titleSmall)
                    visit.encounters.forEach { encounter ->
                        EncounterCard(encounter)
                    }
                }
            }
        }
    )
}

