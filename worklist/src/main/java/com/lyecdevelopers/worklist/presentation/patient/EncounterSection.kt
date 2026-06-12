package com.lyecdevelopers.worklist.presentation.patient

import androidx.compose.foundation.layout.Arrangement
import androidx.compose.foundation.layout.Column
import androidx.compose.material3.MaterialTheme
import androidx.compose.material3.Text
import androidx.compose.runtime.Composable
import androidx.compose.ui.unit.dp
import com.lyecdevelopers.core.data.local.entity.EncounterEntity
import com.lyecdevelopers.worklist.presentation.visit.EncounterCard

@Composable
fun EncounterSection(title: String, encounters: List<EncounterEntity>) {
    Column(verticalArrangement = Arrangement.spacedBy(8.dp)) {
        Text(title, style = MaterialTheme.typography.titleSmall)
        encounters.forEach { encounter ->
            EncounterCard(encounter)
        }
    }
}