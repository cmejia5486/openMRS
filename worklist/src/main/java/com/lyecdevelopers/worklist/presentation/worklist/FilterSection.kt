package com.lyecdevelopers.worklist.presentation.worklist

import androidx.compose.foundation.layout.Arrangement
import androidx.compose.foundation.layout.Column
import androidx.compose.foundation.layout.Row
import androidx.compose.foundation.layout.fillMaxWidth
import androidx.compose.foundation.layout.padding
import androidx.compose.foundation.shape.RoundedCornerShape
import androidx.compose.material3.MaterialTheme
import androidx.compose.material3.OutlinedTextField
import androidx.compose.material3.Surface
import androidx.compose.material3.Text
import androidx.compose.runtime.Composable
import androidx.compose.ui.Modifier
import androidx.compose.ui.unit.dp
import com.lyecdevelopers.core.model.VisitStatus
import com.lyecdevelopers.core.ui.components.DropdownSelector
import com.lyecdevelopers.worklist.domain.model.PatientFilters

@Composable
fun FilterSection(
    filters: PatientFilters,
    onFiltersChanged: (PatientFilters) -> Unit,
) {
    Surface(
        shape = RoundedCornerShape(12.dp),
        tonalElevation = 4.dp,
        modifier = Modifier.fillMaxWidth(),
        color = MaterialTheme.colorScheme.surface
    ) {
        Column(
            modifier = Modifier
                .fillMaxWidth()
                .padding(16.dp),
            verticalArrangement = Arrangement.spacedBy(12.dp)
        ) {
            Text(
                text = "Filter Patients",
                style = MaterialTheme.typography.titleMedium
            )

            OutlinedTextField(
                value = filters.nameQuery,
                onValueChange = { onFiltersChanged(filters.copy(nameQuery = it)) },
                label = { Text("Search by name") },
                modifier = Modifier.fillMaxWidth(),
                singleLine = true
            )

            Row(
                modifier = Modifier.fillMaxWidth(),
                horizontalArrangement = Arrangement.spacedBy(16.dp)
            ) {
                DropdownSelector(
                    label = "Gender",
                    options = listOf("M", "F"),
                    selected = filters.gender,
                    onOptionSelected = { onFiltersChanged(filters.copy(gender = it)) },
                    modifier = Modifier.weight(1f)
                )

                DropdownSelector(
                    label = "Visit Status",
                    options = VisitStatus.values().map {
                        it.name.replace("_", " ").lowercase().replaceFirstChar(Char::uppercase)
                    },
                    selected = filters.visitStatus?.name?.replace("_", " ")?.lowercase()
                        ?.replaceFirstChar(Char::uppercase),
                    onOptionSelected = {
                        onFiltersChanged(
                            filters.copy(
                                visitStatus = it?.let {
                                    VisitStatus.valueOf(
                                        it.uppercase().replace(" ", "_")
                                    )
                                }
                            )
                        )
                    },
                    modifier = Modifier.weight(1f)
                )
            }
        }
    }
}



