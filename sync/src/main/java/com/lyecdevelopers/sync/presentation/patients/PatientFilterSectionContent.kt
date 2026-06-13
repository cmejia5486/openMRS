package com.lyecdevelopers.sync.presentation.patients

import androidx.compose.foundation.layout.Arrangement
import androidx.compose.foundation.layout.Column
import androidx.compose.foundation.layout.fillMaxWidth
import androidx.compose.foundation.layout.padding
import androidx.compose.material3.DropdownMenuItem
import androidx.compose.material3.ExperimentalMaterial3Api
import androidx.compose.material3.ExposedDropdownMenuBox
import androidx.compose.material3.ExposedDropdownMenuDefaults
import androidx.compose.material3.MenuAnchorType
import androidx.compose.material3.Text
import androidx.compose.material3.TextField
import androidx.compose.runtime.Composable
import androidx.compose.runtime.getValue
import androidx.compose.runtime.mutableStateOf
import androidx.compose.runtime.remember
import androidx.compose.runtime.setValue
import androidx.compose.ui.Modifier
import androidx.compose.ui.unit.dp
import com.lyecdevelopers.core.model.cohort.Attribute
import com.lyecdevelopers.core.model.cohort.Cohort
import com.lyecdevelopers.core.model.cohort.Indicator
import com.lyecdevelopers.core.ui.components.IndicatorAttributesScreen

@OptIn(ExperimentalMaterial3Api::class)
@Composable
fun PatientFilterSectionContent(
    cohortOptions: List<Cohort>,
    selectedCohort: Cohort?,
    onSelectedCohortChanged: (Cohort) -> Unit,
    indicatorOptions: List<Indicator>,
    selectedIndicator: Indicator?,
    onIndicatorSelected: (Indicator) -> Unit,
    availableParameters: List<Attribute>,
    selectedParameters: List<Attribute>,
    highlightedAvailable: List<Attribute>,
    highlightedSelected: List<Attribute>,
    onHighlightAvailableToggle: (Attribute) -> Unit,
    onHighlightSelectedToggle: (Attribute) -> Unit,
    onMoveRight: () -> Unit,
    onMoveLeft: () -> Unit,
) {
    var expandedCohort by remember { mutableStateOf(false) }
    var expandedIndicator by remember { mutableStateOf(false) }


    Column(verticalArrangement = Arrangement.spacedBy(16.dp), modifier = Modifier.padding(16.dp)) {

        // --- Cohort Dropdown ---
        ExposedDropdownMenuBox(
            expanded = expandedCohort, onExpandedChange = { expandedCohort = !expandedCohort }) {
            TextField(
                readOnly = true,
                value = selectedCohort?.display ?: "Select Cohort",
                onValueChange = {},
                label = { Text("Cohort") },
                trailingIcon = { ExposedDropdownMenuDefaults.TrailingIcon(expandedCohort) },
                modifier = Modifier
                    .menuAnchor(
                        type = MenuAnchorType.SecondaryEditable, enabled = true
                    )
                    .fillMaxWidth()
            )
            ExposedDropdownMenu(
                expanded = expandedCohort, onDismissRequest = { expandedCohort = false }) {
                cohortOptions.forEach { cohort ->
                    DropdownMenuItem(
                        text = { Text(cohort.display ?: "Unnamed Cohort") },
                        onClick = {
                            onSelectedCohortChanged(cohort)
                            expandedCohort = false
                        })
                }
            }
        }

        // --- Indicator Dropdown ---
        ExposedDropdownMenuBox(
            expanded = expandedIndicator,
            onExpandedChange = { expandedIndicator = !expandedIndicator }) {
            TextField(
                readOnly = true,
                value = selectedIndicator?.label ?: "Select Indicator",
                onValueChange = {},
                label = { Text("Indicator") },
                trailingIcon = { ExposedDropdownMenuDefaults.TrailingIcon(expandedIndicator) },
                modifier = Modifier
                    .menuAnchor(
                        type = MenuAnchorType.SecondaryEditable, enabled = true
                    )
                    .fillMaxWidth()
            )
            ExposedDropdownMenu(
                expanded = expandedIndicator, onDismissRequest = { expandedIndicator = false }) {
                indicatorOptions.forEach { indicator ->
                    DropdownMenuItem(text = { Text(indicator.label) }, onClick = {
                        onIndicatorSelected(indicator)
                        expandedIndicator = false
                    })
                }
            }
        }


        // --- Parameter Transfer Box (Custom Logic) ---
        IndicatorAttributesScreen(
            selectedIndicator = selectedIndicator,
            availableParameters = availableParameters,
            selectedParameters = selectedParameters,
            highlightedAvailable = highlightedAvailable,
            highlightedSelected = highlightedSelected,
            toggleHighlightAvailable = onHighlightAvailableToggle,
            toggleHighlightSelected = onHighlightSelectedToggle,
            moveRight = onMoveRight,
            moveLeft = onMoveLeft,
        )

    }
}
