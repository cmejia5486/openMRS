package com.lyecdevelopers.sync.presentation.state

import com.lyecdevelopers.core.model.Form
import com.lyecdevelopers.core.model.cohort.Attribute
import com.lyecdevelopers.core.model.cohort.Cohort
import com.lyecdevelopers.core.model.cohort.Indicator

data class SyncUiState(
    val isLoading: Boolean = false,
    val error: String? = null,

    val formItems: List<Form> = emptyList(),
    val selectedFormIds: Set<String> = emptySet(),
    val searchQuery: String = "",
    val formCount: Int = 0,
    val patientCount: Int = 0,
    val encounterCount: Int = 0,
    val syncedPatientCount: Int = 0,
    val syncedEncounterCount: Int = 0,

    val cohorts: List<Cohort> = emptyList(),
    val selectedCohort: Cohort? = null,

    val selectedIndicator: Indicator? = null,

    val encounterTypes: List<Indicator> = emptyList(),
    val orderTypes: List<Indicator> = emptyList(),
    val identifiers: List<Attribute> = emptyList(),
    val personAttributeTypes: List<Attribute> = emptyList(),

    val availableParameters: List<Attribute> = emptyList(),
    val selectedParameters: List<Attribute> = emptyList(),
    val highlightedAvailable: List<Attribute> = emptyList(),
    val highlightedSelected: List<Attribute> = emptyList(),

    val lastSyncTime: String = "Not synced yet",
    val lastSyncStatus: String = "Never Synced",
    val lastSyncBy: String = "N/A",
    val lastSyncError: String? = null,
    val autoSyncEnabled: Boolean = false,
    val autoSyncInterval: Int = 1,
)



