package com.lyecdevelopers.sync.presentation.event

import com.lyecdevelopers.core.model.cohort.Attribute
import com.lyecdevelopers.core.model.cohort.Cohort
import com.lyecdevelopers.core.model.cohort.Indicator

sealed class SyncEvent {

    // --------------------
    // Forms related
    // --------------------
    data class FilterForms(val query: String) : SyncEvent()
    data class ToggleFormSelection(val uuid: String) : SyncEvent()
    object ClearSelection : SyncEvent()
    object DownloadForms : SyncEvent()

    // --------------------
    // Cohort / Indicator / Filters
    // --------------------
    data class SelectedCohortChanged(val cohort: Cohort) : SyncEvent()
    data class IndicatorSelected(val indicator: Indicator) : SyncEvent()
    object ApplyFilters : SyncEvent()

    data class ToggleHighlightAvailable(val item: Attribute) : SyncEvent()
    data class ToggleHighlightSelected(val item: Attribute) : SyncEvent()
    object MoveRight : SyncEvent()
    object MoveLeft : SyncEvent()

    // --------------------
    // Sync meta updates
    // --------------------
    data class UpdateLastSyncTime(val time: String) : SyncEvent()
    data class UpdateLastSyncStatus(val status: String) : SyncEvent()
    data class UpdateLastSyncBy(val user: String) : SyncEvent()
    data class UpdateLastSyncError(val error: String?) : SyncEvent()

    // --------------------
    // Manual & Auto Sync
    // --------------------
    object SyncNow : SyncEvent()
    data class ToggleAutoSync(val enabled: Boolean) : SyncEvent()
}


