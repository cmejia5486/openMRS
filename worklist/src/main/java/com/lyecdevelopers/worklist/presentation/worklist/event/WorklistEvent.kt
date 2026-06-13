package com.lyecdevelopers.worklist.presentation.worklist.event

import com.lyecdevelopers.core.model.VisitStatus
import com.lyecdevelopers.worklist.domain.model.Vitals

sealed class WorklistEvent {
    // ──────────────── Filters ────────────────
    data class OnNameFilterChanged(val name: String) : WorklistEvent()
    data class OnGenderFilterChanged(val gender: String?) : WorklistEvent()
    data class OnStatusFilterChanged(val status: VisitStatus?) : WorklistEvent()
    object OnClearFilters : WorklistEvent()
    object OnRefresh : WorklistEvent()

    // ──────────────── Patient ────────────────
    data class OnPatientSelected(val patientId: String) : WorklistEvent()

    data class OnMarkPatientEligible(val patientId: String?) : WorklistEvent()

    data class OnSyncPatientNow(val patientId: String?) : WorklistEvent()

    // ──────────────── Start Visit ────────────────
    data class OnVisitTypeChanged(val type: String) : WorklistEvent()
    data class OnVisitLocationChanged(val location: String) : WorklistEvent()
    data class OnVisitStatusChanged(val status: String) : WorklistEvent()
    data class OnStartDateChanged(val date: String) : WorklistEvent()
    data class OnStartTimeChanged(val time: String) : WorklistEvent()
    data class OnVisitNotesChanged(val notes: String) : WorklistEvent()
    data class OnAmPmChanged(val amPm: String) : WorklistEvent()
    data class OnLocationMenuExpandedChanged(val expanded: Boolean) : WorklistEvent()
    data class OnAmPmMenuExpandedChanged(val expanded: Boolean) : WorklistEvent()

    object StartVisit : WorklistEvent()

    // ──────────────── Vitals ────────────────
    data class OnVitalsChanged(val vitals: Vitals) : WorklistEvent()
    object SaveVitals : WorklistEvent()
}
