package com.lyecdevelopers.worklist.presentation.worklist.state

import com.lyecdevelopers.core.data.local.entity.EncounterEntity
import com.lyecdevelopers.core.data.local.entity.FormEntity
import com.lyecdevelopers.core.data.local.entity.PatientEntity
import com.lyecdevelopers.core.data.local.entity.VitalsEntity
import com.lyecdevelopers.core.model.VisitWithDetails
import com.lyecdevelopers.worklist.domain.model.Vitals
import java.text.SimpleDateFormat
import java.util.Calendar
import java.util.Locale

data class WorklistUiState(
    val isLoading: Boolean = false,
    val error: String? = null,

    // forms
    val forms: List<FormEntity> = emptyList(),

    val patients: List<PatientEntity> = emptyList(),
    val selectedPatient: PatientEntity? = null,
    val visits: List<VisitWithDetails>? = emptyList(),
    val encounters: List<EncounterEntity> = emptyList(),
    val mostRecentVisit: VisitWithDetails? = null,
    val vitals: Vitals? = null,
    val vitalsEntity: VitalsEntity? = null,

    // ──────────────── Start Visit state ────────────────
    val visitType: String = "",
    val visitLocation: String = "ART Clinic",
    val visitStatus: String = "New",
    val visitNotes: String = "",
    val startDate: String = SimpleDateFormat(
        "dd/MM/yyyy",
        Locale.getDefault()
    ).format(Calendar.getInstance().time),
    val visitStatuses: List<String> = listOf("New", "Ongoing", "In the past"),
    val visitTypes: List<String> = listOf("Facility Visit", "Community Visit"),
    val visitLocations: List<String> = listOf("ART Clinic", "Community Clinic"),


    val startTime: String = SimpleDateFormat(
        "hh:mm",
        Locale.getDefault()
    ).format(Calendar.getInstance().time),
    val amPm: String = if (Calendar.getInstance()
            .get(Calendar.AM_PM) == Calendar.AM
    ) "AM" else "PM",
    val locationMenuExpanded: Boolean = false,
    val amPmMenuExpanded: Boolean = false,
)


