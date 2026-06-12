package com.lyecdevelopers.core.model.cohort


data class ReportParamItem(
    val label: String,
    val type: String,
    val expression: String,
    val modifier: Int? = null,
    val extras: List<Map<String, Any>> = emptyList(),
)
