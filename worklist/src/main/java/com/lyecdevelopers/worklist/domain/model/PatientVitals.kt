package com.lyecdevelopers.worklist.domain.model

data class Vitals(
    val temperature: String = "",
    val bloodPressureSystolic: String = "",
    val bloodPressureDiastolic: String = "",
    val heartRate: String = "",
    val respirationRate: String = "",
    val spo2: String = "",
    val notes: String = "",
    val weight: String = "",
    val height: String = "",
    val bmi: String = "",
    val muac: String = "",
)

