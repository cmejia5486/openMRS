package com.lyecdevelopers.core.model

data class OpenmrsEncounter(
    val patient: String,
    val encounterType: String,
    val location: String,
    val encounterDatetime: String,
    val obs: List<OpenmrsObs>,
)