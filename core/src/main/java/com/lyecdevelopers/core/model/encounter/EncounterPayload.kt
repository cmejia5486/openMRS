package com.lyecdevelopers.core.model.encounter

import com.lyecdevelopers.core.model.OpenmrsObs

data class EncounterPayload(
    val uuid: String? = null,                 // Optional when creating
    val visitUuid: String,
    val encounterType: String,
    val encounterDatetime: String,            // Use ISO format for JSON
    val patientUuid: String,
    val locationUuid: String,
    val provider: String? = null,
    val obs: List<OpenmrsObs> = emptyList(),
    val orders: List<Order> = emptyList(),
    val formUuid: String? = null,
)


