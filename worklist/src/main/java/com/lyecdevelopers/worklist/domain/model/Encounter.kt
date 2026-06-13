package com.lyecdevelopers.worklist.domain.model

import com.lyecdevelopers.core.model.OpenmrsObs
import com.lyecdevelopers.core.model.encounter.Order
import java.time.Instant

data class Encounter(
    val uuid: String,
    val encounterTypeUuid: String,
    val encounterDatetime: Instant,
    val patientUuid: String,
    val locationUuid: String,
    val providerUuid: String?,
    val obs: List<OpenmrsObs> = emptyList(),
    val orders: List<Order> = emptyList(),
    val formUuid: String,
    val visitUuid: String,
    val voided: Boolean = false,
    val synced: Boolean = false,
    val createdAt: Instant,
)

