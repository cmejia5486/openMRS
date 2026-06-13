package com.lyecdevelopers.core.data.local.entity

import androidx.room.Entity
import androidx.room.ForeignKey
import androidx.room.Index
import androidx.room.PrimaryKey
import com.lyecdevelopers.core.model.OpenmrsObs
import com.lyecdevelopers.core.model.encounter.Order
import java.util.UUID

@Entity(
    tableName = "encounters",
    foreignKeys = [ForeignKey(
        entity = VisitEntity::class,
        parentColumns = ["id"],
        childColumns = ["visitUuid"],
        onDelete = ForeignKey.CASCADE
    )], indices = [Index(value = ["visitUuid"])]
)

data class EncounterEntity(
    @PrimaryKey val id: String = UUID.randomUUID().toString(),
    val encounterTypeUuid: String,
    val encounterDatetime: String,
    val patientUuid: String,
    val locationUuid: String,
    val providerUuid: String?,
    val obs: List<OpenmrsObs> = emptyList(),
    val orders: List<Order> = emptyList(),
    val formUuid: String,
    val visitUuid: String,
    val voided: Boolean = false,
    val synced: Boolean = false,
    val createdAt: String,
)



