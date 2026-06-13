package com.lyecdevelopers.core.model

import androidx.room.Embedded
import androidx.room.Relation
import com.lyecdevelopers.core.data.local.entity.EncounterEntity
import com.lyecdevelopers.core.data.local.entity.VisitEntity
import com.lyecdevelopers.core.data.local.entity.VitalsEntity

data class VisitWithDetails(
    @Embedded val visit: VisitEntity,

    @Relation(
        parentColumn = "id",
        entityColumn = "visitUuid"
    )
    val encounters: List<EncounterEntity>,

    @Relation(
        parentColumn = "id",
        entityColumn = "visitUuid"
    )
    val vitals: List<VitalsEntity>,
)

