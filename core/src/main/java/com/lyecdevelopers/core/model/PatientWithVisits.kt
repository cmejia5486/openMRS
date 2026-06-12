package com.lyecdevelopers.core.model

import androidx.room.Embedded
import androidx.room.Relation
import com.lyecdevelopers.core.data.local.entity.PatientEntity
import com.lyecdevelopers.core.data.local.entity.VisitEntity

data class PatientWithVisits(
    @Embedded val patient: PatientEntity,

    @Relation(
        parentColumn = "id",
        entityColumn = "patientId"
    )
    val visits: List<VisitEntity>,
)
