package com.lyecdevelopers.worklist.domain.model

import androidx.compose.runtime.saveable.Saver
import androidx.compose.runtime.saveable.listSaver
import com.lyecdevelopers.core.model.VisitStatus

data class PatientFilters(
    val nameQuery: String = "",
    val gender: String? = null,
    val visitStatus: VisitStatus? = null,
) {
    companion object {
        val Saver: Saver<PatientFilters, *> = listSaver(
            save = {
                listOf(it.nameQuery, it.gender, it.visitStatus?.name)
            },
            restore = {
                PatientFilters(
                    nameQuery = it[0] as String,
                    gender = it[1],
                    visitStatus = it[2]?.let { name -> VisitStatus.valueOf(name) }
                )
            }
        )
    }
}

