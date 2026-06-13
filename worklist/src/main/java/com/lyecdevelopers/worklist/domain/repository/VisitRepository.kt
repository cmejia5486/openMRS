package com.lyecdevelopers.worklist.domain.repository

import com.lyecdevelopers.core.data.local.entity.EncounterEntity
import com.lyecdevelopers.core.data.local.entity.FormEntity
import com.lyecdevelopers.core.data.local.entity.VisitEntity
import com.lyecdevelopers.core.model.Result
import com.lyecdevelopers.core.model.VisitWithDetails
import kotlinx.coroutines.flow.Flow

interface VisitRepository {
    fun getVisitSummariesForPatient(patientId: String): Flow<Result<List<VisitWithDetails>>>
    fun getMostRecentForVisitPatient(patientId: String): Flow<Result<VisitWithDetails>>
    fun saveVisit(visit: VisitEntity): Flow<Result<Boolean>>
    fun getEncountersByPatientIdAndVisitId(
        patientId: String,
        visitId: String,
    ): Flow<Result<List<EncounterEntity>>>

    // get forms
    fun getForms(): Flow<Result<List<FormEntity>>>

    // get all visitsWithDetails
    fun getAllVisitsWithDetails(): Flow<Result<List<VisitWithDetails>>>

}
