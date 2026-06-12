package com.lyecdevelopers.form.domain.repository

import com.lyecdevelopers.core.data.local.entity.EncounterEntity
import com.lyecdevelopers.core.data.local.entity.FormEntity
import com.lyecdevelopers.core.data.local.entity.VisitEntity
import com.lyecdevelopers.core.model.Form
import com.lyecdevelopers.core.model.Result
import com.lyecdevelopers.core.model.VisitWithDetails
import com.lyecdevelopers.core.model.o3.o3Form
import kotlinx.coroutines.flow.Flow


interface FormRepository {
    fun loadForms(): Flow<Result<List<Form>>>
    fun filterForms(query: String, allForms: List<Form>): Flow<Result<List<Form>>>
    fun getFormByUuid(uuid: String, allForms: List<Form>): Flow<Result<Form>>
    fun getO3FormByUuid(uuid: String): Flow<Result<o3Form>>

    // local db
    suspend fun saveForms(forms: List<FormEntity>)
    suspend fun saveForm(form: FormEntity)
    suspend fun getAllForms(): Flow<Result<List<FormEntity>>>
    suspend fun getFormById(uuid: String): Flow<Result<FormEntity?>>
    suspend fun clearAllForms()
    suspend fun deleteForm(uuid: String)

    suspend fun saveEncounterLocally(encounter: EncounterEntity)

    // get latest visit for patient
    fun getMostRecentForVisitPatient(patientId: String): Flow<Result<VisitWithDetails>>

    // craete a default   visit
    suspend fun createDefault(visit: VisitEntity)
}
