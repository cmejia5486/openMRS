package com.lyecdevelopers.form.domain.usecase

import com.lyecdevelopers.core.data.local.entity.EncounterEntity
import com.lyecdevelopers.core.data.local.entity.FormEntity
import com.lyecdevelopers.core.data.local.entity.VisitEntity
import com.lyecdevelopers.core.model.Form
import com.lyecdevelopers.core.model.Result
import com.lyecdevelopers.core.model.VisitWithDetails
import com.lyecdevelopers.core.model.o3.o3Form
import com.lyecdevelopers.form.domain.repository.FormRepository
import kotlinx.coroutines.flow.Flow
import javax.inject.Inject

class FormsUseCase @Inject constructor(
    private val repository: FormRepository,
) {

    // Remote
    operator fun invoke(): Flow<Result<List<Form>>> {
        return repository.loadForms()
    }

    fun filterForms(query: String, allForms: List<Form>): Flow<Result<List<Form>>> {
        return repository.filterForms(query, allForms)
    }

    fun getFormByUuid(uuid: String, allForms: List<Form>): Flow<Result<Form>> {
        return repository.getFormByUuid(uuid, allForms)
    }

    fun getO3FormByUuid(uuid: String): Flow<Result<o3Form>> {
        return repository.getO3FormByUuid(uuid)
    }

    // -------------------------------
    // Local DB Handling
    // -------------------------------

    suspend fun saveFormsLocally(forms: List<FormEntity>) {
        repository.saveForms(forms)
    }

    suspend fun saveFormLocally(form: FormEntity) {
        repository.saveForm(form)
    }

    suspend fun getAllLocalForms(): Flow<Result<List<FormEntity>>> {
        return repository.getAllForms()
    }

    suspend fun getLocalFormById(uuid: String): Flow<Result<FormEntity?>> {
        return repository.getFormById(uuid)
    }

    suspend fun clearLocalForms() {
        repository.clearAllForms()
    }

    suspend fun deleteLocalForm(uuid: String) {
        repository.deleteForm(uuid)
    }

    suspend fun saveEncounterLocally(encounter: EncounterEntity) {
        repository.saveEncounterLocally(encounter)
    }

    // get most recent visit
    fun getMostRecentForVisitPatient(patientId: String): Flow<Result<VisitWithDetails>> {
        return repository.getMostRecentForVisitPatient(patientId)
    }

    // create a default visit
    suspend fun createADefault(visit: VisitEntity) {
        repository.createDefault(visit)
    }

}


