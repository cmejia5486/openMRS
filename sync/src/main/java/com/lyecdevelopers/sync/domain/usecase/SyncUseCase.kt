package com.lyecdevelopers.sync.domain.usecase

import com.lyecdevelopers.core.data.local.entity.EncounterEntity
import com.lyecdevelopers.core.data.local.entity.PatientEntity
import com.lyecdevelopers.core.model.Form
import com.lyecdevelopers.core.model.Identifier
import com.lyecdevelopers.core.model.PersonAttributeType
import com.lyecdevelopers.core.model.Result
import com.lyecdevelopers.core.model.cohort.Cohort
import com.lyecdevelopers.core.model.cohort.DataDefinition
import com.lyecdevelopers.core.model.encounter.EncounterType
import com.lyecdevelopers.core.model.o3.o3Form
import com.lyecdevelopers.core.model.order.OrderType
import com.lyecdevelopers.sync.domain.repository.SyncRepository
import kotlinx.coroutines.flow.Flow
import javax.inject.Inject

class SyncUseCase @Inject constructor(
    private val repository: SyncRepository,
) {

    // forms
    fun loadForms(): Flow<Result<List<Form>>> {
        return repository.loadForms()
    }

    fun filterForms(query: String): Flow<Result<List<Form>>> {
        return repository.filterForms(query)
    }

    fun loadFormByUuid(uuid: String): Flow<Result<o3Form>> {
        return repository.loadFormByUuid(uuid)
    }

    fun saveFormsLocally(forms: List<o3Form>): Flow<Result<List<o3Form>>> {
        return repository.saveFormsLocally(forms)
    }
    fun getFormCount(): Flow<Result<Int>> {
        return repository.getFormCount()
    }

    fun getPatientCount(): Flow<Result<Int>> {
        return repository.getPatientsCount()
    }

    fun getEncounterCount(): Flow<Result<Int>> {
        return repository.getEncountersCount()
    }

    // cohorts
    fun getCohorts(): Flow<Result<List<Cohort>>> {
        return repository.loadCohorts()
    }

    // orders
    fun getOrderTypes(): Flow<Result<List<OrderType>>> {
        return repository.loadOrderTypes()
    }

    // encounters
    fun getEncounterTypes(): Flow<Result<List<EncounterType>>> {
        return repository.loadEncounterTypes()
    }

    // Patient Identifiers
    fun getIdentifiers(): Flow<Result<List<Identifier>>> {
        return repository.loadPatientIndentifiers()
    }

    // Person Attributes types
    fun getPersonAttributeTypes(): Flow<Result<List<PersonAttributeType>>> {
        return repository.loadPersonAttributeTypes()
    }

    // data definition
    fun createDataDefinition(payload: DataDefinition): Flow<Result<List<PatientEntity>>> {
        return repository.createDataDefinition(payload)
    }


    // encounters
    fun getUnsynced(): Flow<List<EncounterEntity>> {
        return repository.getUnsyncedEncounters()
    }

    fun markSynced(encounter: EncounterEntity): Flow<Unit> {
        return repository.markSyncedEncounter(encounter)
    }

    fun getSyncedEncounterCount(): Flow<Result<Int>> {
        return repository.getSyncedEncountersCount()
    }


    // patients
    fun getEligibleUnsyncedPatients(): Flow<List<PatientEntity>> {
        return repository.getEligibleUnsyncedPatients()
    }

    fun getUnsyncedPatients(): Flow<List<PatientEntity>> {
        return repository.getUnsyncedPatients()
    }

    fun markSyncedPatient(patient: PatientEntity): Flow<Unit> {
        return repository.markSyncedPatient(patient)
    }

    fun getSyncedPatientsCount(): Flow<Result<Int>> {
        return repository.getSyncedPatientsCount()
    }




}