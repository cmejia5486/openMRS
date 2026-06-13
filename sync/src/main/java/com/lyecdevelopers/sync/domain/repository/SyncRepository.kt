package com.lyecdevelopers.sync.domain.repository

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
import kotlinx.coroutines.flow.Flow

interface SyncRepository {

    // forms
    fun loadForms(): Flow<Result<List<Form>>>
    fun loadFormByUuid(uuid: String): Flow<Result<o3Form>>
    fun filterForms(query: String): Flow<Result<List<Form>>>


    // local db
    fun saveFormsLocally(forms: List<o3Form>): Flow<Result<List<o3Form>>>
    fun getFormCount(): Flow<Result<Int>>
    fun getPatientsCount(): Flow<Result<Int>>

    fun getEncountersCount(): Flow<Result<Int>>

    // sync
    // encounters
    fun getUnsyncedEncounters(): Flow<List<EncounterEntity>>
    fun markSyncedEncounter(encounter: EncounterEntity): Flow<Unit>
    fun getSyncedEncountersCount(): Flow<Result<Int>>

    // patients
    fun getEligibleUnsyncedPatients(): Flow<List<PatientEntity>>
    fun getUnsyncedPatients(): Flow<List<PatientEntity>>
    fun markSyncedPatient(patient: PatientEntity): Flow<Unit>
    fun getSyncedPatientsCount(): Flow<Result<Int>>


    // cohorts
    fun loadPatientsByCohort(): Flow<Result<List<Any>>>
    fun loadCohorts(): Flow<Result<List<Cohort>>>
    fun loadIndicators(): Flow<Result<List<Any>>>
    fun loadParameter(): Flow<Result<List<Any>>>

    // others
    // orders
    fun loadOrderTypes(): Flow<Result<List<OrderType>>>

    // encounters
    fun loadEncounterTypes(): Flow<Result<List<EncounterType>>>

    // patientIdentifiers
    fun loadPatientIndentifiers(): Flow<Result<List<Identifier>>>

    // personattributetype
    fun loadPersonAttributeTypes(): Flow<Result<List<PersonAttributeType>>>

    // conditions
    fun loadConditions(): Flow<Result<List<Any>>>

    // data definition
    fun createDataDefinition(payload: DataDefinition): Flow<Result<List<PatientEntity>>>





}