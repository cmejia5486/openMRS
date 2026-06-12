package com.lyecdevelopers.form.domain.usecase

import androidx.paging.Pager
import androidx.paging.PagingConfig
import androidx.paging.PagingData
import com.lyecdevelopers.core.data.local.entity.PatientEntity
import com.lyecdevelopers.core.data.local.entity.VitalsEntity
import com.lyecdevelopers.core.model.Result
import com.lyecdevelopers.form.domain.repository.PatientRepository
import kotlinx.coroutines.flow.Flow
import org.hl7.fhir.r4.model.Patient
import javax.inject.Inject


class PatientsUseCase @Inject constructor(
    private val repository: PatientRepository,
) {

    private suspend fun createPatient(patient: Patient, entity: PatientEntity) {
        repository.createInFhir(patient)
        repository.saveToLocalDb(entity)
    }

    private suspend fun updatePatient(patient: Patient, entity: PatientEntity) {
        repository.updateInFhir(patient)
        repository.saveToLocalDb(entity)
    }

    suspend fun saveLocallyOnly(entity: PatientEntity) {
        repository.saveToLocalDb(entity)
    }

    suspend fun getPatientById(id: String): Flow<Result<PatientEntity?>> {
        return repository.getLocalPatient(id)
    }

    suspend fun loadPatients(): Flow<Result<List<PatientEntity>>> {
        return repository.loadPatients()
    }

    suspend fun searchPatients(
        name: String?,
        gender: String?,
        status: String?,
    ): Flow<Result<List<PatientEntity>>> {
        return repository.searchPatients(name, gender, status)
    }

    fun getPagedPatients(
        name: String? = null,
        gender: String? = null,
        status: String? = null,
    ): Flow<PagingData<PatientEntity>> {
        return Pager(
            config = PagingConfig(pageSize = 5),
            pagingSourceFactory = { repository.getPagedPatients(name, gender, status) }).flow
    }

    /**
     * Common submit logic for patient registration
     */
    suspend fun submitPatient(
        patient: Patient,
        isEdit: Boolean,
        entity: PatientEntity,
    ) {
        if (isEdit) {
            updatePatient(patient, entity)
        } else {
            createPatient(patient, entity)
        }
    }

    // save vitals
    suspend fun saveVitals(vitals: VitalsEntity): Flow<Result<Boolean>> {
        return repository.saveVital(vitals)
    }

    // get vitals by visit
    suspend fun getVitalsByVisit(visitId: String): Flow<Result<VitalsEntity>> {
        return repository.getVitalsByVisit(visitId)
    }

    // get vitals by patient
    fun getVitalsByPatient(patientId: String): Flow<Result<List<VitalsEntity>>> {
        return repository.getVitalsByPatient(patientId)
    }
    suspend fun markPatientEligible(patientId: String, eligible: Boolean) {
        return repository.markPatientEligible(patientId, eligible)
    }
}
