package com.lyecdevelopers.form.domain.repository

import androidx.paging.PagingSource
import com.lyecdevelopers.core.data.local.entity.PatientEntity
import com.lyecdevelopers.core.data.local.entity.VitalsEntity
import com.lyecdevelopers.core.model.PatientWithVisits
import com.lyecdevelopers.core.model.Result
import kotlinx.coroutines.flow.Flow
import org.hl7.fhir.r4.model.Patient

interface PatientRepository {

    suspend fun getPatientWithVisits(patientId: String): Flow<Result<PatientWithVisits?>>

    suspend fun getAllPatientsWithVisits(): Flow<Result<List<PatientWithVisits>>>

    suspend fun createInFhir(patient: Patient)

    suspend fun updateInFhir(patient: Patient)

    suspend fun saveToLocalDb(entity: PatientEntity)

    suspend fun getLocalPatient(id: String): Flow<Result<PatientEntity?>>

    suspend fun loadPatients(): Flow<Result<List<PatientEntity>>>

    suspend fun searchPatients(
        name: String? = null,
        gender: String? = null,
        status: String? = null,
    ): Flow<Result<List<PatientEntity>>>

    fun getPagedPatients(
        name: String?,
        gender: String?,
        status: String?,
    ): PagingSource<Int, PatientEntity>

    // save vitals
    suspend fun saveVital(vitals: VitalsEntity): Flow<Result<Boolean>>

    // get vitals by visit
    suspend fun getVitalsByVisit(visitId: String): Flow<Result<VitalsEntity>>

    // get vitals by patient
    fun getVitalsByPatient(patientId: String): Flow<Result<List<VitalsEntity>>>

    suspend fun markPatientEligible(patientId: String, eligible: Boolean)

}

 