package com.lyecdevelopers.form.data.repository

import android.database.sqlite.SQLiteConstraintException
import android.database.sqlite.SQLiteDatabaseCorruptException
import android.database.sqlite.SQLiteDatabaseLockedException
import android.database.sqlite.SQLiteException
import androidx.paging.PagingSource
import com.google.android.fhir.FhirEngine
import com.lyecdevelopers.core.data.local.dao.PatientDao
import com.lyecdevelopers.core.data.local.dao.VitalsDao
import com.lyecdevelopers.core.data.local.entity.PatientEntity
import com.lyecdevelopers.core.data.local.entity.VitalsEntity
import com.lyecdevelopers.core.model.PatientWithVisits
import com.lyecdevelopers.core.model.Result
import com.lyecdevelopers.core.utils.AppLogger
import com.lyecdevelopers.form.domain.repository.PatientRepository
import kotlinx.coroutines.Dispatchers
import kotlinx.coroutines.flow.Flow
import kotlinx.coroutines.flow.catch
import kotlinx.coroutines.flow.distinctUntilChanged
import kotlinx.coroutines.flow.flow
import kotlinx.coroutines.flow.flowOn
import kotlinx.coroutines.flow.map
import kotlinx.coroutines.flow.onStart
import org.hl7.fhir.r4.model.Patient
import javax.inject.Inject

class PatientRepositoryImpl @Inject constructor(
    private val patientDao: PatientDao,
    private val vitalsDao: VitalsDao,
    private val fhirEngine: FhirEngine,
) : PatientRepository {
    override suspend fun getPatientWithVisits(patientId: String): Flow<Result<PatientWithVisits?>> =
        patientDao.observePatientWithVisits(patientId) // updated to the Flow version
            .map { Result.Success(it) }.catch { e ->
                AppLogger.e("getPatientWithVisits", e.message ?: "Unknown error", e)
            }.flowOn(Dispatchers.IO)



    override suspend fun getAllPatientsWithVisits(): Flow<Result<List<PatientWithVisits>>> =
        patientDao.observeAllPatientsWithVisits()
            .map { Result.Success(it) }.catch { e ->
                AppLogger.e("getAllPatientsWithVisits", e.message ?: "Unknown error", e)
            }.flowOn(Dispatchers.IO)


    override suspend fun createInFhir(patient: Patient) {
        fhirEngine.create(patient)
    }

    override suspend fun updateInFhir(patient: Patient) {
        fhirEngine.update(patient)
    }

    override suspend fun saveToLocalDb(entity: PatientEntity) {
        patientDao.insertPatient(entity)
    }

    override suspend fun getLocalPatient(id: String): Flow<Result<PatientEntity?>> = flow {
        patientDao.getPatientById(id)
            .map { patient ->
                if (patient != null) {
                    Result.Success(patient)
                } else {
                    Result.Error("Patient not found")
                }
            }
            .catch { e ->
                AppLogger.e("getLocalPatient", e.message ?: "Unknown error", e)

                val errorMessage = when (e) {
                    is SQLiteException -> "Database error occurred: ${e.localizedMessage}"
                    is IllegalStateException -> "Invalid state during DB fetch: ${e.localizedMessage}"
                    else -> "Unexpected error during DB fetch: ${e.localizedMessage}"
                }

                emit(Result.Error(errorMessage))
            }
            .collect { emit(it) }
    }.flowOn(Dispatchers.IO)


    override suspend fun loadPatients(): Flow<Result<List<PatientEntity>>> = flow {
        emit(Result.Loading)

        try {
            val patients = patientDao.getAllPatients()
            emit(Result.Success(patients))

        } catch (e: SQLiteDatabaseLockedException) {
            AppLogger.e("loadPatients", "Database is locked", e)
            emit(Result.Error("Database is currently locked. Please try again."))

        } catch (e: SQLiteDatabaseCorruptException) {
            AppLogger.e("loadPatients", "Database is corrupt", e)
            emit(Result.Error("Database is corrupt. Please restore or reinstall."))

        } catch (e: SQLiteException) {
            AppLogger.e("loadPatients", "SQLite error", e)
            emit(Result.Error("Database error: ${e.localizedMessage}"))

        } catch (e: Exception) {
            AppLogger.e("loadPatients", "Unexpected error", e)
            emit(Result.Error("Unexpected error: ${e.localizedMessage ?: "Unknown"}"))
        }

    }.flowOn(Dispatchers.IO)

    override suspend fun searchPatients(
        name: String?,
        gender: String?,
        status: String?,
    ): Flow<Result<List<PatientEntity>>> = flow {
        emit(Result.Loading)
        try {
            patientDao.searchPatients(name, gender, status).collect { list ->
                emit(Result.Success(list))
            }
        } catch (e: Exception) {
            AppLogger.e("searchPatients", e.message ?: "Unknown error", e)
            emit(Result.Error(e.localizedMessage ?: "Unable to search patients"))
        }
    }.flowOn(Dispatchers.IO)

    override fun getPagedPatients(
        name: String?, gender: String?, status: String?,
    ): PagingSource<Int, PatientEntity> = patientDao.getPagedPatients(name, gender, status)

    override suspend fun saveVital(vitals: VitalsEntity): Flow<Result<Boolean>> = flow {
        try {
            vitalsDao.insertVitals(vitals)
            emit(Result.Success(true))
        } catch (e: SQLiteConstraintException) {
            emit(Result.Error("Constraint violation: ${e.localizedMessage ?: "Unknown constraint error"}"))
        } catch (e: SQLiteException) {
            emit(Result.Error("Database error: ${e.localizedMessage ?: "Unknown SQLite error"}"))
        } catch (e: Exception) {
            emit(Result.Error("Unexpected error: ${e.localizedMessage ?: "Unknown error"}"))
        }
    }.flowOn(Dispatchers.IO)


    override suspend fun getVitalsByVisit(visitId: String): Flow<Result<VitalsEntity>> {
        return vitalsDao.getVitalsByVisit(visitId).map { vitals ->
            if (vitals != null) {
                Result.Success(vitals)
            } else {
                Result.Error("No vitals found for this visit")
            }
        }.catch { e ->
            AppLogger.e("getVitalsByVisit", "Database error", e)
            emit(Result.Error("Database error: ${e.localizedMessage}"))
        }.flowOn(Dispatchers.IO)
    }




    override fun getVitalsByPatient(patientId: String): Flow<Result<List<VitalsEntity>>> =
        vitalsDao.getVitalsForPatient(patientId).map { vitalsList ->
            if (vitalsList.isNotEmpty()) {
                Result.Success(vitalsList)
            } else {
                Result.Error("No vitals found for this patient.")
            }
        }.onStart { emit(Result.Loading) }.catch { e ->
            AppLogger.e("loadPatients", "Error getting vitals", e)
            emit(Result.Error("Error: ${e.localizedMessage}"))
        }.distinctUntilChanged().flowOn(Dispatchers.IO)

    override suspend fun markPatientEligible(patientId: String, eligible: Boolean) {
        try {
            patientDao.updateEligibilityForSync(
                patientId = patientId,
                isEligible = eligible,
                lastModified = System.currentTimeMillis()
            )
        } catch (e: Exception) {
            AppLogger.e(
                "DB error marking patient eligible for sync",
                "Unable to update synced: ${e.message}"
            )
            throw e
        }

    }

}
