package com.lyecdevelopers.sync.data.repository

import com.lyecdevelopers.core.data.local.dao.EncounterDao
import com.lyecdevelopers.core.data.local.dao.FormDao
import com.lyecdevelopers.core.data.local.dao.PatientDao
import com.lyecdevelopers.core.data.local.entity.EncounterEntity
import com.lyecdevelopers.core.data.local.entity.PatientEntity
import com.lyecdevelopers.core.data.local.entity.mapToPatientEntity
import com.lyecdevelopers.core.data.remote.FormApi
import com.lyecdevelopers.core.model.Form
import com.lyecdevelopers.core.model.Identifier
import com.lyecdevelopers.core.model.PersonAttributeType
import com.lyecdevelopers.core.model.Result
import com.lyecdevelopers.core.model.cohort.Cohort
import com.lyecdevelopers.core.model.cohort.DataDefinition
import com.lyecdevelopers.core.model.encounter.EncounterType
import com.lyecdevelopers.core.model.o3.o3Form
import com.lyecdevelopers.core.model.order.OrderType
import com.lyecdevelopers.core.utils.AppLogger
import com.lyecdevelopers.form.domain.mapper.toEntity
import com.lyecdevelopers.sync.domain.repository.SyncRepository
import com.squareup.moshi.JsonAdapter
import kotlinx.coroutines.Dispatchers
import kotlinx.coroutines.flow.Flow
import kotlinx.coroutines.flow.catch
import kotlinx.coroutines.flow.flow
import kotlinx.coroutines.flow.flowOn
import kotlinx.coroutines.flow.map
import retrofit2.HttpException
import javax.inject.Inject


class SyncRepositoryImpl @Inject constructor(
    private val formApi: FormApi,
    private val formDao: FormDao,
    private val encounterDao: EncounterDao,
    private val patientDao: PatientDao,
    private val listOfMapAdapter: JsonAdapter<List<Map<String, Any>>>,

    ) : SyncRepository {

    override fun loadForms(): Flow<Result<List<Form>>> = flow {
        emit(Result.Loading)

        val response = formApi.getForms()

        if (response.isSuccessful) {
            val forms = response.body()?.results?.filter { it.published } ?: emptyList()
            emit(Result.Success(forms))
        } else {
            throw HttpException(response)
        }
    }.catch { e ->
        AppLogger.e(e.message ?: "Failed to load forms")
        emit(Result.Error(e.message ?: "Failed to load forms"))
    }.flowOn(Dispatchers.IO)


    override fun loadFormByUuid(uuid: String): Flow<Result<o3Form>> = flow {
        emit(Result.Loading)
        val response = formApi.loadFormByUuid(uuid)
        if (response.isSuccessful) {
            val form = response.body()
            if (form != null) {
                emit(Result.Success(form))
            } else {
                throw IllegalStateException("Form with uuid $uuid not found")
            }
        } else {
            throw HttpException(response)
        }
    }.catch { e ->
        AppLogger.e("Error ${e.localizedMessage}")
        emit(Result.Error("Error ${e.localizedMessage}"))
    }.flowOn(Dispatchers.IO)


    override fun filterForms(query: String): Flow<Result<List<Form>>> = flow {
        emit(Result.Loading)

        val response = formApi.filterForms(query)

        if (response.isSuccessful) {
            val forms = response.body()?.results
            if (forms != null) {
                emit(Result.Success(forms))
            } else {
                throw IllegalStateException("Empty form list received.")
            }
        } else {
            throw HttpException(response)
        }
    }.catch { e ->
        AppLogger.e("Error ${e.localizedMessage}")
            emit(Result.Error("Error ${e.localizedMessage}"))
    }.flowOn(Dispatchers.IO)



    override fun saveFormsLocally(forms: List<o3Form>): Flow<Result<List<o3Form>>> = flow {
        emit(Result.Loading)

        val entities = forms.map { it.toEntity() }

        if (entities.isNotEmpty()) {
            formDao.insertForms(entities)
            emit(Result.Success(forms))
        } else {
            throw IllegalStateException("Empty form list received.")
        }
    }.catch { e ->
            AppLogger.e(e.message ?: "Failed to save forms locally")
        emit(Result.Error(e.message ?: "Failed to save forms locally"))
    }.flowOn(Dispatchers.IO)


    override fun getFormCount(): Flow<Result<Int>> =
        formDao.getFormCount().map { Result.Success(it) }.catch { e ->
            val errorMsg = "Error getting form count: ${e.localizedMessage ?: "Unknown error"}"
            AppLogger.e("FormCountFlowCatch", errorMsg, e)
        }.flowOn(Dispatchers.IO)


    override fun getPatientsCount(): Flow<Result<Int>> =
        patientDao.getPatientsCount().map { Result.Success(it) }.catch { e ->
            val errorMsg = "Error getting patient count: ${e.localizedMessage ?: "Unknown error"}"
            AppLogger.e("PatientCountFlowCatch", errorMsg, e)
        }.flowOn(Dispatchers.IO)

    override fun getEncountersCount(): Flow<Result<Int>> =
        encounterDao.getEncountersCount().map { Result.Success(it) }.catch { e ->
            val errorMsg = "Error getting encounter count: ${e.localizedMessage ?: "Unknown error"}"
            AppLogger.e("EncounterCountFlowCatch", errorMsg, e)
        }.flowOn(Dispatchers.IO)


    override fun loadPatientsByCohort(): Flow<Result<List<Any>>> {
        TODO("Not yet implemented")
    }

    override fun loadCohorts(): Flow<Result<List<Cohort>>> = flow {
        emit(Result.Loading)

        val response = formApi.getCohorts()
        if (response.isSuccessful) {
            val cohorts = response.body()?.results
            if (cohorts != null) {
                emit(Result.Success(cohorts))
            } else {
                throw IllegalStateException("No cohorts available")
            }
        } else {
            throw HttpException(response)
        }
    }.catch { e ->
        AppLogger.e("Error ${e.localizedMessage}")
            emit(Result.Error(e.message ?: "Failed to load cohorts"))
    }.flowOn(Dispatchers.IO)


    override fun loadIndicators(): Flow<Result<List<Any>>> {
        TODO("Not yet implemented")
    }

    override fun loadParameter(): Flow<Result<List<Any>>> {
        TODO("Not yet implemented")
    }

    override fun loadOrderTypes(): Flow<Result<List<OrderType>>> = flow {
        emit(Result.Loading)

        val response = formApi.getOrderTypes()

        if (response.isSuccessful) {
            val ordertypes = response.body()?.results
            if (ordertypes != null) {
                emit(Result.Success(ordertypes))
            } else {
                throw IllegalStateException("No orderTypes available")
            }
        } else {
            throw HttpException(response)
        }
    }.catch { e ->
            AppLogger.e(e.message ?: "Failed to load orderTypes")
        emit(Result.Error(e.message ?: "Failed to load orderTypes"))
    }.flowOn(Dispatchers.IO)


    override fun loadEncounterTypes(): Flow<Result<List<EncounterType>>> = flow {
        emit(Result.Loading)

        val response = formApi.getEncounterTypes()

        if (response.isSuccessful) {
            val encountertypes = response.body()?.results
            if (encountertypes != null) {
                emit(Result.Success(encountertypes))
            } else {
                throw IllegalStateException("No encounterTypes available")
            }
        } else {
            throw HttpException(response)
        }
    }.catch { e ->
            AppLogger.e(e.message ?: "Failed to load encounterTypes")
        emit(Result.Error(e.message ?: "Failed to load encounterTypes"))
    }.flowOn(Dispatchers.IO)


    override fun loadPatientIndentifiers(): Flow<Result<List<Identifier>>> = flow {
        emit(Result.Loading)

        val response = formApi.getPatientIdentifiers()

        if (response.isSuccessful) {
            val identifiers = response.body()?.results
            if (identifiers != null) {
                emit(Result.Success(identifiers))
            } else {
                throw IllegalStateException("No patient identifiers available")
            }
        } else {
            throw HttpException(response)
        }
    }.catch { e ->
            AppLogger.e(e.message ?: "Failed to load patient identifiers types")
        emit(Result.Error(e.message ?: "Failed to load patient identifiers types"))
    }.flowOn(Dispatchers.IO)


    override fun loadPersonAttributeTypes(): Flow<Result<List<PersonAttributeType>>> = flow {
        emit(Result.Loading)

        val response = formApi.getPersonAttributeTypes()

        if (response.isSuccessful) {
            val personAttributeTypes = response.body()?.results
            if (personAttributeTypes != null) {
                emit(Result.Success(personAttributeTypes))
            } else {
                throw IllegalStateException("No person attributes available")
            }
        } else {
            throw HttpException(response)
        }
    }.catch { e ->
            AppLogger.e(e.message ?: "Failed to load attribute types")
        emit(Result.Error(e.message ?: "Failed to load person attribute types"))
    }.flowOn(Dispatchers.IO)


    override fun loadConditions(): Flow<Result<List<Any>>> {
        TODO("Not yet implemented")
    }

    override fun createDataDefinition(payload: DataDefinition): Flow<Result<List<PatientEntity>>> =
        flow {
            emit(Result.Loading)

            val response = formApi.generateDataDefinition(payload)

            if (response.isSuccessful) {
                val body = response.body()
                if (body != null) {
                    val listOfMaps = body.use { listOfMapAdapter.fromJson(it.source()) }
                    if (!listOfMaps.isNullOrEmpty()) {
                        val patients = listOfMaps.map { mapToPatientEntity(it) }
                        patientDao.insertAll(patients)  // save to DB
                        emit(Result.Success(patients))
                    } else {
                        throw IllegalStateException("No data definitions returned")
                    }
                } else {
                    throw IllegalStateException("Response body was null")
                }
            } else {
                throw HttpException(response)
            }
        }.catch { e ->
            AppLogger.e(e.message ?: "Failed to create data definition")
            emit(Result.Error(e.message ?: "Failed to create data definition"))
        }.flowOn(Dispatchers.IO)


    override fun getUnsyncedEncounters(): Flow<List<EncounterEntity>> = flow {
        try {
            val unsynced = encounterDao.getUnsynced()
            emit(unsynced)
        } catch (e: Exception) {
            AppLogger.e("DB error when fetching unsynced encounters: ${e.message}")
            throw e // ⚡ Let the caller handle it!
        }
    }

    override fun markSyncedEncounter(encounter: EncounterEntity): Flow<Unit> = flow {
        try {
            val rows = encounterDao.update(encounter.copy(synced = true))
            if (rows > 0) {
                emit(Unit)
            } else {
                throw IllegalStateException("No rows updated — does encounter exist?")
            }
        } catch (e: Exception) {
            AppLogger.e("DB error marking encounter synced: ${e.message}")
            throw e // ⚡ Let the caller handle it!
        }
    }

    override fun getSyncedEncountersCount(): Flow<Result<Int>> =
        encounterDao.getSyncedEncountersCount().map {
            Result.Success(it)
        }.catch { e ->
            val errorMsg =
                "Error getting synced encounter count: ${e.localizedMessage ?: "Unknown error"}"
            AppLogger.e("SyncedEncounterCountFlowCatch", errorMsg, e)
        }.flowOn(Dispatchers.IO)


    override fun getEligibleUnsyncedPatients(): Flow<List<PatientEntity>> = flow {
        try {
            val unsynced = patientDao.getEligibleUnsyncedPatients()
            emit(unsynced)
        } catch (e: Exception) {
            AppLogger.e("DB error when fetching unsynced patients: ${e.message}")
            throw e // ⚡ Let the caller handle it!
        }

    }


    override fun getUnsyncedPatients(): Flow<List<PatientEntity>> = flow {
        try {
            val unsynced = patientDao.getUnsyncedPatients()
            emit(unsynced)
        } catch (e: Exception) {
            AppLogger.e("DB error when fetching unsynced patients: ${e.message}")
            throw e // ⚡ Let the caller handle it!
        }
    }



    override fun markSyncedPatient(patient: PatientEntity): Flow<Unit> = flow {
        try {
            val rows = patientDao.updatePatient(patient.copy(synced = true))
            if (rows > 0) {
                emit(Unit)
            } else {
                throw IllegalStateException("No rows updated — does patient exist?")
            }
        } catch (e: Exception) {
            AppLogger.e("DB error marking patient synced: ${e.message}")
            throw e // ⚡ Let the caller handle it!
        }
    }

    override fun getSyncedPatientsCount(): Flow<Result<Int>> =
        patientDao.getSyncedPatientsCount().map { it ->
            Result.Success(it)
        }.catch { e ->
            val errorMsg =
                "Error getting synced patient count: ${e.localizedMessage ?: "Unknown error"}"
            AppLogger.e("SyncedPatientCountFlowCatch", errorMsg, e)
        }.flowOn(Dispatchers.IO)

}






