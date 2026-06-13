package com.lyecdevelopers.worklist.data.repository

import android.database.sqlite.SQLiteConstraintException
import android.database.sqlite.SQLiteException
import com.lyecdevelopers.core.data.local.dao.FormDao
import com.lyecdevelopers.core.data.local.dao.VisitDao
import com.lyecdevelopers.core.data.local.entity.EncounterEntity
import com.lyecdevelopers.core.data.local.entity.FormEntity
import com.lyecdevelopers.core.data.local.entity.VisitEntity
import com.lyecdevelopers.core.model.Result
import com.lyecdevelopers.core.model.VisitWithDetails
import com.lyecdevelopers.worklist.domain.repository.VisitRepository
import kotlinx.coroutines.Dispatchers
import kotlinx.coroutines.flow.Flow
import kotlinx.coroutines.flow.flow
import kotlinx.coroutines.flow.flowOn
import javax.inject.Inject

class VisitRepositoryImpl @Inject constructor(
    private val visitDao: VisitDao,
    private val formDao: FormDao,
) : VisitRepository {


    override fun getVisitSummariesForPatient(patientId: String): Flow<Result<List<VisitWithDetails>>> =
        flow {
            try {
                val visits = visitDao.getVisitDetailsForPatient(patientId)
                emit(Result.Success(visits))
            } catch (e: SQLiteConstraintException) {
                emit(Result.Error("Database constraint failed: ${e.localizedMessage ?: "Foreign key violation or unique index error"}"))
            } catch (e: SQLiteException) {
                emit(Result.Error("Database error: ${e.localizedMessage ?: "SQLite exception"}"))
            } catch (e: java.sql.SQLException) {
                emit(Result.Error("SQL error: ${e.localizedMessage ?: "SQL execution failed"}"))
            } catch (e: IllegalStateException) {
                emit(Result.Error("Illegal state: ${e.localizedMessage ?: "Unexpected Room state"}"))
            } catch (e: Exception) {
                emit(Result.Error("Unexpected error: ${e.localizedMessage ?: "Unknown error"}"))
            }
        }.flowOn(Dispatchers.IO)


    override fun getMostRecentForVisitPatient(patientId: String): Flow<Result<VisitWithDetails>> =
        flow {
            try {
                val visits = visitDao.getMostRecentVisitForPatient(patientId)
                emit(Result.Success(visits))
            } catch (e: SQLiteConstraintException) {
                emit(Result.Error("Database constraint failed: ${e.localizedMessage ?: "Foreign key violation or unique index error"}"))
            } catch (e: SQLiteException) {
                emit(Result.Error("Database error: ${e.localizedMessage ?: "SQLite exception"}"))
            } catch (e: java.sql.SQLException) {
                emit(Result.Error("SQL error: ${e.localizedMessage ?: "SQL execution failed"}"))
            } catch (e: IllegalStateException) {
                emit(Result.Error("Illegal state: ${e.localizedMessage ?: "Unexpected Room state"}"))
            } catch (e: Exception) {
                emit(Result.Error("Unexpected error: ${e.localizedMessage ?: "Unknown error"}"))
            }
        }.flowOn(Dispatchers.IO)


    override fun saveVisit(visit: VisitEntity): Flow<Result<Boolean>> = flow {
        try {
            visitDao.insertVisit(visit)
            emit(Result.Success(true))
        } catch (e: SQLiteConstraintException) {
            emit(Result.Error("Constraint violation: ${e.localizedMessage ?: "Unknown constraint error"}"))
        } catch (e: SQLiteException) {
            emit(Result.Error("Database error: ${e.localizedMessage ?: "Unknown SQLite error"}"))
        } catch (e: Exception) {
            emit(Result.Error("Unexpected error: ${e.localizedMessage ?: "Unknown error"}"))
        }
    }.flowOn(Dispatchers.IO)

    override fun getEncountersByPatientIdAndVisitId(
        patientId: String,
        visitId: String,
    ): Flow<Result<List<EncounterEntity>>> = flow {
        try {
            val encounters = visitDao.getEncountersByPatientIdAndVisitId(patientId, visitId)
            emit(Result.Success(encounters))
        } catch (e: SQLiteConstraintException) {
            emit(Result.Error("Database constraint failed: ${e.localizedMessage ?: "Foreign key violation or unique index error"}"))
        } catch (e: SQLiteException) {
            emit(Result.Error("Database error: ${e.localizedMessage ?: "SQLite exception"}"))
        } catch (e: java.sql.SQLException) {
            emit(Result.Error("SQL error: ${e.localizedMessage ?: "SQL execution failed"}"))

        } catch (e: IllegalStateException) {
            emit(Result.Error("Illegal state: ${e.localizedMessage ?: "Unexpected Room state"}"))
        } catch (e: Exception) {
            emit(Result.Error("Unexpected error: ${e.localizedMessage ?: "Unknown error"}"))
        }

    }.flowOn(Dispatchers.IO)

    override fun getForms(): Flow<Result<List<FormEntity>>> = flow {
        try {
            val forms = formDao.getAllForms()
            emit(Result.Success(forms))
        } catch (e: SQLiteConstraintException) {
            emit(Result.Error("Database constraint failed: ${e.localizedMessage ?: "Foreign key violation or unique index error"}"))
        } catch (e: SQLiteException) {
            emit(Result.Error("Database error: ${e.localizedMessage ?: "SQLite exception"}"))
        } catch (e: java.sql.SQLException) {
            emit(Result.Error("SQL error: ${e.localizedMessage ?: "SQL execution failed"}"))

        } catch (e: IllegalStateException) {
            emit(Result.Error("Illegal state: ${e.localizedMessage ?: "Unexpected Room state"}"))
        } catch (e: Exception) {
            emit(Result.Error("Unexpected error: ${e.localizedMessage ?: "Unknown error"}"))
        }

    }.flowOn(Dispatchers.IO)

    override fun getAllVisitsWithDetails(): Flow<Result<List<VisitWithDetails>>> = flow {
        try {
            val visitsWithDetails = visitDao.getAllVisitsWithDetails()
            emit(Result.Success(visitsWithDetails))
        } catch (e: SQLiteConstraintException) {
            emit(Result.Error("Database constraint failed: ${e.localizedMessage ?: "Foreign key violation or unique index error"}"))
        } catch (e: SQLiteException) {
            emit(Result.Error("Database error: ${e.localizedMessage ?: "SQLite exception"}"))
        } catch (e: java.sql.SQLException) {
            emit(Result.Error("SQL error: ${e.localizedMessage ?: "SQL execution failed"}"))

        } catch (e: IllegalStateException) {
            emit(Result.Error("Illegal state: ${e.localizedMessage ?: "Unexpected Room state"}"))
        } catch (e: Exception) {
            emit(Result.Error("Unexpected error: ${e.localizedMessage ?: "Unknown error"}"))
        }
    }.flowOn(Dispatchers.IO)


}