package com.chartlite.app.database.dao

import androidx.room.*
import com.chartlite.app.database.entity.FPVisitEntity
import kotlinx.coroutines.flow.Flow

@Dao
interface FPVisitDao {
    @Insert(onConflict = OnConflictStrategy.ABORT)
    suspend fun insert(fpVisit: FPVisitEntity)

    @Update
    suspend fun update(fpVisit: FPVisitEntity)

    @Query("SELECT * FROM fp_visits WHERE id = :id")
    suspend fun getById(id: String): FPVisitEntity?

    @Query("SELECT * FROM fp_visits WHERE patientId = :patientId ORDER BY createdAt DESC")
    suspend fun getByPatient(patientId: String): List<FPVisitEntity>

    @Query("SELECT * FROM fp_visits WHERE patientId = :patientId AND method != 'NONE' ORDER BY createdAt DESC LIMIT 1")
    suspend fun getActiveMethod(patientId: String): FPVisitEntity?

    @Query("SELECT * FROM fp_visits WHERE nextFollowUpDate IS NOT NULL AND nextFollowUpDate <= :beforeDate ORDER BY nextFollowUpDate")
    suspend fun getOverdueFollowUps(beforeDate: Long): List<FPVisitEntity>

    @Query("SELECT * FROM fp_visits WHERE patientId = :patientId ORDER BY createdAt DESC")
    fun observeByPatient(patientId: String): Flow<List<FPVisitEntity>>
}
