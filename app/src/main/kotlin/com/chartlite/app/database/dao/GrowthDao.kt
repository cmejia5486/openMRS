package com.chartlite.app.database.dao

import androidx.room.*
import com.chartlite.app.database.entity.GrowthMeasurementEntity
import kotlinx.coroutines.flow.Flow

@Dao
interface GrowthDao {
    @Insert(onConflict = OnConflictStrategy.ABORT)
    suspend fun insert(measurement: GrowthMeasurementEntity)

    @Update
    suspend fun update(measurement: GrowthMeasurementEntity)

    @Query("SELECT * FROM growth_measurements WHERE id = :id")
    suspend fun getById(id: String): GrowthMeasurementEntity?

    @Query("SELECT * FROM growth_measurements WHERE patientId = :patientId ORDER BY measuredAt DESC")
    suspend fun getByPatient(patientId: String): List<GrowthMeasurementEntity>

    @Query("SELECT * FROM growth_measurements WHERE patientId = :patientId ORDER BY measuredAt DESC LIMIT 1")
    suspend fun getLatest(patientId: String): GrowthMeasurementEntity?

    @Query("SELECT * FROM growth_measurements WHERE patientId = :patientId ORDER BY measuredAt ASC")
    fun observeByPatient(patientId: String): Flow<List<GrowthMeasurementEntity>>
}
