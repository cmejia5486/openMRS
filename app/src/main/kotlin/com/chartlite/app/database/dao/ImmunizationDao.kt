package com.chartlite.app.database.dao

import androidx.room.*
import com.chartlite.app.database.entity.ImmunizationEntity
import kotlinx.coroutines.flow.Flow

@Dao
interface ImmunizationDao {
    @Insert(onConflict = OnConflictStrategy.ABORT)
    suspend fun insert(immunization: ImmunizationEntity)

    @Update
    suspend fun update(immunization: ImmunizationEntity)

    @Query("SELECT * FROM immunizations WHERE id = :id")
    suspend fun getById(id: String): ImmunizationEntity?

    @Query("SELECT * FROM immunizations WHERE patientId = :patientId ORDER BY administeredAt DESC")
    suspend fun getByPatient(patientId: String): List<ImmunizationEntity>

    @Query("SELECT * FROM immunizations WHERE patientId = :patientId AND vaccineCode = :vaccineCode ORDER BY doseNumber")
    suspend fun getByPatientAndVaccine(patientId: String, vaccineCode: String): List<ImmunizationEntity>

    @Query("SELECT * FROM immunizations WHERE nextDoseDueDate IS NOT NULL AND nextDoseDueDate <= :beforeDate ORDER BY nextDoseDueDate")
    suspend fun getOverdue(beforeDate: Long): List<ImmunizationEntity>

    @Query("SELECT * FROM immunizations WHERE patientId = :patientId ORDER BY administeredAt DESC")
    fun observeByPatient(patientId: String): Flow<List<ImmunizationEntity>>

    @Query("SELECT COUNT(*) FROM immunizations WHERE nextDoseDueDate IS NOT NULL AND nextDoseDueDate <= :beforeDate")
    suspend fun getOverdueCount(beforeDate: Long): Int
}
