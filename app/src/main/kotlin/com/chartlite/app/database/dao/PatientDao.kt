package com.chartlite.app.database.dao

import androidx.room.*
import com.chartlite.app.database.entity.PatientEntity
import kotlinx.coroutines.flow.Flow

@Dao
interface PatientDao {
    @Insert(onConflict = OnConflictStrategy.ABORT)
    suspend fun insert(patient: PatientEntity)

    @Update
    suspend fun update(patient: PatientEntity)

    @Query("SELECT * FROM patients WHERE id = :id")
    suspend fun getById(id: String): PatientEntity?

    @Query("SELECT * FROM patients WHERE id = :id")
    fun observeById(id: String): Flow<PatientEntity?>

    @Query("SELECT * FROM patients WHERE REPLACE(id, '-', '') LIKE :prefix || '%' ORDER BY updatedAt DESC LIMIT 20")
    suspend fun searchByIdPrefix(prefix: String): List<PatientEntity>

    @Query("""
        SELECT * FROM patients
        WHERE firstName LIKE '%' || :query || '%'
           OR lastName LIKE '%' || :query || '%'
           OR id LIKE '%' || :query || '%'
           OR phoneNumber LIKE '%' || :query || '%'
        ORDER BY updatedAt DESC
        LIMIT 20
    """)
    suspend fun search(query: String): List<PatientEntity>

    @Query("SELECT * FROM patients WHERE phoneNumber = :phone")
    suspend fun getByPhone(phone: String): PatientEntity?

    @Query("SELECT * FROM patients ORDER BY updatedAt DESC LIMIT :limit")
    suspend fun getRecent(limit: Int = 20): List<PatientEntity>

    @Query("SELECT COUNT(*) FROM patients")
    suspend fun getCount(): Int

    @Query("SELECT * FROM patients ORDER BY updatedAt DESC")
    fun observeAll(): Flow<List<PatientEntity>>

    @Query("SELECT * FROM patients")
    suspend fun getAll(): List<PatientEntity>
}
