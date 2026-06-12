package com.lyecdevelopers.core.data.local.dao

import androidx.paging.PagingSource
import androidx.room.Dao
import androidx.room.Delete
import androidx.room.Insert
import androidx.room.OnConflictStrategy
import androidx.room.Query
import androidx.room.Transaction
import androidx.room.Update
import com.lyecdevelopers.core.data.local.entity.PatientEntity
import com.lyecdevelopers.core.model.PatientWithVisits
import kotlinx.coroutines.flow.Flow


@Dao
interface PatientDao {


    @Query(
        """
        SELECT * FROM patients 
        WHERE (:name IS NULL OR firstName LIKE '%' || :name || '%' OR lastName LIKE '%' || :name || '%')
        AND (:gender IS NULL OR gender = :gender)
        AND (:status IS NULL OR status = :status)
        ORDER BY lastName ASC
    """
    )
    fun getPagedPatients(
        name: String?,
        gender: String?,
        status: String?,
    ): PagingSource<Int, PatientEntity>


    @Query(
        """
    SELECT * FROM patients 
    WHERE (:name IS NULL OR firstName LIKE '%' || :name || '%' OR lastName LIKE '%' || :name || '%') 
    AND (:gender IS NULL OR gender = :gender)
    AND (:status IS NULL OR status = :status)
    ORDER BY lastName ASC
"""
    )
    fun searchPatients(
        name: String?,
        gender: String?,
        status: String?,
    ): Flow<List<PatientEntity>>


    @Transaction
    @Query("SELECT * FROM patients WHERE id = :patientId")
    fun observePatientWithVisits(patientId: String): Flow<PatientWithVisits?>

    @Transaction
    @Query("SELECT * FROM patients")
    fun observeAllPatientsWithVisits(): Flow<List<PatientWithVisits>>

    @Transaction
    @Query("SELECT * FROM patients WHERE id = :patientId")
    suspend fun getPatientWithVisits(patientId: String): PatientWithVisits?

    @Transaction
    @Query("SELECT * FROM patients")
    suspend fun getAllPatientsWithVisits(): List<PatientWithVisits>

    @Insert(onConflict = OnConflictStrategy.REPLACE)
    suspend fun insertPatient(patient: PatientEntity)

    @Insert(onConflict = OnConflictStrategy.REPLACE)
    suspend fun insertAll(patients: List<PatientEntity>)

    @Update
    suspend fun updatePatient(patient: PatientEntity): Int

    @Delete
    suspend fun deletePatient(patient: PatientEntity)

    @Transaction
    @Query("SELECT * FROM patients WHERE id = :id")
    fun getPatientById(id: String): Flow<PatientEntity?>

    @Transaction
    @Query("SELECT * FROM patients ORDER BY lastName ASC")
    suspend fun getAllPatients(): List<PatientEntity>

    @Transaction
    @Query("DELETE FROM patients")
    suspend fun clearAll()

    @Transaction
    @Query(
        """
    UPDATE patients
    SET isEligibleForSync = :isEligible, lastModified = :lastModified
    WHERE id = :patientId
"""
    )
    suspend fun updateEligibilityForSync(
        patientId: String,
        isEligible: Boolean,
        lastModified: Long = System.currentTimeMillis(),
    )


    @Transaction
    @Query(
        """
    SELECT * FROM patients
    WHERE synced = 0
    AND isEligibleForSync = 1
    AND isVoided = 0
"""
    )
    suspend fun getEligibleUnsyncedPatients(): List<PatientEntity>


    @Query("SELECT * FROM patients WHERE synced = 0")
    suspend fun getUnsyncedPatients(): List<PatientEntity>

    @Query("SELECT COUNT(*) FROM patients")
    fun getPatientsCount(): Flow<Int>

    @Query("SELECT COUNT(*) FROM patients WHERE synced = 1")
    fun getSyncedPatientsCount(): Flow<Int>

}

