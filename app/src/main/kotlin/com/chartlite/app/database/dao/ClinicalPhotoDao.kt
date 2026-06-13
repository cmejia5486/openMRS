package com.chartlite.app.database.dao

import androidx.room.*
import com.chartlite.app.database.entity.ClinicalPhotoEntity
import kotlinx.coroutines.flow.Flow

@Dao
interface ClinicalPhotoDao {
    @Insert(onConflict = OnConflictStrategy.REPLACE)
    suspend fun insert(photo: ClinicalPhotoEntity)

    @Query("SELECT * FROM clinical_photos WHERE encounterId = :encounterId ORDER BY capturedAt DESC")
    fun getByEncounter(encounterId: String): Flow<List<ClinicalPhotoEntity>>

    @Query("SELECT * FROM clinical_photos WHERE patientId = :patientId ORDER BY capturedAt DESC")
    fun getByPatient(patientId: String): Flow<List<ClinicalPhotoEntity>>

    @Query("SELECT * FROM clinical_photos WHERE patientId = :patientId AND contentType = :contentType ORDER BY capturedAt DESC")
    fun getByPatientAndType(patientId: String, contentType: String): Flow<List<ClinicalPhotoEntity>>

    @Delete
    suspend fun delete(photo: ClinicalPhotoEntity)
}
