package com.lyecdevelopers.core.data.local.dao

import androidx.room.Dao
import androidx.room.Insert
import androidx.room.OnConflictStrategy
import androidx.room.Query
import androidx.room.Transaction
import com.lyecdevelopers.core.data.local.entity.VitalsEntity
import kotlinx.coroutines.flow.Flow

@Dao
interface VitalsDao {

    /**
     * Get a single vitals record for a specific visit.
     * Returns null if no vitals recorded for that visit.
     */
    @Transaction
    @Query("SELECT * FROM vitals WHERE visitUuid = :visitUuid LIMIT 1")
    fun getVitalsByVisit(visitUuid: String): Flow<VitalsEntity?>

    /**
     * Get all vitals ever recorded for a specific patient,
     * newest first.
     * Reactive flow for UI.
     */

    @Transaction
    @Query("SELECT * FROM vitals WHERE patientUuid = :patientUuid ORDER BY dateRecorded DESC")
    fun getVitalsForPatient(patientUuid: String): Flow<List<VitalsEntity>>

    /**
     * Insert a new vitals record.
     * Replace on conflict.
     */
    @Insert(onConflict = OnConflictStrategy.REPLACE)
    fun insertVitals(vitals: VitalsEntity)


    /**
     * Delete a specific vitals record by ID.
     */
    @Transaction
    @Query("DELETE FROM vitals WHERE id = :vitalsId")
    suspend fun deleteVitals(vitalsId: String)

    /**
     * Delete all vitals for a patient.
     */
    @Transaction
    @Query("DELETE FROM vitals WHERE patientUuid = :patientUuid")
    suspend fun deleteVitalsForPatient(patientUuid: String)
}
