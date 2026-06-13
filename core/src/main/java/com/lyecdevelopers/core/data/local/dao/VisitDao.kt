package com.lyecdevelopers.core.data.local.dao

import androidx.room.Dao
import androidx.room.Delete
import androidx.room.Insert
import androidx.room.OnConflictStrategy
import androidx.room.Query
import androidx.room.Transaction
import com.lyecdevelopers.core.data.local.entity.EncounterEntity
import com.lyecdevelopers.core.data.local.entity.VisitEntity
import com.lyecdevelopers.core.data.local.entity.VitalsEntity
import com.lyecdevelopers.core.model.VisitStatus
import com.lyecdevelopers.core.model.VisitWithDetails

@Dao
interface VisitDao {

    // ➕ Insert a single visit
    @Insert(onConflict = OnConflictStrategy.REPLACE)
    suspend fun insertVisit(visit: VisitEntity)

    // ➕ Insert multiple visits (e.g., from sync)
    @Insert(onConflict = OnConflictStrategy.REPLACE)
    suspend fun insertAll(visits: List<VisitEntity>)

    // 🔍 Get all visits for a patient (most common)
    @Query("SELECT * FROM visits WHERE patientId = :patientId ORDER BY scheduledTime DESC")
    suspend fun getVisitsForPatient(patientId: String): List<VisitEntity>

    // 🔍 Get a single visit by ID
    @Query("SELECT * FROM visits WHERE id = :visitId")
    suspend fun getVisitById(visitId: String): VisitEntity?

    // 🔄 Update visit status
    @Query("UPDATE visits SET status = :status WHERE id = :visitId")
    suspend fun updateVisitStatus(visitId: String, status: VisitStatus)

    // ❌ Delete a visit
    @Delete
    suspend fun deleteVisit(visit: VisitEntity)

    // 🔍 Get unsynced or pending visits (for syncing)
    @Query("SELECT * FROM visits WHERE status = :status")
    suspend fun getVisitsByStatus(status: VisitStatus): List<VisitEntity>

    // ➕ Insert vitals
    @Insert(onConflict = OnConflictStrategy.REPLACE)
    suspend fun insertVitals(vitals: VitalsEntity)

    // ➕ Insert encounters
    @Insert(onConflict = OnConflictStrategy.REPLACE)
    suspend fun insertEncounters(encounters: List<EncounterEntity>)

    // 🧩 Get visit WITH related details (encounters + vitals)
    @Transaction
    @Query("SELECT * FROM visits WHERE patientId = :patientId")
    suspend fun getVisitDetailsForPatient(patientId: String): List<VisitWithDetails>


    // get most recent visit by date
    @Query("SELECT * FROM visits WHERE patientId = :patientId ORDER BY scheduledTime DESC LIMIT 1")
    suspend fun getMostRecentVisitForPatient(patientId: String): VisitWithDetails

    //  get encounter by patient id and visit id
    @Query("SELECT * FROM encounters WHERE patientUuid = :patientId AND visitUuid = :visitId")
    suspend fun getEncountersByPatientIdAndVisitId(
        patientId: String,
        visitId: String,
    ): List<EncounterEntity>

    // get all visits with details
    @Transaction
    @Query("SELECT * FROM visits")
    suspend fun getAllVisitsWithDetails(): List<VisitWithDetails>

}


