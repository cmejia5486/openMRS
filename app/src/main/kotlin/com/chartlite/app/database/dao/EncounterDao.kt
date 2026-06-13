package com.chartlite.app.database.dao

import androidx.room.*
import com.chartlite.app.database.entity.EncounterEntity
import kotlinx.coroutines.flow.Flow

@Dao
abstract class EncounterDao {
    @Insert(onConflict = OnConflictStrategy.ABORT)
    abstract suspend fun insert(encounter: EncounterEntity)

    @Update
    abstract suspend fun update(encounter: EncounterEntity)

    /** Insert an encounter and return its ID — wraps in a transaction for callers that
     *  chain this with related writes (e.g. visit linking, audit logging). */
    @Transaction
    open suspend fun insertAndReturn(encounter: EncounterEntity): String {
        insert(encounter)
        return encounter.id
    }

    @Query("SELECT * FROM encounters WHERE id = :id")
    abstract suspend fun getById(id: String): EncounterEntity?

    @Query("""
        SELECT * FROM encounters
        WHERE patientId = :patientId
        ORDER BY CASE WHEN timestamp > 0 THEN timestamp ELSE createdAt END DESC
    """)
    abstract suspend fun getByPatientId(patientId: String): List<EncounterEntity>

    @Query("""
        SELECT * FROM encounters
        WHERE patientId = :patientId
        ORDER BY CASE WHEN timestamp > 0 THEN timestamp ELSE createdAt END DESC
    """)
    abstract fun observeByPatientId(patientId: String): Flow<List<EncounterEntity>>

    @Query("""
        SELECT * FROM encounters
        WHERE providerId = :providerId
        ORDER BY CASE WHEN timestamp > 0 THEN timestamp ELSE createdAt END DESC
        LIMIT :limit
    """)
    abstract suspend fun getByProviderId(providerId: String, limit: Int = 50): List<EncounterEntity>

    @Query("""
        SELECT * FROM encounters
        WHERE timestamp BETWEEN :startMs AND :endMs
        ORDER BY timestamp DESC
    """)
    abstract suspend fun getByDateRange(startMs: Long, endMs: Long): List<EncounterEntity>

    @Query("""
        SELECT * FROM encounters
        ORDER BY CASE WHEN timestamp > 0 THEN timestamp ELSE createdAt END DESC
        LIMIT :limit
    """)
    abstract suspend fun getRecent(limit: Int = 20): List<EncounterEntity>

    @Query("""
        SELECT * FROM encounters
        ORDER BY CASE WHEN timestamp > 0 THEN timestamp ELSE createdAt END DESC
    """)
    abstract fun observeAll(): Flow<List<EncounterEntity>>

    @Query("SELECT COUNT(*) FROM encounters")
    abstract suspend fun getCount(): Int

    @Query("SELECT COUNT(*) FROM encounters WHERE timestamp BETWEEN :startMs AND :endMs")
    abstract suspend fun getCountByDateRange(startMs: Long, endMs: Long): Int

    @Query("SELECT * FROM encounters")
    abstract suspend fun getAll(): List<EncounterEntity>

    @Query("UPDATE encounters SET smsStatus = :status WHERE id = :id")
    abstract suspend fun updateSmsStatus(id: String, status: String)

    @Query("UPDATE encounters SET cdssAcknowledged = :acknowledged WHERE id = :id")
    abstract suspend fun updateCdssAcknowledged(id: String, acknowledged: Boolean)

    @Query("UPDATE encounters SET diagnoses = :diagnosesJson, suggestedDiagnoses = :suggestedJson WHERE id = :id")
    abstract suspend fun updateDiagnoses(id: String, diagnosesJson: String, suggestedJson: String)
}
