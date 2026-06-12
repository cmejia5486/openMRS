package com.chartlite.app.database.dao

import androidx.room.*
import com.chartlite.app.database.entity.VisitEntity
import kotlinx.coroutines.flow.Flow

@Dao
abstract class VisitDao {
    @Insert(onConflict = OnConflictStrategy.ABORT)
    abstract suspend fun insert(visit: VisitEntity)

    @Update
    abstract suspend fun update(visit: VisitEntity)

    /** Atomically read a visit and update it — prevents lost updates from concurrent writers. */
    @Transaction
    open suspend fun getAndUpdate(id: String, transform: (VisitEntity) -> VisitEntity): Boolean {
        val visit = getById(id) ?: return false
        update(transform(visit))
        return true
    }

    @Query("SELECT * FROM visits WHERE id = :id")
    abstract suspend fun getById(id: String): VisitEntity?

    @Query("SELECT * FROM visits WHERE id = :id")
    abstract fun observeById(id: String): Flow<VisitEntity?>

    /** Queue for a station: patients in the given waiting statuses, ordered by priority then time. */
    @Query("""
        SELECT * FROM visits
        WHERE visitDate = :today
        AND status IN (:statuses)
        AND facilityId = :facilityId
        ORDER BY priorityLevel DESC, createdAt ASC
    """)
    abstract suspend fun getQueueForStation(today: String, statuses: List<String>, facilityId: String): List<VisitEntity>

    /** Observe queue changes in real-time. */
    @Query("""
        SELECT * FROM visits
        WHERE visitDate = :today
        AND status IN (:statuses)
        AND facilityId = :facilityId
        ORDER BY priorityLevel DESC, createdAt ASC
    """)
    abstract fun observeQueueForStation(today: String, statuses: List<String>, facilityId: String): Flow<List<VisitEntity>>

    /** All visits today at this facility. */
    @Query("SELECT * FROM visits WHERE visitDate = :today AND facilityId = :facilityId ORDER BY updatedAt DESC")
    abstract suspend fun getTodayVisits(today: String, facilityId: String): List<VisitEntity>

    @Query("SELECT * FROM visits WHERE visitDate = :today AND facilityId = :facilityId ORDER BY updatedAt DESC")
    abstract fun observeTodayVisits(today: String, facilityId: String): Flow<List<VisitEntity>>

    @Query("SELECT COUNT(*) FROM visits WHERE visitDate = :today AND facilityId = :facilityId")
    abstract suspend fun getTodayCount(today: String, facilityId: String): Int

    @Query("SELECT COUNT(*) FROM visits WHERE visitDate = :today AND facilityId = :facilityId AND status IN (:statuses)")
    abstract suspend fun getCountByStatuses(today: String, facilityId: String, statuses: List<String>): Int

    @Query("SELECT * FROM visits WHERE patientId = :patientId ORDER BY createdAt DESC")
    abstract suspend fun getByPatientId(patientId: String): List<VisitEntity>

    @Query("SELECT * FROM visits WHERE patientId = :patientId AND visitDate = :today LIMIT 1")
    abstract suspend fun getTodayVisitForPatient(patientId: String, today: String): VisitEntity?

    /** Get visits modified since a given timestamp for a specific facility (incremental sync). */
    @Query("SELECT * FROM visits WHERE updatedAt > :since AND facilityId = :facilityId")
    abstract suspend fun getModifiedSince(since: Long, facilityId: String): List<VisitEntity>

    /** Insert or replace a visit (used for sync merge). */
    @Insert(onConflict = OnConflictStrategy.REPLACE)
    abstract suspend fun upsert(visit: VisitEntity)
}
