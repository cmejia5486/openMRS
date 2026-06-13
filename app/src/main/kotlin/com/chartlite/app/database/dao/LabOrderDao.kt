package com.chartlite.app.database.dao

import androidx.room.*
import com.chartlite.app.database.entity.LabOrderEntity
import kotlinx.coroutines.flow.Flow

@Dao
abstract class LabOrderDao {
    @Insert(onConflict = OnConflictStrategy.ABORT)
    abstract suspend fun insert(order: LabOrderEntity)

    @Update
    abstract suspend fun update(order: LabOrderEntity)

    /** Atomically read a lab order and update it — prevents lost updates from concurrent writers. */
    @Transaction
    open suspend fun getAndUpdate(id: String, transform: (LabOrderEntity) -> LabOrderEntity): Boolean {
        val order = getById(id) ?: return false
        update(transform(order))
        return true
    }

    @Query("SELECT * FROM lab_orders WHERE id = :id")
    abstract suspend fun getById(id: String): LabOrderEntity?

    @Query("SELECT * FROM lab_orders WHERE visitId = :visitId ORDER BY orderedAt DESC")
    abstract suspend fun getByVisitId(visitId: String): List<LabOrderEntity>

    @Query("SELECT * FROM lab_orders WHERE patientId = :patientId ORDER BY orderedAt DESC")
    abstract suspend fun getByPatientId(patientId: String): List<LabOrderEntity>

    @Query("SELECT * FROM lab_orders WHERE patientId = :patientId ORDER BY orderedAt DESC")
    abstract fun observeByPatientId(patientId: String): Flow<List<LabOrderEntity>>

    @Query("SELECT * FROM lab_orders WHERE status IN ('ORDERED', 'COLLECTED') ORDER BY orderedAt ASC")
    abstract suspend fun getPending(): List<LabOrderEntity>

    @Query("SELECT * FROM lab_orders WHERE status IN ('ORDERED', 'COLLECTED') ORDER BY orderedAt ASC")
    abstract fun observePending(): Flow<List<LabOrderEntity>>

    @Query("SELECT COUNT(*) FROM lab_orders WHERE status IN ('ORDERED', 'COLLECTED')")
    abstract suspend fun getPendingCount(): Int

    @Query("SELECT * FROM lab_orders WHERE status = 'RESULTED' AND patientId = :patientId ORDER BY resultedAt DESC")
    abstract suspend fun getResultedByPatient(patientId: String): List<LabOrderEntity>
}
