package com.chartlite.app.database.dao

import androidx.room.*
import com.chartlite.app.database.entity.AppointmentEntity
import kotlinx.coroutines.flow.Flow

@Dao
interface AppointmentDao {
    @Insert(onConflict = OnConflictStrategy.ABORT)
    suspend fun insert(appointment: AppointmentEntity)

    @Update
    suspend fun update(appointment: AppointmentEntity)

    @Query("SELECT * FROM appointments WHERE id = :id")
    suspend fun getById(id: String): AppointmentEntity?

    @Query("""
        SELECT * FROM appointments
        WHERE facilityId = :facilityId AND scheduledDate = :date
        ORDER BY scheduledTime ASC
    """)
    suspend fun getByDate(facilityId: String, date: Long): List<AppointmentEntity>

    @Query("""
        SELECT * FROM appointments
        WHERE facilityId = :facilityId AND scheduledDate = :date
        ORDER BY scheduledTime ASC
    """)
    fun observeByDate(facilityId: String, date: Long): Flow<List<AppointmentEntity>>

    @Query("SELECT * FROM appointments WHERE patientId = :patientId ORDER BY scheduledDate DESC")
    suspend fun getByPatient(patientId: String): List<AppointmentEntity>

    @Query("""
        SELECT * FROM appointments
        WHERE facilityId = :facilityId AND scheduledDate >= :fromDate AND status = 'SCHEDULED'
        ORDER BY scheduledDate ASC, scheduledTime ASC
    """)
    suspend fun getUpcoming(facilityId: String, fromDate: Long): List<AppointmentEntity>

    @Query("""
        SELECT COUNT(*) FROM appointments
        WHERE facilityId = :facilityId AND scheduledDate = :date AND status != 'CANCELLED'
    """)
    suspend fun getCountForDate(facilityId: String, date: Long): Int

    @Query("""
        SELECT * FROM appointments
        WHERE facilityId = :facilityId AND scheduledDate = :date AND status = 'SCHEDULED'
        ORDER BY scheduledTime ASC
        LIMIT 1
    """)
    suspend fun getNextForDate(facilityId: String, date: Long): AppointmentEntity?
}
