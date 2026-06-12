package com.chartlite.app.database.dao

import androidx.room.*
import com.chartlite.app.database.entity.SmsLogEntity

@Dao
interface SmsLogDao {
    @Insert(onConflict = OnConflictStrategy.ABORT)
    suspend fun insert(log: SmsLogEntity)

    @Query("SELECT * FROM sms_logs WHERE patientId = :patientId ORDER BY timestamp DESC")
    suspend fun getByPatientId(patientId: String): List<SmsLogEntity>

    @Query("SELECT * FROM sms_logs WHERE encounterId = :encounterId ORDER BY timestamp DESC")
    suspend fun getByEncounterId(encounterId: String): List<SmsLogEntity>

    @Query("SELECT * FROM sms_logs WHERE messageType = :type ORDER BY timestamp DESC LIMIT :limit")
    suspend fun getByType(type: String, limit: Int = 100): List<SmsLogEntity>

    @Query("SELECT * FROM sms_logs ORDER BY timestamp DESC LIMIT :limit")
    suspend fun getRecent(limit: Int = 100): List<SmsLogEntity>

    @Query("SELECT COUNT(*) FROM sms_logs WHERE patientId = :patientId")
    suspend fun getCountForPatient(patientId: String): Int

    @Query("""
        SELECT * FROM sms_logs
        WHERE timestamp BETWEEN :startTime AND :endTime
        ORDER BY timestamp DESC
    """)
    suspend fun getByDateRange(startTime: Long, endTime: Long): List<SmsLogEntity>
}
