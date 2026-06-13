package com.chartlite.app.database.dao

import androidx.room.*
import com.chartlite.app.database.entity.AuditLogEntity

@Dao
interface AuditLogDao {
    @Insert(onConflict = OnConflictStrategy.ABORT)
    suspend fun insert(log: AuditLogEntity)

    @Query("SELECT * FROM audit_logs WHERE userId = :userId ORDER BY timestamp DESC LIMIT :limit")
    suspend fun getByUserId(userId: String, limit: Int = 100): List<AuditLogEntity>

    @Query("SELECT * FROM audit_logs WHERE action = :action ORDER BY timestamp DESC LIMIT :limit")
    suspend fun getByAction(action: String, limit: Int = 100): List<AuditLogEntity>

    @Query("""
        SELECT * FROM audit_logs
        WHERE timestamp BETWEEN :startTime AND :endTime
        ORDER BY timestamp DESC
        LIMIT :limit
    """)
    suspend fun getByDateRange(startTime: Long, endTime: Long, limit: Int = 500): List<AuditLogEntity>

    @Query("""
        SELECT * FROM audit_logs
        WHERE targetType = :targetType AND targetId = :targetId
        ORDER BY timestamp DESC
    """)
    suspend fun getByTarget(targetType: String, targetId: String): List<AuditLogEntity>

    @Query("SELECT COUNT(*) FROM audit_logs WHERE userId = :userId AND action = 'FAILED_AUTH' AND timestamp > :since")
    suspend fun getRecentFailedAuthCount(userId: String, since: Long): Int

    @Query("SELECT * FROM audit_logs ORDER BY timestamp DESC LIMIT :limit")
    suspend fun getRecent(limit: Int = 100): List<AuditLogEntity>

    @Query("DELETE FROM audit_logs WHERE timestamp < :before")
    suspend fun deleteOlderThan(before: Long): Int
}
