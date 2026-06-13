package com.chartlite.app.database.dao

import androidx.room.*
import com.chartlite.app.database.entity.UserEntity
import kotlinx.coroutines.flow.Flow

@Dao
interface UserDao {
    @Insert(onConflict = OnConflictStrategy.ABORT)
    suspend fun insert(user: UserEntity)

    @Update
    suspend fun update(user: UserEntity)

    @Query("SELECT * FROM users WHERE id = :id")
    suspend fun getById(id: String): UserEntity?

    @Query("SELECT * FROM users WHERE username = :username AND facilityId = :facilityId")
    suspend fun getByUsername(username: String, facilityId: String): UserEntity?

    @Query("SELECT * FROM users WHERE facilityId = :facilityId ORDER BY displayName ASC")
    suspend fun getByFacilityId(facilityId: String): List<UserEntity>

    @Query("SELECT * FROM users WHERE facilityId = :facilityId AND isActive = 1 ORDER BY displayName ASC")
    suspend fun getActiveByFacilityId(facilityId: String): List<UserEntity>

    @Query("SELECT * FROM users WHERE facilityId = :facilityId ORDER BY displayName ASC")
    fun observeByFacilityId(facilityId: String): Flow<List<UserEntity>>

    @Query("SELECT * FROM users WHERE role = :role AND facilityId = :facilityId AND isActive = 1")
    suspend fun getByRole(role: String, facilityId: String): List<UserEntity>

    @Query("SELECT COUNT(*) FROM users WHERE facilityId = :facilityId")
    suspend fun getCount(facilityId: String): Int

    @Query("SELECT COUNT(*) FROM users WHERE facilityId = :facilityId AND role = 'ADMIN' AND isActive = 1")
    suspend fun getActiveAdminCount(facilityId: String): Int
}
