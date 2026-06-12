package com.chartlite.app.database.dao

import androidx.room.*
import com.chartlite.app.database.entity.ReferralEntity
import kotlinx.coroutines.flow.Flow

@Dao
interface ReferralDao {
    @Insert(onConflict = OnConflictStrategy.ABORT)
    suspend fun insert(referral: ReferralEntity)

    @Update
    suspend fun update(referral: ReferralEntity)

    @Query("SELECT * FROM referrals WHERE id = :id")
    suspend fun getById(id: String): ReferralEntity?

    @Query("SELECT * FROM referrals WHERE patientId = :patientId ORDER BY referredAt DESC")
    suspend fun getByPatient(patientId: String): List<ReferralEntity>

    @Query("SELECT * FROM referrals WHERE status = 'PENDING' AND fromFacilityId = :facilityId ORDER BY referredAt DESC")
    suspend fun getPending(facilityId: String): List<ReferralEntity>

    @Query("SELECT * FROM referrals WHERE status = 'PENDING' AND fromFacilityId = :facilityId ORDER BY referredAt DESC")
    fun observePending(facilityId: String): Flow<List<ReferralEntity>>

    @Query("SELECT * FROM referrals WHERE fromFacilityId = :facilityId ORDER BY referredAt DESC LIMIT :limit")
    suspend fun getByFacility(facilityId: String, limit: Int = 100): List<ReferralEntity>

    @Query("SELECT * FROM referrals WHERE visitId = :visitId")
    suspend fun getByVisitId(visitId: String): List<ReferralEntity>

    @Query("SELECT COUNT(*) FROM referrals WHERE status = 'PENDING' AND fromFacilityId = :facilityId")
    suspend fun getPendingCount(facilityId: String): Int
}
