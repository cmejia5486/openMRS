package com.chartlite.app.database.dao

import androidx.room.*
import com.chartlite.app.database.entity.FacilityEntity
import com.chartlite.app.database.entity.ProviderEntity

@Dao
interface ProviderDao {
    @Insert(onConflict = OnConflictStrategy.REPLACE)
    suspend fun insertProvider(provider: ProviderEntity)

    @Query("SELECT * FROM providers LIMIT 1")
    suspend fun getCurrentProvider(): ProviderEntity?

    @Insert(onConflict = OnConflictStrategy.IGNORE)
    suspend fun insertFacility(facility: FacilityEntity)

    @Query("SELECT * FROM facilities LIMIT 1")
    suspend fun getCurrentFacility(): FacilityEntity?
}
