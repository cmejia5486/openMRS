package com.lyecdevelopers.core.data.local.dao

import androidx.room.Dao
import androidx.room.Insert
import androidx.room.OnConflictStrategy
import androidx.room.Query
import androidx.room.Update
import com.lyecdevelopers.core.data.local.entity.EncounterEntity
import kotlinx.coroutines.flow.Flow


@Dao
interface EncounterDao {
    @Insert(onConflict = OnConflictStrategy.REPLACE)
    suspend fun insert(encounter: EncounterEntity)

    @Query("SELECT * FROM encounters WHERE synced = 0")
    suspend fun getUnsynced(): List<EncounterEntity>

    @Update
    suspend fun update(encounter: EncounterEntity): Int

    @Query("SELECT COUNT(*) FROM encounters")
    fun getEncountersCount(): Flow<Int>

    @Query("SELECT COUNT(*) FROM encounters WHERE synced = 1")
    fun getSyncedEncountersCount(): Flow<Int>
}
