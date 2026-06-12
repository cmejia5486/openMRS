package com.chartlite.app.database.dao

import androidx.room.Dao
import androidx.room.Insert
import androidx.room.OnConflictStrategy
import androidx.room.Query
import androidx.room.Update
import com.chartlite.app.database.entity.ExtractionQueueEntity
import kotlinx.coroutines.flow.Flow

@Dao
interface ExtractionQueueDao {
    @Insert(onConflict = OnConflictStrategy.REPLACE)
    suspend fun insert(item: ExtractionQueueEntity)

    @Update
    suspend fun update(item: ExtractionQueueEntity)

    @Query("SELECT * FROM extraction_queue_items WHERE id = :id")
    suspend fun getById(id: String): ExtractionQueueEntity?

    @Query("SELECT * FROM extraction_queue_items WHERE status != 'SAVED' ORDER BY createdAt DESC")
    fun observeActiveItems(): Flow<List<ExtractionQueueEntity>>

    @Query("SELECT * FROM extraction_queue_items WHERE status IN (:statuses) ORDER BY createdAt ASC")
    suspend fun getByStatuses(statuses: List<String>): List<ExtractionQueueEntity>

    @Query("DELETE FROM extraction_queue_items WHERE id = :id")
    suspend fun deleteById(id: String)
}
