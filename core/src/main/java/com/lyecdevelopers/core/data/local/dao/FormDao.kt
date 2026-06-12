package com.lyecdevelopers.core.data.local.dao

import androidx.room.Dao
import androidx.room.Insert
import androidx.room.OnConflictStrategy
import androidx.room.Query
import com.lyecdevelopers.core.data.local.entity.FormEntity
import kotlinx.coroutines.flow.Flow

@Dao
interface FormDao {

    @Insert(onConflict = OnConflictStrategy.REPLACE)
    suspend fun insertForms(forms: List<FormEntity>)

    @Insert(onConflict = OnConflictStrategy.REPLACE)
    suspend fun insertForm(form: FormEntity)

    @Query("SELECT * FROM forms")
    fun getAllForms(): List<FormEntity>

    @Query("SELECT * FROM forms WHERE uuid = :uuid LIMIT 1")
    fun getFormById(uuid: String): FormEntity

    @Query("DELETE FROM forms")
    suspend fun deleteAllForms()

    @Query("DELETE FROM forms WHERE uuid = :uuid")
    suspend fun deleteFormById(uuid: String)

    @Query("SELECT COUNT(*) FROM forms")
    fun getFormCount(): Flow<Int>
}

