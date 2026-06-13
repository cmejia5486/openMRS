package com.lyecdevelopers.core.di

import android.content.Context
import androidx.room.Room
import com.lyecdevelopers.core.data.local.dao.EncounterDao
import com.lyecdevelopers.core.data.local.dao.FormDao
import com.lyecdevelopers.core.data.local.dao.PatientDao
import com.lyecdevelopers.core.data.local.dao.VisitDao
import com.lyecdevelopers.core.data.local.dao.VitalsDao
import com.lyecdevelopers.core.data.local.db.AppDatabase
import dagger.Module
import dagger.Provides
import dagger.hilt.InstallIn
import dagger.hilt.android.qualifiers.ApplicationContext
import dagger.hilt.components.SingletonComponent
import javax.inject.Singleton

@Module
@InstallIn(SingletonComponent::class)
object DatabaseModule {
    @Provides
    @Singleton
    fun provideDatabase(@ApplicationContext context: Context): AppDatabase {
        return Room.databaseBuilder(
            context,
            AppDatabase::class.java,
            "uganda_emr_mobile.db"
        ).build()
    }


    @Provides
    fun provideFormDao(database: AppDatabase): FormDao {
        return database.formDao()
    }

    @Provides
    fun providePatientDao(database: AppDatabase): PatientDao {
        return database.patientDao()
    }

    @Provides
    fun provideVisitDao(database: AppDatabase): VisitDao {
        return database.visitDao()
    }


    @Provides
    fun provideEncounterDao(database: AppDatabase): EncounterDao {
        return database.encounterDao()
    }

    @Provides
    fun provideVitalsDao(database: AppDatabase): VitalsDao {
        return database.vitalsDao()
    }
}