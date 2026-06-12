package com.lyecdevelopers.form.di

import android.content.Context
import com.google.android.fhir.FhirEngine
import com.google.android.fhir.FhirEngineProvider
import com.lyecdevelopers.core.data.local.dao.EncounterDao
import com.lyecdevelopers.core.data.local.dao.FormDao
import com.lyecdevelopers.core.data.local.dao.PatientDao
import com.lyecdevelopers.core.data.local.dao.VisitDao
import com.lyecdevelopers.core.data.local.dao.VitalsDao
import com.lyecdevelopers.core.data.remote.FormApi
import com.lyecdevelopers.form.data.repository.FormRepositoryImpl
import com.lyecdevelopers.form.data.repository.PatientRepositoryImpl
import com.lyecdevelopers.form.domain.repository.FormRepository
import com.lyecdevelopers.form.domain.repository.PatientRepository
import dagger.Module
import dagger.Provides
import dagger.hilt.InstallIn
import dagger.hilt.android.qualifiers.ApplicationContext
import dagger.hilt.components.SingletonComponent
import javax.inject.Singleton

@Module
@InstallIn(SingletonComponent::class)
object FormModule {

    @Provides
    @Singleton
    fun provideFhirEngine(@ApplicationContext context: Context): FhirEngine {
        return FhirEngineProvider.getInstance(context)
    }

    @Provides
    @Singleton
    fun provideFormRepository(
        formApi: FormApi,
        formDao: FormDao,
        visitDao: VisitDao,
        encounterDao: EncounterDao,
    ): FormRepository {
        return FormRepositoryImpl(
            formApi = formApi, formDao = formDao, visitDao = visitDao, encounterDao = encounterDao
        )
    }

    @Provides
    @Singleton
    fun providePatientRepository(
        patientDao: PatientDao,
        vitalsDao: VitalsDao,
        fhirEngine: FhirEngine,
    ): PatientRepository {
        return PatientRepositoryImpl(
            patientDao = patientDao, vitalsDao = vitalsDao, fhirEngine = fhirEngine
        )
    }
}