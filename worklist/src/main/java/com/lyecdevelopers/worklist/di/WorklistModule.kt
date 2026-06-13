package com.lyecdevelopers.worklist.di

import com.lyecdevelopers.core.data.local.dao.FormDao
import com.lyecdevelopers.core.data.local.dao.VisitDao
import com.lyecdevelopers.worklist.data.repository.VisitRepositoryImpl
import com.lyecdevelopers.worklist.domain.repository.VisitRepository
import dagger.Module
import dagger.Provides
import dagger.hilt.InstallIn
import dagger.hilt.components.SingletonComponent
import javax.inject.Singleton

@Module
@InstallIn(SingletonComponent::class)
object WorklistModule {


    @Provides
    @Singleton
    fun provideVisitSummaryRepository(
        visitDao: VisitDao,
        formDao: FormDao,
    ): VisitRepository {
        return VisitRepositoryImpl(
            visitDao = visitDao,
            formDao = formDao,
        )
    }
}
