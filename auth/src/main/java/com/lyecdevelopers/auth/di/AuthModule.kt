package com.lyecdevelopers.auth.di

import com.lyecdevelopers.auth.data.repository.AuthRepositoryImpl
import com.lyecdevelopers.auth.domain.repository.AuthRepository
import com.lyecdevelopers.core.common.scheduler.SchedulerProvider
import com.lyecdevelopers.core.data.remote.AuthApi
import dagger.Module
import dagger.Provides
import dagger.hilt.InstallIn
import dagger.hilt.components.SingletonComponent
import javax.inject.Singleton
@Module
@InstallIn(SingletonComponent::class)
object AuthModule {

    @Provides
    @Singleton
    fun provideAuthRepository(authApi: AuthApi,schedulerProvider: SchedulerProvider): AuthRepository {
        return AuthRepositoryImpl(
            authApi = authApi,
            schedulerProvider = schedulerProvider,
        )
    }
}