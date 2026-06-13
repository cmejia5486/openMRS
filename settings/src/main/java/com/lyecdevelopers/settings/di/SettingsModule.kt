package com.lyecdevelopers.settings.di

import com.lyecdevelopers.core.data.remote.AuthApi
import com.lyecdevelopers.settings.data.repository.SettingsRepositoryImpl
import com.lyecdevelopers.settings.domain.repository.SettingsRepository
import dagger.Module
import dagger.Provides
import dagger.hilt.InstallIn
import dagger.hilt.components.SingletonComponent
import javax.inject.Singleton

@Module
@InstallIn(SingletonComponent::class)
class SettingsModule {

    @Provides
    @Singleton
    fun provideSettingsRepository(
        authApi: AuthApi,
    ): SettingsRepository {
        return SettingsRepositoryImpl(
            authApi = authApi,
        )
    }
}