package com.lyecdevelopers.core.di

import android.content.Context
import com.lyecdevelopers.core.common.scheduler.DefaultSchedulerProvider
import com.lyecdevelopers.core.common.scheduler.SchedulerProvider
import com.lyecdevelopers.core.data.notifications.SyncNotificationHelper
import com.lyecdevelopers.core.data.preference.PreferenceManager
import com.lyecdevelopers.core.data.preference.PreferenceManagerImpl
import com.lyecdevelopers.core.data.sync.SyncManager
import dagger.Module
import dagger.Provides
import dagger.hilt.InstallIn
import dagger.hilt.android.qualifiers.ApplicationContext
import dagger.hilt.components.SingletonComponent
import javax.inject.Singleton

@Module
@InstallIn(SingletonComponent::class)
object CoreModule {

    @Provides
    @Singleton
    fun provideSchedulerProvider(): SchedulerProvider = DefaultSchedulerProvider()

    @Provides
    @Singleton
    fun providePreferenceManager(
        @ApplicationContext context: Context
    ): PreferenceManager = PreferenceManagerImpl(context)

    @Provides
    @Singleton
    fun provideSyncManager(
        @ApplicationContext context: Context,
    ): SyncManager {
        return SyncManager(context)
    }

    @Provides
    @Singleton
    fun provideSyncNotificationsHelper(
        @ApplicationContext context: Context,
    ): SyncNotificationHelper {
        return SyncNotificationHelper(context)
    }
}