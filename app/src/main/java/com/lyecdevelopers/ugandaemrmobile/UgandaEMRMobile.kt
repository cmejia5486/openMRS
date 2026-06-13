package com.lyecdevelopers.ugandaemrmobile

import android.app.Application
import android.app.NotificationChannel
import android.app.NotificationManager
import android.content.Context
import androidx.hilt.work.HiltWorkerFactory
import androidx.work.Configuration
import com.lyecdevelopers.core.utils.AppLogger
import com.lyecdevelopers.core.utils.NotificationConstants.SYNC_NOTIFICATION_CHANNEL_DESCRIPTION
import com.lyecdevelopers.core.utils.NotificationConstants.SYNC_NOTIFICATION_CHANNEL_ID
import com.lyecdevelopers.core.utils.NotificationConstants.SYNC_NOTIFICATION_CHANNEL_NAME
import dagger.hilt.android.HiltAndroidApp
import javax.inject.Inject


@HiltAndroidApp
class UgandaEMRMobile : Application(), Configuration.Provider {

    @Inject
    lateinit var workerFactory: HiltWorkerFactory

    override fun onCreate() {
        super.onCreate()
        AppLogger.init()
        createNotificationChannel()
    }

    override val workManagerConfiguration: Configuration
        get() = Configuration.Builder().setWorkerFactory(workerFactory).build()

    private fun createNotificationChannel() {
        val channel = NotificationChannel(
            SYNC_NOTIFICATION_CHANNEL_ID,
            SYNC_NOTIFICATION_CHANNEL_NAME,
            NotificationManager.IMPORTANCE_LOW
        ).apply {
            description = SYNC_NOTIFICATION_CHANNEL_DESCRIPTION
            setSound(null, null)
            enableVibration(false)
        }
        val notificationManager =
            getSystemService(NOTIFICATION_SERVICE) as NotificationManager
        notificationManager.createNotificationChannel(channel)
    }

}





