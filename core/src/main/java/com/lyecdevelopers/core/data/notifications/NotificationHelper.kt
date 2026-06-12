package com.lyecdevelopers.core.data.notifications

import android.app.Notification
import android.app.NotificationChannel
import android.app.NotificationManager
import android.content.Context
import android.os.Build
import androidx.core.app.NotificationCompat
import com.lyecdevelopers.core.R
import dagger.hilt.android.qualifiers.ApplicationContext
import javax.inject.Inject

class SyncNotificationHelper @Inject constructor(
    @ApplicationContext private val context: Context,
) {
    private val notificationManager: NotificationManager
        get() = context.getSystemService(Context.NOTIFICATION_SERVICE) as NotificationManager

    fun ensureNotificationChannelExists(
        channelId: String,
        channelName: String,
        channelDescription: String,
    ) {
        if (Build.VERSION.SDK_INT >= Build.VERSION_CODES.TIRAMISU) {
            val channel = NotificationChannel(
                channelId, channelName, NotificationManager.IMPORTANCE_LOW
            ).apply {
                description = channelDescription
                setSound(null, null)
                enableVibration(false)
            }
            notificationManager.createNotificationChannel(channel)
        }
    }

    fun createNotification(
        channelId: String,
        channelName: String,
        channelDescription: String,
        title: String,
        content: String,
        progress: Int = 0,
        maxProgress: Int = 0,
    ): Notification {
        ensureNotificationChannelExists(channelId, channelName, channelDescription)

        val builder = NotificationCompat.Builder(context, channelId).setContentTitle(title)
            .setContentText(content).setSmallIcon(R.drawable.ic_launcher_foreground)
            .setOngoing(true).setCategory(NotificationCompat.CATEGORY_PROGRESS)
            .setPriority(NotificationCompat.PRIORITY_LOW)

        if (progress > 0 && maxProgress > 0) {
            builder.setProgress(maxProgress, progress, false)
        } else {
            builder.setProgress(0, 0, true)
        }

        return builder.build()
    }

    fun notify(notificationId: Int, notification: Notification) {
        notificationManager.notify(notificationId, notification)
    }
}
