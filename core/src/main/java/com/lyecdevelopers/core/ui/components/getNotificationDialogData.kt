package com.lyecdevelopers.core.ui.components

import androidx.compose.material.icons.Icons
import androidx.compose.material.icons.filled.CheckCircle
import androidx.compose.material.icons.filled.Error
import androidx.compose.material.icons.filled.Info
import androidx.compose.material3.MaterialTheme
import androidx.compose.runtime.Composable
import com.lyecdevelopers.core.model.NotificationDialogData
import com.lyecdevelopers.core.model.NotificationType

@Composable
fun getNotificationDialogData(type: NotificationType, message: String): NotificationDialogData {
    return when (type) {
        NotificationType.SUCCESS -> NotificationDialogData(
            title = "Success",
            message = message,
            icon = Icons.Default.CheckCircle,
            color = MaterialTheme.colorScheme.primary
        )

        NotificationType.ERROR -> NotificationDialogData(
            title = "Error",
            message = message,
            icon = Icons.Default.Error,
            color = MaterialTheme.colorScheme.error
        )

        NotificationType.INFO -> NotificationDialogData(
            title = "Info",
            message = message,
            icon = Icons.Default.Info,
            color = MaterialTheme.colorScheme.secondary
        )
    }
}
