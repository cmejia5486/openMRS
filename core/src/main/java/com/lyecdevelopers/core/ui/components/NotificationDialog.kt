package com.lyecdevelopers.core.ui.components

import androidx.compose.runtime.Composable
import com.lyecdevelopers.core.model.NotificationType

@Composable
fun NotificationDialog(
    title: String,
    type: NotificationType,
    message: String,
    onDismiss: () -> Unit,
    onConfirm: () -> Unit = onDismiss,
) {
    val data = getNotificationDialogData(type, message)

    CustomAlertDialog(
        onDismissRequest = onDismiss,
        onConfirmation = onConfirm,
        dialogTitle = data.title,
        dialogText = data.message,
        icon = data.icon,
        color = data.color
    )
}
