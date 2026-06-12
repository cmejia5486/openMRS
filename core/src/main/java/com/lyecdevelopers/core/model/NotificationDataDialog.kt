package com.lyecdevelopers.core.model

import androidx.compose.ui.graphics.Color
import androidx.compose.ui.graphics.vector.ImageVector

data class NotificationDialogData(
    val title: String,
    val message: String,
    val icon: ImageVector,
    val color: Color,
)
