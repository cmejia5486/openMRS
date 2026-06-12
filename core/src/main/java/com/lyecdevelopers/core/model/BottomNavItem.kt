package com.lyecdevelopers.core.model

import androidx.compose.material.icons.Icons
import androidx.compose.material.icons.filled.Home
import androidx.compose.material.icons.filled.Settings
import androidx.compose.material.icons.filled.Sync
import androidx.compose.ui.graphics.vector.ImageVector

sealed class BottomNavItem(val route: String, val icon: ImageVector, val label: String) {
    object Worklist : BottomNavItem("worklist", Icons.Filled.Home, "Worklist")
    object Sync : BottomNavItem("sync", Icons.Filled.Sync, "Sync")
    object Settings : BottomNavItem("settings", Icons.Filled.Settings, "Settings")
}

