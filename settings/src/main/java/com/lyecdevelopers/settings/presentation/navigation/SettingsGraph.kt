package com.lyecdevelopers.settings.presentation.navigation

import androidx.navigation.NavController
import androidx.navigation.NavGraphBuilder
import androidx.navigation.compose.composable
import com.lyecdevelopers.core.model.BottomNavItem
import com.lyecdevelopers.settings.presentation.SettingsScreen

fun NavGraphBuilder.settingsGraph(navController: NavController) {
    composable(BottomNavItem.Settings.route) {
        SettingsScreen(navController = navController)
    }
}
