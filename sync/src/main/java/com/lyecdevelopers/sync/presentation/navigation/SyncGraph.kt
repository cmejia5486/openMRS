package com.lyecdevelopers.sync.presentation.navigation

import androidx.navigation.NavController
import androidx.navigation.NavGraphBuilder
import androidx.navigation.compose.composable
import com.lyecdevelopers.core.model.BottomNavItem
import com.lyecdevelopers.sync.presentation.SyncScreen

fun NavGraphBuilder.syncGraph(navController: NavController) {
    composable(BottomNavItem.Sync.route) {
        SyncScreen(
            onBack = { navController.popBackStack() }
        )
    }
}
