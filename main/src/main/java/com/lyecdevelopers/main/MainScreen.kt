package com.lyecdevelopers.main

import androidx.compose.foundation.layout.padding
import androidx.compose.material.icons.Icons
import androidx.compose.material.icons.filled.FilterList
import androidx.compose.material.icons.filled.MoreVert
import androidx.compose.material3.AlertDialog
import androidx.compose.material3.DropdownMenu
import androidx.compose.material3.ExperimentalMaterial3Api
import androidx.compose.material3.Icon
import androidx.compose.material3.IconButton
import androidx.compose.material3.Scaffold
import androidx.compose.material3.Text
import androidx.compose.material3.TextButton
import androidx.compose.material3.TopAppBar
import androidx.compose.runtime.Composable
import androidx.compose.runtime.LaunchedEffect
import androidx.compose.runtime.getValue
import androidx.compose.runtime.mutableStateOf
import androidx.compose.runtime.remember
import androidx.compose.runtime.saveable.rememberSaveable
import androidx.compose.runtime.setValue
import androidx.compose.ui.Modifier
import androidx.fragment.app.FragmentManager
import androidx.hilt.navigation.compose.hiltViewModel
import androidx.navigation.NavHostController
import androidx.navigation.compose.currentBackStackEntryAsState
import com.lyecdevelopers.core.model.BottomNavItem
import com.lyecdevelopers.core.ui.components.BottomNavigationBar
import com.lyecdevelopers.worklist.domain.model.PatientFilters
import com.lyecdevelopers.worklist.presentation.worklist.FilterSection
import com.lyecdevelopers.worklist.presentation.worklist.WorklistViewModel
import com.lyecdevelopers.worklist.presentation.worklist.event.WorklistEvent

@OptIn(ExperimentalMaterial3Api::class)
@Composable
fun MainScreen(
    fragmentManager: FragmentManager,
    navController: NavHostController,
    viewModel: WorklistViewModel = hiltViewModel(),

    ) {
    val currentBackStackEntry by navController.currentBackStackEntryAsState()
    val currentRoute = currentBackStackEntry?.destination?.route ?: ""

    val topBarTitle = when {
        currentRoute.startsWith(BottomNavItem.Worklist.route) -> BottomNavItem.Worklist.label
        currentRoute.startsWith(BottomNavItem.Sync.route) -> BottomNavItem.Sync.label
        currentRoute.startsWith(BottomNavItem.Settings.route) -> BottomNavItem.Settings.label
        else -> ""
    }

    var menuExpanded by remember { mutableStateOf(false) }
    var isFilterDialogVisible by remember { mutableStateOf(false) }

    var filters by rememberSaveable(stateSaver = PatientFilters.Saver) {
        mutableStateOf(PatientFilters())
    }

    // Send filter changes to ViewModel
    LaunchedEffect(filters) {
        viewModel.onEvent(WorklistEvent.OnNameFilterChanged(filters.nameQuery))
        viewModel.onEvent(WorklistEvent.OnGenderFilterChanged(filters.gender))
        viewModel.onEvent(WorklistEvent.OnStatusFilterChanged(filters.visitStatus))
    }

    Scaffold(
        topBar = {
            if (shouldShowBottomBar(currentRoute)) {
                TopAppBar(title = { Text(topBarTitle) }, actions = {
                    if (currentRoute.startsWith(BottomNavItem.Worklist.route)) {
                        IconButton(onClick = { isFilterDialogVisible = true }) {
                            Icon(
                                Icons.Default.FilterList, contentDescription = "Filter Patients"
                            )
                        }
                    } else {
                        IconButton(onClick = { menuExpanded = true }) {
                            Icon(Icons.Default.MoreVert, contentDescription = "Menu")
                        }
                        DropdownMenu(
                            expanded = menuExpanded, onDismissRequest = { menuExpanded = false }) {
                            // Other route-based actions here
                        }
                    }
                })
            }
        },
        bottomBar = {
            if (shouldShowBottomBar(currentRoute)) {
                BottomNavigationBar(navController = navController)
            }
        }
    ) { paddingValues ->
        MainNavGraph(
            fragmentManager = fragmentManager,
            navController = navController,
            modifier = Modifier.padding(paddingValues)
        )
    }

    // ✅ Global Filter Dialog
    if (isFilterDialogVisible) {
        AlertDialog(
            onDismissRequest = { isFilterDialogVisible = false },
            title = { Text("Filters") },
            text = {
                FilterSection(
                    filters = filters, onFiltersChanged = { filters = it })
            },
            confirmButton = {
                TextButton(onClick = { isFilterDialogVisible = false }) {
                    Text("Apply")
                }
            },
            dismissButton = {
                TextButton(onClick = {
                    filters = PatientFilters()
                    isFilterDialogVisible = false
                }) {
                    Text("Clear")
                }
            })
    }
}

fun shouldShowBottomBar(route: String): Boolean {
    val bottomRoutes = listOf(
        BottomNavItem.Worklist.route,
        BottomNavItem.Sync.route,
        BottomNavItem.Settings.route,
    )

    return bottomRoutes.any { route.startsWith(it) }
}






