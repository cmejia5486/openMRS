package com.lyecdevelopers.ugandaemrmobile

import android.Manifest
import android.content.pm.PackageManager
import android.os.Build
import android.os.Bundle
import androidx.activity.compose.setContent
import androidx.activity.result.contract.ActivityResultContracts
import androidx.appcompat.app.AppCompatActivity
import androidx.compose.runtime.LaunchedEffect
import androidx.compose.runtime.collectAsState
import androidx.compose.runtime.getValue
import androidx.compose.runtime.mutableStateOf
import androidx.compose.runtime.remember
import androidx.compose.runtime.setValue
import androidx.core.content.ContextCompat
import androidx.navigation.compose.NavHost
import androidx.navigation.compose.composable
import androidx.navigation.compose.rememberNavController
import com.lyecdevelopers.auth.presentation.AuthScreen
import com.lyecdevelopers.core.data.preference.PreferenceManager
import com.lyecdevelopers.core.data.remote.interceptor.AuthInterceptor
import com.lyecdevelopers.core.ui.components.SplashScreen
import com.lyecdevelopers.core.ui.theme.UgandaEMRMobileTheme
import com.lyecdevelopers.core.utils.AppLogger
import com.lyecdevelopers.core_navigation.navigation.Destinations
import com.lyecdevelopers.main.MainScreen
import dagger.hilt.android.AndroidEntryPoint
import kotlinx.coroutines.flow.firstOrNull
import javax.inject.Inject


@AndroidEntryPoint
class MainActivity : AppCompatActivity() {

    @Inject
    lateinit var preferenceManager: PreferenceManager

    @Inject
    lateinit var authInterceptor: AuthInterceptor

    private val requestNotificationPermissionLauncher = registerForActivityResult(
        ActivityResultContracts.RequestPermission()
    ) { isGranted: Boolean ->
        if (isGranted) {
            AppLogger.d("Notifications permission granted!")
        } else {
            AppLogger.w("Notifications permission denied. Sync status may not be visible.")
        }
    }


    override fun onCreate(savedInstanceState: Bundle?) {
        super.onCreate(savedInstanceState)

        askNotificationPermission()

        setContent {
            UgandaEMRMobileTheme {
                val navController = rememberNavController()
                val navBarNavController = rememberNavController()
                val isLoggedIn by preferenceManager.isLoggedIn().collectAsState(initial = false)
                var showSplash by remember { mutableStateOf(true) }

                LaunchedEffect(Unit) {
                    val username = preferenceManager.getUsername().firstOrNull()
                    val password = preferenceManager.getPassword().firstOrNull()

                    if (!username.isNullOrEmpty() && !password.isNullOrEmpty()) {
                        authInterceptor.updateCredentials(username, password)
                    }
                }

                if (showSplash) {
                    SplashScreen(
                        isLoggedIn = isLoggedIn,
                        onSplashFinished = {
                            showSplash = false
                        },
                    )
                } else {
                    LaunchedEffect(isLoggedIn) {
                        if (isLoggedIn) {
                            navController.navigate(Destinations.MAIN) {
                                popUpTo(navController.graph.startDestinationId) { inclusive = true }
                                launchSingleTop = true
                            }
                        } else {
                            navController.navigate(Destinations.AUTH) {
                                popUpTo(navController.graph.startDestinationId) { inclusive = true }
                                launchSingleTop = true
                            }
                        }
                    }

                    NavHost(navController = navController, startDestination = Destinations.AUTH) {
                        composable(Destinations.SPLASH) {
                            SplashScreen(
                                isLoggedIn = isLoggedIn,
                                onSplashFinished = {
                                    showSplash = false
                                },
                            )
                        }

                        composable(Destinations.AUTH) {
                            AuthScreen(onLoginSuccess = {
                                navController.navigate(Destinations.MAIN) {
                                    popUpTo(Destinations.AUTH) { inclusive = true }
                                }
                            })
                        }

                        composable(Destinations.MAIN) {
                            MainScreen(
                                fragmentManager = supportFragmentManager,
                                navController = navBarNavController
                            )
                        }
                    }
                }
            }
        }
    }

    private fun askNotificationPermission() {
        if (Build.VERSION.SDK_INT >= Build.VERSION_CODES.TIRAMISU) {
            when {
                ContextCompat.checkSelfPermission(
                    this, Manifest.permission.POST_NOTIFICATIONS
                ) == PackageManager.PERMISSION_GRANTED -> {
                    AppLogger.d("Notifications permission already granted.")
                }

                shouldShowRequestPermissionRationale(Manifest.permission.POST_NOTIFICATIONS) -> {
                    AppLogger.i("Showing rationale for notifications permission (not implemented in UI).")
                    requestNotificationPermissionLauncher.launch(Manifest.permission.POST_NOTIFICATIONS)
                }

                else -> {
                    requestNotificationPermissionLauncher.launch(Manifest.permission.POST_NOTIFICATIONS)
                }
            }
        }
    }
}








