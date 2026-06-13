package com.chartlite.app

import android.os.Bundle
import android.view.MotionEvent
import android.widget.Toast
import androidx.activity.compose.setContent
import androidx.activity.enableEdgeToEdge
import androidx.appcompat.app.AppCompatActivity
import androidx.appcompat.app.AppCompatDelegate
import androidx.core.os.LocaleListCompat
import androidx.biometric.BiometricManager
import androidx.biometric.BiometricPrompt
import androidx.compose.foundation.layout.*
import androidx.compose.material.icons.Icons
import androidx.compose.material.icons.filled.Fingerprint
import androidx.compose.material3.*
import androidx.compose.runtime.*
import androidx.compose.ui.Alignment
import androidx.compose.ui.Modifier
import androidx.compose.ui.text.font.FontWeight
import androidx.compose.ui.unit.dp
import androidx.core.content.ContextCompat
import androidx.lifecycle.Lifecycle
import androidx.lifecycle.LifecycleEventObserver
import androidx.navigation.compose.rememberNavController
import com.chartlite.app.ui.components.TierIndicator
import com.chartlite.app.ui.navigation.AppNavigation
import com.chartlite.app.ui.screens.LoginScreen
import com.chartlite.app.ui.screens.LockScreen
import com.chartlite.app.ui.theme.ChartLiteTheme

/**
 * Authentication states for the main activity.
 */
private enum class AuthState {
    /** Checking if there's an existing session to restore */
    LOADING,
    /** No session — show login screen */
    NEEDS_LOGIN,
    /** Session exists but locked due to inactivity */
    LOCKED,
    /** Optional biometric check before allowing access */
    BIOMETRIC_PROMPT,
    /** Fully authenticated — show the app (or setup wizard if !isSetupComplete) */
    AUTHENTICATED
}

class MainActivity : AppCompatActivity() {

    private var authState by mutableStateOf(AuthState.LOADING)

    override fun onCreate(savedInstanceState: Bundle?) {
        super.onCreate(savedInstanceState)
        enableEdgeToEdge()

        val app = application as App

        // Apply saved locale so all string resources resolve to the correct language
        val savedLang = app.appConfig.language
        AppCompatDelegate.setApplicationLocales(LocaleListCompat.forLanguageTags(savedLang))

        // Register lifecycle observer for auto-lock
        lifecycle.addObserver(LifecycleEventObserver { _, event ->
            when (event) {
                Lifecycle.Event.ON_PAUSE -> {
                    // Record the time when app goes to background
                    app.sessionManager.touch()
                }
                Lifecycle.Event.ON_RESUME -> {
                    // Check if we should lock on resume
                    if (authState == AuthState.AUTHENTICATED && app.sessionManager.shouldLock()) {
                        authState = AuthState.LOCKED
                    }
                }
                else -> {}
            }
        })

        setContent {
            ChartLiteTheme {
                Surface(modifier = Modifier.fillMaxSize()) {
                    // Periodic foreground idle check — locks unattended tablets
                    LaunchedEffect(authState) {
                        if (authState == AuthState.AUTHENTICATED) {
                            while (true) {
                                kotlinx.coroutines.delay(30_000L) // check every 30s
                                if (app.sessionManager.shouldLock()) {
                                    authState = AuthState.LOCKED
                                    break
                                }
                            }
                        }
                    }

                    // Try to restore session on first launch
                    LaunchedEffect(Unit) {
                        if (authState == AuthState.LOADING) {
                            if (!app.appConfig.isSetupComplete) {
                                // Fresh install or incomplete setup — go straight to
                                // AUTHENTICATED which routes to SetupScreen via AppNavigation.
                                // SetupScreen handles facility creation, admin creation,
                                // and auto-login as a single atomic flow.
                                authState = AuthState.AUTHENTICATED
                            } else {
                                val hasUsers = app.database.userDao()
                                    .getCount(app.appConfig.facilityId) > 0

                                if (!hasUsers) {
                                    // Setup was completed but all users were deleted —
                                    // reset setup and redo the full wizard to avoid
                                    // inconsistent facility/user state.
                                    app.appConfig.isSetupComplete = false
                                    authState = AuthState.AUTHENTICATED
                                } else {
                                    val restored = app.sessionManager.restoreSession()
                                    authState = if (restored) {
                                        // Check auto-lock BEFORE granting access — prevents
                                        // bypassing auto-lock by killing and restarting the app
                                        if (app.sessionManager.shouldLock()) {
                                            AuthState.LOCKED
                                        } else if (app.appConfig.useBiometric && canUseBiometric()) {
                                            AuthState.BIOMETRIC_PROMPT
                                        } else {
                                            AuthState.AUTHENTICATED
                                        }
                                    } else {
                                        AuthState.NEEDS_LOGIN
                                    }
                                }
                            }
                        }
                    }

                    when (authState) {
                        AuthState.LOADING -> {
                            // Brief loading state
                            Box(
                                modifier = Modifier.fillMaxSize(),
                                contentAlignment = Alignment.Center
                            ) {
                                CircularProgressIndicator()
                            }
                        }

                        AuthState.NEEDS_LOGIN -> {
                            LoginScreen(
                                onLoginSuccess = {
                                    authState = AuthState.AUTHENTICATED
                                }
                            )
                        }

                        AuthState.LOCKED -> {
                            LockScreen(
                                onUnlocked = {
                                    authState = AuthState.AUTHENTICATED
                                },
                                onSwitchUser = {
                                    authState = AuthState.NEEDS_LOGIN
                                }
                            )
                        }

                        AuthState.BIOMETRIC_PROMPT -> {
                            BiometricLockScreen(
                                onRetry = { promptBiometric() },
                                showRetry = true
                            )
                            LaunchedEffect(Unit) {
                                promptBiometric()
                            }
                        }

                        AuthState.AUTHENTICATED -> {
                            Column(modifier = Modifier.fillMaxSize()) {
                                TierIndicator()
                                val navController = rememberNavController()
                                AppNavigation(
                                    navController = navController,
                                    isSetupComplete = app.appConfig.isSetupComplete,
                                    modifier = Modifier.weight(1f)
                                )
                            }
                        }
                    }
                }
            }
        }
    }

    override fun dispatchTouchEvent(ev: MotionEvent?): Boolean {
        // Reset idle timer on every touch so foreground sessions auto-lock after inactivity
        if (authState == AuthState.AUTHENTICATED) {
            (application as App).sessionManager.touch()
        }
        return super.dispatchTouchEvent(ev)
    }

    private fun canUseBiometric(): Boolean {
        val manager = BiometricManager.from(this)
        return manager.canAuthenticate(BiometricManager.Authenticators.BIOMETRIC_STRONG or BiometricManager.Authenticators.BIOMETRIC_WEAK) == BiometricManager.BIOMETRIC_SUCCESS
    }

    private fun promptBiometric() {
        val executor = ContextCompat.getMainExecutor(this)

        val callback = object : BiometricPrompt.AuthenticationCallback() {
            override fun onAuthenticationSucceeded(result: BiometricPrompt.AuthenticationResult) {
                authState = AuthState.AUTHENTICATED
            }

            override fun onAuthenticationError(errorCode: Int, errString: CharSequence) {
                if (errorCode == BiometricPrompt.ERROR_NO_BIOMETRICS ||
                    errorCode == BiometricPrompt.ERROR_HW_NOT_PRESENT) {
                    // Device can't do biometrics — fall back to PIN lock screen
                    authState = AuthState.LOCKED
                } else if (errorCode == BiometricPrompt.ERROR_NEGATIVE_BUTTON ||
                    errorCode == BiometricPrompt.ERROR_USER_CANCELED) {
                    // User dismissed biometric prompt — fall back to PIN
                    authState = AuthState.LOCKED
                } else {
                    Toast.makeText(this@MainActivity, "Auth error: $errString", Toast.LENGTH_SHORT).show()
                }
            }

            override fun onAuthenticationFailed() {
                // Keep on biometric prompt screen — user can retry
            }
        }

        val prompt = BiometricPrompt(this, executor, callback)
        val info = BiometricPrompt.PromptInfo.Builder()
            .setTitle("ChartLite")
            .setSubtitle("Authenticate to access patient data")
            .setNegativeButtonText("Cancel")
            .build()

        prompt.authenticate(info)
    }
}

@Composable
private fun BiometricLockScreen(onRetry: () -> Unit, showRetry: Boolean) {
    Column(
        modifier = Modifier
            .fillMaxSize()
            .padding(48.dp),
        verticalArrangement = Arrangement.Center,
        horizontalAlignment = Alignment.CenterHorizontally
    ) {
        Icon(
            Icons.Default.Fingerprint,
            contentDescription = "Biometric",
            modifier = Modifier.size(80.dp),
            tint = MaterialTheme.colorScheme.primary
        )
        Spacer(Modifier.height(24.dp))
        Text(
            "ChartLite",
            style = MaterialTheme.typography.headlineMedium,
            fontWeight = FontWeight.Bold
        )
        Spacer(Modifier.height(8.dp))
        Text(
            "Authenticate to access patient data",
            style = MaterialTheme.typography.bodyMedium,
            color = MaterialTheme.colorScheme.onSurfaceVariant
        )

        if (showRetry) {
            Spacer(Modifier.height(32.dp))
            Button(onClick = onRetry) {
                Icon(Icons.Default.Fingerprint, contentDescription = null, modifier = Modifier.size(18.dp))
                Spacer(Modifier.width(8.dp))
                Text("Try Again")
            }
        }
    }
}

