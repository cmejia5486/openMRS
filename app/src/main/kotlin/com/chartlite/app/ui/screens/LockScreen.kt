package com.chartlite.app.ui.screens

import androidx.compose.foundation.layout.*
import androidx.compose.material.icons.Icons
import androidx.compose.material.icons.filled.Lock
import androidx.compose.material3.*
import androidx.compose.runtime.*
import androidx.compose.runtime.saveable.rememberSaveable
import androidx.compose.ui.Alignment
import androidx.compose.ui.Modifier
import androidx.compose.ui.platform.LocalContext
import androidx.compose.ui.res.stringResource
import androidx.compose.ui.text.font.FontWeight
import androidx.compose.ui.unit.dp
import com.chartlite.app.App
import com.chartlite.app.R
import com.chartlite.app.ui.components.PinPad
import kotlinx.coroutines.delay
import kotlinx.coroutines.launch

/**
 * Lock screen for quick re-authentication after auto-lock.
 * Shows the current user's name and a PIN pad — no user switching.
 */
@Composable
fun LockScreen(
    onUnlocked: () -> Unit,
    onSwitchUser: () -> Unit
) {
    val context = LocalContext.current
    val app = context.applicationContext as App
    val scope = rememberCoroutineScope()

    val session = app.sessionManager.currentSession

    val tooManyAttemptsFormat = stringResource(R.string.too_many_attempts_format)
    val incorrectPinMsg = stringResource(R.string.incorrect_pin)

    var pin by remember { mutableStateOf("") }
    var errorMessage by rememberSaveable { mutableStateOf<String?>(null) }
    var isAuthenticating by remember { mutableStateOf(false) }
    var lockoutSeconds by remember { mutableIntStateOf(0) }

    // Countdown timer for lockout
    LaunchedEffect(lockoutSeconds) {
        if (lockoutSeconds > 0) {
            delay(1000L)
            val remaining = app.sessionManager.lockoutRemainingSeconds()
            lockoutSeconds = remaining
            if (remaining <= 0) {
                errorMessage = null
            }
        }
    }

    Scaffold { padding ->
        Column(
            modifier = Modifier
                .fillMaxSize()
                .padding(padding)
                .padding(horizontal = 24.dp, vertical = 16.dp),
            verticalArrangement = Arrangement.Center,
            horizontalAlignment = Alignment.CenterHorizontally
        ) {
            Icon(
                Icons.Default.Lock,
                contentDescription = stringResource(R.string.locked),
                modifier = Modifier.size(64.dp),
                tint = MaterialTheme.colorScheme.primary
            )

            Spacer(Modifier.height(16.dp))

            Text(
                session?.displayName ?: stringResource(R.string.locked),
                style = MaterialTheme.typography.headlineMedium,
                fontWeight = FontWeight.Bold
            )

            Spacer(Modifier.height(4.dp))

            Text(
                stringResource(R.string.enter_pin_to_unlock),
                style = MaterialTheme.typography.bodyMedium,
                color = MaterialTheme.colorScheme.onSurfaceVariant
            )

            Spacer(Modifier.height(32.dp))

            PinPad(
                pin = pin,
                onPinChange = { newPin ->
                    pin = newPin
                    if (lockoutSeconds <= 0) errorMessage = null
                },
                onSubmit = { enteredPin ->
                    if (isAuthenticating || lockoutSeconds > 0) return@PinPad
                    isAuthenticating = true
                    scope.launch {
                        val success = app.sessionManager.reauthenticate(enteredPin)
                        if (success) {
                            onUnlocked()
                        } else {
                            if (app.sessionManager.isLockedOut()) {
                                val remaining = app.sessionManager.lockoutRemainingSeconds()
                                lockoutSeconds = remaining
                                errorMessage = String.format(tooManyAttemptsFormat, remaining)
                            } else {
                                errorMessage = incorrectPinMsg
                            }
                            pin = ""
                        }
                        isAuthenticating = false
                    }
                },
                enabled = !isAuthenticating && lockoutSeconds <= 0
            )

            if (errorMessage != null) {
                Spacer(Modifier.height(16.dp))
                Text(
                    errorMessage.orEmpty(),
                    style = MaterialTheme.typography.bodyMedium,
                    color = MaterialTheme.colorScheme.error
                )
            }

            Spacer(Modifier.height(32.dp))

            TextButton(onClick = {
                scope.launch {
                    app.sessionManager.logout()
                    onSwitchUser()
                }
            }) {
                Text(stringResource(R.string.switch_user))
            }
        }
    }
}
