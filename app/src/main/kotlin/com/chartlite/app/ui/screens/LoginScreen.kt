package com.chartlite.app.ui.screens

import androidx.activity.compose.rememberLauncherForActivityResult
import androidx.compose.foundation.layout.*
import androidx.compose.foundation.rememberScrollState
import androidx.compose.foundation.verticalScroll
import androidx.compose.material.icons.Icons
import androidx.compose.material.icons.filled.*
import androidx.compose.material3.*
import androidx.compose.runtime.*
import androidx.compose.runtime.saveable.rememberSaveable
import androidx.compose.ui.Alignment
import androidx.compose.ui.Modifier
import androidx.compose.ui.platform.LocalContext
import androidx.compose.ui.text.font.FontWeight
import androidx.compose.ui.text.input.KeyboardType
import androidx.compose.ui.text.input.PasswordVisualTransformation
import androidx.compose.ui.text.style.TextAlign
import androidx.compose.ui.unit.dp
import androidx.compose.foundation.text.KeyboardOptions
import androidx.compose.ui.res.stringResource
import com.chartlite.app.App
import com.chartlite.app.R
import com.chartlite.app.auth.AuditLogger
import com.chartlite.app.auth.AuthResult
import com.chartlite.app.auth.JoinCodeManager
import com.chartlite.app.auth.PinHasher
import com.chartlite.app.auth.UserRole
import com.chartlite.app.database.entity.UserEntity
import com.chartlite.app.ui.components.PinPad
import com.journeyapps.barcodescanner.ScanContract
import com.journeyapps.barcodescanner.ScanOptions
import kotlinx.coroutines.delay
import kotlinx.coroutines.launch
import java.util.UUID

/**
 * Login screen with user selector and PIN entry.
 * Shows list of active users for the facility, then a PIN pad for authentication.
 */
@OptIn(ExperimentalMaterial3Api::class)
@Composable
fun LoginScreen(onLoginSuccess: () -> Unit) {
    val context = LocalContext.current
    val app = context.applicationContext as App
    val scope = rememberCoroutineScope()

    var users by remember { mutableStateOf<List<UserEntity>>(emptyList()) }
    var selectedUser by rememberSaveable { mutableStateOf<String?>(null) }
    // PIN must NOT survive config changes — use remember for security
    var pin by remember { mutableStateOf("") }
    var errorMessage by remember { mutableStateOf<String?>(null) }
    // isAuthenticating must NOT survive config changes — could get stuck as true
    var isAuthenticating by remember { mutableStateOf(false) }
    // Lockout countdown state
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
    var showJoinDialog by rememberSaveable { mutableStateOf(false) }

    fun refreshUsers() {
        scope.launch {
            users = app.database.userDao().getActiveByFacilityId(app.appConfig.facilityId)
        }
    }

    // Load users for this facility
    LaunchedEffect(Unit) {
        refreshUsers()
    }

    Scaffold { padding ->
        Column(
            modifier = Modifier
                .fillMaxSize()
                .padding(padding)
                .verticalScroll(rememberScrollState())
                .padding(24.dp),
            horizontalAlignment = Alignment.CenterHorizontally
        ) {
            Spacer(Modifier.height(32.dp))

            // App branding header
            Surface(
                color = MaterialTheme.colorScheme.primaryContainer,
                shape = MaterialTheme.shapes.large,
                modifier = Modifier.fillMaxWidth()
            ) {
                Column(
                    modifier = Modifier.padding(24.dp),
                    horizontalAlignment = Alignment.CenterHorizontally
                ) {
                    Surface(
                        color = MaterialTheme.colorScheme.primary,
                        shape = MaterialTheme.shapes.medium,
                        modifier = Modifier.size(72.dp)
                    ) {
                        Icon(
                            Icons.Default.LocalHospital,
                            contentDescription = null,
                            modifier = Modifier
                                .padding(16.dp)
                                .size(40.dp),
                            tint = MaterialTheme.colorScheme.onPrimary
                        )
                    }
                    Spacer(Modifier.height(12.dp))
                    Text(
                        stringResource(R.string.app_name),
                        style = MaterialTheme.typography.headlineLarge,
                        fontWeight = FontWeight.Bold,
                        color = MaterialTheme.colorScheme.onPrimaryContainer
                    )
                    Spacer(Modifier.height(4.dp))
                    Text(
                        stringResource(R.string.sign_in_to_continue),
                        style = MaterialTheme.typography.bodyMedium,
                        color = MaterialTheme.colorScheme.onPrimaryContainer.copy(alpha = 0.7f)
                    )
                }
            }

            Spacer(Modifier.height(32.dp))

            if (selectedUser == null) {
                // Step 1: Select user
                Text(
                    stringResource(R.string.select_your_account),
                    style = MaterialTheme.typography.titleMedium,
                    fontWeight = FontWeight.Medium
                )
                Spacer(Modifier.height(16.dp))

                if (users.isEmpty()) {
                    Text(
                        stringResource(R.string.no_users_found),
                        style = MaterialTheme.typography.bodyMedium,
                        textAlign = TextAlign.Center,
                        color = MaterialTheme.colorScheme.onSurfaceVariant
                    )
                } else {
                    users.forEach { user ->
                        val roleLabel = user.role.lowercase().replaceFirstChar { it.uppercase() }
                            .replace("_", " ")
                        val roleBadgeColor = when (user.role.uppercase()) {
                            "ADMIN" -> MaterialTheme.colorScheme.error
                            "DOCTOR", "PHYSICIAN" -> MaterialTheme.colorScheme.primary
                            "NURSE" -> MaterialTheme.colorScheme.tertiary
                            else -> MaterialTheme.colorScheme.secondary
                        }
                        OutlinedCard(
                            onClick = { selectedUser = user.id },
                            modifier = Modifier
                                .fillMaxWidth()
                                .padding(vertical = 8.dp)
                        ) {
                            Row(
                                modifier = Modifier
                                    .fillMaxWidth()
                                    .padding(16.dp),
                                verticalAlignment = Alignment.CenterVertically,
                                horizontalArrangement = Arrangement.spacedBy(12.dp)
                            ) {
                                Icon(
                                    Icons.Default.Person,
                                    contentDescription = null,
                                    tint = MaterialTheme.colorScheme.primary
                                )
                                Column(modifier = Modifier.weight(1f)) {
                                    Text(
                                        user.displayName,
                                        style = MaterialTheme.typography.titleSmall,
                                        fontWeight = FontWeight.Medium
                                    )
                                    Spacer(Modifier.height(4.dp))
                                    Surface(
                                        color = roleBadgeColor.copy(alpha = 0.12f),
                                        shape = MaterialTheme.shapes.small
                                    ) {
                                        Text(
                                            roleLabel,
                                            modifier = Modifier.padding(horizontal = 8.dp, vertical = 2.dp),
                                            style = MaterialTheme.typography.labelSmall,
                                            color = roleBadgeColor
                                        )
                                    }
                                }
                                Icon(
                                    Icons.Default.ChevronRight,
                                    contentDescription = null,
                                    tint = MaterialTheme.colorScheme.onSurfaceVariant
                                )
                            }
                        }
                    }
                }

                // Join facility divider + button
                Spacer(Modifier.height(16.dp))
                HorizontalDivider()
                Spacer(Modifier.height(8.dp))
                OutlinedButton(
                    onClick = { showJoinDialog = true },
                    modifier = Modifier.fillMaxWidth()
                ) {
                    Icon(
                        Icons.Default.GroupAdd,
                        contentDescription = stringResource(R.string.content_desc_join_facility),
                        modifier = Modifier.size(18.dp)
                    )
                    Spacer(Modifier.width(8.dp))
                    Text(stringResource(R.string.join_facility))
                }
            } else {
                // Step 2: Enter PIN
                val user = users.find { it.id == selectedUser }
                if (user != null) {
                    Text(
                        user.displayName,
                        style = MaterialTheme.typography.titleLarge,
                        fontWeight = FontWeight.SemiBold
                    )
                    Spacer(Modifier.height(4.dp))
                    Text(
                        stringResource(R.string.enter_your_pin),
                        style = MaterialTheme.typography.bodyMedium,
                        color = MaterialTheme.colorScheme.onSurfaceVariant
                    )

                    Spacer(Modifier.height(24.dp))

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
                                val result = app.sessionManager.login(
                                    username = user.username,
                                    pin = enteredPin,
                                    facilityId = app.appConfig.facilityId
                                )
                                when (result) {
                                    is AuthResult.Success -> {
                                        onLoginSuccess()
                                    }
                                    is AuthResult.Failed -> {
                                        errorMessage = result.reason
                                        pin = ""
                                    }
                                    is AuthResult.AccountDisabled -> {
                                        errorMessage = "Account is disabled"
                                        pin = ""
                                    }
                                    is AuthResult.TooManyAttempts -> {
                                        val remaining = app.sessionManager.lockoutRemainingSeconds()
                                        lockoutSeconds = remaining
                                        errorMessage = "Too many attempts. Try again in ${remaining}s"
                                        pin = ""
                                    }
                                }
                                isAuthenticating = false
                            }
                        },
                        enabled = !isAuthenticating && lockoutSeconds <= 0
                    )

                    // Error message
                    if (errorMessage != null) {
                        Spacer(Modifier.height(16.dp))
                        Surface(
                            color = MaterialTheme.colorScheme.errorContainer,
                            shape = MaterialTheme.shapes.small,
                            modifier = Modifier.fillMaxWidth()
                        ) {
                            Text(
                                errorMessage.orEmpty(),
                                modifier = Modifier.padding(12.dp),
                                style = MaterialTheme.typography.bodyMedium,
                                color = MaterialTheme.colorScheme.onErrorContainer
                            )
                        }
                    }

                    Spacer(Modifier.height(24.dp))

                    TextButton(onClick = {
                        selectedUser = null
                        pin = ""
                        errorMessage = null
                    }) {
                        Text(stringResource(R.string.switch_user))
                    }
                }
            }
        }
    }

    // Join facility dialog
    if (showJoinDialog) {
        JoinFacilityDialog(
            app = app,
            onDismiss = { showJoinDialog = false },
            onJoinSuccess = {
                showJoinDialog = false
                refreshUsers()
                // Auto-login: the newly created user is now in the list
                onLoginSuccess()
            }
        )
    }
}

/**
 * Multi-step dialog for joining a facility with a join code.
 * Step 1: Enter 6-digit code → validate → show assigned role
 * Step 2: Enter display name + username
 * Step 3: Create PIN + confirm → create user → auto-login
 */
@OptIn(ExperimentalMaterial3Api::class)
@Composable
private fun JoinFacilityDialog(
    app: App,
    onDismiss: () -> Unit,
    onJoinSuccess: () -> Unit
) {
    val scope = rememberCoroutineScope()

    // Step tracking: 1=code, 2=name, 3=pin
    var step by rememberSaveable { mutableIntStateOf(1) }
    var joinCode by rememberSaveable { mutableStateOf("") }
    var validatedCode by remember { mutableStateOf<JoinCodeManager.JoinCode?>(null) }
    var codeError by rememberSaveable { mutableStateOf<String?>(null) }

    // QR code scanner
    val scanLauncher = rememberLauncherForActivityResult(ScanContract()) { result ->
        result.contents?.let { scanned ->
            // Supports:
            // - raw "123456"
            // - "chartlite-join:123456"
            // - "chartlite-join:123456:FACILITY_ID"
            // - "chartlite-join:123456:FACILITY_ID:ROLE"
            val code = parseJoinCodeFromQr(scanned)
            if (code != null) {
                joinCode = code
                // Auto-validate
                val validated = app.joinCodeManager.validate(code)
                if (validated != null) {
                    validatedCode = validated
                    codeError = null
                    step = 2
                } else {
                    codeError = "Invalid or expired code"
                }
            } else {
                codeError = "Invalid QR code"
            }
        }
    }
    var displayName by rememberSaveable { mutableStateOf("") }
    var username by rememberSaveable { mutableStateOf("") }
    var nameError by rememberSaveable { mutableStateOf<String?>(null) }
    var newPin by remember { mutableStateOf("") }
    var confirmPin by remember { mutableStateOf("") }
    var isCreating by remember { mutableStateOf(false) }

    AlertDialog(
        onDismissRequest = onDismiss,
        title = {
            Text(
                when (step) {
                    1 -> stringResource(R.string.join_facility)
                    2 -> stringResource(R.string.your_details)
                    else -> stringResource(R.string.create_pin)
                }
            )
        },
        text = {
            Column(verticalArrangement = Arrangement.spacedBy(12.dp)) {
                when (step) {
                    1 -> {
                        // Step 1: Enter join code or scan QR
                        Text(
                            stringResource(R.string.scan_qr_instruction),
                            style = MaterialTheme.typography.bodyMedium,
                            color = MaterialTheme.colorScheme.onSurfaceVariant
                        )

                        // Scan QR button
                        OutlinedButton(
                            onClick = {
                                scanLauncher.launch(
                                    ScanOptions().apply {
                                        setDesiredBarcodeFormats(ScanOptions.QR_CODE)
                                        setPrompt("Scan the join code QR from your admin")
                                        setBeepEnabled(false)
                                        setOrientationLocked(false)
                                    }
                                )
                            },
                            modifier = Modifier.fillMaxWidth()
                        ) {
                            Icon(
                                Icons.Default.QrCodeScanner,
                                contentDescription = stringResource(R.string.content_desc_scan_qr_code),
                                modifier = Modifier.size(20.dp)
                            )
                            Spacer(Modifier.width(8.dp))
                            Text(stringResource(R.string.scan_qr_code))
                        }

                        Row(
                            modifier = Modifier.fillMaxWidth(),
                            verticalAlignment = Alignment.CenterVertically,
                            horizontalArrangement = Arrangement.spacedBy(8.dp)
                        ) {
                            HorizontalDivider(modifier = Modifier.weight(1f))
                            Text(
                                stringResource(R.string.or_enter_code),
                                style = MaterialTheme.typography.bodySmall,
                                color = MaterialTheme.colorScheme.onSurfaceVariant
                            )
                            HorizontalDivider(modifier = Modifier.weight(1f))
                        }

                        OutlinedTextField(
                            value = joinCode,
                            onValueChange = {
                                if (it.length <= 6 && it.all { c -> c.isDigit() }) {
                                    joinCode = it
                                    codeError = null
                                }
                            },
                            label = { Text(stringResource(R.string.join_code)) },
                            placeholder = { Text(stringResource(R.string.join_code_placeholder)) },
                            singleLine = true,
                            isError = codeError != null,
                            supportingText = codeError?.let { { Text(it) } },
                            modifier = Modifier.fillMaxWidth()
                        )
                    }

                    2 -> {
                        // Step 2: Name + username
                        val code = validatedCode ?: return@Column
                        val role = try {
                            UserRole.valueOf(code.role)
                        } catch (_: Exception) { null }

                        Card(
                            colors = CardDefaults.cardColors(
                                containerColor = MaterialTheme.colorScheme.secondaryContainer
                            ),
                            modifier = Modifier.fillMaxWidth()
                        ) {
                            Row(
                                modifier = Modifier.padding(12.dp),
                                verticalAlignment = Alignment.CenterVertically,
                                horizontalArrangement = Arrangement.spacedBy(8.dp)
                            ) {
                                Icon(
                                    Icons.Default.Badge,
                                    contentDescription = null,
                                    tint = MaterialTheme.colorScheme.onSecondaryContainer
                                )
                                Column {
                                    Text(
                                        stringResource(R.string.setup_joining_as, role?.displayName ?: code.role),
                                        style = MaterialTheme.typography.titleSmall,
                                        fontWeight = FontWeight.Medium,
                                        color = MaterialTheme.colorScheme.onSecondaryContainer
                                    )
                                    if (role != null) {
                                        Text(
                                            role.description,
                                            style = MaterialTheme.typography.bodySmall,
                                            color = MaterialTheme.colorScheme.onSecondaryContainer
                                        )
                                    }
                                }
                            }
                        }

                        OutlinedTextField(
                            value = displayName,
                            onValueChange = {
                                displayName = it
                                nameError = null
                            },
                            label = { Text(stringResource(R.string.your_full_name)) },
                            singleLine = true,
                            modifier = Modifier.fillMaxWidth()
                        )

                        OutlinedTextField(
                            value = username,
                            onValueChange = {
                                username = it.lowercase().filter { c -> c.isLetterOrDigit() || c == '.' }
                                nameError = null
                            },
                            label = { Text(stringResource(R.string.username)) },
                            supportingText = {
                                Text(nameError ?: stringResource(R.string.username_hint))
                            },
                            isError = nameError != null,
                            singleLine = true,
                            modifier = Modifier.fillMaxWidth()
                        )
                    }

                    3 -> {
                        // Step 3: Create PIN
                        Text(
                            "Create a PIN to secure your account.",
                            style = MaterialTheme.typography.bodyMedium,
                            color = MaterialTheme.colorScheme.onSurfaceVariant
                        )

                        OutlinedTextField(
                            value = newPin,
                            onValueChange = {
                                if (it.length <= 6 && it.all { c -> c.isDigit() }) newPin = it
                            },
                            label = { Text(stringResource(R.string.pin_label)) },
                            singleLine = true,
                            visualTransformation = PasswordVisualTransformation(),
                            keyboardOptions = KeyboardOptions(keyboardType = KeyboardType.NumberPassword),
                            modifier = Modifier.fillMaxWidth()
                        )

                        OutlinedTextField(
                            value = confirmPin,
                            onValueChange = {
                                if (it.length <= 6 && it.all { c -> c.isDigit() }) confirmPin = it
                            },
                            label = { Text(stringResource(R.string.confirm_pin)) },
                            singleLine = true,
                            visualTransformation = PasswordVisualTransformation(),
                            keyboardOptions = KeyboardOptions(keyboardType = KeyboardType.NumberPassword),
                            isError = confirmPin.isNotEmpty() && newPin != confirmPin,
                            supportingText = if (confirmPin.isNotEmpty() && newPin != confirmPin) {
                                { Text(stringResource(R.string.pins_dont_match)) }
                            } else null,
                            modifier = Modifier.fillMaxWidth()
                        )
                    }
                }
            }
        },
        confirmButton = {
            when (step) {
                1 -> {
                    Button(
                        onClick = {
                            val result = app.joinCodeManager.validate(joinCode)
                            if (result != null) {
                                validatedCode = result
                                codeError = null
                                step = 2
                            } else {
                                codeError = "Invalid or expired code"
                            }
                        },
                        enabled = joinCode.length == 6
                    ) {
                        Text(stringResource(R.string.next))
                    }
                }

                2 -> {
                    Button(
                        onClick = {
                            scope.launch {
                                // Check username uniqueness
                                val existing = app.database.userDao().getByUsername(
                                    username, app.appConfig.facilityId
                                )
                                if (existing != null) {
                                    nameError = "Username already taken"
                                } else {
                                    step = 3
                                }
                            }
                        },
                        enabled = displayName.isNotBlank() && username.length >= 2
                    ) {
                        Text(stringResource(R.string.next))
                    }
                }

                3 -> validatedCode?.let { code ->
                    Button(
                        onClick = {
                            if (isCreating) return@Button
                            isCreating = true
                            scope.launch {
                                val salt = PinHasher.generateSalt()
                                val hash = PinHasher.hash(newPin, salt)

                                val newUser = UserEntity(
                                    id = UUID.randomUUID().toString(),
                                    username = username,
                                    displayName = displayName,
                                    pinHash = hash,
                                    pinSalt = salt,
                                    role = code.role,
                                    facilityId = app.appConfig.facilityId,
                                    isActive = true,
                                    createdBy = "join:${code.code}",
                                    createdAt = System.currentTimeMillis(),
                                    updatedAt = System.currentTimeMillis()
                                )
                                try {
                                    app.database.userDao().insert(newUser)
                                } catch (e: android.database.sqlite.SQLiteConstraintException) {
                                    nameError = "Username '$username' already exists"
                                    step = 2
                                    isCreating = false
                                    return@launch
                                }

                                // Consume the join code (single-use)
                                app.joinCodeManager.consume(code.code)

                                // Audit log
                                app.auditLogger.log(
                                    action = "USER_JOINED",
                                    targetType = "USER",
                                    targetId = newUser.id,
                                    details = AuditLogger.buildDetails(
                                        "role" to code.role,
                                        "username" to username
                                    )
                                )

                                // Auto-login the new user
                                val loginResult = app.sessionManager.login(
                                    username = username,
                                    pin = newPin,
                                    facilityId = app.appConfig.facilityId
                                )
                                if (loginResult is AuthResult.Success) {
                                    onJoinSuccess()
                                }
                                isCreating = false
                            }
                        },
                        enabled = newPin.length >= 4 && newPin == confirmPin && !isCreating
                    ) {
                        if (isCreating) {
                            CircularProgressIndicator(
                                modifier = Modifier.size(16.dp),
                                strokeWidth = 2.dp
                            )
                        } else {
                            Text(stringResource(R.string.create_account))
                        }
                    }
                }
            }
        },
        dismissButton = {
            when (step) {
                1 -> TextButton(onClick = onDismiss) { Text(stringResource(R.string.cancel)) }
                2 -> TextButton(onClick = { step = 1 }) { Text(stringResource(R.string.back)) }
                3 -> TextButton(onClick = { step = 2 }) { Text(stringResource(R.string.back)) }
            }
        }
    )
}

private fun parseJoinCodeFromQr(raw: String): String? {
    val trimmed = raw.trim()
    if (Regex("^\\d{6}$").matches(trimmed)) return trimmed

    if (trimmed.startsWith("chartlite-join:", ignoreCase = true)) {
        val payload = trimmed.substringAfter("chartlite-join:", "")
        val candidate = payload.substringBefore(":").trim()
        if (Regex("^\\d{6}$").matches(candidate)) return candidate
    }
    return null
}
