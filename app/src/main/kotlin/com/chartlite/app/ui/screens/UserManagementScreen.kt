package com.chartlite.app.ui.screens

import androidx.compose.foundation.layout.*
import androidx.compose.foundation.lazy.LazyColumn
import androidx.compose.foundation.lazy.items
import androidx.compose.material.icons.Icons
import androidx.compose.material.icons.automirrored.filled.ArrowBack
import androidx.compose.material.icons.filled.*
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
import com.chartlite.app.auth.AuditLogger
import com.chartlite.app.auth.JoinCodeManager
import com.chartlite.app.auth.PinHasher
import com.chartlite.app.auth.UserRole
import com.chartlite.app.database.entity.UserEntity
import com.chartlite.app.ui.components.QrCodeImage
import kotlinx.coroutines.launch
import java.text.SimpleDateFormat
import java.util.Date
import java.util.Locale
import java.util.UUID

/**
 * Admin-only screen for creating, editing, and deactivating user accounts.
 */
@OptIn(ExperimentalMaterial3Api::class)
@Composable
fun UserManagementScreen(onBack: () -> Unit) {
    val context = LocalContext.current
    val app = context.applicationContext as App
    val scope = rememberCoroutineScope()

    val usernameExistsFormat = stringResource(R.string.user_mgmt_username_exists)

    var users by remember { mutableStateOf<List<UserEntity>>(emptyList()) }
    var showCreateDialog by rememberSaveable { mutableStateOf(false) }
    var editingUser by remember { mutableStateOf<UserEntity?>(null) }
    var showJoinCodeDialog by rememberSaveable { mutableStateOf(false) }
    var activeCodes by remember { mutableStateOf<List<JoinCodeManager.JoinCode>>(emptyList()) }

    fun refreshUsers() {
        scope.launch {
            users = app.database.userDao().getByFacilityId(app.appConfig.facilityId)
        }
    }

    fun refreshCodes() {
        activeCodes = app.joinCodeManager.getActiveCodes()
    }

    // Refresh on load + poll every 3s to catch new joins from other devices
    LaunchedEffect(Unit) {
        while (true) {
            refreshUsers()
            refreshCodes()
            kotlinx.coroutines.delay(3_000L)
        }
    }

    Scaffold(
        topBar = {
            TopAppBar(
                title = { Text(stringResource(R.string.user_management)) },
                navigationIcon = {
                    IconButton(onClick = onBack) {
                        Icon(Icons.AutoMirrored.Filled.ArrowBack, stringResource(R.string.back))
                    }
                },
                actions = {
                    IconButton(onClick = { showJoinCodeDialog = true }) {
                        Icon(Icons.Default.QrCode, stringResource(R.string.user_mgmt_join_code))
                    }
                    IconButton(onClick = { showCreateDialog = true }) {
                        Icon(Icons.Default.PersonAdd, stringResource(R.string.user_mgmt_add_user))
                    }
                }
            )
        }
    ) { padding ->
        if (users.isEmpty()) {
            Box(
                modifier = Modifier
                    .fillMaxSize()
                    .padding(padding),
                contentAlignment = Alignment.Center
            ) {
                Column(horizontalAlignment = Alignment.CenterHorizontally) {
                    Icon(
                        Icons.Default.Group,
                        contentDescription = null,
                        modifier = Modifier.size(64.dp),
                        tint = MaterialTheme.colorScheme.onSurfaceVariant
                    )
                    Spacer(Modifier.height(12.dp))
                    Text(stringResource(R.string.user_mgmt_no_users), style = MaterialTheme.typography.titleMedium)
                    Spacer(Modifier.height(4.dp))
                    Text(
                        stringResource(R.string.user_mgmt_tap_to_create),
                        style = MaterialTheme.typography.bodyMedium,
                        color = MaterialTheme.colorScheme.onSurfaceVariant
                    )
                }
            }
        } else {
            LazyColumn(
                modifier = Modifier.padding(padding),
                contentPadding = PaddingValues(16.dp),
                verticalArrangement = Arrangement.spacedBy(8.dp)
            ) {
                items(users, key = { it.id }) { user ->
                    UserCard(
                        user = user,
                        onEdit = { editingUser = user },
                        onToggleActive = {
                            scope.launch {
                                val updated = user.copy(
                                    isActive = !user.isActive,
                                    updatedAt = System.currentTimeMillis()
                                )
                                app.database.userDao().update(updated)
                                app.auditLogger.log(
                                    action = if (updated.isActive) "ACTIVATE_USER" else "DEACTIVATE_USER",
                                    targetType = "USER",
                                    targetId = user.id
                                )
                                refreshUsers()
                            }
                        }
                    )
                }

                // Active join codes section
                if (activeCodes.isNotEmpty()) {
                    item {
                        Spacer(Modifier.height(16.dp))
                        Text(
                            stringResource(R.string.user_mgmt_active_join_codes),
                            style = MaterialTheme.typography.titleSmall,
                            fontWeight = FontWeight.Bold,
                            color = MaterialTheme.colorScheme.onSurfaceVariant
                        )
                        Spacer(Modifier.height(8.dp))
                    }
                    items(activeCodes, key = { it.code }) { joinCode ->
                        JoinCodeCard(
                            joinCode = joinCode,
                            onRevoke = {
                                app.joinCodeManager.revoke(joinCode.code)
                                scope.launch {
                                    app.auditLogger.log(
                                        action = "REVOKE_JOIN_CODE",
                                        details = AuditLogger.buildDetails("role" to joinCode.role)
                                    )
                                }
                                refreshCodes()
                            }
                        )
                    }
                }
            }
        }
    }

    // Create user dialog
    if (showCreateDialog) {
        CreateUserDialog(
            onDismiss = { showCreateDialog = false },
            onCreate = { username, displayName, role, pin ->
                scope.launch {
                    val salt = PinHasher.generateSalt()
                    val hash = PinHasher.hash(pin, salt)
                    val currentUser = app.sessionManager.currentSession

                    val newUser = UserEntity(
                        id = UUID.randomUUID().toString(),
                        username = username,
                        displayName = displayName,
                        pinHash = hash,
                        pinSalt = salt,
                        role = role.name,
                        facilityId = app.appConfig.facilityId,
                        isActive = true,
                        createdBy = currentUser?.userId ?: "system",
                        createdAt = System.currentTimeMillis(),
                        updatedAt = System.currentTimeMillis()
                    )
                    try {
                        app.database.userDao().insert(newUser)
                    } catch (e: android.database.sqlite.SQLiteConstraintException) {
                        android.widget.Toast.makeText(
                            context,
                            String.format(usernameExistsFormat, username),
                            android.widget.Toast.LENGTH_LONG
                        ).show()
                        return@launch
                    }
                    app.auditLogger.log(
                        action = "CREATE_USER",
                        targetType = "USER",
                        targetId = newUser.id,
                        details = AuditLogger.buildDetails("role" to role.name, "username" to username)
                    )
                    refreshUsers()
                    showCreateDialog = false
                }
            }
        )
    }

    // Edit user dialog
    editingUser?.let { currentEditingUser ->
        EditUserDialog(
            user = currentEditingUser,
            onDismiss = { editingUser = null },
            onSave = { displayName, role, newPin ->
                scope.launch {
                    var updated = currentEditingUser.copy(
                        displayName = displayName,
                        role = role.name,
                        updatedAt = System.currentTimeMillis()
                    )
                    if (newPin != null) {
                        val salt = PinHasher.generateSalt()
                        val hash = PinHasher.hash(newPin, salt)
                        updated = updated.copy(pinHash = hash, pinSalt = salt)
                    }
                    app.database.userDao().update(updated)
                    app.auditLogger.log(
                        action = "UPDATE_USER",
                        targetType = "USER",
                        targetId = updated.id,
                        details = AuditLogger.buildDetails("role" to role.name)
                    )
                    refreshUsers()
                    editingUser = null
                }
            }
        )
    }

    // Generate join code dialog
    if (showJoinCodeDialog) {
        GenerateJoinCodeDialog(
            facilityId = app.appConfig.facilityId,
            onDismiss = {
                showJoinCodeDialog = false
                refreshCodes()
            },
            onGenerate = { role ->
                val currentUser = app.sessionManager.currentSession
                val code = app.joinCodeManager.generate(role, currentUser?.userId ?: "admin")
                scope.launch {
                    app.auditLogger.log(
                        action = "GENERATE_JOIN_CODE",
                        details = AuditLogger.buildDetails("role" to role.name, "code" to code)
                    )
                }
                code
            }
        )
    }
}

@Composable
private fun UserCard(
    user: UserEntity,
    onEdit: () -> Unit,
    onToggleActive: () -> Unit
) {
    OutlinedCard(modifier = Modifier.fillMaxWidth()) {
        Row(
            modifier = Modifier
                .fillMaxWidth()
                .padding(16.dp),
            verticalAlignment = Alignment.CenterVertically,
            horizontalArrangement = Arrangement.spacedBy(12.dp)
        ) {
            // Avatar with role indicator
            Surface(
                modifier = Modifier.size(44.dp),
                shape = MaterialTheme.shapes.medium,
                color = if (user.isActive) MaterialTheme.colorScheme.primaryContainer
                else MaterialTheme.colorScheme.surfaceVariant
            ) {
                Box(contentAlignment = Alignment.Center) {
                    Icon(
                        Icons.Default.Person,
                        contentDescription = null,
                        tint = if (user.isActive) MaterialTheme.colorScheme.onPrimaryContainer
                        else MaterialTheme.colorScheme.onSurfaceVariant
                    )
                }
            }

            Column(modifier = Modifier.weight(1f)) {
                Text(
                    user.displayName,
                    style = MaterialTheme.typography.titleSmall,
                    fontWeight = FontWeight.Medium
                )
                Text(
                    "@${user.username} · ${user.role.lowercase().replaceFirstChar { it.uppercase() }.replace("_", " ")}",
                    style = MaterialTheme.typography.bodySmall,
                    color = MaterialTheme.colorScheme.onSurfaceVariant
                )
                if (!user.isActive) {
                    Text(
                        stringResource(R.string.user_mgmt_deactivated),
                        style = MaterialTheme.typography.labelSmall,
                        color = MaterialTheme.colorScheme.error
                    )
                }
            }

            // Edit button
            IconButton(onClick = onEdit) {
                Icon(Icons.Default.Edit, stringResource(R.string.edit))
            }

            // Activate/deactivate toggle
            IconButton(onClick = onToggleActive) {
                Icon(
                    if (user.isActive) Icons.Default.PersonOff else Icons.Default.PersonAdd,
                    contentDescription = if (user.isActive) stringResource(R.string.user_mgmt_deactivate) else stringResource(R.string.user_mgmt_activate),
                    tint = if (user.isActive) MaterialTheme.colorScheme.error
                    else MaterialTheme.colorScheme.primary
                )
            }
        }
    }
}

@OptIn(ExperimentalMaterial3Api::class)
@Composable
private fun CreateUserDialog(
    onDismiss: () -> Unit,
    onCreate: (username: String, displayName: String, role: UserRole, pin: String) -> Unit
) {
    var username by rememberSaveable { mutableStateOf("") }
    var displayName by rememberSaveable { mutableStateOf("") }
    var selectedRole by rememberSaveable { mutableStateOf(UserRole.NURSE) }
    var pin by remember { mutableStateOf("") }
    var confirmPin by remember { mutableStateOf("") }
    var expanded by rememberSaveable { mutableStateOf(false) }

    val isValid = username.isNotBlank()
        && displayName.isNotBlank()
        && pin.length >= 4
        && pin == confirmPin

    AlertDialog(
        onDismissRequest = onDismiss,
        title = { Text(stringResource(R.string.user_mgmt_create_user)) },
        text = {
            Column(verticalArrangement = Arrangement.spacedBy(12.dp)) {
                OutlinedTextField(
                    value = username,
                    onValueChange = { username = it.lowercase().filter { c -> c.isLetterOrDigit() || c == '.' } },
                    label = { Text(stringResource(R.string.username)) },
                    singleLine = true,
                    modifier = Modifier.fillMaxWidth()
                )
                OutlinedTextField(
                    value = displayName,
                    onValueChange = { displayName = it },
                    label = { Text(stringResource(R.string.user_mgmt_display_name)) },
                    singleLine = true,
                    modifier = Modifier.fillMaxWidth()
                )

                // Role dropdown
                ExposedDropdownMenuBox(
                    expanded = expanded,
                    onExpandedChange = { expanded = it }
                ) {
                    OutlinedTextField(
                        value = selectedRole.displayName,
                        onValueChange = {},
                        readOnly = true,
                        label = { Text(stringResource(R.string.user_mgmt_role)) },
                        trailingIcon = { ExposedDropdownMenuDefaults.TrailingIcon(expanded) },
                        modifier = Modifier
                            .menuAnchor()
                            .fillMaxWidth()
                    )
                    ExposedDropdownMenu(
                        expanded = expanded,
                        onDismissRequest = { expanded = false }
                    ) {
                        UserRole.entries.forEach { role ->
                            DropdownMenuItem(
                                text = { Text(role.displayName) },
                                onClick = {
                                    selectedRole = role
                                    expanded = false
                                }
                            )
                        }
                    }
                }

                OutlinedTextField(
                    value = pin,
                    onValueChange = { if (it.length <= 6 && it.all { c -> c.isDigit() }) pin = it },
                    label = { Text(stringResource(R.string.user_mgmt_pin_label)) },
                    singleLine = true,
                    modifier = Modifier.fillMaxWidth()
                )
                OutlinedTextField(
                    value = confirmPin,
                    onValueChange = { if (it.length <= 6 && it.all { c -> c.isDigit() }) confirmPin = it },
                    label = { Text(stringResource(R.string.user_mgmt_confirm_pin)) },
                    singleLine = true,
                    isError = confirmPin.isNotEmpty() && pin != confirmPin,
                    supportingText = if (confirmPin.isNotEmpty() && pin != confirmPin) {
                        { Text(stringResource(R.string.user_mgmt_pins_dont_match)) }
                    } else null,
                    modifier = Modifier.fillMaxWidth()
                )
            }
        },
        confirmButton = {
            Button(
                onClick = { onCreate(username, displayName, selectedRole, pin) },
                enabled = isValid
            ) {
                Text(stringResource(R.string.user_mgmt_create))
            }
        },
        dismissButton = {
            TextButton(onClick = onDismiss) {
                Text(stringResource(R.string.cancel))
            }
        }
    )
}

@Composable
private fun JoinCodeCard(
    joinCode: JoinCodeManager.JoinCode,
    onRevoke: () -> Unit
) {
    val role = try { UserRole.valueOf(joinCode.role) } catch (_: Exception) { null }
    val expiresIn = joinCode.expiresAt - System.currentTimeMillis()
    val hoursLeft = (expiresIn / (60 * 60 * 1000)).coerceAtLeast(0)
    val minutesLeft = ((expiresIn % (60 * 60 * 1000)) / (60 * 1000)).coerceAtLeast(0)

    OutlinedCard(modifier = Modifier.fillMaxWidth()) {
        Row(
            modifier = Modifier
                .fillMaxWidth()
                .padding(12.dp),
            verticalAlignment = Alignment.CenterVertically,
            horizontalArrangement = Arrangement.spacedBy(12.dp)
        ) {
            Column(modifier = Modifier.weight(1f)) {
                Text(
                    joinCode.code.chunked(3).joinToString(" "),
                    style = MaterialTheme.typography.titleMedium,
                    fontWeight = FontWeight.Bold,
                    letterSpacing = MaterialTheme.typography.titleMedium.letterSpacing * 1.5
                )
                Text(
                    "${role?.displayName ?: joinCode.role} · ${stringResource(R.string.user_mgmt_time_left_format, hoursLeft, minutesLeft)}",
                    style = MaterialTheme.typography.bodySmall,
                    color = MaterialTheme.colorScheme.onSurfaceVariant
                )
            }
            IconButton(onClick = onRevoke) {
                Icon(
                    Icons.Default.Close,
                    contentDescription = stringResource(R.string.user_mgmt_revoke),
                    tint = MaterialTheme.colorScheme.error
                )
            }
        }
    }
}

@OptIn(ExperimentalMaterial3Api::class)
@Composable
private fun GenerateJoinCodeDialog(
    facilityId: String,
    onDismiss: () -> Unit,
    onGenerate: (UserRole) -> String
) {
    var selectedRole by rememberSaveable { mutableStateOf(UserRole.NURSE) }
    var expanded by rememberSaveable { mutableStateOf(false) }
    var generatedCode by rememberSaveable { mutableStateOf<String?>(null) }

    AlertDialog(
        onDismissRequest = onDismiss,
        title = { Text(if (generatedCode == null) stringResource(R.string.user_mgmt_generate_join_code) else stringResource(R.string.user_mgmt_join_code_ready)) },
        text = {
            Column(verticalArrangement = Arrangement.spacedBy(12.dp)) {
                if (generatedCode == null) {
                    Text(
                        stringResource(R.string.user_mgmt_generate_code_desc),
                        style = MaterialTheme.typography.bodyMedium,
                        color = MaterialTheme.colorScheme.onSurfaceVariant
                    )

                    // Role dropdown
                    ExposedDropdownMenuBox(
                        expanded = expanded,
                        onExpandedChange = { expanded = it }
                    ) {
                        OutlinedTextField(
                            value = selectedRole.displayName,
                            onValueChange = {},
                            readOnly = true,
                            label = { Text(stringResource(R.string.user_mgmt_role_for_new_user)) },
                            trailingIcon = { ExposedDropdownMenuDefaults.TrailingIcon(expanded) },
                            modifier = Modifier
                                .menuAnchor()
                                .fillMaxWidth()
                        )
                        ExposedDropdownMenu(
                            expanded = expanded,
                            onDismissRequest = { expanded = false }
                        ) {
                            UserRole.entries.filter { it != UserRole.ADMIN }.forEach { role ->
                                DropdownMenuItem(
                                    text = {
                                        Column {
                                            Text(role.displayName, fontWeight = FontWeight.Medium)
                                            Text(
                                                role.description,
                                                style = MaterialTheme.typography.bodySmall,
                                                color = MaterialTheme.colorScheme.onSurfaceVariant
                                            )
                                        }
                                    },
                                    onClick = {
                                        selectedRole = role
                                        expanded = false
                                    }
                                )
                            }
                        }
                    }
                } else {
                    // Show generated code
                    Text(
                        stringResource(R.string.user_mgmt_share_code_hint),
                        style = MaterialTheme.typography.bodyMedium,
                        color = MaterialTheme.colorScheme.onSurfaceVariant
                    )

                    Card(
                        colors = CardDefaults.cardColors(
                            containerColor = MaterialTheme.colorScheme.primaryContainer
                        ),
                        modifier = Modifier.fillMaxWidth()
                    ) {
                        Column(
                            modifier = Modifier
                                .fillMaxWidth()
                                .padding(16.dp),
                            horizontalAlignment = Alignment.CenterHorizontally
                        ) {
                            Text(
                                (generatedCode ?: "").chunked(3).joinToString("  "),
                                style = MaterialTheme.typography.headlineLarge,
                                fontWeight = FontWeight.Bold,
                                color = MaterialTheme.colorScheme.onPrimaryContainer
                            )
                            Spacer(Modifier.height(4.dp))
                            Text(
                                stringResource(R.string.user_mgmt_joining_as_format, selectedRole.displayName),
                                style = MaterialTheme.typography.bodyMedium,
                                color = MaterialTheme.colorScheme.onPrimaryContainer
                            )
                        }
                    }

                    // QR code for easy scanning
                    QrCodeImage(
                        content = "chartlite-join:${generatedCode ?: ""}:$facilityId:${selectedRole.name}",
                        size = 180.dp,
                        modifier = Modifier.align(Alignment.CenterHorizontally)
                    )

                    Text(
                        stringResource(R.string.user_mgmt_qr_scan_hint),
                        style = MaterialTheme.typography.bodySmall,
                        color = MaterialTheme.colorScheme.onSurfaceVariant
                    )
                }
            }
        },
        confirmButton = {
            if (generatedCode == null) {
                Button(onClick = {
                    generatedCode = onGenerate(selectedRole)
                }) {
                    Text(stringResource(R.string.user_mgmt_generate))
                }
            } else {
                Button(onClick = onDismiss) {
                    Text(stringResource(R.string.done))
                }
            }
        },
        dismissButton = {
            if (generatedCode == null) {
                TextButton(onClick = onDismiss) {
                    Text(stringResource(R.string.cancel))
                }
            }
        }
    )
}

@OptIn(ExperimentalMaterial3Api::class)
@Composable
private fun EditUserDialog(
    user: UserEntity,
    onDismiss: () -> Unit,
    onSave: (displayName: String, role: UserRole, newPin: String?) -> Unit
) {
    var displayName by rememberSaveable { mutableStateOf(user.displayName) }
    var selectedRole by rememberSaveable { mutableStateOf(try { UserRole.valueOf(user.role) } catch (_: Exception) { UserRole.NURSE }) }
    var newPin by remember { mutableStateOf("") }
    var confirmPin by remember { mutableStateOf("") }
    var expanded by rememberSaveable { mutableStateOf(false) }
    var resetPin by rememberSaveable { mutableStateOf(false) }

    val isValid = displayName.isNotBlank()
        && (!resetPin || (newPin.length >= 4 && newPin == confirmPin))

    AlertDialog(
        onDismissRequest = onDismiss,
        title = { Text(stringResource(R.string.user_mgmt_edit_user)) },
        text = {
            Column(verticalArrangement = Arrangement.spacedBy(12.dp)) {
                Text(
                    "@${user.username}",
                    style = MaterialTheme.typography.labelMedium,
                    color = MaterialTheme.colorScheme.onSurfaceVariant
                )

                OutlinedTextField(
                    value = displayName,
                    onValueChange = { displayName = it },
                    label = { Text(stringResource(R.string.user_mgmt_display_name)) },
                    singleLine = true,
                    modifier = Modifier.fillMaxWidth()
                )

                ExposedDropdownMenuBox(
                    expanded = expanded,
                    onExpandedChange = { expanded = it }
                ) {
                    OutlinedTextField(
                        value = selectedRole.displayName,
                        onValueChange = {},
                        readOnly = true,
                        label = { Text(stringResource(R.string.user_mgmt_role)) },
                        trailingIcon = { ExposedDropdownMenuDefaults.TrailingIcon(expanded) },
                        modifier = Modifier
                            .menuAnchor()
                            .fillMaxWidth()
                    )
                    ExposedDropdownMenu(
                        expanded = expanded,
                        onDismissRequest = { expanded = false }
                    ) {
                        UserRole.entries.forEach { role ->
                            DropdownMenuItem(
                                text = { Text(role.displayName) },
                                onClick = {
                                    selectedRole = role
                                    expanded = false
                                }
                            )
                        }
                    }
                }

                Row(
                    verticalAlignment = Alignment.CenterVertically,
                    horizontalArrangement = Arrangement.spacedBy(8.dp)
                ) {
                    Checkbox(checked = resetPin, onCheckedChange = { resetPin = it })
                    Text(stringResource(R.string.user_mgmt_reset_pin), style = MaterialTheme.typography.bodyMedium)
                }

                if (resetPin) {
                    OutlinedTextField(
                        value = newPin,
                        onValueChange = { if (it.length <= 6 && it.all { c -> c.isDigit() }) newPin = it },
                        label = { Text(stringResource(R.string.user_mgmt_new_pin_label)) },
                        singleLine = true,
                        modifier = Modifier.fillMaxWidth()
                    )
                    OutlinedTextField(
                        value = confirmPin,
                        onValueChange = { if (it.length <= 6 && it.all { c -> c.isDigit() }) confirmPin = it },
                        label = { Text(stringResource(R.string.user_mgmt_confirm_new_pin)) },
                        singleLine = true,
                        isError = confirmPin.isNotEmpty() && newPin != confirmPin,
                        supportingText = if (confirmPin.isNotEmpty() && newPin != confirmPin) {
                            { Text(stringResource(R.string.user_mgmt_pins_dont_match)) }
                        } else null,
                        modifier = Modifier.fillMaxWidth()
                    )
                }
            }
        },
        confirmButton = {
            Button(
                onClick = {
                    onSave(
                        displayName,
                        selectedRole,
                        if (resetPin) newPin else null
                    )
                },
                enabled = isValid
            ) {
                Text(stringResource(R.string.save))
            }
        },
        dismissButton = {
            TextButton(onClick = onDismiss) {
                Text(stringResource(R.string.cancel))
            }
        }
    )
}
