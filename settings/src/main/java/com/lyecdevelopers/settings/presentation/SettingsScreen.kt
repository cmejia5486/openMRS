package com.lyecdevelopers.settings.presentation

import androidx.compose.foundation.background
import androidx.compose.foundation.clickable
import androidx.compose.foundation.layout.Arrangement
import androidx.compose.foundation.layout.Column
import androidx.compose.foundation.layout.ColumnScope
import androidx.compose.foundation.layout.Row
import androidx.compose.foundation.layout.Spacer
import androidx.compose.foundation.layout.fillMaxSize
import androidx.compose.foundation.layout.fillMaxWidth
import androidx.compose.foundation.layout.height
import androidx.compose.foundation.layout.padding
import androidx.compose.foundation.layout.size
import androidx.compose.foundation.layout.width
import androidx.compose.foundation.lazy.LazyColumn
import androidx.compose.foundation.shape.RoundedCornerShape
import androidx.compose.material.icons.Icons
import androidx.compose.material.icons.filled.Business
import androidx.compose.material.icons.filled.Cloud
import androidx.compose.material.icons.filled.DarkMode
import androidx.compose.material.icons.filled.Edit
import androidx.compose.material.icons.filled.ExitToApp
import androidx.compose.material.icons.filled.Info
import androidx.compose.material.icons.filled.Language
import androidx.compose.material.icons.filled.Person
import androidx.compose.material.icons.filled.Schedule
import androidx.compose.material3.AlertDialog
import androidx.compose.material3.Button
import androidx.compose.material3.ButtonDefaults
import androidx.compose.material3.DropdownMenuItem
import androidx.compose.material3.ExperimentalMaterial3Api
import androidx.compose.material3.ExposedDropdownMenuBox
import androidx.compose.material3.ExposedDropdownMenuDefaults
import androidx.compose.material3.HorizontalDivider
import androidx.compose.material3.Icon
import androidx.compose.material3.MaterialTheme
import androidx.compose.material3.OutlinedTextField
import androidx.compose.material3.Scaffold
import androidx.compose.material3.Switch
import androidx.compose.material3.Text
import androidx.compose.material3.TextButton
import androidx.compose.runtime.Composable
import androidx.compose.runtime.collectAsState
import androidx.compose.runtime.getValue
import androidx.compose.runtime.mutableIntStateOf
import androidx.compose.runtime.mutableStateOf
import androidx.compose.runtime.remember
import androidx.compose.runtime.setValue
import androidx.compose.ui.Alignment
import androidx.compose.ui.Modifier
import androidx.compose.ui.graphics.vector.ImageVector
import androidx.compose.ui.text.font.FontWeight
import androidx.compose.ui.unit.dp
import androidx.hilt.navigation.compose.hiltViewModel
import androidx.navigation.NavController
import com.lyecdevelopers.core.ui.components.BaseScreen
import com.lyecdevelopers.settings.presentation.event.SettingsEvent

@Composable
fun SettingsScreen(
    navController: NavController,
    viewModel: SettingsViewModel = hiltViewModel(),
) {
    var showServerDialog by remember { mutableStateOf(false) }
    val state by viewModel.uiState.collectAsState()
    var isLoading by remember { mutableStateOf(false) }

    BaseScreen(
        uiEventFlow = viewModel.uiEvent,
        isLoading = isLoading,
        showLoading = { isLoading = it },
        navController = navController
    ) {
        Scaffold { padding ->
            LazyColumn(
                contentPadding = padding,
                modifier = Modifier
                    .fillMaxSize()
                    .padding(horizontal = 16.dp, vertical = 12.dp),
                verticalArrangement = Arrangement.spacedBy(24.dp)
            ) {
                item {
                    SettingsSection(title = "Account") {
                        Column(
                            Modifier
                                .fillMaxWidth()
                                .background(
                                    MaterialTheme.colorScheme.surfaceVariant,
                                    RoundedCornerShape(8.dp)
                                )
                        ) {
                            SettingsItem(
                                icon = Icons.Default.Person,
                                title = "Username",
                                subtitle = state.username,
                                onClick = { /* Open editable username dialog */ },
                                trailingIcon = Icons.Default.Edit
                            )
                            HorizontalDivider(Modifier.padding(horizontal = 16.dp))
                            SettingsItem(
                                icon = Icons.Default.Business,
                                title = "Facility",
                                subtitle = "Kampala Health Center",
                                onClick = { /* Maybe show facility info */ })
                        }
                    }
                }


                item {
                    SettingsSection(title = "Preferences") {
                        Column(
                            Modifier
                                .fillMaxWidth()
                                .background(
                                    MaterialTheme.colorScheme.surfaceVariant,
                                    RoundedCornerShape(8.dp)
                                )
                        ) {
                            SettingsItem(
                                icon = Icons.Default.Language,
                                title = "Language",
                                subtitle = "English",
                                onClick = { /* Open language selector */ })
                            HorizontalDivider(Modifier.padding(horizontal = 16.dp))
                            SettingsItemSwitch(
                                icon = Icons.Default.DarkMode,
                                title = "Dark Mode",
                                checked = state.isDarkMode,
                                onCheckedChange = {
                                    viewModel.onEvent(SettingsEvent.ToggleDarkMode(it))
                                })
                        }
                    }
                }


                item {
                    SettingsSection(title = "Server") {
                        Column(
                            Modifier
                                .fillMaxWidth()
                                .background(
                                    MaterialTheme.colorScheme.surfaceVariant,
                                    RoundedCornerShape(8.dp)
                                )
                        ) {
                            SettingsItem(
                                icon = Icons.Default.Cloud,
                                title = "Server URL",
                                subtitle = state.serverUrl, onClick = { showServerDialog = true })
                            HorizontalDivider(Modifier.padding(horizontal = 16.dp))

                            SettingsItem(
                                icon = Icons.Default.Schedule,
                                title = "Sync Interval",
                                subtitle = "${state.syncIntervalInHours} hrs",
                                onClick = { showServerDialog = true }
                            )

                            HorizontalDivider(Modifier.padding(horizontal = 16.dp))

                            SettingsItem(
                                icon = Icons.Default.Info,
                                title = "Server Version",
                                subtitle = state.serverVersion ?: "Unknown",
                                onClick = { /* Optional: maybe show changelog */ }
                            )
                        }
                    }
                }



                item {
                    Button(
                        onClick = { viewModel.onEvent(SettingsEvent.Logout) },
                        colors = ButtonDefaults.buttonColors(
                            containerColor = MaterialTheme.colorScheme.error,
                            contentColor = MaterialTheme.colorScheme.onError
                        ),
                        modifier = Modifier
                            .fillMaxWidth()
                            .padding(vertical = 12.dp)
                            .height(52.dp),
                        shape = RoundedCornerShape(8.dp)
                    ) {
                        Icon(
                            imageVector = Icons.Default.ExitToApp,
                            contentDescription = "Logout",
                            modifier = Modifier.size(20.dp)
                        )
                        Spacer(Modifier.width(8.dp))
                        Text(
                            text = "Logout",
                            style = MaterialTheme.typography.labelLarge.copy(fontWeight = FontWeight.SemiBold)
                        )
                    }
                }

            }
        }

        if (showServerDialog) {
            SettingsServerConfigurationDialog(
                currentUrl = state.serverUrl, currentIntervalHours = state.syncIntervalInHours,
                onDismiss = { showServerDialog = false },
                onSave = { newUrl, newInterval ->
                    viewModel.onEvent(SettingsEvent.UpdateServerUrl(newUrl))
                    viewModel.onEvent(SettingsEvent.UpdateSyncInterval(newInterval))
                    showServerDialog = false
                })
        }
    }
}



@Composable
fun SettingsSection(
    title: String,
    content: @Composable ColumnScope.() -> Unit,
) {
    Column(
        modifier = Modifier
            .fillMaxWidth()
            .padding(16.dp),
        verticalArrangement = Arrangement.spacedBy(8.dp)
    ) {
        Text(
            text = title,
            style = MaterialTheme.typography.titleMedium,
            modifier = Modifier.padding(bottom = 8.dp)
        )
        content()
    }
}


@OptIn(ExperimentalMaterial3Api::class)
@Composable
fun SettingsServerConfigurationDialog(
    currentUrl: String,
    currentIntervalHours: Int,
    onDismiss: () -> Unit,
    onSave: (String, Int) -> Unit,
) {
    var url by remember { mutableStateOf(currentUrl) }
    var selectedInterval by remember { mutableIntStateOf(currentIntervalHours) }
    var expanded by remember { mutableStateOf(false) }

    val intervalOptions = listOf(1, 6, 12, 24) // HOURS!
    MaterialTheme.colorScheme

    AlertDialog(
        onDismissRequest = onDismiss,
        title = {
            Text(
                text = "Server Settings",
                style = MaterialTheme.typography.titleLarge.copy(fontWeight = FontWeight.SemiBold)
            )
        },
        text = {
            Column(
                verticalArrangement = Arrangement.spacedBy(20.dp),
                modifier = Modifier.fillMaxWidth()
            ) {
                OutlinedTextField(
                    value = url,
                    onValueChange = { url = it },
                    label = { Text("Server URL") },
                    singleLine = true,
                    modifier = Modifier.fillMaxWidth(),
                    placeholder = { Text("https://example.org/api/") }
                )

                ExposedDropdownMenuBox(
                    expanded = expanded,
                    onExpandedChange = { expanded = !expanded },
                ) {
                    OutlinedTextField(
                        readOnly = true,
                        value = "$selectedInterval hours",
                        onValueChange = {},
                        label = { Text("Sync Interval") },
                        trailingIcon = { ExposedDropdownMenuDefaults.TrailingIcon(expanded) },
                        modifier = Modifier
                            .menuAnchor()
                            .fillMaxWidth()
                    )

                    ExposedDropdownMenu(
                        expanded = expanded,
                        onDismissRequest = { expanded = false }
                    ) {
                        intervalOptions.forEach { interval ->
                            DropdownMenuItem(
                                text = { Text("$interval hours") },
                                onClick = {
                                    selectedInterval = interval
                                    expanded = false
                                }
                            )
                        }
                    }
                }
            }
        },
        confirmButton = {
            TextButton(
                onClick = { onSave(url.trim(), selectedInterval) },
                enabled = url.isNotBlank()
            ) {
                Text("Save")
            }
        },
        dismissButton = {
            TextButton(onClick = onDismiss) {
                Text("Cancel")
            }
        },
        shape = RoundedCornerShape(12.dp)
    )
}


@Composable
fun SettingsItem(
    icon: ImageVector,
    title: String,
    subtitle: String,
    onClick: () -> Unit,
    trailingIcon: ImageVector? = null,
) {
    val colors = MaterialTheme.colorScheme

    Row(
        modifier = Modifier
            .fillMaxWidth()
            .clickable { onClick() }
            .padding(horizontal = 16.dp, vertical = 12.dp),
        verticalAlignment = Alignment.CenterVertically) {
        Icon(
            icon, contentDescription = null, tint = colors.primary, modifier = Modifier.size(24.dp)
        )
        Spacer(Modifier.width(16.dp))
        Column(Modifier.weight(1f)) {
            Text(
                text = title, style = MaterialTheme.typography.bodyMedium, color = colors.onSurface
            )
            Text(
                text = subtitle,
                style = MaterialTheme.typography.bodySmall,
                color = colors.onSurfaceVariant
            )
        }
        if (trailingIcon != null) {
            Icon(
                trailingIcon,
                contentDescription = null,
                tint = colors.outline,
                modifier = Modifier.size(20.dp)
            )
        }
    }
}


@Composable
fun SettingsItemSwitch(
    icon: ImageVector,
    title: String,
    checked: Boolean,
    onCheckedChange: (Boolean) -> Unit,
) {
    val colors = MaterialTheme.colorScheme

    Row(
        modifier = Modifier
            .fillMaxWidth()
            .clickable { onCheckedChange(!checked) }
            .padding(horizontal = 16.dp, vertical = 12.dp),
        verticalAlignment = Alignment.CenterVertically) {
        Icon(
            icon, contentDescription = null, tint = colors.primary, modifier = Modifier.size(24.dp)
        )
        Spacer(Modifier.width(16.dp))
        Text(
            text = title,
            style = MaterialTheme.typography.bodyMedium,
            color = colors.onSurface,
            modifier = Modifier.weight(1f)
        )
        Switch(
            checked = checked, onCheckedChange = onCheckedChange
        )
    }
}
