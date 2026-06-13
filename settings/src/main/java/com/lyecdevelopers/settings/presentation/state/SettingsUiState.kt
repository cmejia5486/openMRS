package com.lyecdevelopers.settings.presentation.state

data class SettingsUiState(
    val isDarkMode: Boolean = false,
    val isSyncing: Boolean = false,
    val username: String = "",
    val serverUrl: String = "",
    val serverVersion: String? = null,
    val syncIntervalInHours: Int = 1,
    val autoSyncEnabled: Boolean = false,
    val versionName: String = "v1.0.0",
)
