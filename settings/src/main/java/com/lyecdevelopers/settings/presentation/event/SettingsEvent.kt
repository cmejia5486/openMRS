package com.lyecdevelopers.settings.presentation.event

sealed class SettingsEvent {
    object LoadSettings : SettingsEvent()

    data class ToggleDarkMode(val enabled: Boolean) : SettingsEvent()
    object SyncNow : SettingsEvent()

    object Logout : SettingsEvent()
    object NavigateToProfile : SettingsEvent()
    object NavigateToAbout : SettingsEvent()
    object NavigateToLanguageSelection : SettingsEvent()

    data class UpdateUsername(val username: String) : SettingsEvent()
    data class UpdateServerUrl(val serverUrl: String) : SettingsEvent()
    data class UpdateSyncInterval(val intervalInHours: Int) : SettingsEvent()
}
