package com.lyecdevelopers.settings.presentation

import androidx.lifecycle.viewModelScope
import com.lyecdevelopers.core._base.BaseViewModel
import com.lyecdevelopers.core.common.scheduler.SchedulerProvider
import com.lyecdevelopers.core.data.preference.PreferenceManager
import com.lyecdevelopers.core.data.sync.SyncManager
import com.lyecdevelopers.core.model.Result
import com.lyecdevelopers.core_navigation.navigation.Destinations
import com.lyecdevelopers.settings.domain.usecase.SettingsUseCase
import com.lyecdevelopers.settings.presentation.event.SettingsEvent
import com.lyecdevelopers.settings.presentation.state.SettingsUiState
import com.lyecdevelopers.sync.data.sync.EncountersSyncWorker
import com.lyecdevelopers.sync.data.sync.PatientsSyncWorker
import dagger.hilt.android.lifecycle.HiltViewModel
import kotlinx.coroutines.flow.MutableStateFlow
import kotlinx.coroutines.flow.StateFlow
import kotlinx.coroutines.flow.firstOrNull
import kotlinx.coroutines.flow.update
import kotlinx.coroutines.launch
import kotlinx.coroutines.withContext
import javax.inject.Inject

@HiltViewModel
class SettingsViewModel @Inject constructor(
    private val settingsUseCase: SettingsUseCase,
    private val preferenceManager: PreferenceManager,
    private val schedulerProvider: SchedulerProvider,
    private val syncManager: SyncManager,
) : BaseViewModel() {

    // state
    private val _uiState = MutableStateFlow(SettingsUiState())
    val uiState: StateFlow<SettingsUiState> = _uiState

    // handle events
    fun onEvent(event: SettingsEvent) {
        when (event) {
            is SettingsEvent.LoadSettings -> loadSettings()
            is SettingsEvent.ToggleDarkMode -> toggleDarkMode(event.enabled)
            is SettingsEvent.SyncNow -> sync()
            is SettingsEvent.Logout -> logout()
            is SettingsEvent.NavigateToProfile -> {}
            is SettingsEvent.NavigateToAbout -> {}
            is SettingsEvent.NavigateToLanguageSelection -> {}
            is SettingsEvent.UpdateUsername -> updateUsername(event.username)
            is SettingsEvent.UpdateServerUrl -> updateServerUrl(event.serverUrl)
            is SettingsEvent.UpdateSyncInterval -> updateSyncInterval(event.intervalInHours)
        }
    }


    private fun logout() {
        viewModelScope.launch(schedulerProvider.io) {
            val username = preferenceManager.getUsername().firstOrNull() ?: ""
            val password = preferenceManager.getPassword().firstOrNull() ?: ""
            settingsUseCase.logout(
                username, password
            ).collect { result ->
                withContext(schedulerProvider.main) {
                    showLoading()
                    handleResult(
                        result = result,
                        onSuccess = {
                            viewModelScope.launch {
                                preferenceManager.clear()
                            }
                        },
                        successMessage = "Successfully logged out",
                        errorMessage = (result as? Result.Error)?.message
                    )
                    navigate(Destinations.SPLASH)
                    hideLoading()
                }
            }
        }
    }


    private fun loadSettings() {
        viewModelScope.launch(schedulerProvider.io) {}
    }

    private fun toggleDarkMode(event: Boolean) {
        viewModelScope.launch(schedulerProvider.io) {}

    }

    private fun sync() {
        viewModelScope.launch(schedulerProvider.io) {}

    }

    private fun updateUsername(username: String) {
        viewModelScope.launch {
            _uiState.update { it.copy(username = username) }
        }
    }

    private fun updateServerUrl(url: String) {
        viewModelScope.launch {
            preferenceManager.saveServerUrl(url)
        }
    }

    private fun updateSyncInterval(interval: Int) {
        viewModelScope.launch {
            preferenceManager.saveAutoSyncInterval(interval)
            // If auto-sync is ON, reschedule
            if (_uiState.value.autoSyncEnabled) {
                syncManager.cancelPeriodicSync(
                    workers = listOf(
                        PatientsSyncWorker::class,
                        EncountersSyncWorker::class
                    )
                )
                syncManager.schedulePeriodicSync(
                    workers = listOf(
                        PatientsSyncWorker::class,
                        EncountersSyncWorker::class
                    ),
                    intervalHours = interval.toLong()
                )
            }
        }
    }

}