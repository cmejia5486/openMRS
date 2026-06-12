package com.lyecdevelopers.auth.presentation

import androidx.lifecycle.viewModelScope
import com.lyecdevelopers.auth.domain.usecase.LoginUseCase
import com.lyecdevelopers.auth.presentation.event.LoginEvent
import com.lyecdevelopers.auth.presentation.state.LoginUIState
import com.lyecdevelopers.core._base.BaseViewModel
import com.lyecdevelopers.core.common.scheduler.SchedulerProvider
import com.lyecdevelopers.core.data.preference.PreferenceManager
import com.lyecdevelopers.core.data.remote.interceptor.AuthInterceptor
import com.lyecdevelopers.core.model.Result
import dagger.hilt.android.lifecycle.HiltViewModel
import kotlinx.coroutines.flow.MutableStateFlow
import kotlinx.coroutines.flow.StateFlow
import kotlinx.coroutines.flow.update
import kotlinx.coroutines.launch
import kotlinx.coroutines.withContext
import javax.inject.Inject

@HiltViewModel
class AuthViewModel @Inject constructor(
    private val loginUseCase: LoginUseCase,
    private val schedulerProvider: SchedulerProvider,
    private val preferenceManager: PreferenceManager,
    private val authInterceptor: AuthInterceptor,
) : BaseViewModel() {

    // state
    private val _uiState = MutableStateFlow(LoginUIState())
    val uiState: StateFlow<LoginUIState> = _uiState

    fun onEvent(event: LoginEvent) {
        when (event) {
            is LoginEvent.Login -> {
                _uiState.update {
                    it.copy(
                        username = event.username, password = event.password
                    )
                }
            }

            LoginEvent.Submit -> {
                validateAndLogin()
            }
        }
    }


    private fun validateAndLogin() {
        val username = uiState.value.username.trim()
        val password = uiState.value.password

        val validationError = validateCredentials(username, password)
        if (validationError != null) {
            showSnackbar(validationError)
            return
        }

        viewModelScope.launch(schedulerProvider.io) {
            loginUseCase(username, password).collect { result ->
                withContext(schedulerProvider.main) {
                    _uiState.update { it.copy(isLoading = true) }
                    handleResult(
                        result = result,
                        onSuccess = {
                            saveLogin(username, password)
                            _uiState.update { it.copy(isLoading = false) }
                        },
                        successMessage = "Successfully LoggedIn",
                        errorMessage = (result as? Result.Error)?.message
                    )
                }
            }

        }
    }


    private fun validateCredentials(username: String, password: String): String? {
        return when {
            username.isBlank() -> "Username is required"
            password.isBlank() -> "Password is required"
            password.length < 8 -> "Password must be at least 8 characters"
            password.lowercase() in listOf(
                "123456", "password", "admin"
            ) -> "Password is too common. Please choose a stronger one."

            else -> null
        }
    }


    private fun saveLogin(username: String, password: String) {
        viewModelScope.launch(schedulerProvider.io) {
            preferenceManager.saveUsername(username)
            preferenceManager.savePassword(password)
            preferenceManager.setIsLoggedIn(true)

            // This makes future requests use Basic Auth
            authInterceptor.updateCredentials(username, password)
        }
    }
}
