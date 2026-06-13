package com.lyecdevelopers.auth.presentation.state

data class LoginUIState(
    val username: String = "",
    val password: String = "",
    val isLoading: Boolean = false,
    val isLoginSuccessful: Boolean = false,
    val errorMessage: String? = null,
    val hasSubmitted: Boolean = false
)
