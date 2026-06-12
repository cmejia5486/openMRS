package com.lyecdevelopers.core.ui.event

sealed class UiEvent {
    data class Success(
        val message: String,
        val title: String = "Success",
        val confirmText: String = "OK",
        val onConfirm: (() -> Unit)? = null,
        val autoDismissAfterMillis: Long? = null,
    ) : UiEvent()

    data class Error(
        val message: String,
        val title: String = "Error",
        val confirmText: String = "OK",
        val onConfirm: (() -> Unit)? = null,
        val autoDismissAfterMillis: Long? = null,
    ) : UiEvent()

    data class Snackbar(
        val message: String,
        val actionLabel: String? = null,
        val duration: SnackbarDuration = SnackbarDuration.Short,
        val onAction: (() -> Unit)? = null,
    ) : UiEvent()

    object ShowLoading : UiEvent()
    object HideLoading : UiEvent()

    data class Navigate(val route: String) : UiEvent()
    object PopBackStack : UiEvent()

}


enum class SnackbarDuration {
    Short, Long, Indefinite
}




