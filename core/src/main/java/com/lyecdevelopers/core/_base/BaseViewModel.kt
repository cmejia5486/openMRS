package com.lyecdevelopers.core._base

import androidx.lifecycle.ViewModel
import androidx.lifecycle.viewModelScope
import com.lyecdevelopers.core.model.Result
import com.lyecdevelopers.core.ui.event.SnackbarDuration
import com.lyecdevelopers.core.ui.event.UiEvent
import kotlinx.coroutines.flow.MutableSharedFlow
import kotlinx.coroutines.flow.SharedFlow
import kotlinx.coroutines.flow.asSharedFlow
import kotlinx.coroutines.launch

open class BaseViewModel : ViewModel() {

    private val _uiEvent = MutableSharedFlow<UiEvent>()
    val uiEvent: SharedFlow<UiEvent> = _uiEvent.asSharedFlow()

    protected fun emitUiEvent(event: UiEvent) {
        viewModelScope.launch {
            _uiEvent.emit(event)
        }
    }

    protected fun showSnackbar(
        message: String,
        actionLabel: String? = null,
        duration: SnackbarDuration = SnackbarDuration.Short,
        onAction: (() -> Unit)? = null,
    ) {
        emitUiEvent(UiEvent.Snackbar(message, actionLabel, duration, onAction))
    }

    protected fun <T> handleResult(
        result: Result<T>,
        onSuccess: (T) -> Unit = {},
        onError: (String) -> Unit = {},
        successMessage: String? = null,
        errorMessage: String? = null,
    ) {
        when (result) {
            is Result.Success -> {
                onSuccess(result.data)
                successMessage?.let {
                    emitUiEvent(UiEvent.Success(message = it))
                }
            }

            is Result.Error -> {
                onError(result.message)
                emitUiEvent(UiEvent.Error(message = errorMessage ?: result.message))
            }

            Result.Loading -> {
                // Optional: trigger loading state
            }
        }
    }

    protected fun navigate(route: String) {
        viewModelScope.launch {
            _uiEvent.emit(UiEvent.Navigate(route))
        }
    }


    protected fun showLoading() {
        emitUiEvent(UiEvent.ShowLoading)
    }

    protected fun hideLoading() {
        emitUiEvent(UiEvent.HideLoading)
    }

    protected fun popBackStack() {
        emitUiEvent(UiEvent.PopBackStack)
    }

}
