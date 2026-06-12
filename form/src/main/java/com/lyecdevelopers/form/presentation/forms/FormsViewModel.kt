package com.lyecdevelopers.form.presentation.forms

import androidx.lifecycle.viewModelScope
import com.lyecdevelopers.core._base.BaseViewModel
import com.lyecdevelopers.core.common.scheduler.SchedulerProvider
import com.lyecdevelopers.core.model.Result
import com.lyecdevelopers.form.domain.mapper.o3Form
import com.lyecdevelopers.form.domain.usecase.FormsUseCase
import com.lyecdevelopers.form.presentation.event.FormsEvent
import com.lyecdevelopers.form.presentation.state.FormsUiState
import dagger.hilt.android.lifecycle.HiltViewModel
import kotlinx.coroutines.flow.MutableStateFlow
import kotlinx.coroutines.flow.StateFlow
import kotlinx.coroutines.flow.asStateFlow
import kotlinx.coroutines.flow.update
import kotlinx.coroutines.launch
import kotlinx.coroutines.withContext
import javax.inject.Inject


@HiltViewModel
class FormsViewModel @Inject constructor(
    private val formsUseCase: FormsUseCase,
    private val schedulerProvider: SchedulerProvider,
) : BaseViewModel() {

    private val _uiState = MutableStateFlow(FormsUiState())
    val uiState: StateFlow<FormsUiState> = _uiState.asStateFlow()


    init {
        loadLocalForms()
    }

    fun onEvent(event: FormsEvent) {
        when (event) {
            is FormsEvent.LoadForms -> loadLocalForms()
            is FormsEvent.SelectForm -> {
                _uiState.update { it.copy(selectedForm = event.form) }
            }
            is FormsEvent.SearchQueryChanged -> {
                val query = event.query.trim()
                val filtered = if (query.isEmpty()) {
                    _uiState.value.allForms
                } else {
                    _uiState.value.allForms.filter {
                        it.name?.contains(query, ignoreCase = true) == true ||
                                it.description?.contains(query, ignoreCase = true) == true
                    }
                }
                _uiState.update {
                    it.copy(searchQuery = query, filteredForms = filtered)
                }
            }
        }
    }

    private fun loadLocalForms() {
        viewModelScope.launch(schedulerProvider.io) {
            formsUseCase.getAllLocalForms().collect { result ->
                withContext(schedulerProvider.main) {
                    _uiState.update {
                        it.copy(
                            isLoading = true, errorMessage = null
                        )
                    }
                    handleResult(
                        result = result,
                        onSuccess = { formEntities ->
                            val localForms = formEntities.map { it.o3Form() }
                            _uiState.update {
                                it.copy(
                                    isLoading = false,
                                    allForms = localForms,
                                    filteredForms = localForms,
                                    errorMessage = null
                                )
                            }
                        },
                        successMessage = "Successfully loaded local forms",
                        errorMessage = (result as? Result.Error)?.message
                    )
                    hideLoading()
                }
            }
        }
    }


}

