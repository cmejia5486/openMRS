package com.lyecdevelopers.form.presentation.state

import com.lyecdevelopers.core.model.o3.o3Form


data class FormsUiState(
    val isLoading: Boolean = false,
    val allForms: List<o3Form> = emptyList(),
    val filteredForms: List<o3Form> = emptyList(),
    val selectedForm: o3Form? = null,
    val searchQuery: String = "",
    val errorMessage: String? = null,
    val isEmpty: Boolean = false,
)
