package com.lyecdevelopers.form.presentation.event

import com.lyecdevelopers.core.model.o3.o3Form


sealed class FormsEvent {
    object LoadForms : FormsEvent()
    data class SelectForm(val form: o3Form) : FormsEvent()
    data class SearchQueryChanged(val query: String) : FormsEvent()
}
