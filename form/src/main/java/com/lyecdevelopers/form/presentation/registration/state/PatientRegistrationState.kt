package com.lyecdevelopers.form.presentation.registration.state

data class PatientRegistrationState(
    val isLoading: Boolean = false,
    val questionnaireJson: String? = null,
    val answers: Map<String, Any?> = emptyMap(), // ✅ each entry: linkId -> user answer
    val isEditMode: Boolean = false,
    val patientId: String? = null,
    val error: String? = null,
    val isSubmitted: Boolean = false,
)
