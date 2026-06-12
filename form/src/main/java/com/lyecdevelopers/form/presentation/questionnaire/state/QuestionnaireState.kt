package com.lyecdevelopers.form.presentation.questionnaire.state

import org.hl7.fhir.r4.model.Questionnaire

data class QuestionnaireState(
    val isLoading: Boolean = false,
    val visitId: String? = null,
    val questionnaireJson: String? = null,
    val questionnaire: Questionnaire? = null,
    val answers: Map<String, Any?> = emptyMap(),
    val isEditMode: Boolean = false,
    val patientId: String? = null,
    val error: String? = null,
    val isSubmitted: Boolean = false,
)