package com.lyecdevelopers.form.presentation.questionnaire.event

import org.hl7.fhir.r4.model.Questionnaire

sealed class QuestionnaireEvent {
    object Load : QuestionnaireEvent()
    data class UpdateAnswer(val linkId: String, val answer: Any?) : QuestionnaireEvent()
    data class SubmitWithResponse(val questionnaireResponseJson: String) :
        QuestionnaireEvent()

    data class LoadForEdit(val questionnaire: Questionnaire) : QuestionnaireEvent()
    object Reset : QuestionnaireEvent()
}


