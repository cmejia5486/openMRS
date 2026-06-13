package com.lyecdevelopers.form.presentation.registration.event

import org.hl7.fhir.r4.model.Patient

sealed class PatientRegistrationEvent {
    object Load : PatientRegistrationEvent()
    data class UpdateAnswer(val linkId: String, val answer: Any?) : PatientRegistrationEvent()
    object Submit : PatientRegistrationEvent()
    data class SubmitWithResponse(val questionnaireResponseJson: String) :
        PatientRegistrationEvent()

    data class LoadForEdit(val patient: Patient) : PatientRegistrationEvent()
    object Reset : PatientRegistrationEvent()
}


