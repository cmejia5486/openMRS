package com.lyecdevelopers.form.presentation.registration

import android.content.Context
import androidx.lifecycle.viewModelScope
import ca.uhn.fhir.context.FhirContext
import com.google.android.fhir.FhirEngine
import com.lyecdevelopers.core._base.BaseViewModel
import com.lyecdevelopers.core.common.scheduler.SchedulerProvider
import com.lyecdevelopers.core.utils.AppLogger
import com.lyecdevelopers.form.domain.usecase.PatientsUseCase
import com.lyecdevelopers.form.presentation.registration.event.PatientRegistrationEvent
import com.lyecdevelopers.form.presentation.registration.state.PatientRegistrationState
import com.lyecdevelopers.form.utils.QuestionnaireResponseConverter
import com.lyecdevelopers.form.utils.QuestionnaireUtils
import com.lyecdevelopers.form.utils.toPatient
import com.lyecdevelopers.form.utils.toPatientEntity
import com.lyecdevelopers.form.utils.toQuestionnaireAnswers
import dagger.hilt.android.lifecycle.HiltViewModel
import dagger.hilt.android.qualifiers.ApplicationContext
import kotlinx.coroutines.flow.MutableStateFlow
import kotlinx.coroutines.flow.StateFlow
import kotlinx.coroutines.flow.asStateFlow
import kotlinx.coroutines.flow.update
import kotlinx.coroutines.launch
import org.hl7.fhir.r4.model.Patient
import org.hl7.fhir.r4.model.Questionnaire
import org.hl7.fhir.r4.model.QuestionnaireResponse
import javax.inject.Inject


@HiltViewModel
class RegisterPatientViewModel @Inject constructor(
    private val fhirEngine: FhirEngine,
    private val schedulerProvider: SchedulerProvider,
    @ApplicationContext private val context: Context,
    private val patientsUseCase: PatientsUseCase,
) : BaseViewModel() {

    private val _state = MutableStateFlow(PatientRegistrationState())
    val state: StateFlow<PatientRegistrationState> = _state.asStateFlow()

    private lateinit var questionnaire: Questionnaire
    private var questionnaireResponse: QuestionnaireResponse? = null

    fun onEvent(event: PatientRegistrationEvent) {
        when (event) {
            is PatientRegistrationEvent.Load -> loadRegisterPatientQuestionnaireFromAssets()
            is PatientRegistrationEvent.LoadForEdit -> loadPatientForEdit(event.patient)
            is PatientRegistrationEvent.UpdateAnswer -> updateAnswer(event.linkId, event.answer)
            is PatientRegistrationEvent.Submit -> submit()
            is PatientRegistrationEvent.Reset -> reset()
            is PatientRegistrationEvent.SubmitWithResponse -> handleSubmitWithResponse(event.questionnaireResponseJson)
        }
    }

    private fun loadRegisterPatientQuestionnaireFromAssets(
        filename: String = "questionnaires/register-patient-questionnaire.json",
    ) {
        viewModelScope.launch(schedulerProvider.io) {
            _state.value = _state.value.copy(isLoading = true)
            try {
                val json = context.assets.open(filename).bufferedReader().use { it.readText() }
                loadRegisterPatientQuestionnaireFromJson(json)
                _state.value = _state.value.copy(isLoading = false)

            } catch (e: Exception) {
                AppLogger.e(("FHIR_PARSE_ERROR" + e.message), e)
                _state.value = _state.value.copy(
                    isLoading = false, error = "Failed to load form: ${e.localizedMessage}"
                )
            }
        }
    }

    private fun loadRegisterPatientQuestionnaireFromJson(questionnaireJson: String) {
        try {
            val fhirContext = FhirContext.forR4()
            val parser = fhirContext.newJsonParser()

            questionnaire = parser.parseResource(Questionnaire::class.java, questionnaireJson)
            questionnaireResponse = QuestionnaireResponse()
            _state.value = _state.value.copy(
                isLoading = false, questionnaireJson = parser.encodeResourceToString(questionnaire)
            )
        } catch (e: Exception) {
            AppLogger.e(("FHIR_PARSE_ERROR" + e.message), e)
            _state.value = _state.value.copy(
                isLoading = false, error = e.localizedMessage
            )
        }
    }

    private fun loadPatientForEdit(patient: Patient) {
        val prefillAnswers = patient.toQuestionnaireAnswers()
        _state.value = _state.value.copy(
            isEditMode = true, patientId = patient.idElement.idPart, answers = prefillAnswers
        )
    }

    private fun updateAnswer(linkId: String, answer: Any?) {
        _state.update {
            it.copy(answers = it.answers.toMutableMap().apply { put(linkId, answer) })
        }
        questionnaireResponse?.let {
            QuestionnaireUtils.updateResponseItem(it, linkId, answer)
        }
    }

    private fun submit() {
        viewModelScope.launch(schedulerProvider.io) {
            _state.update { it.copy(isLoading = true) }
            try {
                val patient = _state.value.answers.toPatient(_state.value.patientId)

                if (_state.value.isEditMode) {
                    fhirEngine.update(patient)
                } else {
                    fhirEngine.create(patient)
                }

                // ✅ Save to Room DB
                patientsUseCase.saveLocallyOnly(patient.toPatientEntity())

                _state.update { it.copy(isLoading = false, isSubmitted = true) }

                navigate("worklist_main")

            } catch (e: Exception) {
                AppLogger.e("RegisterPatient", "Failed to save patient: ${e.localizedMessage}")
                _state.update { it.copy(isLoading = false, error = e.localizedMessage) }
            }
        }
    }


    private fun handleSubmitWithResponse(responseJson: String) {
        viewModelScope.launch(schedulerProvider.io) {
            _state.update { it.copy(isLoading = true) }
            try {
                val parser = FhirContext.forR4().newJsonParser()
                val response = parser.parseResource(QuestionnaireResponse::class.java, responseJson)
                questionnaireResponse = response

                val patient = QuestionnaireResponseConverter.toPatient(response)

                if (_state.value.isEditMode) {
                    fhirEngine.update(patient)
                } else {
                    fhirEngine.create(patient)
                }

                // ✅ Save to Room DB
                patientsUseCase.saveLocallyOnly(patient.toPatientEntity())
                _state.update { it.copy(isLoading = false, isSubmitted = true) }

                navigate("worklist_main")

            } catch (e: Exception) {
                AppLogger.e("RegisterPatient", "Submit failed: ${e.localizedMessage}")
                _state.update { it.copy(isLoading = false, error = e.localizedMessage) }
            }
        }
    }

    private fun reset() {
        _state.value = PatientRegistrationState()
        viewModelScope.launch {}
    }

    fun getQuestionnaireResponse(): QuestionnaireResponse? = questionnaireResponse
}



