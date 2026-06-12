package com.lyecdevelopers.form.presentation.questionnaire

import androidx.lifecycle.SavedStateHandle
import androidx.lifecycle.viewModelScope
import ca.uhn.fhir.context.FhirContext
import com.lyecdevelopers.core._base.BaseViewModel
import com.lyecdevelopers.core.common.scheduler.SchedulerProvider
import com.lyecdevelopers.core.data.local.entity.VisitEntity
import com.lyecdevelopers.core.model.Result
import com.lyecdevelopers.core.model.VisitStatus
import com.lyecdevelopers.core.utils.AppLogger
import com.lyecdevelopers.form.domain.mapper.FormMapper
import com.lyecdevelopers.form.domain.usecase.FormsUseCase
import com.lyecdevelopers.form.presentation.questionnaire.event.QuestionnaireEvent
import com.lyecdevelopers.form.presentation.questionnaire.state.QuestionnaireState
import com.lyecdevelopers.form.utils.EncounterExtensions.toEncounterEntity
import com.lyecdevelopers.form.utils.EncounterExtensions.toOpenmrsEncounter
import com.lyecdevelopers.form.utils.QuestionnaireUtils
import dagger.hilt.android.lifecycle.HiltViewModel
import kotlinx.coroutines.flow.MutableStateFlow
import kotlinx.coroutines.flow.StateFlow
import kotlinx.coroutines.flow.asStateFlow
import kotlinx.coroutines.flow.update
import kotlinx.coroutines.launch
import kotlinx.coroutines.withContext
import org.hl7.fhir.r4.model.Questionnaire
import org.hl7.fhir.r4.model.QuestionnaireResponse
import java.time.Instant
import java.time.LocalDate
import java.util.UUID
import javax.inject.Inject

@HiltViewModel
class QuestionnaireViewModel @Inject constructor(
    private val formsUseCase: FormsUseCase,
    private val schedulerProvider: SchedulerProvider,
    savedStateHandle: SavedStateHandle,
) : BaseViewModel() {

    private val _state = MutableStateFlow(QuestionnaireState(isLoading = true))
    val state: StateFlow<QuestionnaireState> = _state.asStateFlow()

    private val formId: String = checkNotNull(savedStateHandle["formId"])
    private val patientId: String = checkNotNull(savedStateHandle["patientId"])

    private var questionnaireResponse: QuestionnaireResponse? = null

    init {
        getMostRecentVisitForPatient(patientId)
    }


    fun onEvent(event: QuestionnaireEvent) {
        when (event) {
            is QuestionnaireEvent.Load -> loadQuestionnaireByUuid(formId)
            is QuestionnaireEvent.LoadForEdit -> loadPatientForEdit(event.questionnaire)
            is QuestionnaireEvent.UpdateAnswer -> updateAnswer(event.linkId, event.answer)
            is QuestionnaireEvent.Reset -> reset()
            is QuestionnaireEvent.SubmitWithResponse -> handleSubmitWithResponse(event.questionnaireResponseJson)
        }
    }

    /**
     * Load a questionnaire using its UUID from formsUseCase.
     */
    fun loadQuestionnaireByUuid(uuid: String) {
        viewModelScope.launch(schedulerProvider.io) {
            formsUseCase.getLocalFormById(uuid).collect { result ->
                withContext(schedulerProvider.main) {
                    _state.value = _state.value.copy(isLoading = true)
                    handleResult(
                        result = result,
                        onSuccess = { formEntity ->
                            try {
                                val questionnaire =
                                    formEntity?.let { FormMapper.toQuestionnaire(it) }
                                val questionnaireJson = FhirContext.forR4().newJsonParser()
                                    .encodeResourceToString(questionnaire)
                                _state.update {
                                    it.copy(
                                        isLoading = false,
                                        questionnaireJson = questionnaireJson,
                                        questionnaire = questionnaire,
                                        error = null
                                    )
                                }
                            } catch (e: Exception) {
                                AppLogger.e(
                                    "FormMapper${e.message}",
                                    "Error parsing form to questionnaire: ${e.message}",
                                    e
                                )
                                _state.update {
                                    it.copy(
                                        isLoading = false,
                                        error = "Failed to parse questionnaire: ${e.localizedMessage}"
                                    )
                                }
                            }
                        },
                        successMessage = "Successfully loaded form",
                        errorMessage = (result as? Result.Error)?.message
                    )
                }
            }
        }
    }


    private fun loadPatientForEdit(questionnaire: Questionnaire) {


    }

    private fun updateAnswer(linkId: String, answer: Any?) {
        _state.update {
            it.copy(answers = it.answers.toMutableMap().apply { put(linkId, answer) })
        }

        questionnaireResponse?.let {
            QuestionnaireUtils.updateResponseItem(it, linkId, answer)
        }
    }


    /**
     * Handles the submission of a questionnaire response.
     * It parses the response JSON, updates the ViewModel's state with the questionnaire and response,
     * and prepares for further actions like creating an encounter.
     *
     * @param responseJson A JSON string representing the questionnaire response.
     */
    private fun handleSubmitWithResponse(responseJson: String) {
        viewModelScope.launch(schedulerProvider.io) {
            withContext(schedulerProvider.main) { showLoading() }
            _state.update { it.copy(isLoading = true) }

            try {
                val parser = FhirContext.forR4().newJsonParser()
                val response = parser.parseResource(QuestionnaireResponse::class.java, responseJson)
                questionnaireResponse = response

                val state = _state.value
                val questionnaire = state.questionnaire

                if (questionnaire != null) {
                    val patientUuid = patientId
                    val encounterTypeUuid = "test-encounter"
                    val locationUuid = "tests-location"

                    val toSubmit = response.toOpenmrsEncounter(
                        questionnaireItems = questionnaire.item,
                        patientUuid = patientUuid,
                        encounterTypeUuid = encounterTypeUuid,
                        locationUuid = locationUuid
                    )

                    AppLogger.d("Mapped OpenMRS Encounter: $toSubmit")

                    val createdAt = Instant.now().toString()

                    // ✅ Get or create visit
                    val visitUuid: String = if (state.visitId != null) {
                        state.visitId
                    } else {
                        val newVisit = VisitEntity(
                            id = UUID.randomUUID().toString(),
                            patientId = patientUuid,
                            type = "Community Visit",
                            date = LocalDate.now().toString(),
                            status = VisitStatus.PENDING,
                        )
                        formsUseCase.createADefault(newVisit)
                        newVisit.id
                    }

                    val encounterEntity = toSubmit.toEncounterEntity(
                        visitUuid = visitUuid,
                        synced = false,
                        formUuid = questionnaire.id,
                        createdAt = createdAt
                    )

                    formsUseCase.saveEncounterLocally(encounterEntity)

                    AppLogger.d("Encounter saved locally: $encounterEntity")

                    _state.update { it.copy(isLoading = false, isSubmitted = true) }

                    withContext(schedulerProvider.main) {
                        hideLoading()
                        navigate("worklist_main")
                    }

                } else {
                    AppLogger.e("No Questionnaire found in state — cannot map response.")
                    _state.update {
                        it.copy(
                            isLoading = false, error = "Form definition is missing."
                        )
                    }
                    withContext(schedulerProvider.main) { hideLoading() }
                    return@launch
                }

            } catch (e: Exception) {
                AppLogger.e("Submit failed: ${e.localizedMessage}", e.stackTraceToString())
                _state.update {
                    it.copy(isLoading = false, error = e.localizedMessage ?: "Unknown error")
                }
                withContext(schedulerProvider.main) { hideLoading() }
            }
        }
    }

    private fun getMostRecentVisitForPatient(patientId: String) {
        viewModelScope.launch(schedulerProvider.io) {
            formsUseCase.getMostRecentForVisitPatient(patientId).collect { result ->
                withContext(schedulerProvider.main) {
                    handleResult(
                        result = result, onSuccess = { visit ->
                            _state.update {
                                it.copy(
                                    isLoading = false, visitId = visit.visit.id, error = null
                                )
                            }
                        }, errorMessage = (result as? Result.Error)?.message
                    )
                }
            }
        }

    }
    private fun reset() {
        _state.value = QuestionnaireState()
    }


}






