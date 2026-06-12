package com.lyecdevelopers.worklist.presentation.worklist

import androidx.lifecycle.SavedStateHandle
import androidx.lifecycle.viewModelScope
import androidx.paging.PagingData
import androidx.paging.cachedIn
import androidx.work.ListenableWorker
import com.lyecdevelopers.core._base.BaseViewModel
import com.lyecdevelopers.core.common.scheduler.SchedulerProvider
import com.lyecdevelopers.core.data.local.entity.PatientEntity
import com.lyecdevelopers.core.data.local.entity.VisitEntity
import com.lyecdevelopers.core.data.preference.PreferenceManager
import com.lyecdevelopers.core.data.sync.SyncManager
import com.lyecdevelopers.core.model.Result
import com.lyecdevelopers.core.model.VisitStatus
import com.lyecdevelopers.core.ui.event.UiEvent.Navigate
import com.lyecdevelopers.form.domain.usecase.PatientsUseCase
import com.lyecdevelopers.sync.data.sync.EncountersSyncWorker
import com.lyecdevelopers.sync.data.sync.PatientsSyncWorker
import com.lyecdevelopers.worklist.domain.mapper.toDomain
import com.lyecdevelopers.worklist.domain.mapper.toEntity
import com.lyecdevelopers.worklist.domain.model.Vitals
import com.lyecdevelopers.worklist.domain.usecase.VisitUseCases
import com.lyecdevelopers.worklist.presentation.worklist.event.WorklistEvent
import com.lyecdevelopers.worklist.presentation.worklist.state.WorklistUiState
import dagger.hilt.android.lifecycle.HiltViewModel
import kotlinx.coroutines.Job
import kotlinx.coroutines.delay
import kotlinx.coroutines.flow.MutableStateFlow
import kotlinx.coroutines.flow.StateFlow
import kotlinx.coroutines.flow.asStateFlow
import kotlinx.coroutines.flow.collectLatest
import kotlinx.coroutines.flow.update
import kotlinx.coroutines.launch
import kotlinx.coroutines.withContext
import java.util.UUID
import javax.inject.Inject
import kotlin.reflect.KClass


@HiltViewModel
class WorklistViewModel @Inject constructor(
    private val patientsUseCase: PatientsUseCase,
    private val visitUseCases: VisitUseCases,
    private val schedulerProvider: SchedulerProvider,
    private val preferenceManager: PreferenceManager,
    private val syncManager: SyncManager,
    savedStateHandle: SavedStateHandle,
) : BaseViewModel() {

    private val _uiState = MutableStateFlow(WorklistUiState())
    val uiState: StateFlow<WorklistUiState> = _uiState.asStateFlow()

    private val _pagingData = MutableStateFlow<PagingData<PatientEntity>>(PagingData.empty())
    val pagingData: StateFlow<PagingData<PatientEntity>> = _pagingData.asStateFlow()

    private var searchJob: Job? = null

    private var nameFilter: String? = null
    private var genderFilter: String? = null
    private var statusFilter: String? = null

    init {
        loadPatients()
        loadPagedPatients()
        getForms()
        getAllVisitsWithDetails()


        val patientId = savedStateHandle.get<String>("patientId")
        if (patientId != null) {
            loadPatient(patientId)
            loadPatientVisits(patientId)
            loadPatientMostRecentVisit(patientId)
            getVitalsByPatient(patientId)

        } else {
            _uiState.update { it.copy(error = "Patient ID not provided") }
        }
    }

    fun onEvent(event: WorklistEvent) {
        when (event) {
            is WorklistEvent.OnNameFilterChanged -> {
                nameFilter = event.name.takeIf { it.isNotBlank() }
                debounceLoadPatients()
            }

            is WorklistEvent.OnGenderFilterChanged -> {
                genderFilter = event.gender
                debounceLoadPatients()
            }

            is WorklistEvent.OnStatusFilterChanged -> {
                statusFilter = event.status?.name
                debounceLoadPatients()
            }

            is WorklistEvent.OnClearFilters -> {
                nameFilter = null
                genderFilter = null
                statusFilter = null
                debounceLoadPatients()
            }

            is WorklistEvent.OnPatientSelected -> {
                emitUiEvent(Navigate("patient_details/${event.patientId}"))
            }

            is WorklistEvent.OnRefresh -> debounceLoadPatients()

            is WorklistEvent.OnVisitTypeChanged -> {
                _uiState.update { it.copy(visitType = event.type) }
            }

            is WorklistEvent.OnVisitLocationChanged -> {
                _uiState.update { it.copy(visitLocation = event.location) }
            }

            is WorklistEvent.OnVisitStatusChanged -> {
                _uiState.update { it.copy(visitStatus = event.status) }
            }

            is WorklistEvent.OnStartDateChanged -> {
                _uiState.update { it.copy(startDate = event.date) }
            }

            is WorklistEvent.OnStartTimeChanged -> {
                _uiState.update { it.copy(startTime = event.time) }
            }

            is WorklistEvent.OnAmPmChanged -> {
                _uiState.update { it.copy(amPm = event.amPm) }
            }

            is WorklistEvent.OnVisitNotesChanged -> {
                _uiState.update { it.copy(visitNotes = event.notes) }
            }

            is WorklistEvent.OnLocationMenuExpandedChanged -> {
                _uiState.update { it.copy(locationMenuExpanded = event.expanded) }
            }

            is WorklistEvent.OnAmPmMenuExpandedChanged -> {
                _uiState.update { it.copy(amPmMenuExpanded = event.expanded) }
            }

            is WorklistEvent.OnVitalsChanged -> updateVitals(event.vitals)

            WorklistEvent.SaveVitals -> saveVitals()

            WorklistEvent.StartVisit -> startPatientVisit()
            is WorklistEvent.OnMarkPatientEligible -> markPatientEligibleForSync()
            is WorklistEvent.OnSyncPatientNow -> syncPatientNow()
        }
    }

    private fun debounceLoadPatients(delayMillis: Long = 300L) {
        searchJob?.cancel()
        searchJob = viewModelScope.launch {
            delay(delayMillis)
            loadPatients()
        }
    }

    private fun loadPatients() {
        viewModelScope.launch(schedulerProvider.io) {
            patientsUseCase.searchPatients(nameFilter, genderFilter, statusFilter)
                .collect { result ->
                    withContext(schedulerProvider.main) {
                        _uiState.value = _uiState.value.copy(isLoading = true)
                        handleResult(
                            result,
                            onSuccess = { patients ->
                                _uiState.update {
                                    it.copy(
                                        patients = patients, error = null, isLoading = false
                                    )
                                }
                            },
                            errorMessage = (result as? Result.Error)?.message
                        )
                    }
                }
        }
    }

    fun loadPagedPatients() {
        viewModelScope.launch {
            patientsUseCase.getPagedPatients(nameFilter, genderFilter, statusFilter)
                .cachedIn(viewModelScope).collectLatest {
                    _pagingData.value = it
                }
        }
    }

    private fun loadPatient(patientId: String) {
        viewModelScope.launch(schedulerProvider.io) {
            patientsUseCase.getPatientById(patientId).collect { result ->
                withContext(schedulerProvider.main) {
                    _uiState.value = _uiState.value.copy(isLoading = true)
                    handleResult(
                        result,
                        onSuccess = { patient ->
                            _uiState.update {
                                it.copy(
                                    selectedPatient = patient, isLoading = false
                                )
                            }
                        }, successMessage = "Patient loaded successfully",
                        errorMessage = (result as? Result.Error)?.message
                    )
                }
            }
        }
    }

    private fun loadPatientVisits(patientId: String) {
        viewModelScope.launch(schedulerProvider.io) {
            visitUseCases.getVisitSummariesForPatient(patientId).collect { result ->
                withContext(schedulerProvider.main) {
                    handleResult(
                        result, onSuccess = { visits ->
                            _uiState.update {
                                it.copy(
                                    encounters = visits.firstOrNull()?.encounters ?: emptyList()
                                )
                            }
                        },
                        errorMessage = (result as? Result.Error)?.message
                    )
                }
            }
        }
    }

    private fun loadPatientMostRecentVisit(patientId: String) {
        viewModelScope.launch(schedulerProvider.io) {
            visitUseCases.getMostRecentVisitForPatient(patientId).collect { result ->
                withContext(schedulerProvider.main) {
                    handleResult(
                        result, onSuccess = { visit ->
                            _uiState.update { it.copy(mostRecentVisit = visit) }
                        }, errorMessage = (result as? Result.Error)?.message
                    )
                }
            }
        }
    }

    private fun getForms() {
        viewModelScope.launch(schedulerProvider.io) {
            visitUseCases.getForms().collect { result ->
                withContext(schedulerProvider.main) {
                    handleResult(
                        result,
                        onSuccess = { forms -> _uiState.update { it.copy(forms = forms) } },
                        errorMessage = (result as? Result.Error)?.message
                    )
                }
            }
        }
    }

    fun getAllVisitsWithDetails() {
        viewModelScope.launch(schedulerProvider.io) {
            visitUseCases.getAllVisitsWithDetails().collect { result ->
                withContext(schedulerProvider.main) {
                    handleResult(
                        result,
                        onSuccess = { visits -> _uiState.update { it.copy(visits = visits) } },
                        errorMessage = (result as? Result.Error)?.message
                    )
                }
            }
        }
    }

    fun updateVitals(newVitals: Vitals) {
        _uiState.update { it.copy(vitals = newVitals) }
    }

    private fun saveVitals() {
        val state = uiState.value
        val vitals = state.vitals ?: return
        val visitId = state.mostRecentVisit?.visit?.id.orEmpty()
        val patientId = state.selectedPatient?.id.orEmpty()

        if (visitId.isBlank() || patientId.isBlank()) {
            _uiState.update { it.copy(error = "Cannot save vitals: missing visit or patient.") }
            return
        }

        val entity = vitals.toEntity(
            visitUuid = visitId, patientId = patientId
        )
        viewModelScope.launch(schedulerProvider.io) {
            patientsUseCase.saveVitals(vitals = entity).collect { result ->
                withContext(schedulerProvider.main) {
                    _uiState.value = _uiState.value.copy(isLoading = true)
                    handleResult(
                        result, onSuccess = {
                            _uiState.update { it.copy(isLoading = false) }
                            loadPatientMostRecentVisit(patientId)
                            loadPatientVisits(patientId)
                        }, onError = {
                            _uiState.value = _uiState.value.copy(isLoading = false)

                        }, errorMessage = (result as? Result.Error)?.message
                    )

                }
            }


        }

    }

    fun getVitalsByVisit(visitId: String) {
        viewModelScope.launch(schedulerProvider.io) {
            patientsUseCase.getVitalsByVisit(visitId).collect { result ->
                handleResult(
                    result, onSuccess = { vitals ->
                        _uiState.update {
                            it.copy(vitals = vitals.toDomain())
                        }
                    }, errorMessage = (result as? Result.Error)?.message
                )
            }
        }
    }

    fun getVitalsByPatient(patientId: String) {
        viewModelScope.launch(schedulerProvider.io) {
            patientsUseCase.getVitalsByPatient(patientId).collect { result ->
                handleResult(
                    result, onSuccess = { vitalsList ->
                        _uiState.update { it.copy(vitalsEntity = vitalsList.firstOrNull()) }
                    }, errorMessage = (result as? Result.Error)?.message
                )
            }
        }
    }

    private fun startPatientVisit() {
        viewModelScope.launch(schedulerProvider.io) {
            val state = _uiState.value
            val patientId = state.selectedPatient?.id
            if (patientId == null) {
                _uiState.update { it.copy(error = "No patient selected") }
                return@launch
            }

            val visitId = UUID.randomUUID().toString()
            val status = when (state.visitStatus) {
                "New" -> VisitStatus.PENDING
                "Ongoing" -> VisitStatus.IN_PROGRESS
                "In the past" -> VisitStatus.COMPLETED
                else -> VisitStatus.PENDING
            }

            val visit = VisitEntity(
                id = visitId,
                patientId = patientId,
                status = status,
                scheduledTime = "${state.startDate} ${state.startTime} ${state.amPm}",
                type = state.visitType,
                date = state.startDate,
                notes = state.visitNotes
            )

            visitUseCases.saveVisit(visit).collect { result ->
                withContext(schedulerProvider.main) {
                    _uiState.value = _uiState.value.copy(isLoading = true)
                    handleResult(
                        result, onSuccess = {
                            loadPatientMostRecentVisit(patientId)
                        _uiState.value = _uiState.value.copy(isLoading = false)

                        }, onError = {
                            _uiState.value = _uiState.value.copy(isLoading = false)

                        }, errorMessage = (result as? Result.Error)?.message
                    )
                }

            }
        }
    }


    private fun markPatientEligibleForSync() {
        val patient = _uiState.value.selectedPatient
        if (patient != null) {
            viewModelScope.launch(schedulerProvider.io) {
                patientsUseCase.markPatientEligible(patient.id, eligible = true)
            }
        }

    }

    private fun syncPatientNow() {
        viewModelScope.launch {
            syncManager.syncNow(
                workers = listOf<KClass<out ListenableWorker>>(
                    PatientsSyncWorker::class, EncountersSyncWorker::class
                )
            )

        }
    }
}





