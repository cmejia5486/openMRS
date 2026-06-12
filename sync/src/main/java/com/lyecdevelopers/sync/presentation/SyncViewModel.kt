package com.lyecdevelopers.sync.presentation

import android.app.Application
import androidx.lifecycle.viewModelScope
import com.lyecdevelopers.core._base.BaseViewModel
import com.lyecdevelopers.core.common.scheduler.SchedulerProvider
import com.lyecdevelopers.core.data.preference.PreferenceManager
import com.lyecdevelopers.core.data.sync.SyncManager
import com.lyecdevelopers.core.model.Result
import com.lyecdevelopers.core.model.cohort.Attribute
import com.lyecdevelopers.core.model.cohort.CQIReportingCohort
import com.lyecdevelopers.core.model.cohort.Cohort
import com.lyecdevelopers.core.model.cohort.CohortResponse
import com.lyecdevelopers.core.model.cohort.DataDefinition
import com.lyecdevelopers.core.model.cohort.Indicator
import com.lyecdevelopers.core.model.cohort.Parameters
import com.lyecdevelopers.core.model.cohort.RenderType
import com.lyecdevelopers.core.model.cohort.ReportCategory
import com.lyecdevelopers.core.model.cohort.ReportCategoryWrapper
import com.lyecdevelopers.core.model.cohort.ReportRequest
import com.lyecdevelopers.core.model.cohort.ReportType
import com.lyecdevelopers.core.model.cohort.formatReportArray
import com.lyecdevelopers.core.model.encounter.toIndicators
import com.lyecdevelopers.core.model.order.toIndicators
import com.lyecdevelopers.core.model.toAttributes
import com.lyecdevelopers.core.utils.AppLogger
import com.lyecdevelopers.sync.data.sync.EncountersSyncWorker
import com.lyecdevelopers.sync.data.sync.PatientsSyncWorker
import com.lyecdevelopers.sync.domain.usecase.SyncUseCase
import com.lyecdevelopers.sync.presentation.event.SyncEvent
import com.lyecdevelopers.sync.presentation.state.SyncUiState
import dagger.hilt.android.lifecycle.HiltViewModel
import kotlinx.coroutines.async
import kotlinx.coroutines.awaitAll
import kotlinx.coroutines.flow.MutableStateFlow
import kotlinx.coroutines.flow.StateFlow
import kotlinx.coroutines.flow.asStateFlow
import kotlinx.coroutines.flow.firstOrNull
import kotlinx.coroutines.flow.update
import kotlinx.coroutines.launch
import kotlinx.coroutines.withContext
import javax.inject.Inject


@HiltViewModel
class SyncViewModel @Inject constructor(
    private val syncUseCase: SyncUseCase,
    private val schedulerProvider: SchedulerProvider,
    private val preferenceManager: PreferenceManager,
    private val context: Application,
    private val syncManager: SyncManager,
) : BaseViewModel() {

    private val _uiState = MutableStateFlow(SyncUiState())
    val uiState: StateFlow<SyncUiState> = _uiState.asStateFlow()


    init {
        loadForms()
        loadCohorts()
        loadOrderTypes()
        loadEncounterTypes()
        loadPatientIndentifiers()
        loadPersonAttributeTypes()
        restoreSelectedForms()
        updateFormCount()
        updatePatientCount()
        updateEncounterCount()
        restoreAutoSyncSettings()
        updateSyncedPatientsCount()
        updateSyncedEncounterCount()
    }

    fun onEvent(event: SyncEvent) {
        when (event) {
            is SyncEvent.FilterForms -> filterForms(event.query)
            is SyncEvent.ToggleFormSelection -> toggleFormSelection(event.uuid)
            SyncEvent.ClearSelection -> clearSelection()
            SyncEvent.DownloadForms -> onDownloadClick()

            is SyncEvent.SelectedCohortChanged -> updateUi { copy(selectedCohort = event.cohort) }
            is SyncEvent.IndicatorSelected -> onIndicatorSelected(event.indicator)
            SyncEvent.ApplyFilters -> onApplyFilters()

            is SyncEvent.ToggleHighlightAvailable -> toggleHighlightAvailable(event.item)
            is SyncEvent.ToggleHighlightSelected -> toggleHighlightSelected(event.item)
            SyncEvent.MoveRight -> moveRight()
            SyncEvent.MoveLeft -> moveLeft()
            is SyncEvent.UpdateLastSyncTime -> {
                _uiState.update { it.copy(lastSyncTime = event.time) }
            }

            is SyncEvent.UpdateLastSyncStatus -> {
                _uiState.update { it.copy(lastSyncStatus = event.status) }
            }

            is SyncEvent.UpdateLastSyncBy -> {
                _uiState.update { it.copy(lastSyncBy = event.user) }
            }

            is SyncEvent.UpdateLastSyncError -> {
                _uiState.update { it.copy(lastSyncError = event.error) }
            }

            is SyncEvent.ToggleAutoSync -> handleToggleAutoSync(event.enabled)

            SyncEvent.SyncNow -> syncManager.syncNow(
                workers = listOf(
                    PatientsSyncWorker::class, EncountersSyncWorker::class
                )
            )
        }

    }

    private fun loadForms() {
        viewModelScope.launch(schedulerProvider.io) {
            syncUseCase.loadForms().collect { result ->
                updateUi { copy(isLoading = true) }
                handleResult(
                    result = result, onSuccess = { forms ->
                        updateUi {
                            copy(
                                isLoading = false,
                                formItems = forms,
                                selectedFormIds = emptySet(),
                                searchQuery = ""
                            )
                        }
                    }, errorMessage = (result as? Result.Error)?.message
                )
                updateUi { copy(isLoading = false) }

            }
        }
    }

    private fun filterForms(query: String) {
        updateUi { copy(searchQuery = query) }
        viewModelScope.launch(schedulerProvider.io) {
            syncUseCase.filterForms(query).collect { result ->
                updateUi { copy(isLoading = true) }
                handleResult(
                    result = result, onSuccess = { forms ->
                        updateUi {
                            copy(formItems = forms, selectedFormIds = emptySet())
                        }
                    }, errorMessage = (result as? Result.Error)?.message
                )
                updateUi { copy(isLoading = false) }

            }
        }
    }

    private fun toggleFormSelection(uuid: String) {
        val newIds = uiState.value.selectedFormIds.toMutableSet().apply {
            if (!add(uuid)) remove(uuid)
        }
        updateUi { copy(selectedFormIds = newIds) }

        viewModelScope.launch {
            preferenceManager.saveSelectedForms(context, newIds)
        }
    }
    private fun clearSelection() {
        updateUi { copy(selectedFormIds = emptySet()) }
    }

    private fun onDownloadClick() {
        val selectedForms = getSelectedForms()
        if (selectedForms.isEmpty()) {
            return
        }

        viewModelScope.launch(schedulerProvider.io) {
            updateUi { copy(isLoading = true) }

            val loadedForms = selectedForms.map { form ->
                async {
                    syncUseCase.loadFormByUuid(form.uuid)
                        .firstOrNull { it is Result.Success } as? Result.Success
                }
            }.awaitAll().mapNotNull { it?.data }

            if (loadedForms.isEmpty()) {
                updateUi { copy(isLoading = false) }
                return@launch
            }

            syncUseCase.saveFormsLocally(loadedForms).collect { saveResult ->
                withContext(schedulerProvider.main) {
                    handleResult(
                        result = saveResult, onSuccess = {
                            clearSelection()
                        }, successMessage = "Successfully downloaded selected forms", onError = {
                            updateUi { copy(isLoading = false) }
                        },
                        errorMessage = (saveResult as? Result.Error)?.message
                    )
                    updateUi { copy(isLoading = false) }
                }
            }
        }

    }

    private fun getSelectedForms() =
        uiState.value.formItems.filter { uiState.value.selectedFormIds.contains(it.uuid) }

    private fun loadCohorts() {
        viewModelScope.launch(schedulerProvider.io) {
            syncUseCase.getCohorts().collect { result ->
                handleResult(
                    result = result, onSuccess = { cohorts ->
                        updateUi { copy(cohorts = cohorts) }
                    }, errorMessage = (result as? Result.Error)?.message
                )
            }
        }
    }
    private fun loadEncounterTypes() {
        viewModelScope.launch(schedulerProvider.io) {
            syncUseCase.getEncounterTypes().collect { result ->
                handleResult(
                    result = result, onSuccess = { encounterTypes ->
                        updateUi { copy(encounterTypes = encounterTypes.toIndicators()) }
                    }, errorMessage = (result as? Result.Error)?.message
                )
            }
        }
    }

    private fun loadOrderTypes() {
        viewModelScope.launch(schedulerProvider.io) {
            syncUseCase.getOrderTypes().collect { result ->
                handleResult(
                    result = result, onSuccess = { orderTypes ->
                        updateUi { copy(orderTypes = orderTypes.toIndicators()) }
                    }, errorMessage = (result as? Result.Error)?.message
                )
            }
        }
    }

    private fun loadPatientIndentifiers() {
        viewModelScope.launch(schedulerProvider.io) {
            syncUseCase.getIdentifiers().collect { result ->
                handleResult(
                    result = result, onSuccess = { identifiers ->
                        updateUi { copy(identifiers = identifiers.toAttributes()) }
                    }, errorMessage = (result as? Result.Error)?.message
                )
            }
        }
    }

    private fun loadPersonAttributeTypes() {
        viewModelScope.launch(schedulerProvider.io) {
            syncUseCase.getPersonAttributeTypes().collect { result ->
                handleResult(
                    result = result, onSuccess = { personAttributeTypes ->
                        updateUi { copy(personAttributeTypes = personAttributeTypes.toAttributes()) }
                    }, errorMessage = (result as? Result.Error)?.message
                )
            }

        }
    }

    private fun onIndicatorSelected(indicator: Indicator) {
        updateUi {
            when (indicator.id) {
                "IDN" -> copy(
                    selectedIndicator = indicator,
                    availableParameters = identifiers,
                    highlightedAvailable = emptyList(),
                    highlightedSelected = emptyList()
                )

                "PAT" -> copy(
                    selectedIndicator = indicator,
                    availableParameters = personAttributeTypes,
                    highlightedAvailable = emptyList(),
                    highlightedSelected = emptyList()
                )

                else -> copy(
                    selectedIndicator = indicator,
                    availableParameters = indicator.attributes,
                    highlightedAvailable = emptyList(),
                    highlightedSelected = emptyList()
                )
            }
        }
    }

    fun onApplyFilters() {
        viewModelScope.launch(schedulerProvider.io) {
            val error = validateFilters()
            if (error != null) {
                AppLogger.e("Validation failed: $error")
                updateUi { copy(error = error) }
                return@launch
            }

            val indicator = uiState.value.selectedIndicator
            val cohort = uiState.value.selectedCohort


            if (indicator == null || cohort == null) {
                AppLogger.e("Missing indicator or cohort")
                updateUi { copy(error = "Missing indicator or cohort") }
                return@launch
            }

            val reportRequest = buildReportRequest(cohort)
            val payload = buildDataDefinitionPayload(reportRequest)


            syncUseCase.createDataDefinition(payload).collect { result ->
                withContext(schedulerProvider.main) {
                    _uiState.value = _uiState.value.copy(isLoading = true)
                    handleResult(
                        result = result,
                        onSuccess = { data ->
                            _uiState.value = _uiState.value.copy(isLoading = false)
                        },
                        onError = {
                            _uiState.value =
                                _uiState.value.copy(
                                    error = "Error occurred ${(result as? Result.Error)?.message}",
                                    isLoading = false
                                )
                        },
                        successMessage = "Successfully created data definition",
                        errorMessage = (result as? Result.Error)?.message
                    )
                }
            }
        }
    }


    private fun toggleHighlightAvailable(item: Attribute) {
        val new = uiState.value.highlightedAvailable.toMutableSet().apply {
            if (!add(item)) remove(item)
        }.toList()
        updateUi { copy(highlightedAvailable = new) }
    }

    private fun toggleHighlightSelected(item: Attribute) {
        val new = uiState.value.highlightedSelected.toMutableSet().apply {
            if (!add(item)) remove(item)
        }.toList()
        updateUi { copy(highlightedSelected = new) }
    }

    private fun moveRight() {
        val items = uiState.value.highlightedAvailable
        val remaining = uiState.value.availableParameters - items.toSet()
        updateUi {
            copy(
                availableParameters = remaining,
                selectedParameters = (selectedParameters + items).distinctBy { it.id },
                highlightedAvailable = emptyList()
            )
        }
    }

    private fun moveLeft() {
        val items = uiState.value.highlightedSelected
        val updated = (uiState.value.availableParameters + items).distinctBy { it.id }
        updateUi {
            copy(
                selectedParameters = selectedParameters - items.toSet(),
                availableParameters = updated,
                highlightedSelected = emptyList()
            )
        }
    }

    private fun restoreSelectedForms() {
        viewModelScope.launch {
            val ids = preferenceManager.loadSelectedForms(context)
            updateUi { copy(selectedFormIds = ids) }
        }
    }

    private fun updateFormCount() {
        viewModelScope.launch(schedulerProvider.io) {
            syncUseCase.getFormCount().collect { result ->
                withContext(schedulerProvider.main) {
                    handleResult(
                        result = result, onSuccess = { formCount ->
                            updateUi { copy(formCount = formCount) }
                        }, errorMessage = (result as? Result.Error)?.message
                    )
                }

            }
        }
    }

    private fun updatePatientCount() {
        viewModelScope.launch(schedulerProvider.io) {
            syncUseCase.getPatientCount().collect { result ->
                withContext(schedulerProvider.main) {
                    handleResult(
                        result = result, onSuccess = { patientCount ->
                            updateUi { copy(patientCount = patientCount) }
                        }, errorMessage = (result as? Result.Error)?.message
                    )

                }
            }
        }
    }
    private fun updateEncounterCount() {
        viewModelScope.launch(schedulerProvider.io) {
            syncUseCase.getEncounterCount().collect { result ->
                withContext(schedulerProvider.main) {
                    handleResult(
                        result = result, onSuccess = { encounterCount ->
                            updateUi { copy(encounterCount = encounterCount) }
                        }, errorMessage = (result as? Result.Error)?.message
                    )

                }
            }
        }
    }
    private fun updateSyncedEncounterCount() {
        viewModelScope.launch(schedulerProvider.io) {
            syncUseCase.getSyncedEncounterCount().collect { result ->
                withContext(schedulerProvider.main) {
                    handleResult(
                        result = result, onSuccess = { syncedEncounterCount ->
                            updateUi { copy(syncedEncounterCount = syncedEncounterCount) }
                        }, errorMessage = (result as? Result.Error)?.message
                    )
                }
            }
        }
    }

    private fun updateSyncedPatientsCount() {
        viewModelScope.launch(schedulerProvider.io) {
            syncUseCase.getSyncedPatientsCount().collect { result ->
                withContext(schedulerProvider.main) {
                    handleResult(
                        result = result, onSuccess = { syncedPatientCount ->
                            updateUi { copy(syncedPatientCount = syncedPatientCount) }
                        }, errorMessage = (result as? Result.Error)?.message
                    )
                }
            }
        }
    }
    private fun buildReportRequest(cohort: Cohort) =


        ReportRequest(
            uuid = cohort.uuid, startDate = "", endDate = "",
            type = "Cohort",
            reportCategory = ReportCategoryWrapper(ReportCategory.FACILITY, RenderType.JSON),
            reportIndicators = uiState.value.selectedParameters,
            reportType = ReportType.DYNAMIC,
            reportingCohort = CQIReportingCohort.PATIENTS_WITH_ENCOUNTERS
        )
    private fun buildDataDefinitionPayload(
        reportRequest: ReportRequest,
    ) = DataDefinition(
        cohort = CohortResponse(
            type = reportRequest.type,
            clazz = "",
            uuid = reportRequest.uuid,
            name = "",
            description = "",
            parameters = listOf(
                Parameters(startdate = reportRequest.startDate, enddate = reportRequest.endDate)
            )
        ), columns = formatReportArray(reportRequest.reportIndicators)
    )

    private fun validateFilters(): String? = when {
        uiState.value.selectedIndicator == null -> "Please select an indicator"
        uiState.value.selectedCohort == null -> "Please select a cohort"
        else -> null
    }

    private fun updateUi(reducer: SyncUiState.() -> SyncUiState) {
        _uiState.update { it.reducer() }
    }

    private fun restoreAutoSyncSettings() {
        viewModelScope.launch {
            val enabled = preferenceManager.loadAutoSyncEnabled()
            val interval = preferenceManager.loadAutoSyncInterval()
            updateUi { copy(autoSyncEnabled = enabled, autoSyncInterval = interval) }
        }
    }
    private fun handleToggleAutoSync(enabled: Boolean) {
        updateUi { copy(autoSyncEnabled = enabled) }

        viewModelScope.launch {
            preferenceManager.saveAutoSyncEnabled(enabled)

            if (enabled) {
                val interval = preferenceManager.loadAutoSyncInterval()
                val intervalHours = interval

                syncManager.schedulePeriodicSync(
                    workers = listOf(
                        PatientsSyncWorker::class, EncountersSyncWorker::class
                    ), intervalHours = intervalHours.toLong()
                )
            } else {
                syncManager.cancelPeriodicSync(
                    workers = listOf(
                        PatientsSyncWorker::class, EncountersSyncWorker::class
                    )
                )
            }
        }
    }
}




