package com.lyecdevelopers.form.presentation.registration

import androidx.compose.foundation.layout.Box
import androidx.compose.foundation.layout.fillMaxSize
import androidx.compose.foundation.layout.padding
import androidx.compose.material3.ExperimentalMaterial3Api
import androidx.compose.material3.Scaffold
import androidx.compose.runtime.Composable
import androidx.compose.runtime.DisposableEffect
import androidx.compose.runtime.LaunchedEffect
import androidx.compose.runtime.collectAsState
import androidx.compose.runtime.getValue
import androidx.compose.runtime.mutableStateOf
import androidx.compose.runtime.remember
import androidx.compose.runtime.setValue
import androidx.compose.ui.Modifier
import androidx.compose.ui.platform.LocalContext
import androidx.core.os.bundleOf
import androidx.fragment.app.FragmentActivity
import androidx.fragment.app.FragmentManager
import androidx.fragment.app.FragmentResultListener
import androidx.hilt.navigation.compose.hiltViewModel
import androidx.lifecycle.compose.LocalLifecycleOwner
import androidx.navigation.NavController
import com.lyecdevelopers.core.ui.components.BaseScreen
import com.lyecdevelopers.core.ui.components.FragmentContainer
import com.lyecdevelopers.form.presentation.registration.event.PatientRegistrationEvent
import org.hl7.fhir.r4.model.Patient


@OptIn(ExperimentalMaterial3Api::class)
@Composable
fun RegisterPatientScreen(
    navController: NavController,
    fragmentManager: FragmentManager = LocalContext.current.let {
        (it as? FragmentActivity)?.supportFragmentManager
            ?: throw IllegalStateException("Not a FragmentActivity")
    },
    patient: Patient? = null, // Add this if you want to support edit mode
) {
    val viewModel: RegisterPatientViewModel = hiltViewModel()
    val uiState by viewModel.state.collectAsState()
    var isLoading by remember { mutableStateOf(false) }
    val lifecycleOwner = LocalLifecycleOwner.current

    // Load form: either for new registration or edit
    LaunchedEffect(patient?.id) {
        val event = patient?.let { PatientRegistrationEvent.LoadForEdit(it) }
            ?: PatientRegistrationEvent.Load
        viewModel.onEvent(event)

    }

    LaunchedEffect(uiState.isLoading) {
        isLoading = uiState.isLoading
    }


    // Handle result from QuestionnaireFragment
    DisposableEffect(fragmentManager, lifecycleOwner) {
        val submitListener = FragmentResultListener { _, bundle ->
            bundle.getString(RegisterPatientFragment.RESPONSE_BUNDLE_KEY)?.let { responseJson ->
                viewModel.onEvent(PatientRegistrationEvent.SubmitWithResponse(responseJson))
            }
        }

        val cancelListener = FragmentResultListener { _, bundle ->
            if (bundle.getBoolean(RegisterPatientFragment.CANCEL_BUNDLE_KEY, false)) {
                viewModel.onEvent(PatientRegistrationEvent.Reset)
                // No navController.popBackStack() here — BaseScreen will handle via UiEvent
            }
        }

        fragmentManager.setFragmentResultListener(
            RegisterPatientFragment.SUBMIT_RESULT_KEY, lifecycleOwner, submitListener
        )
        fragmentManager.setFragmentResultListener(
            RegisterPatientFragment.CANCEL_RESULT_KEY, lifecycleOwner, cancelListener
        )

        onDispose {
            fragmentManager.clearFragmentResultListener(RegisterPatientFragment.SUBMIT_RESULT_KEY)
            fragmentManager.clearFragmentResultListener(RegisterPatientFragment.CANCEL_RESULT_KEY)
        }
    }

    BaseScreen(
        uiEventFlow = viewModel.uiEvent,
        showLoading = { loading -> isLoading = loading },
        content = {
            Scaffold { padding ->
                Box(
                    modifier = Modifier
                        .fillMaxSize()
                        .padding(padding)
                ) {
                    uiState.questionnaireJson?.let { json ->
                        val fragment = RegisterPatientFragment().apply {
                            arguments = bundleOf(
                                RegisterPatientFragment.ARG_QUESTIONNAIRE_JSON to json,
                                RegisterPatientFragment.ARG_PREFILLED_ANSWERS to uiState.answers
                            )
                        }

                        FragmentContainer(
                            modifier = Modifier.fillMaxSize(),
                            fragmentManager = fragmentManager,
                            fragment = fragment,
                            tag = RegisterPatientFragment.TAG
                        )
                    }
                }
            }
        }, navController = navController, isLoading = isLoading
    )
}















