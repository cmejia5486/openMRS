package com.lyecdevelopers.form.presentation.questionnaire

import androidx.compose.foundation.layout.Box
import androidx.compose.foundation.layout.fillMaxSize
import androidx.compose.foundation.layout.padding
import androidx.compose.material3.Scaffold
import androidx.compose.runtime.Composable
import androidx.compose.runtime.DisposableEffect
import androidx.compose.runtime.LaunchedEffect
import androidx.compose.runtime.collectAsState
import androidx.compose.runtime.getValue
import androidx.compose.runtime.mutableStateOf
import androidx.compose.runtime.remember
import androidx.compose.runtime.rememberUpdatedState
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
import com.lyecdevelopers.form.presentation.questionnaire.event.QuestionnaireEvent

@Composable
fun QuestionnaireScreen(
    navController: NavController,
    fragmentManager: FragmentManager = LocalContext.current.let { it as? FragmentActivity }?.supportFragmentManager
        ?: throw IllegalStateException("Not a FragmentActivity"),
    formId: String,
    patientId: String,
) {
    val viewModel: QuestionnaireViewModel = hiltViewModel()
    val state by viewModel.state.collectAsState()

    val currentState by rememberUpdatedState(state)
    val lifecycleOwner = LocalLifecycleOwner.current

    var isLoading by remember { mutableStateOf(false) }


    // Prevent re-triggering when recomposing
    LaunchedEffect(key1 = formId) {
        viewModel.loadQuestionnaireByUuid(formId)
    }
    LaunchedEffect(state.isLoading) {
        isLoading = state.isLoading
    }


    // Handle result from QuestionnaireFragment
    DisposableEffect(fragmentManager, lifecycleOwner) {
        val submitListener = FragmentResultListener { _, bundle ->
            bundle.getString(FormQuestionnaireFragment.RESPONSE_BUNDLE_KEY)?.let { responseJson ->
                viewModel.onEvent(QuestionnaireEvent.SubmitWithResponse(responseJson))
            }
        }

        val cancelListener = FragmentResultListener { _, bundle ->
            if (bundle.getBoolean(FormQuestionnaireFragment.CANCEL_BUNDLE_KEY, false)) {
                viewModel.onEvent(QuestionnaireEvent.Reset)
            }
        }

        fragmentManager.setFragmentResultListener(
            FormQuestionnaireFragment.SUBMIT_RESULT_KEY, lifecycleOwner, submitListener
        )
        fragmentManager.setFragmentResultListener(
            FormQuestionnaireFragment.CANCEL_RESULT_KEY, lifecycleOwner, cancelListener
        )

        onDispose {
            fragmentManager.clearFragmentResultListener(FormQuestionnaireFragment.SUBMIT_RESULT_KEY)
            fragmentManager.clearFragmentResultListener(FormQuestionnaireFragment.CANCEL_RESULT_KEY)
        }
    }


    BaseScreen(
        uiEventFlow = viewModel.uiEvent,
        navController = navController,
        showLoading = { loading -> isLoading = loading },
        isLoading = isLoading,
    ) {
        Scaffold { paddingValues ->
            Box(
                modifier = Modifier
                    .padding(paddingValues)
                    .fillMaxSize()
            ) {
                currentState.questionnaireJson?.let { json ->
                    val fragment = FormQuestionnaireFragment().apply {
                        arguments = bundleOf(
                            FormQuestionnaireFragment.ARG_QUESTIONNAIRE_JSON to json,
                            FormQuestionnaireFragment.ARG_PREFILLED_ANSWERS to currentState.answers
                        )
                    }
                    FragmentContainer(
                        modifier = Modifier.fillMaxSize(),
                        fragmentManager = fragmentManager,
                        fragment = fragment,
                        tag = FormQuestionnaireFragment.TAG
                    )
                }
            }
        }

    }


}



