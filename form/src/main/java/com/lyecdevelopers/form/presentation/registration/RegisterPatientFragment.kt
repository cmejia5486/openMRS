package com.lyecdevelopers.form.presentation.registration

import android.os.Bundle
import android.view.LayoutInflater
import android.view.View
import android.view.ViewGroup
import androidx.core.os.bundleOf
import androidx.fragment.app.Fragment
import androidx.fragment.app.commitNow
import androidx.lifecycle.lifecycleScope
import ca.uhn.fhir.context.FhirContext
import com.google.android.fhir.datacapture.QuestionnaireFragment
import com.lyecdevelopers.form.R
import dagger.hilt.android.AndroidEntryPoint
import kotlinx.coroutines.launch


@AndroidEntryPoint
class RegisterPatientFragment : Fragment() {

    override fun onCreateView(
        inflater: LayoutInflater,
        container: ViewGroup?,
        savedInstanceState: Bundle?,
    ): View {
        // Inflate the container layout that holds the nested QuestionnaireFragment
        return inflater.inflate(R.layout.fragment_questionnaire_container, container, false)
    }

    override fun onViewCreated(view: View, savedInstanceState: Bundle?) {
        super.onViewCreated(view, savedInstanceState)

        val questionnaireJson = requireArguments().getString(ARG_QUESTIONNAIRE_JSON)
            ?: error("Missing questionnaire JSON in RegisterPatientFragment arguments")

        val questionnaireFragment = QuestionnaireFragment.builder()
            .setQuestionnaire(questionnaireJson).setShowCancelButton(true).setShowSubmitButton(true)
            .showOptionalText(true).showRequiredText(false)
            .setSubmitButtonText(getString(com.google.android.fhir.datacapture.R.string.submit_questionnaire))
            .build()

        // Replace any existing instance
        childFragmentManager.commitNow(allowStateLoss = true) {
            setReorderingAllowed(true)
            replace(
                R.id.fragment_container_view, questionnaireFragment, TAG
            )
        }

        // Submit handler
        childFragmentManager.setFragmentResultListener(
            QuestionnaireFragment.SUBMIT_REQUEST_KEY, viewLifecycleOwner
        ) { _, _ ->
            viewLifecycleOwner.lifecycleScope.launch {
                handleSubmit()
            }
        }


        // Cancel handler
        childFragmentManager.setFragmentResultListener(
            QuestionnaireFragment.CANCEL_REQUEST_KEY, viewLifecycleOwner
        ) { _, _ ->
            handleCancel()
        }
    }

    /**
     * Extracts QuestionnaireResponse from nested QuestionnaireFragment
     * and emits it as a result to the parent (Compose).
     */
    private suspend fun handleSubmit() {
        val nestedFragment = childFragmentManager.findFragmentByTag(TAG)
        if (nestedFragment is QuestionnaireFragment) {
            val questionnaireResponse = nestedFragment.getQuestionnaireResponse()

            // Serialize QuestionnaireResponse to JSON
            val responseJson =
                FhirContext.forR4().newJsonParser().encodeResourceToString(questionnaireResponse)

            // Send to Compose parent via FragmentResult
            parentFragmentManager.setFragmentResult(
                SUBMIT_RESULT_KEY, bundleOf(RESPONSE_BUNDLE_KEY to responseJson)
            )
        }
    }

    private fun handleCancel() {
        parentFragmentManager.setFragmentResult(
            CANCEL_RESULT_KEY, bundleOf(CANCEL_BUNDLE_KEY to true)
        )
    }


    companion object {
        const val TAG = "RegisterPatientFragment"

        // Argument keys (ensure they're unique!)
        const val ARG_QUESTIONNAIRE_JSON = "questionnaire-json"
        const val ARG_PREFILLED_ANSWERS = "prefilled-answers"

        // Result keys
        const val SUBMIT_RESULT_KEY = "submit-questionnaire-response"
        const val RESPONSE_BUNDLE_KEY = "questionnaire-response-json"

        // cancel
        const val CANCEL_RESULT_KEY = "cancel-questionnaire"
        const val CANCEL_BUNDLE_KEY = "cancelled"

    }
}







