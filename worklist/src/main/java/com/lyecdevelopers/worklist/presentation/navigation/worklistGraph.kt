package com.lyecdevelopers.worklist.presentation.navigation

import androidx.fragment.app.FragmentManager
import androidx.navigation.NavController
import androidx.navigation.NavGraphBuilder
import androidx.navigation.NavType
import androidx.navigation.compose.composable
import androidx.navigation.navArgument
import androidx.navigation.navigation
import com.lyecdevelopers.core.model.BottomNavItem
import com.lyecdevelopers.form.presentation.forms.FormsScreen
import com.lyecdevelopers.form.presentation.questionnaire.QuestionnaireScreen
import com.lyecdevelopers.form.presentation.registration.RegisterPatientScreen
import com.lyecdevelopers.worklist.presentation.patient.PatientDetailsScreen
import com.lyecdevelopers.worklist.presentation.worklist.WorklistScreen

fun NavGraphBuilder.worklistGraph(fragmentManager: FragmentManager, navController: NavController) {
    navigation(
        route = BottomNavItem.Worklist.route, startDestination = "worklist_main"
    ) {
        composable("worklist_main") {

            WorklistScreen(
                onPatientClick = { patient ->
                    navController.navigate("patient_details/${patient.id}")
                },
                onRegisterPatient = {
                    navController.navigate("register_patient")
                },
            )
        }


        // 👇 New route for patient registration
        composable("register_patient") {
            RegisterPatientScreen(fragmentManager = fragmentManager, navController = navController)
        }

        composable(
            "patient_details/{patientId}", arguments = listOf(
                navArgument("patientId") { type = NavType.StringType })
        ) { backStackEntry ->
            val patientId = backStackEntry.arguments?.getString("patientId") ?: return@composable

            PatientDetailsScreen(
                onStartEncounter = { _, _ ->
                    navController.navigate("patient_details/$patientId/forms")
                },
                navController = navController,
            )
        }

        composable("patient_details/{patientId}/forms") { backStackEntry ->
            val patientId = backStackEntry.arguments?.getString("patientId") ?: return@composable

            FormsScreen(
                onFormClick = { form ->
                    navController.navigate("patient_details/$patientId/forms/${form.uuid}")
                },
                patientId = patientId,
            )
        }

        composable(
            "patient_details/{patientId}/forms/{formId}",
            arguments = listOf(
                navArgument("patientId") { type = NavType.StringType },
                navArgument("formId") { type = NavType.StringType })
        ) { it ->
            QuestionnaireScreen(
                navController = navController,
                fragmentManager = fragmentManager,
                formId = it.arguments?.getString("formId")!!,
                patientId = it.arguments?.getString("patientId")!!
            )
        }


    }

}
