package com.chartlite.app.ui.navigation

import androidx.compose.animation.*
import androidx.compose.animation.core.tween
import androidx.activity.compose.BackHandler
import androidx.compose.runtime.Composable
import androidx.compose.runtime.LaunchedEffect
import androidx.compose.ui.Modifier
import androidx.compose.ui.platform.LocalContext
import androidx.navigation.NavHostController
import androidx.navigation.NavType
import androidx.navigation.compose.NavHost
import androidx.navigation.compose.composable
import androidx.navigation.compose.currentBackStackEntryAsState
import androidx.navigation.navArgument
import com.chartlite.app.App
import com.chartlite.app.ui.screens.*
import java.net.URLEncoder
import java.net.URLDecoder
import kotlinx.coroutines.CoroutineScope
import kotlinx.coroutines.Dispatchers
import kotlinx.coroutines.launch

sealed class Screen(val route: String) {
    data object Home : Screen("home")
    data object Setup : Screen("setup")
    data object PatientRegistration : Screen("patient_registration?allergies={allergies}&patientId={patientId}") {
        fun createRoute(allergies: String? = null, patientId: String? = null): String {
            val params = mutableListOf<String>()
            allergies?.let { params.add("allergies=${URLEncoder.encode(it, "UTF-8")}") }
            patientId?.let { params.add("patientId=${URLEncoder.encode(it, "UTF-8")}") }
            return if (params.isNotEmpty()) "patient_registration?" + params.joinToString("&")
            else "patient_registration"
        }
    }
    data object PatientSearch : Screen("patient_search")
    data object PatientTimeline : Screen("patient_timeline/{patientId}") {
        fun createRoute(patientId: String) = "patient_timeline/$patientId"
    }
    data object EncounterRecord : Screen("encounter_record/{patientId}?visitId={visitId}&station={station}") {
        fun createRoute(
            patientId: String,
            visitId: String? = null,
            station: String? = null
        ): String {
            var route = "encounter_record/$patientId"
            val params = mutableListOf<String>()
            visitId?.let { params.add("visitId=$it") }
            station?.let { params.add("station=$it") }
            if (params.isNotEmpty()) route += "?" + params.joinToString("&")
            return route
        }
    }
    data object EncounterReview : Screen("encounter_review/{encounterId}") {
        fun createRoute(encounterId: String) = "encounter_review/$encounterId"
    }
    data object ExtractionQueue : Screen("extraction_queue")
    data object QueuedExtractionReview : Screen("queued_extraction_review/{queueId}") {
        fun createRoute(queueId: String) = "queued_extraction_review/$queueId"
    }
    data object SMSDecrypt : Screen("sms_decrypt")
    data object Sync : Screen("sync")
    data object Settings : Screen("settings")
    data object FacilityDashboard : Screen("facility_dashboard")
    data object Pharmacy : Screen("pharmacy/{visitId}") {
        fun createRoute(visitId: String) = "pharmacy/$visitId"
    }
    data object Login : Screen("login")
    data object Lock : Screen("lock")
    data object UserManagement : Screen("user_management")
    data object LabOrders : Screen("lab_orders/{visitId}/{patientId}") {
        fun createRoute(visitId: String, patientId: String) = "lab_orders/$visitId/$patientId"
    }
    data object Appointments : Screen("appointments")
    data object Referrals : Screen("referrals")
    data object StockManagement : Screen("stock_management")
    data object Immunizations : Screen("immunizations/{patientId}") {
        fun createRoute(patientId: String) = "immunizations/$patientId"
    }
    data object FamilyPlanning : Screen("family_planning/{patientId}") {
        fun createRoute(patientId: String) = "family_planning/$patientId"
    }
    data object GrowthChart : Screen("growth_chart/{patientId}") {
        fun createRoute(patientId: String) = "growth_chart/$patientId"
    }
    data object SMSHistory : Screen("sms_history/{patientId}") {
        fun createRoute(patientId: String) = "sms_history/$patientId"
    }
    data object DHIS2Export : Screen("dhis2_export")
    data object ClinicalProtocols : Screen("clinical_protocols?icd10={icd10}") {
        fun createRoute(icd10Code: String? = null) = if (icd10Code != null) "clinical_protocols?icd10=$icd10Code" else "clinical_protocols"
    }
    data object PatientSummary : Screen("patient_summary/{patientId}") {
        fun createRoute(patientId: String) = "patient_summary/$patientId"
    }
    data object AppointmentReminders : Screen("appointment_reminders")
    data object FacilityDirectory : Screen("facility_directory?service={service}&urgency={urgency}") {
        fun createRoute(service: String? = null, urgency: String? = null): String {
            var route = "facility_directory"
            val params = mutableListOf<String>()
            service?.let { params.add("service=${URLEncoder.encode(it, "UTF-8")}") }
            urgency?.let { params.add("urgency=${URLEncoder.encode(it, "UTF-8")}") }
            if (params.isNotEmpty()) route += "?" + params.joinToString("&")
            return route
        }
    }
}

private const val NAV_ANIM_DURATION = 300

private val slideInFromRight = slideInHorizontally(
    animationSpec = tween(NAV_ANIM_DURATION),
    initialOffsetX = { it }
) + fadeIn(animationSpec = tween(NAV_ANIM_DURATION))

private val slideOutToLeft = slideOutHorizontally(
    animationSpec = tween(NAV_ANIM_DURATION),
    targetOffsetX = { -it / 3 }
) + fadeOut(animationSpec = tween(NAV_ANIM_DURATION / 2))

private val slideInFromLeft = slideInHorizontally(
    animationSpec = tween(NAV_ANIM_DURATION),
    initialOffsetX = { -it / 3 }
) + fadeIn(animationSpec = tween(NAV_ANIM_DURATION))

private val slideOutToRight = slideOutHorizontally(
    animationSpec = tween(NAV_ANIM_DURATION),
    targetOffsetX = { it }
) + fadeOut(animationSpec = tween(NAV_ANIM_DURATION / 2))

private fun NavHostController.navigateBackOrMainMenu(isSetupComplete: Boolean) {
    if (popBackStack()) return

    val fallbackRoute = if (isSetupComplete) Screen.Home.route else Screen.Setup.route
    navigate(fallbackRoute) {
        popUpTo(graph.startDestinationId) { inclusive = true }
        launchSingleTop = true
    }
}

@Composable
fun AppNavigation(
    navController: NavHostController,
    isSetupComplete: Boolean,
    modifier: Modifier = Modifier
) {
    val currentBackStackEntry = navController.currentBackStackEntryAsState().value
    val currentRoute = currentBackStackEntry?.destination?.route
    val rootRoute = if (isSetupComplete) Screen.Home.route else Screen.Setup.route
    val navigateBackOrMainMenu = { navController.navigateBackOrMainMenu(isSetupComplete) }

    NavHost(
        navController = navController,
        startDestination = rootRoute,
        enterTransition = { slideInFromRight },
        exitTransition = { slideOutToLeft },
        popEnterTransition = { slideInFromLeft },
        popExitTransition = { slideOutToRight },
        modifier = modifier
    ) {
        composable(
            Screen.Setup.route,
            enterTransition = { fadeIn(tween(NAV_ANIM_DURATION)) },
            exitTransition = { fadeOut(tween(NAV_ANIM_DURATION)) }
        ) {
            SetupScreen(
                onSetupComplete = {
                    navController.navigate(Screen.Home.route) {
                        popUpTo(Screen.Setup.route) { inclusive = true }
                    }
                }
            )
        }

        composable(
            Screen.Home.route,
            enterTransition = { fadeIn(tween(NAV_ANIM_DURATION)) },
            exitTransition = { slideOutToLeft }
        ) {
            HomeScreen(
                onNewPatient = { navController.navigate(Screen.PatientRegistration.createRoute()) },
                onFindPatient = { navController.navigate(Screen.PatientSearch.route) },
                onReadSMS = { navController.navigate(Screen.SMSDecrypt.route) },
                onSync = { navController.navigate(Screen.Sync.route) },
                onSettings = { navController.navigate(Screen.Settings.route) },
                onDashboard = { navController.navigate(Screen.FacilityDashboard.route) },
                onExtractionQueue = { navController.navigate(Screen.ExtractionQueue.route) },
                onAppointments = { navController.navigate(Screen.Appointments.route) },
                onStockManagement = { navController.navigate(Screen.StockManagement.route) },
                onReferrals = { navController.navigate(Screen.Referrals.route) },
                onClinicalProtocols = { navController.navigate(Screen.ClinicalProtocols.createRoute()) },
                onAppointmentReminders = { navController.navigate(Screen.AppointmentReminders.route) },
                onFacilityDirectory = { navController.navigate(Screen.FacilityDirectory.createRoute()) },
                onPatientSelected = { patientId ->
                    navController.navigate(Screen.PatientTimeline.createRoute(patientId))
                },
                onStartTriage = { patientId, visitId ->
                    navController.navigate(Screen.EncounterRecord.createRoute(patientId, visitId, "TRIAGE"))
                },
                onStartConsultation = { patientId, visitId ->
                    navController.navigate(Screen.EncounterRecord.createRoute(patientId, visitId, "CONSULTATION"))
                },
                onStartPharmacy = { visitId ->
                    navController.navigate(Screen.Pharmacy.createRoute(visitId))
                }
            )
        }

        composable(
            route = "patient_registration?allergies={allergies}&patientId={patientId}",
            arguments = listOf(
                navArgument("allergies") { type = NavType.StringType; nullable = true; defaultValue = null },
                navArgument("patientId") { type = NavType.StringType; nullable = true; defaultValue = null }
            )
        ) { backStackEntry ->
            val app = LocalContext.current.applicationContext as App
            if (app.sessionManager.currentSession?.role?.canRegister != true) {
                LaunchedEffect(Unit) { navController.navigateBackOrMainMenu(isSetupComplete) }
                return@composable
            }
            val allergies = backStackEntry.arguments?.getString("allergies")?.takeIf { it != "{null}" && it.isNotBlank() }
                ?.let { URLDecoder.decode(it, "UTF-8") }
            val prefillPatientId = backStackEntry.arguments?.getString("patientId")?.takeIf { it != "{null}" && it.isNotBlank() }
                ?.let { URLDecoder.decode(it, "UTF-8") }
            PatientRegistrationScreen(
                onPatientRegistered = { patientId ->
                    if (app.appConfig.isMultiStation) {
                        navController.navigate(Screen.Home.route) {
                            popUpTo(Screen.Home.route) { inclusive = true }
                        }
                    } else {
                        navController.navigate(Screen.PatientTimeline.createRoute(patientId)) {
                            popUpTo(Screen.Home.route)
                        }
                    }
                },
                onBack = navigateBackOrMainMenu,
                prefillAllergies = allergies,
                prefillPatientId = prefillPatientId
            )
        }

        composable(Screen.PatientSearch.route) {
            val app = LocalContext.current.applicationContext as App
            val currentRole = app.sessionManager.currentSession?.role
            PatientSearchScreen(
                onPatientSelected = { patientId ->
                    if (currentRole?.canViewClinicalHistory != false) {
                        navController.navigate(Screen.PatientTimeline.createRoute(patientId))
                    } else {
                        android.widget.Toast.makeText(
                            app, "Clinical history requires a clinical role", android.widget.Toast.LENGTH_SHORT
                        ).show()
                    }
                },
                onCheckIn = if (app.appConfig.isMultiStation) { patientId ->
                    CoroutineScope(Dispatchers.Main).launch {
                        val existing = app.visitRepository.getTodayVisitForPatient(patientId)
                        if (existing == null) {
                            app.visitRepository.createVisit(
                                patientId = patientId,
                                facilityId = app.appConfig.facilityId,
                                providerId = app.sessionManager.currentSession?.userId ?: app.appConfig.providerId
                            )
                        }
                        navController.navigate(Screen.Home.route) {
                            popUpTo(Screen.Home.route) { inclusive = true }
                        }
                    }
                    Unit
                } else null,
                onBack = navigateBackOrMainMenu
            )
        }

        composable(
            route = Screen.PatientTimeline.route,
            arguments = listOf(navArgument("patientId") { type = NavType.StringType })
        ) { backStackEntry ->
            val patientId = backStackEntry.arguments?.getString("patientId") ?: return@composable
            val app = LocalContext.current.applicationContext as App
            if (app.sessionManager.currentSession?.role?.canViewClinicalHistory == false) {
                LaunchedEffect(Unit) { navController.navigateBackOrMainMenu(isSetupComplete) }
                return@composable
            }
            PatientTimelineScreen(
                patientId = patientId,
                onNewEncounter = {
                    navController.navigate(Screen.EncounterRecord.createRoute(patientId))
                },
                onCheckIn = if (app.appConfig.isMultiStation) { pid ->
                    CoroutineScope(Dispatchers.Main).launch {
                        val existing = app.visitRepository.getTodayVisitForPatient(pid)
                        if (existing == null) {
                            app.visitRepository.createVisit(
                                patientId = pid,
                                facilityId = app.appConfig.facilityId,
                                providerId = app.sessionManager.currentSession?.userId ?: app.appConfig.providerId
                            )
                        }
                        navController.navigate(Screen.Home.route) {
                            popUpTo(Screen.Home.route) { inclusive = true }
                        }
                    }
                    Unit
                } else null,
                onEncounterSelected = { encounterId ->
                    navController.navigate(Screen.EncounterReview.createRoute(encounterId))
                },
                onViewSMSHistory = {
                    navController.navigate(Screen.SMSHistory.createRoute(patientId))
                },
                onBack = navigateBackOrMainMenu
            )
        }

        composable(
            route = "encounter_record/{patientId}?visitId={visitId}&station={station}",
            arguments = listOf(
                navArgument("patientId") { type = NavType.StringType },
                navArgument("visitId") { type = NavType.StringType; nullable = true; defaultValue = null },
                navArgument("station") { type = NavType.StringType; nullable = true; defaultValue = null }
            )
        ) { backStackEntry ->
            val app = LocalContext.current.applicationContext as App
            val patientId = backStackEntry.arguments?.getString("patientId") ?: return@composable
            val visitId = backStackEntry.arguments?.getString("visitId")?.takeIf { it != "{null}" }
            val station = backStackEntry.arguments?.getString("station")?.takeIf { it != "{null}" }
            // Station-aware RBAC: TRIAGE requires canTriage, CONSULTATION requires canConsult
            val role = app.sessionManager.currentSession?.role
            val allowed = when (station?.uppercase()) {
                "TRIAGE" -> role?.canTriage == true
                "CONSULTATION" -> role?.canConsult == true
                else -> role?.canConsult == true || role?.canTriage == true // solo mode
            }
            if (!allowed) {
                LaunchedEffect(Unit) { navController.navigateBackOrMainMenu(isSetupComplete) }
                return@composable
            }
            EncounterRecordScreen(
                patientId = patientId,
                visitId = visitId,
                stationName = station,
                onEncounterSaved = { encounterId ->
                    if (visitId != null) {
                        // Multi-station mode: go back to home
                        navController.navigate(Screen.Home.route) {
                            popUpTo(Screen.Home.route) { inclusive = true }
                        }
                    } else {
                        navController.navigate(Screen.EncounterReview.createRoute(encounterId)) {
                            popUpTo(Screen.PatientTimeline.createRoute(patientId))
                        }
                    }
                },
                onBack = navigateBackOrMainMenu
            )
        }

        composable(
            route = Screen.EncounterReview.route,
            arguments = listOf(navArgument("encounterId") { type = NavType.StringType })
        ) { backStackEntry ->
            val app = LocalContext.current.applicationContext as App
            if (app.sessionManager.currentSession?.role?.canViewClinicalHistory == false) {
                LaunchedEffect(Unit) { navController.navigateBackOrMainMenu(isSetupComplete) }
                return@composable
            }
            val encounterId = backStackEntry.arguments?.getString("encounterId") ?: return@composable
            EncounterReviewScreen(
                encounterId = encounterId,
                onBack = navigateBackOrMainMenu
            )
        }

        composable(Screen.ExtractionQueue.route) {
            val app = LocalContext.current.applicationContext as App
            if (app.sessionManager.currentSession?.role?.canViewClinicalHistory == false) {
                LaunchedEffect(Unit) { navController.navigateBackOrMainMenu(isSetupComplete) }
                return@composable
            }
            ExtractionQueueScreen(
                onBack = navigateBackOrMainMenu,
                onReviewQueueItem = { queueId ->
                    navController.navigate(Screen.QueuedExtractionReview.createRoute(queueId))
                }
            )
        }

        composable(
            route = Screen.QueuedExtractionReview.route,
            arguments = listOf(navArgument("queueId") { type = NavType.StringType })
        ) { backStackEntry ->
            val app = LocalContext.current.applicationContext as App
            if (app.sessionManager.currentSession?.role?.canViewClinicalHistory == false) {
                LaunchedEffect(Unit) { navController.navigateBackOrMainMenu(isSetupComplete) }
                return@composable
            }
            val queueId = backStackEntry.arguments?.getString("queueId") ?: return@composable
            QueuedExtractionReviewScreen(
                queueId = queueId,
                onBack = navigateBackOrMainMenu,
                onSaved = { savedEncounterId, queuedVisitId ->
                    if (queuedVisitId != null) {
                        navController.navigate(Screen.Home.route) {
                            popUpTo(Screen.Home.route) { inclusive = true }
                        }
                    } else {
                        navController.navigate(Screen.EncounterReview.createRoute(savedEncounterId)) {
                            popUpTo(Screen.Home.route)
                        }
                    }
                }
            )
        }

        composable(Screen.SMSDecrypt.route) {
            val app = LocalContext.current.applicationContext as App
            if (app.sessionManager.currentSession?.role?.canViewClinicalHistory == false) {
                LaunchedEffect(Unit) { navController.navigateBackOrMainMenu(isSetupComplete) }
                return@composable
            }
            SMSDecryptScreen(
                onRegisterFromSMS = { patientId, allergies, decodedV4 ->
                    // Store decoded SMS for full history import after patient registration
                    app.pendingSmsImport = decodedV4
                    val allergyParam = allergies.joinToString(",")
                    navController.navigate(
                        Screen.PatientRegistration.createRoute(
                            allergies = allergyParam.ifBlank { null },
                            patientId = patientId
                        )
                    )
                },
                onBack = navigateBackOrMainMenu
            )
        }

        composable(Screen.Sync.route) {
            val app = LocalContext.current.applicationContext as App
            if (app.sessionManager.currentSession?.role?.canSync != true) {
                LaunchedEffect(Unit) { navController.navigateBackOrMainMenu(isSetupComplete) }
                return@composable
            }
            SyncScreen(
                onBack = navigateBackOrMainMenu
            )
        }

        composable(Screen.Settings.route) {
            val app = LocalContext.current.applicationContext as App
            val session = app.sessionManager.currentSession
            // Allow if no auth session (solo mode) or admin role
            if (session != null && session.role.canEditSettings != true) {
                LaunchedEffect(Unit) { navController.navigateBackOrMainMenu(isSetupComplete) }
                return@composable
            }
            SettingsScreen(
                onBack = navigateBackOrMainMenu,
                onUserManagement = { navController.navigate(Screen.UserManagement.route) }
            )
        }

        composable(Screen.FacilityDashboard.route) {
            val app = LocalContext.current.applicationContext as App
            if (app.sessionManager.currentSession?.role?.canViewDashboard != true) {
                LaunchedEffect(Unit) { navController.navigateBackOrMainMenu(isSetupComplete) }
                return@composable
            }
            FacilityDashboardScreen(
                onBack = navigateBackOrMainMenu,
                onDHIS2Export = { navController.navigate(Screen.DHIS2Export.route) },
                onExtractionQueue = { navController.navigate(Screen.ExtractionQueue.route) }
            )
        }

        composable(Screen.DHIS2Export.route) {
            val app = LocalContext.current.applicationContext as App
            if (app.sessionManager.currentSession?.role?.canViewDashboard != true) {
                LaunchedEffect(Unit) { navController.navigateBackOrMainMenu(isSetupComplete) }
                return@composable
            }
            DHIS2ExportScreen(
                onBack = navigateBackOrMainMenu
            )
        }

        composable(
            route = Screen.Pharmacy.route,
            arguments = listOf(navArgument("visitId") { type = NavType.StringType })
        ) { backStackEntry ->
            val app = LocalContext.current.applicationContext as App
            if (app.sessionManager.currentSession?.role?.canDispense != true) {
                LaunchedEffect(Unit) { navController.navigateBackOrMainMenu(isSetupComplete) }
                return@composable
            }
            val visitId = backStackEntry.arguments?.getString("visitId") ?: return@composable
            PharmacyScreen(
                visitId = visitId,
                onComplete = {
                    navController.navigate(Screen.Home.route) {
                        popUpTo(Screen.Home.route) { inclusive = true }
                    }
                },
                onBack = navigateBackOrMainMenu
            )
        }

        composable(Screen.UserManagement.route) {
            val app = LocalContext.current.applicationContext as App
            if (app.sessionManager.currentSession?.role?.canManageUsers != true) {
                LaunchedEffect(Unit) { navController.navigateBackOrMainMenu(isSetupComplete) }
                return@composable
            }
            UserManagementScreen(
                onBack = navigateBackOrMainMenu
            )
        }

        composable(
            route = Screen.LabOrders.route,
            arguments = listOf(
                navArgument("visitId") { type = NavType.StringType },
                navArgument("patientId") { type = NavType.StringType }
            )
        ) { backStackEntry ->
            val app = LocalContext.current.applicationContext as App
            if (app.sessionManager.currentSession?.role?.canConsult != true) {
                LaunchedEffect(Unit) { navController.navigateBackOrMainMenu(isSetupComplete) }
                return@composable
            }
            val visitId = backStackEntry.arguments?.getString("visitId") ?: return@composable
            val patientId = backStackEntry.arguments?.getString("patientId") ?: return@composable
            LabOrderScreen(
                visitId = visitId,
                patientId = patientId,
                onBack = navigateBackOrMainMenu
            )
        }

        composable(Screen.Appointments.route) {
            val app = LocalContext.current.applicationContext as App
            if (app.sessionManager.currentSession?.role?.canTriage != true) {
                LaunchedEffect(Unit) { navController.navigateBackOrMainMenu(isSetupComplete) }
                return@composable
            }
            AppointmentScreen(
                onBack = navigateBackOrMainMenu
            )
        }

        composable(Screen.Referrals.route) {
            val app = LocalContext.current.applicationContext as App
            if (app.sessionManager.currentSession?.role?.canConsult != true) {
                LaunchedEffect(Unit) { navController.navigateBackOrMainMenu(isSetupComplete) }
                return@composable
            }
            ReferralScreen(
                onPatientSelected = { patientId ->
                    navController.navigate(Screen.PatientTimeline.createRoute(patientId))
                },
                onBack = navigateBackOrMainMenu
            )
        }

        composable(Screen.StockManagement.route) {
            val app = LocalContext.current.applicationContext as App
            if (app.sessionManager.currentSession?.role?.canDispense != true) {
                LaunchedEffect(Unit) { navController.navigateBackOrMainMenu(isSetupComplete) }
                return@composable
            }
            StockManagementScreen(
                onBack = navigateBackOrMainMenu
            )
        }

        composable(
            route = Screen.Immunizations.route,
            arguments = listOf(navArgument("patientId") { type = NavType.StringType })
        ) { backStackEntry ->
            val app = LocalContext.current.applicationContext as App
            if (app.sessionManager.currentSession?.role?.canTriage != true) {
                LaunchedEffect(Unit) { navController.navigateBackOrMainMenu(isSetupComplete) }
                return@composable
            }
            val patientId = backStackEntry.arguments?.getString("patientId") ?: return@composable
            ImmunizationScreen(
                patientId = patientId,
                onBack = navigateBackOrMainMenu
            )
        }

        composable(
            route = Screen.FamilyPlanning.route,
            arguments = listOf(navArgument("patientId") { type = NavType.StringType })
        ) { backStackEntry ->
            val app = LocalContext.current.applicationContext as App
            if (app.sessionManager.currentSession?.role?.canConsult != true) {
                LaunchedEffect(Unit) { navController.navigateBackOrMainMenu(isSetupComplete) }
                return@composable
            }
            val patientId = backStackEntry.arguments?.getString("patientId") ?: return@composable
            FamilyPlanningScreen(
                patientId = patientId,
                onBack = navigateBackOrMainMenu
            )
        }

        composable(
            route = Screen.GrowthChart.route,
            arguments = listOf(navArgument("patientId") { type = NavType.StringType })
        ) { backStackEntry ->
            val app = LocalContext.current.applicationContext as App
            if (app.sessionManager.currentSession?.role?.canViewClinicalHistory == false) {
                LaunchedEffect(Unit) { navController.navigateBackOrMainMenu(isSetupComplete) }
                return@composable
            }
            val patientId = backStackEntry.arguments?.getString("patientId") ?: return@composable
            GrowthChartScreen(
                patientId = patientId,
                onBack = navigateBackOrMainMenu
            )
        }

        composable(
            route = Screen.SMSHistory.route,
            arguments = listOf(navArgument("patientId") { type = NavType.StringType })
        ) { backStackEntry ->
            val patientId = backStackEntry.arguments?.getString("patientId") ?: return@composable
            SMSHistoryScreen(
                patientId = patientId,
                onBack = navigateBackOrMainMenu
            )
        }

        composable(
            route = "clinical_protocols?icd10={icd10}",
            arguments = listOf(navArgument("icd10") { type = NavType.StringType; nullable = true; defaultValue = null })
        ) { backStackEntry ->
            val app = LocalContext.current.applicationContext as App
            if (app.sessionManager.currentSession?.role?.canViewClinicalHistory == false) {
                LaunchedEffect(Unit) { navController.navigateBackOrMainMenu(isSetupComplete) }
                return@composable
            }
            val icd10 = backStackEntry.arguments?.getString("icd10")?.takeIf { it != "{null}" }
            ClinicalProtocolScreen(
                preSelectedIcd10 = icd10,
                onBack = navigateBackOrMainMenu
            )
        }

        composable(
            route = Screen.PatientSummary.route,
            arguments = listOf(navArgument("patientId") { type = NavType.StringType })
        ) { backStackEntry ->
            val app = LocalContext.current.applicationContext as App
            if (app.sessionManager.currentSession?.role?.canViewClinicalHistory == false) {
                LaunchedEffect(Unit) { navController.navigateBackOrMainMenu(isSetupComplete) }
                return@composable
            }
            val patientId = backStackEntry.arguments?.getString("patientId") ?: return@composable
            PatientSummaryScreen(
                patientId = patientId,
                onEncounterSelected = { encounterId ->
                    navController.navigate(Screen.EncounterReview.createRoute(encounterId))
                },
                onNewEncounter = {
                    navController.navigate(Screen.EncounterRecord.createRoute(patientId))
                },
                onViewTimeline = {
                    navController.navigate(Screen.PatientTimeline.createRoute(patientId))
                },
                onViewImmunizations = {
                    navController.navigate(Screen.Immunizations.createRoute(patientId))
                },
                onViewGrowthChart = {
                    navController.navigate(Screen.GrowthChart.createRoute(patientId))
                },
                onViewSMSHistory = {
                    navController.navigate(Screen.SMSHistory.createRoute(patientId))
                },
                onBack = navigateBackOrMainMenu
            )
        }

        composable(Screen.AppointmentReminders.route) {
            val app = LocalContext.current.applicationContext as App
            if (app.sessionManager.currentSession?.role?.canTriage != true) {
                LaunchedEffect(Unit) { navController.navigateBackOrMainMenu(isSetupComplete) }
                return@composable
            }
            AppointmentReminderScreen(
                onBack = navigateBackOrMainMenu
            )
        }

        composable(
            route = "facility_directory?service={service}&urgency={urgency}",
            arguments = listOf(
                navArgument("service") { type = NavType.StringType; nullable = true; defaultValue = null },
                navArgument("urgency") { type = NavType.StringType; nullable = true; defaultValue = null }
            )
        ) { backStackEntry ->
            val app = LocalContext.current.applicationContext as App
            if (app.sessionManager.currentSession?.role?.canTriage != true) {
                LaunchedEffect(Unit) { navController.navigateBackOrMainMenu(isSetupComplete) }
                return@composable
            }
            val service = backStackEntry.arguments?.getString("service")?.takeIf { it != "{null}" }
            val urgency = backStackEntry.arguments?.getString("urgency")?.takeIf { it != "{null}" }
            FacilityDirectoryScreen(
                preSelectedService = service,
                urgency = urgency,
                onBack = navigateBackOrMainMenu
            )
        }
    }

    BackHandler(enabled = currentRoute != null && currentRoute != rootRoute) {
        navController.navigateBackOrMainMenu(isSetupComplete)
    }
}
