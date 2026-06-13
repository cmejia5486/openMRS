package com.chartlite.app

import androidx.compose.ui.test.*
import androidx.compose.ui.test.junit4.createComposeRule
import androidx.test.ext.junit.runners.AndroidJUnit4
import org.junit.Rule
import org.junit.Test
import org.junit.runner.RunWith

/**
 * Example instrumentation test for LoginScreen.
 *
 * STATUS: This is a template/starting point. Full UI test coverage is a separate initiative.
 *
 * KNOWN GAPS (P2-15):
 * - No instrumentation tests exist for any screen beyond this template
 * - Critical flows needing tests: login, patient registration, encounter recording,
 *   RBAC enforcement, first-admin setup, facility switching
 * - Recommended approach: one test class per screen, using Compose test APIs
 * - Consider Hilt test modules for dependency injection in tests
 *
 * To run: ./gradlew connectedDebugAndroidTest
 */
@RunWith(AndroidJUnit4::class)
class LoginScreenTest {

    @get:Rule
    val composeTestRule = createComposeRule()

    @Test
    fun loginScreen_showsAppBranding() {
        composeTestRule.setContent {
            com.chartlite.app.ui.screens.LoginScreen(
                onLoginSuccess = {}
            )
        }

        // Verify branding elements are visible
        composeTestRule.onNodeWithText("ChartLite").assertIsDisplayed()
        composeTestRule.onNodeWithText("Sign in to continue").assertIsDisplayed()
    }

    @Test
    fun loginScreen_showsJoinFacilityButton() {
        composeTestRule.setContent {
            com.chartlite.app.ui.screens.LoginScreen(
                onLoginSuccess = {}
            )
        }

        // Join facility button should be available
        composeTestRule.onNodeWithText("Join Facility").assertIsDisplayed()
    }
}
