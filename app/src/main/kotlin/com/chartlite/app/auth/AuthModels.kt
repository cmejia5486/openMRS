package com.chartlite.app.auth

/**
 * User roles in the clinic hierarchy.
 * Each role maps to a set of allowed screens/actions.
 */
enum class UserRole {
    ADMIN,
    DOCTOR,
    NURSE,
    PHARMACIST,
    CHW,                // Community Health Worker
    REGISTRATION_CLERK;

    val displayName: String
        get() = when (this) {
            ADMIN -> "Administrator"
            DOCTOR -> "Doctor"
            NURSE -> "Nurse"
            PHARMACIST -> "Pharmacist"
            CHW -> "Community Health Worker"
            REGISTRATION_CLERK -> "Registration Clerk"
        }

    /** Short description of what this role can do — shown during join and user creation. */
    val description: String
        get() = when (this) {
            ADMIN -> "Full access: users, settings, sync, all clinical"
            DOCTOR -> "Consultations, registration, triage, dashboard"
            NURSE -> "Registration, triage, dashboard"
            PHARMACIST -> "Dispensing, stock management, dashboard"
            CHW -> "Registration, triage (community outreach)"
            REGISTRATION_CLERK -> "Patient registration only"
        }

    /** Can this role access the consultation station? */
    val canConsult: Boolean get() = this == ADMIN || this == DOCTOR

    /** Can this role access the pharmacy station? */
    val canDispense: Boolean get() = this == ADMIN || this == PHARMACIST

    /** Can this role register patients? */
    val canRegister: Boolean get() = this != PHARMACIST

    /** Can this role triage patients? */
    val canTriage: Boolean get() = this == ADMIN || this == DOCTOR || this == NURSE || this == CHW

    /** Can this role manage users? */
    val canManageUsers: Boolean get() = this == ADMIN

    /** Can this role access facility dashboard? */
    val canViewDashboard: Boolean get() = this == ADMIN || this == DOCTOR || this == NURSE || this == PHARMACIST

    /** Can this role access sync? */
    val canSync: Boolean get() = this == ADMIN

    /** Can this role change settings (full access, not just view)? */
    val canEditSettings: Boolean get() = this == ADMIN

    /** Can this role view clinical history (encounters, diagnoses, meds, vitals)? */
    val canViewClinicalHistory: Boolean get() = this != REGISTRATION_CLERK
}

/**
 * Represents an active user session.
 */
data class UserSession(
    val userId: String,
    val username: String,
    val displayName: String,
    val role: UserRole,
    val facilityId: String,
    val sessionStartedAt: Long = System.currentTimeMillis()
)

/**
 * Result of an authentication attempt.
 */
sealed class AuthResult {
    data class Success(val session: UserSession) : AuthResult()
    data class Failed(val reason: String) : AuthResult()
    data object AccountDisabled : AuthResult()
    data object TooManyAttempts : AuthResult()
}
