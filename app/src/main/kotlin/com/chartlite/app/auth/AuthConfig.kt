package com.chartlite.app.auth

/**
 * Interface for auth-related configuration fields.
 * Extracted from AppConfig to enable testing without EncryptedSharedPreferences.
 */
interface AuthConfig {
    var currentUserId: String
    var sessionStartedAt: Long
    var autoLockEnabled: Boolean
    var autoLockMinutes: Int
    var pinLength: Int
    /** Persisted failed login attempts (survives process restart). */
    var failedAttempts: Int
    /** Persisted lockout-until timestamp (survives process restart). 0 = not locked out. */
    var lockoutUntil: Long

    /** Serialized per-principal lockout map (survives process restart). */
    var lockoutStatesJson: String

    /** Persisted last-active timestamp (survives process death for auto-lock). */
    var lastActiveAt: Long
}
