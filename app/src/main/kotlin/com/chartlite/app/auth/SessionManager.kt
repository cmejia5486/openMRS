package com.chartlite.app.auth

import com.chartlite.app.database.dao.AuditLogDao
import com.chartlite.app.database.dao.UserDao
import com.chartlite.app.database.entity.AuditLogEntity
import java.util.UUID

/**
 * Manages the current user session, auto-lock timing, and login attempts.
 *
 * Session state is persisted via [AuthConfig].
 * The auto-lock timer tracks when the app was last active — if the gap exceeds
 * [AuthConfig.autoLockMinutes], the session is locked and the user must re-enter their PIN.
 *
 * All auth events (login, logout, failed auth, lockout) are logged to the audit trail
 * via [AuditLogDao] for compliance and security monitoring.
 */
class SessionManager(
    private val appConfig: AuthConfig,
    private val userDao: UserDao,
    private val auditLogDao: AuditLogDao? = null
) {
    private data class LockoutState(
        var failedAttempts: Int = 0,
        var lockoutUntil: Long = 0L
    )

    private data class LockoutEvent(
        val triggered: Boolean,
        val attempts: Int
    )

    /** Currently active session, or null if no user is logged in. */
    @Volatile var currentSession: UserSession? = null
        private set

    /** Timestamp of last user interaction — used for auto-lock. Persisted to survive process death. */
    @Volatile private var lastActiveAt: Long = appConfig.lastActiveAt

    /** Lock for atomic updates to lockout state. */
    private val authLock = Any()

    /** Per-principal failed-attempt tracking (user/facility scoped). Persisted via AuthConfig. */
    private val lockoutStates = mutableMapOf<String, LockoutState>()
    @Volatile private var lastLockoutScopeKey: String? = null

    companion object {
        /** Maximum failed attempts before temporary lockout. */
        const val MAX_FAILED_ATTEMPTS = 5

        /** Lockout duration in milliseconds (2 minutes). */
        const val LOCKOUT_DURATION_MS = 2 * 60 * 1000L
    }

    init {
        // Restore persisted lockout states from AuthConfig (survives process death).
        restoreLockoutStates()

        // Migrate legacy global state into a scope-limited bucket, then clear global counters.
        val legacyAttempts = appConfig.failedAttempts
        val legacyUntil = appConfig.lockoutUntil
        if (legacyAttempts > 0 || legacyUntil > System.currentTimeMillis()) {
            val existing = lockoutStates["legacy"]
            if (existing == null || legacyUntil > existing.lockoutUntil) {
                lockoutStates["legacy"] = LockoutState(
                    failedAttempts = legacyAttempts,
                    lockoutUntil = legacyUntil
                )
                lastLockoutScopeKey = "legacy"
            }
            // Clear legacy fields after migration
            appConfig.failedAttempts = 0
            appConfig.lockoutUntil = 0L
        }
        persistLockoutState()
    }

    /**
     * Attempt to log in with username + PIN.
     * Returns [AuthResult] indicating success or failure reason.
     */
    suspend fun login(username: String, pin: String, facilityId: String): AuthResult {
        val trimmedUsername = username.trim().lowercase()
        val principalScope = loginScopeKey(trimmedUsername, facilityId)

        if (isLockedOut(principalScope)) {
            return AuthResult.TooManyAttempts
        }

        val user = userDao.getByUsername(trimmedUsername, facilityId)
            ?: run {
                val result = recordFailedAttempt(principalScope)
                logAudit("FAILED_AUTH", userId = "unknown:$trimmedUsername")
                if (result.triggered) logAudit(
                    "LOCKOUT",
                    userId = "unknown:$trimmedUsername",
                    details = """{"duration_ms":$LOCKOUT_DURATION_MS,"attempts":${result.attempts}}"""
                )
                return AuthResult.Failed("Invalid credentials")
            }

        val userScope = userScopeKey(user.id)
        if (isLockedOut(userScope)) {
            return AuthResult.TooManyAttempts
        }

        if (!user.isActive) {
            logAudit("FAILED_AUTH", userId = user.id, details = """{"reason":"account_disabled"}""")
            return AuthResult.AccountDisabled
        }

        if (!PinHasher.verify(pin, user.pinHash, user.pinSalt)) {
            val result = recordFailedAttempt(userScope)
            logAudit("FAILED_AUTH", userId = user.id)
            if (result.triggered) logAudit(
                "LOCKOUT",
                userId = user.id,
                details = """{"duration_ms":$LOCKOUT_DURATION_MS,"attempts":${result.attempts}}"""
            )
            return AuthResult.Failed("Invalid credentials")
        }

        // Success — clear relevant login lockout scopes.
        clearLockout(principalScope)
        clearLockout(userScope)

        val role = try {
            UserRole.valueOf(user.role)
        } catch (_: IllegalArgumentException) {
            UserRole.REGISTRATION_CLERK // Safe fallback
        }

        val session = UserSession(
            userId = user.id,
            username = user.username,
            displayName = user.displayName,
            role = role,
            facilityId = user.facilityId
        )

        currentSession = session
        val now = System.currentTimeMillis()
        lastActiveAt = now
        appConfig.lastActiveAt = now

        // Persist session in AppConfig
        appConfig.currentUserId = session.userId
        appConfig.sessionStartedAt = session.sessionStartedAt

        logAudit("LOGIN", userId = user.id)
        return AuthResult.Success(session)
    }

    /**
     * Log out the current user — clears session state.
     */
    suspend fun logout() {
        val userId = currentSession?.userId
        currentSession = null
        userId?.let { clearLockout(userScopeKey(it)) }
        appConfig.currentUserId = ""
        appConfig.sessionStartedAt = 0L
        if (userId != null) {
            logAudit("LOGOUT", userId = userId)
        }
    }

    /**
     * Restore session from AppConfig after process restart.
     * Returns true if a valid session was restored.
     */
    suspend fun restoreSession(): Boolean {
        val userId = appConfig.currentUserId
        if (userId.isBlank()) return false

        val user = userDao.getById(userId) ?: return false
        if (!user.isActive) {
            logout()
            return false
        }

        val role = try {
            UserRole.valueOf(user.role)
        } catch (_: IllegalArgumentException) {
            UserRole.REGISTRATION_CLERK
        }

        currentSession = UserSession(
            userId = user.id,
            username = user.username,
            displayName = user.displayName,
            role = role,
            facilityId = user.facilityId,
            sessionStartedAt = appConfig.sessionStartedAt
        )
        // Preserve persisted lastActiveAt so auto-lock survives process death.
        // Do NOT reset to System.currentTimeMillis() — that would bypass auto-lock.
        lastActiveAt = appConfig.lastActiveAt
        return true
    }

    /**
     * Record user activity — resets the auto-lock timer.
     */
    fun touch() {
        val now = System.currentTimeMillis()
        lastActiveAt = now
        appConfig.lastActiveAt = now
    }

    /**
     * Check if the session should be locked due to inactivity.
     * Returns true if the auto-lock threshold has been exceeded.
     */
    fun shouldLock(): Boolean {
        if (currentSession == null) return false
        if (!appConfig.autoLockEnabled) return false
        val elapsed = System.currentTimeMillis() - lastActiveAt
        return elapsed > appConfig.autoLockMinutes.toLong() * 60L * 1000L
    }

    /**
     * Quick re-authenticate (for lock screen) — verifies PIN for the current session user.
     */
    suspend fun reauthenticate(pin: String): Boolean {
        val session = currentSession ?: return false
        val scopeKey = userScopeKey(session.userId)

        if (isLockedOut(scopeKey)) return false

        val user = userDao.getById(session.userId) ?: return false
        if (!user.isActive) {
            logout()
            return false
        }

        if (!PinHasher.verify(pin, user.pinHash, user.pinSalt)) {
            val result = recordFailedAttempt(scopeKey)
            logAudit("FAILED_AUTH", userId = session.userId, details = """{"context":"reauthenticate"}""")
            if (result.triggered) logAudit(
                "LOCKOUT",
                userId = session.userId,
                details = """{"duration_ms":$LOCKOUT_DURATION_MS,"attempts":${result.attempts},"context":"reauthenticate"}"""
            )
            return false
        }

        clearLockout(scopeKey)
        val now = System.currentTimeMillis()
        lastActiveAt = now
        appConfig.lastActiveAt = now
        logAudit("UNLOCK", userId = session.userId)
        return true
    }

    /**
     * Check if the user is currently locked out due to too many failed attempts.
     */
    fun isLockedOut(): Boolean {
        currentSession?.let { session ->
            if (isLockedOut(userScopeKey(session.userId))) return true
        }
        val lastScope = lastLockoutScopeKey ?: return false
        return isLockedOut(lastScope)
    }

    /** Remaining lockout time in seconds, or 0 if not locked out. */
    fun lockoutRemainingSeconds(): Int {
        currentSession?.let { session ->
            val currentUserScope = userScopeKey(session.userId)
            if (isLockedOut(currentUserScope)) {
                return lockoutRemainingSeconds(currentUserScope)
            }
        }
        val lastScope = lastLockoutScopeKey ?: return 0
        return lockoutRemainingSeconds(lastScope)
    }

    private fun isLockedOut(scopeKey: String): Boolean {
        synchronized(authLock) {
            val state = lockoutStates[scopeKey] ?: return false
            if (state.lockoutUntil == 0L) return false
            if (System.currentTimeMillis() >= state.lockoutUntil) {
                lockoutStates.remove(scopeKey)
                if (lastLockoutScopeKey == scopeKey) lastLockoutScopeKey = null
                persistLockoutState()
                return false
            }
            lastLockoutScopeKey = scopeKey
            return true
        }
    }

    private fun lockoutRemainingSeconds(scopeKey: String): Int {
        synchronized(authLock) {
            val state = lockoutStates[scopeKey] ?: return 0
            if (!isLockedOut(scopeKey)) return 0
            return ((state.lockoutUntil - System.currentTimeMillis()) / 1000).toInt().coerceAtLeast(0)
        }
    }

    /**
     * Record a failed auth attempt and trigger lockout if threshold exceeded.
     * @return true if lockout was just triggered (for audit logging)
     */
    private fun recordFailedAttempt(scopeKey: String): LockoutEvent {
        synchronized(authLock) {
            val state = lockoutStates.getOrPut(scopeKey) { LockoutState() }
            state.failedAttempts++
            val triggered = state.failedAttempts >= MAX_FAILED_ATTEMPTS
            if (triggered) {
                state.lockoutUntil = System.currentTimeMillis() + LOCKOUT_DURATION_MS
                lastLockoutScopeKey = scopeKey
            }
            persistLockoutState()
            return LockoutEvent(triggered = triggered, attempts = state.failedAttempts)
        }
    }

    private fun clearLockout(scopeKey: String) {
        synchronized(authLock) {
            lockoutStates.remove(scopeKey)
            if (lastLockoutScopeKey == scopeKey) {
                lastLockoutScopeKey = null
            }
            persistLockoutState()
        }
    }

    private fun loginScopeKey(username: String, facilityId: String): String {
        return "login:${facilityId.trim().uppercase()}:${username.trim().lowercase()}"
    }

    private fun userScopeKey(userId: String): String = "user:${userId.trim()}"

    /**
     * Persist lockout state so it survives process death.
     * Format: "scope\tattempts\tuntil\n" per entry (tab-delimited lines).
     */
    private fun persistLockoutState() {
        val now = System.currentTimeMillis()
        val serialized = lockoutStates.entries
            .filter { it.value.lockoutUntil == 0L || it.value.lockoutUntil > now }
            .joinToString("\n") { (key, state) ->
                "${key}\t${state.failedAttempts}\t${state.lockoutUntil}"
            }
        appConfig.lockoutStatesJson = serialized
    }

    /** Restore persisted lockout states from AuthConfig. */
    private fun restoreLockoutStates() {
        val raw = appConfig.lockoutStatesJson
        if (raw.isBlank()) return
        val now = System.currentTimeMillis()
        raw.split("\n").forEach { line ->
            val parts = line.split("\t")
            if (parts.size == 3) {
                val scope = parts[0]
                val attempts = parts[1].toIntOrNull() ?: return@forEach
                val until = parts[2].toLongOrNull() ?: return@forEach
                // Only restore if lockout hasn't expired, or if there are pending attempts
                if (until > now || attempts > 0) {
                    lockoutStates[scope] = LockoutState(attempts, until)
                    if (until > now) lastLockoutScopeKey = scope
                }
            }
        }
    }

    /** Log an auth event to the audit trail (fire-and-forget). */
    private suspend fun logAudit(action: String, userId: String? = null, details: String? = null) {
        val dao = auditLogDao ?: return
        try {
            dao.insert(AuditLogEntity(
                id = UUID.randomUUID().toString(),
                userId = userId ?: currentSession?.userId ?: "system",
                action = action,
                targetType = "AUTH",
                targetId = null,
                details = details,
                timestamp = System.currentTimeMillis()
            ))
        } catch (_: Exception) {
            // Audit logging must never crash the auth flow
        }
    }
}
