package com.chartlite.app.auth

import com.chartlite.app.database.dao.AuditLogDao
import com.chartlite.app.database.entity.AuditLogEntity
import java.util.UUID

/**
 * Central audit logging service.
 * Records all significant actions (clinical, auth, settings, sync) for compliance and security.
 *
 * Usage:
 * ```
 * auditLogger.log("CREATE_PATIENT", targetType = "PATIENT", targetId = patientId)
 * auditLogger.log("LOGIN", details = buildDetails("method" to "pin"))
 * ```
 */
class AuditLogger(
    private val auditLogDao: AuditLogDao,
    private val sessionManager: SessionManager
) {

    /**
     * Log an auditable action.
     *
     * @param action Action type (LOGIN, LOGOUT, FAILED_AUTH, CREATE_PATIENT, CREATE_ENCOUNTER, DISPENSE, SETTINGS_CHANGE, SYNC, etc.)
     * @param targetType Optional entity type (PATIENT, ENCOUNTER, VISIT, USER, SETTING)
     * @param targetId Optional entity ID
     * @param details Optional JSON string with extra context — use [buildDetails] for safe construction
     * @param userId Override user ID (e.g., for failed login where no session exists)
     */
    suspend fun log(
        action: String,
        targetType: String? = null,
        targetId: String? = null,
        details: String? = null,
        userId: String? = null
    ) {
        val resolvedUserId = userId
            ?: sessionManager.currentSession?.userId
            ?: "system"

        val entity = AuditLogEntity(
            id = UUID.randomUUID().toString(),
            userId = resolvedUserId,
            action = action,
            targetType = targetType,
            targetId = targetId,
            details = details,
            timestamp = System.currentTimeMillis()
        )
        auditLogDao.insert(entity)
    }

    companion object {
        /**
         * Build a safe JSON details string from key-value pairs.
         * All string values are escaped to prevent JSON injection.
         *
         * Usage: `buildDetails("testCode" to "CBC", "priority" to "URGENT", "count" to 5)`
         */
        fun buildDetails(vararg pairs: Pair<String, Any?>): String {
            return pairs.joinToString(",", "{", "}") { (key, value) ->
                val escapedKey = escapeJson(key)
                when (value) {
                    null -> "\"$escapedKey\":null"
                    is Number -> "\"$escapedKey\":$value"
                    is Boolean -> "\"$escapedKey\":$value"
                    else -> "\"$escapedKey\":\"${escapeJson(value.toString())}\""
                }
            }
        }

        /** Escape special characters for safe JSON string embedding. */
        private fun escapeJson(value: String): String = value
            .replace("\\", "\\\\")
            .replace("\"", "\\\"")
            .replace("\n", "\\n")
            .replace("\r", "\\r")
            .replace("\t", "\\t")
    }
}
