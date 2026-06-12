package com.chartlite.app.agent

/**
 * Context for an AI agent action. Captures who initiated it,
 * what permissions are available, and which agent is acting.
 *
 * Every agent action carries this context so the system can:
 * 1. Enforce permissions before data access
 * 2. Audit-log the action with full provenance
 * 3. Rate-limit or throttle agent activity
 * 4. Distinguish human-initiated vs agent-initiated actions
 */
data class AgentContext(
    /** Human user who authorized this agent action */
    val userId: String,
    /** User's role (determines permission ceiling) */
    val userRole: String,
    /** Agent identifier — e.g. "voice_assistant", "cdss_engine", "auto_scheduler" */
    val agentId: String,
    /** Permissions granted for this action scope */
    val permissions: Set<AgentPermission> = AgentPermission.forRole(userRole),
    /** Session correlation ID for tracking multi-step agent workflows */
    val sessionId: String? = null,
    /** Optional reason/intent for the action (for audit trail) */
    val intent: String? = null
) {
    fun hasPermission(permission: AgentPermission): Boolean = permission in permissions

    fun requirePermission(permission: AgentPermission) {
        if (!hasPermission(permission)) {
            throw AgentPermissionDeniedException(
                agentId = agentId,
                userId = userId,
                permission = permission
            )
        }
    }
}

class AgentPermissionDeniedException(
    val agentId: String,
    val userId: String,
    val permission: AgentPermission
) : SecurityException(
    "Agent '$agentId' (user: $userId) denied permission: ${permission.resource}:${permission.action}"
)
