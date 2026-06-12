package com.chartlite.app.agent

/**
 * Permission system for AI agent access to clinical data.
 *
 * Designed for forward-looking integration where AI agents (voice assistants,
 * clinical decision support, automated workflows) need structured access to
 * patient data with clear permission boundaries.
 *
 * Permissions are scoped by:
 * - Resource type (patient, encounter, lab, appointment, referral, stock, etc.)
 * - Action (read, create, update, delete)
 * - Context (which user/role initiated the agent action)
 *
 * All agent actions are audit-logged with agent identification.
 */
enum class AgentPermission(val resource: String, val action: String) {
    // Patient data
    PATIENT_READ("patient", "read"),
    PATIENT_CREATE("patient", "create"),
    PATIENT_UPDATE("patient", "update"),
    PATIENT_SEARCH("patient", "search"),

    // Encounter / clinical notes
    ENCOUNTER_READ("encounter", "read"),
    ENCOUNTER_CREATE("encounter", "create"),
    ENCOUNTER_UPDATE("encounter", "update"),

    // Lab orders
    LAB_ORDER_READ("lab_order", "read"),
    LAB_ORDER_CREATE("lab_order", "create"),
    LAB_ORDER_UPDATE_STATUS("lab_order", "update_status"),
    LAB_RESULT_ENTER("lab_order", "enter_result"),

    // Appointments
    APPOINTMENT_READ("appointment", "read"),
    APPOINTMENT_CREATE("appointment", "create"),
    APPOINTMENT_UPDATE_STATUS("appointment", "update_status"),

    // Referrals
    REFERRAL_READ("referral", "read"),
    REFERRAL_CREATE("referral", "create"),
    REFERRAL_UPDATE_STATUS("referral", "update_status"),

    // Stock / pharmacy
    STOCK_READ("stock", "read"),
    STOCK_UPDATE("stock", "update"),
    STOCK_DISPENSE("stock", "dispense"),

    // Immunizations
    IMMUNIZATION_READ("immunization", "read"),
    IMMUNIZATION_CREATE("immunization", "create"),

    // Clinical decision support (read-only by nature)
    CDSS_QUERY("cdss", "query"),

    // Analytics / dashboards
    ANALYTICS_READ("analytics", "read"),

    // Audit logs (admin-only)
    AUDIT_READ("audit", "read");

    companion object {
        /**
         * Returns default permissions for an agent operating under a given user role.
         * Follows principle of least privilege — agents get read access broadly
         * but write access only where clinically appropriate for the role.
         */
        fun forRole(role: String): Set<AgentPermission> = when (role.uppercase()) {
            "ADMIN" -> entries.toSet()
            "DOCTOR" -> setOf(
                PATIENT_READ, PATIENT_SEARCH, PATIENT_CREATE, PATIENT_UPDATE,
                ENCOUNTER_READ, ENCOUNTER_CREATE, ENCOUNTER_UPDATE,
                LAB_ORDER_READ, LAB_ORDER_CREATE, LAB_ORDER_UPDATE_STATUS, LAB_RESULT_ENTER,
                APPOINTMENT_READ, APPOINTMENT_CREATE, APPOINTMENT_UPDATE_STATUS,
                REFERRAL_READ, REFERRAL_CREATE, REFERRAL_UPDATE_STATUS,
                IMMUNIZATION_READ, IMMUNIZATION_CREATE,
                CDSS_QUERY, ANALYTICS_READ
            )
            "NURSE" -> setOf(
                PATIENT_READ, PATIENT_SEARCH, PATIENT_CREATE, PATIENT_UPDATE,
                ENCOUNTER_READ, ENCOUNTER_CREATE,
                LAB_ORDER_READ, LAB_ORDER_CREATE, LAB_ORDER_UPDATE_STATUS,
                APPOINTMENT_READ, APPOINTMENT_CREATE, APPOINTMENT_UPDATE_STATUS,
                REFERRAL_READ,
                IMMUNIZATION_READ, IMMUNIZATION_CREATE,
                CDSS_QUERY
            )
            "PHARMACIST" -> setOf(
                PATIENT_READ, PATIENT_SEARCH,
                ENCOUNTER_READ,
                LAB_ORDER_READ,
                STOCK_READ, STOCK_UPDATE, STOCK_DISPENSE,
                APPOINTMENT_READ
            )
            "CHW" -> setOf(
                PATIENT_READ, PATIENT_SEARCH, PATIENT_CREATE,
                ENCOUNTER_READ, ENCOUNTER_CREATE,
                IMMUNIZATION_READ, IMMUNIZATION_CREATE,
                APPOINTMENT_READ,
                CDSS_QUERY
            )
            "REGISTRATION_CLERK" -> setOf(
                PATIENT_READ, PATIENT_SEARCH, PATIENT_CREATE, PATIENT_UPDATE,
                APPOINTMENT_READ, APPOINTMENT_CREATE
            )
            else -> setOf(PATIENT_READ, CDSS_QUERY) // Minimum read-only
        }
    }
}
