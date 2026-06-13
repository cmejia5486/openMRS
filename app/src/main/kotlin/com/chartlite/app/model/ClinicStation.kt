package com.chartlite.app.model

/**
 * Clinic stations represent the workflow stages a patient passes through.
 * A provider can work at multiple stations (common in LMIC settings).
 */
enum class ClinicStation {
    REGISTRATION,
    TRIAGE,
    CONSULTATION,
    PHARMACY;

    val displayName: String
        get() = when (this) {
            REGISTRATION -> "Registration"
            TRIAGE -> "Triage"
            CONSULTATION -> "Consultation"
            PHARMACY -> "Pharmacy"
        }
}

/**
 * Visit status tracks a patient's journey through the clinic on a given day.
 * Linear state machine: REGISTERED → TRIAGE → CONSULTATION → PHARMACY → COMPLETED.
 * Stations can be skipped (e.g., no meds = skip pharmacy).
 */
enum class VisitStatus {
    REGISTERED,
    AWAITING_TRIAGE,
    IN_TRIAGE,
    AWAITING_CONSULT,
    IN_CONSULTATION,
    AWAITING_PHARMACY,
    IN_PHARMACY,
    COMPLETED,
    LEFT_WITHOUT_SEEN;

    /** Which station's queue this visit should appear in, or null if not queued. */
    fun queueStation(): ClinicStation? = when (this) {
        REGISTERED, AWAITING_TRIAGE -> ClinicStation.TRIAGE
        AWAITING_CONSULT -> ClinicStation.CONSULTATION
        AWAITING_PHARMACY -> ClinicStation.PHARMACY
        else -> null
    }

    /** The statuses that represent "waiting" at each station. */
    companion object {
        fun waitingStatuses(station: ClinicStation): List<VisitStatus> = when (station) {
            ClinicStation.REGISTRATION -> listOf(REGISTERED)
            ClinicStation.TRIAGE -> listOf(AWAITING_TRIAGE)
            ClinicStation.CONSULTATION -> listOf(AWAITING_CONSULT)
            ClinicStation.PHARMACY -> listOf(AWAITING_PHARMACY)
        }

        fun inProgressStatus(station: ClinicStation): VisitStatus = when (station) {
            ClinicStation.REGISTRATION -> REGISTERED
            ClinicStation.TRIAGE -> IN_TRIAGE
            ClinicStation.CONSULTATION -> IN_CONSULTATION
            ClinicStation.PHARMACY -> IN_PHARMACY
        }

        fun nextWaitingStatus(station: ClinicStation): VisitStatus = when (station) {
            ClinicStation.REGISTRATION -> AWAITING_TRIAGE
            ClinicStation.TRIAGE -> AWAITING_CONSULT
            ClinicStation.CONSULTATION -> AWAITING_PHARMACY
            ClinicStation.PHARMACY -> COMPLETED
        }
    }
}
