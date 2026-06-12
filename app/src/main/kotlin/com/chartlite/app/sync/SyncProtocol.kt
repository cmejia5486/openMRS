package com.chartlite.app.sync

import com.chartlite.app.database.entity.EncounterEntity
import com.chartlite.app.database.entity.PatientEntity
import com.chartlite.app.database.entity.VisitEntity

/**
 * Defines the data exchange format for device-to-device sync.
 *
 * Protocol:
 * 1. Devices connect via Nearby Connections
 * 2. Exchange "last sync timestamp"
 * 3. Each sends patients + encounters + visits modified since last sync
 * 4. Conflict resolution: last-write-wins based on updatedAt
 *
 * Two sync modes:
 * - SAME_FACILITY: bulk sync of all modified records (existing behavior)
 * - CROSS_FACILITY: patient-scoped sync with user confirmation
 */

// ── Sync mode ──

enum class SyncMode {
    /** Bulk sync within a single facility (existing behavior). */
    SAME_FACILITY,
    /** Patient-scoped sync between different facilities (requires user confirmation). */
    CROSS_FACILITY
}

// ── Envelope ──

/**
 * Wire envelope wrapping all sync payloads. The receiver inspects [mode] to determine
 * which payload type to deserialize from [payload].
 *
 * Backward compatibility: if deserialization as SyncEnvelope fails, the receiver
 * falls back to parsing the bytes directly as a [SyncPayload] (pre-envelope format).
 */
data class SyncEnvelope(
    val mode: SyncMode,
    val payload: String  // JSON of SyncPayload or CrossFacilitySyncPayload
)

// ── Same-facility payload (unchanged) ──

data class SyncPayload(
    val facilityId: String,
    val timestamp: Long,
    val patients: List<PatientEntity>,
    val encounters: List<EncounterEntity>,
    val visits: List<VisitEntity> = emptyList()
)

// ── Cross-facility payload ──

/**
 * Patient-scoped payload for cross-facility sync.
 *
 * Only the specified patients' records are included — no bulk data dump.
 * Encounters and visits retain their original [facilityId] so the receiving
 * facility sees exactly where each record originated.
 */
data class CrossFacilitySyncPayload(
    val sourceFacilityId: String,
    val sourceFacilityName: String,
    val targetPatientIds: List<String>,
    val timestamp: Long,
    val patients: List<PatientEntity>,
    val encounters: List<EncounterEntity>,
    val visits: List<VisitEntity> = emptyList()
)

// ── Results ──

data class SyncResult(
    val patientsReceived: Int,
    val encountersReceived: Int,
    val patientsSent: Int,
    val encountersSent: Int,
    val visitsSent: Int = 0,
    val visitsReceived: Int = 0,
    val conflicts: Int,
    val durationMs: Long
)

data class CrossFacilitySyncResult(
    val sourceFacilityId: String,
    val sourceFacilityName: String,
    val patientIds: List<String>,
    val patientsReceived: Int,
    val encountersReceived: Int,
    val visitsReceived: Int,
    val durationMs: Long
)

// ── State ──

enum class SyncState {
    IDLE,
    DISCOVERING,
    CONNECTING,
    /** Waiting for user to approve an inbound cross-facility sync request. */
    AWAITING_CROSS_FACILITY_CONFIRMATION,
    SYNCING,
    COMPLETED,
    ERROR
}
