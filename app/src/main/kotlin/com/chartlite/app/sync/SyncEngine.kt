package com.chartlite.app.sync

import android.content.Context
import android.util.Log
import com.chartlite.app.auth.AuditLogger
import com.chartlite.app.config.AppConfig
import com.chartlite.app.database.EncounterRepository
import com.chartlite.app.database.PatientRepository
import com.chartlite.app.database.VisitRepository
import com.google.android.gms.nearby.Nearby
import com.google.android.gms.nearby.connection.*
import com.google.gson.Gson
import kotlinx.coroutines.CoroutineScope
import kotlinx.coroutines.Dispatchers
import kotlinx.coroutines.SupervisorJob
import kotlinx.coroutines.cancel
import kotlinx.coroutines.flow.MutableStateFlow
import kotlinx.coroutines.flow.StateFlow
import kotlinx.coroutines.flow.update
import kotlinx.coroutines.launch
import java.util.concurrent.ConcurrentHashMap

/**
 * Orchestrates peer-to-peer data sync using Android Nearby Connections API.
 *
 * Uses P2P_CLUSTER strategy for multi-device discovery.
 * Supports both manual sync (SyncScreen) and continuous auto-sync (ContinuousSyncService).
 *
 * Two sync modes:
 * - **Same-facility**: bulk sync of all modified records (existing behavior)
 * - **Cross-facility**: patient-scoped sync with explicit user confirmation
 */
class SyncEngine(
    private val context: Context,
    private val patientRepository: PatientRepository,
    private val encounterRepository: EncounterRepository,
    private val visitRepository: VisitRepository,
    private val appConfig: AppConfig,
    var auditLogger: AuditLogger? = null
) {
    private val connectionsClient = Nearby.getConnectionsClient(context)
    private val gson = Gson()
    private val scope = CoroutineScope(SupervisorJob() + Dispatchers.IO)

    private val _state = MutableStateFlow(SyncState.IDLE)
    val state: StateFlow<SyncState> = _state

    private val _discoveredDevices = MutableStateFlow<List<DiscoveredDevice>>(emptyList())
    val discoveredDevices: StateFlow<List<DiscoveredDevice>> = _discoveredDevices

    private val _syncResult = MutableStateFlow<SyncResult?>(null)
    val syncResult: StateFlow<SyncResult?> = _syncResult

    private val _errorMessage = MutableStateFlow<String?>(null)
    val errorMessage: StateFlow<String?> = _errorMessage

    /** All currently connected peer endpoint IDs. */
    private val _connectedEndpoints = MutableStateFlow<Set<String>>(emptyList<String>().toSet())
    val connectedEndpoints: StateFlow<Set<String>> = _connectedEndpoints

    /** Per-peer last-push timestamp for delta sync (accessed from multiple coroutines). */
    private val lastPushTimestamps = ConcurrentHashMap<String, Long>()

    /** Set to true while merging remote data to suppress sync trigger echo. */
    @Volatile
    var suppressTrigger = false
        private set

    private val _pendingConnection = MutableStateFlow<PendingConnection?>(null)
    val pendingConnection: StateFlow<PendingConnection?> = _pendingConnection

    /** Whether to auto-accept connections (continuous mode) or require user approval (manual mode). */
    @Volatile var autoAcceptConnections = false

    // ── Send-on-connect intent ──
    // Set by the UI before starting discovery to declare what (if anything) should be
    // sent once a peer connects. This moves the send decision into the engine so that
    // incoming cross-facility payloads can cancel a pending same-facility send before
    // it transmits. Without this, a race exists: the UI's LaunchedEffect could fire
    // sendSyncData() before the engine processes an inbound cross-facility payload.

    /** What kind of data to send automatically once a peer connects. */
    enum class SendOnConnect { NONE, SAME_FACILITY, CROSS_FACILITY }

    /** The send intent for the next connection. Set before calling [startDiscovery]. */
    @Volatile var sendOnConnect: SendOnConnect = SendOnConnect.NONE

    /** Patient IDs to send for cross-facility transfers. Only used when [sendOnConnect] is [SendOnConnect.CROSS_FACILITY]. */
    @Volatile var crossFacilityOutboundPatientIds: List<String> = emptyList()

    /**
     * Endpoints whose peer declared cross-facility intent via the connection name tag.
     * Checked in [onConnectionResult] to deterministically suppress same-facility
     * auto-send when the peer is a cross-facility sender — no timing dependency.
     */
    private val peerCrossFacilityEndpoints = ConcurrentHashMap.newKeySet<String>()

    // ── Cross-facility state ──

    /** Inbound cross-facility payload awaiting user confirmation. */
    private val _pendingCrossFacilityPayload = MutableStateFlow<CrossFacilitySyncPayload?>(null)
    val pendingCrossFacilityPayload: StateFlow<CrossFacilitySyncPayload?> = _pendingCrossFacilityPayload

    /** Result of the most recent cross-facility sync. */
    private val _crossFacilityResult = MutableStateFlow<CrossFacilitySyncResult?>(null)
    val crossFacilityResult: StateFlow<CrossFacilitySyncResult?> = _crossFacilityResult

    data class PendingConnection(
        val endpointId: String,
        val deviceName: String,
        val authenticationDigits: String
    )

    data class DiscoveredDevice(
        val endpointId: String,
        val name: String
    )

    /** Service ID — facility-scoped in continuous mode so only same-facility devices discover each other. */
    fun getServiceId(facilityScopedId: String? = null): String {
        return if (facilityScopedId != null) {
            "com.chartlite.sync.${facilityScopedId.trim().uppercase()}"
        } else {
            "com.chartlite.app.sync"
        }
    }

    // ── Discovery ──

    fun startDiscovery(facilityScopedServiceId: String? = null) {
        _state.value = SyncState.DISCOVERING
        _discoveredDevices.value = emptyList()
        _errorMessage.value = null

        val sid = getServiceId(facilityScopedServiceId)

        val options = DiscoveryOptions.Builder()
            .setStrategy(Strategy.P2P_CLUSTER)
            .build()

        connectionsClient.startDiscovery(
            sid,
            endpointDiscoveryCallback,
            options
        ).addOnFailureListener { e ->
            _state.value = SyncState.ERROR
            _errorMessage.value = "Discovery failed: ${e.message}"
        }

        // Also advertise so the other device can find us.
        // Tag the name with CROSS_FACILITY_TAG if this device intends to send
        // cross-facility data, so the peer can detect it in onConnectionInitiated
        // and suppress its own same-facility auto-send deterministically.
        val deviceName = getTaggedConnectionName()
        val advertiseOptions = AdvertisingOptions.Builder()
            .setStrategy(Strategy.P2P_CLUSTER)
            .build()

        connectionsClient.startAdvertising(
            deviceName,
            sid,
            connectionLifecycleCallback,
            advertiseOptions
        )
    }

    fun stopDiscovery() {
        connectionsClient.stopDiscovery()
        connectionsClient.stopAdvertising()
        if (_state.value == SyncState.DISCOVERING) {
            _state.value = SyncState.IDLE
        }
    }

    // ── Connection ──

    fun connectToDevice(device: DiscoveredDevice) {
        _state.value = SyncState.CONNECTING
        connectionsClient.stopDiscovery()

        connectionsClient.requestConnection(
            getTaggedConnectionName(),
            device.endpointId,
            connectionLifecycleCallback
        ).addOnFailureListener { e ->
            _state.value = SyncState.ERROR
            _errorMessage.value = "Connection failed: ${e.message}"
        }
    }

    fun disconnect() {
        _connectedEndpoints.value.forEach { connectionsClient.disconnectFromEndpoint(it) }
        _connectedEndpoints.value = emptySet()
        lastPushTimestamps.clear()
        _state.value = SyncState.IDLE
    }

    fun disconnectEndpoint(endpointId: String) {
        connectionsClient.disconnectFromEndpoint(endpointId)
        _connectedEndpoints.update { it - endpointId }
        lastPushTimestamps.remove(endpointId)
        if (_connectedEndpoints.value.isEmpty() && _state.value == SyncState.SYNCING) {
            _state.value = SyncState.IDLE
        }
    }

    // ── Same-facility data sync ──

    /**
     * Send sync data to the connected peer(s).
     * Uses incremental sync: only sends records modified since last successful sync.
     * Pass fullSync=true to force sending all records (first sync or recovery).
     *
     * Payloads are sent as raw [SyncPayload] JSON for backward compatibility with older versions.
     */
    suspend fun sendSyncData(fullSync: Boolean = false, targetEndpointId: String? = null) {
        val endpoints = if (targetEndpointId != null) {
            if (targetEndpointId in _connectedEndpoints.value) listOf(targetEndpointId) else return
        } else {
            _connectedEndpoints.value.toList()
        }
        if (endpoints.isEmpty()) return
        _state.value = SyncState.SYNCING

        try {
            val startTime = System.currentTimeMillis()
            val lastSync = if (fullSync) 0L else appConfig.lastSyncTimestamp

            // Gather local data — filter encounters to current facility
            val allEncounters = encounterRepository.getAll()
            val currentFacilityId = appConfig.facilityId.trim()
            val canonicalFacilityId = currentFacilityId.uppercase()
            val facilityPatientIds = allEncounters
                .asSequence()
                .filter { sameFacility(it.facilityId, currentFacilityId) }
                .map { it.patientId }
                .toSet()
            val encounters = allEncounters
                .filter { sameFacility(it.facilityId, currentFacilityId) && it.timestamp > lastSync }
            val patientsReferencedByPayload = encounters
                .asSequence()
                .map { it.patientId }
                .toSet()
            val allPatients = patientRepository.getAll()
            val patients = allPatients.filter { patient ->
                patient.id in facilityPatientIds &&
                    (patient.updatedAt > lastSync || patient.id in patientsReferencedByPayload)
            }
            val visits = visitRepository.getModifiedSince(lastSync, currentFacilityId)
            val crossFacilitySkipped = allEncounters.count { !sameFacility(it.facilityId, currentFacilityId) }

            val payload = SyncPayload(
                facilityId = canonicalFacilityId,
                timestamp = System.currentTimeMillis(),
                patients = patients.map { it.copy(pin = null) }, // Strip PIN from sync payloads
                encounters = encounters,
                visits = visits
            )

            // Send raw SyncPayload (not wrapped in SyncEnvelope) for same-facility sync.
            // This maintains backward compatibility with older app versions that don't
            // understand the envelope protocol. The receiver already handles both formats.
            val bytes = gson.toJson(payload).toByteArray(Charsets.UTF_8)

            for (endpointId in endpoints) {
                connectionsClient.sendPayload(
                    endpointId,
                    Payload.fromBytes(bytes)
                ).addOnSuccessListener {
                    lastPushTimestamps[endpointId] = payload.timestamp
                    _syncResult.value = SyncResult(
                        patientsReceived = 0,
                        encountersReceived = 0,
                        patientsSent = patients.size,
                        encountersSent = encounters.size,
                        visitsSent = visits.size,
                        conflicts = 0,
                        durationMs = System.currentTimeMillis() - startTime
                    )
                    scope.launch {
                        auditLogger?.log("SYNC_SEND", targetType = "SYNC",
                            details = AuditLogger.buildDetails(
                                "patients" to patients.size,
                                "encounters" to encounters.size,
                                "visits" to visits.size,
                                "crossFacilitySkipped" to crossFacilitySkipped
                            ))
                    }
                }.addOnFailureListener { e ->
                    _state.value = SyncState.ERROR
                    _errorMessage.value = "Send failed: ${e.message}"
                    scope.launch {
                        auditLogger?.log("SYNC_ERROR", targetType = "SYNC",
                            details = AuditLogger.buildDetails("phase" to "send", "error" to e.message?.take(100)))
                    }
                }
            }
        } catch (e: Exception) {
            _state.value = SyncState.ERROR
            _errorMessage.value = "Sync error: ${e.message}"
            scope.launch {
                auditLogger?.log("SYNC_ERROR", targetType = "SYNC",
                    details = AuditLogger.buildDetails("phase" to "send", "error" to e.message?.take(100)))
            }
        }
    }

    /**
     * Push a delta of recently changed records to all connected peers.
     * Used by ContinuousSyncService for reactive sync on local DB changes.
     * Only sends records modified since the last push to each peer.
     */
    suspend fun pushDelta() {
        val endpoints = _connectedEndpoints.value.toList()
        if (endpoints.isEmpty()) return

        try {
            val currentFacilityId = appConfig.facilityId.trim()
            val canonicalFacilityId = currentFacilityId.uppercase()
            val now = System.currentTimeMillis()

            for (endpointId in endpoints) {
                val since = lastPushTimestamps[endpointId] ?: appConfig.lastSyncTimestamp

                val encounters = encounterRepository.getAll().filter { enc ->
                    sameFacility(enc.facilityId, currentFacilityId) && enc.timestamp > since
                }
                val visits = visitRepository.getModifiedSince(since, currentFacilityId)

                // Include patient rows for all referenced encounters/visits to prevent
                // FK constraint violations on the receiving device
                val referencedPatientIds = (encounters.map { it.patientId } +
                    visits.map { it.patientId }).toSet()
                val patients = patientRepository.getAll().filter { patient ->
                    patient.updatedAt > since || patient.id in referencedPatientIds
                }

                if (patients.isEmpty() && encounters.isEmpty() && visits.isEmpty()) continue

                val payload = SyncPayload(
                    facilityId = canonicalFacilityId,
                    timestamp = now,
                    patients = patients.map { it.copy(pin = null) }, // Strip PIN from sync payloads
                    encounters = encounters,
                    visits = visits
                )

                // Send raw SyncPayload for backward compatibility with older app versions
                // (same approach as sendSyncData — envelope only used for cross-facility)
                val bytes = gson.toJson(payload).toByteArray(Charsets.UTF_8)

                connectionsClient.sendPayload(endpointId, Payload.fromBytes(bytes))
                    .addOnSuccessListener {
                        lastPushTimestamps[endpointId] = now
                        Log.d(TAG, "Delta pushed to $endpointId: ${patients.size}p/${encounters.size}e/${visits.size}v")
                    }
                    .addOnFailureListener { e ->
                        Log.w(TAG, "Delta push failed to $endpointId: ${e.message}")
                    }
            }
        } catch (e: Exception) {
            Log.e(TAG, "pushDelta error", e)
        }
    }

    // ── Cross-facility data sync ──

    /**
     * Send patient-scoped data to a connected peer from a different facility.
     *
     * Only the specified patients' records (demographics, encounters, visits) are included.
     * Encounters retain their original [facilityId] so the receiving facility sees provenance.
     */
    suspend fun sendCrossFacilityData(patientIds: List<String>, targetEndpointId: String) {
        if (targetEndpointId !in _connectedEndpoints.value) return
        _state.value = SyncState.SYNCING

        try {
            val patients = patientIds.mapNotNull { patientRepository.getById(it) }
                .map { it.copy(pin = null) } // Strip PIN from cross-facility sync
            val encounters = patientIds.flatMap { encounterRepository.getByPatientId(it) }
            val visits = patientIds.flatMap { visitRepository.getByPatientId(it) }

            val payload = CrossFacilitySyncPayload(
                sourceFacilityId = appConfig.facilityId.trim().uppercase(),
                sourceFacilityName = appConfig.facilityName.ifBlank {
                    "Facility ${appConfig.facilityId.take(8)}"
                },
                targetPatientIds = patientIds,
                timestamp = System.currentTimeMillis(),
                patients = patients,
                encounters = encounters,
                visits = visits
            )

            val envelope = SyncEnvelope(
                mode = SyncMode.CROSS_FACILITY,
                payload = gson.toJson(payload)
            )
            val bytes = gson.toJson(envelope).toByteArray(Charsets.UTF_8)

            connectionsClient.sendPayload(targetEndpointId, Payload.fromBytes(bytes))
                .addOnSuccessListener {
                    _crossFacilityResult.value = CrossFacilitySyncResult(
                        sourceFacilityId = payload.sourceFacilityId,
                        sourceFacilityName = payload.sourceFacilityName,
                        patientIds = patientIds,
                        patientsReceived = 0,
                        encountersReceived = 0,
                        visitsReceived = 0,
                        durationMs = System.currentTimeMillis() - payload.timestamp
                    )
                    _state.value = SyncState.COMPLETED
                    scope.launch {
                        auditLogger?.log("CROSS_FACILITY_SYNC_SEND", targetType = "SYNC",
                            details = AuditLogger.buildDetails(
                                "targetEndpoint" to targetEndpointId.take(20),
                                "patients" to patients.size,
                                "encounters" to encounters.size,
                                "visits" to visits.size,
                                "patientIds" to patientIds.joinToString(",")
                            ))
                    }
                }
                .addOnFailureListener { e ->
                    _state.value = SyncState.ERROR
                    _errorMessage.value = "Cross-facility send failed: ${e.message}"
                }
        } catch (e: Exception) {
            _state.value = SyncState.ERROR
            _errorMessage.value = "Cross-facility sync error: ${e.message}"
        }
    }

    /**
     * Accept an inbound cross-facility sync payload after user confirmation.
     * Merges patient-scoped data using last-write-wins for patients/visits
     * and insert-if-new for encounters (which are immutable).
     */
    suspend fun acceptCrossFacilitySync() {
        val payload = _pendingCrossFacilityPayload.value ?: return
        _pendingCrossFacilityPayload.value = null
        _state.value = SyncState.SYNCING

        val startTime = System.currentTimeMillis()
        suppressTrigger = true
        try {
            var mergedUpdates = 0

            // Merge patients: insert new, update if remote is newer
            for (remotePatient in payload.patients) {
                val local = patientRepository.getById(remotePatient.id)
                if (local == null) {
                    patientRepository.register(remotePatient)
                } else if (remotePatient.updatedAt > local.updatedAt) {
                    patientRepository.mergeFromSync(remotePatient)
                    mergedUpdates++
                }
            }

            // Merge encounters: insert new, skip existing (encounters are immutable).
            // Encounters keep their original facilityId — provenance is preserved.
            for (remoteEncounter in payload.encounters) {
                if (encounterRepository.getById(remoteEncounter.id) == null) {
                    encounterRepository.insertEntity(remoteEncounter)
                }
            }

            // Merge visits: insert new, update if remote is newer
            for (remoteVisit in payload.visits) {
                val local = visitRepository.getById(remoteVisit.id)
                if (local == null) {
                    visitRepository.mergeFromSync(remoteVisit)
                } else if (remoteVisit.updatedAt > local.updatedAt) {
                    visitRepository.mergeFromSync(remoteVisit)
                    mergedUpdates++
                }
            }

            _crossFacilityResult.value = CrossFacilitySyncResult(
                sourceFacilityId = payload.sourceFacilityId,
                sourceFacilityName = payload.sourceFacilityName,
                patientIds = payload.targetPatientIds,
                patientsReceived = payload.patients.size,
                encountersReceived = payload.encounters.size,
                visitsReceived = payload.visits.size,
                durationMs = System.currentTimeMillis() - startTime
            )
            _state.value = SyncState.COMPLETED

            auditLogger?.log("CROSS_FACILITY_SYNC_ACCEPT", targetType = "SYNC",
                details = AuditLogger.buildDetails(
                    "sourceFacility" to payload.sourceFacilityId.take(20),
                    "sourceName" to payload.sourceFacilityName.take(40),
                    "patients" to payload.patients.size,
                    "encounters" to payload.encounters.size,
                    "visits" to payload.visits.size,
                    "merged" to mergedUpdates,
                    "patientIds" to payload.targetPatientIds.joinToString(",")
                ))
        } catch (e: Exception) {
            _state.value = SyncState.ERROR
            _errorMessage.value = "Failed to merge cross-facility data: ${e.message}"
            auditLogger?.log("SYNC_ERROR", targetType = "SYNC",
                details = AuditLogger.buildDetails("phase" to "cross_facility_accept", "error" to e.message?.take(100)))
        } finally {
            suppressTrigger = false
        }
    }

    /**
     * Reject an inbound cross-facility sync request. No data is merged.
     */
    fun rejectCrossFacilitySync() {
        val payload = _pendingCrossFacilityPayload.value
        _pendingCrossFacilityPayload.value = null
        _state.value = SyncState.IDLE
        if (payload != null) {
            scope.launch {
                auditLogger?.log("CROSS_FACILITY_SYNC_REJECT", targetType = "SYNC",
                    details = AuditLogger.buildDetails(
                        "sourceFacility" to payload.sourceFacilityId.take(20),
                        "patients" to payload.patients.size,
                        "encounters" to payload.encounters.size
                    ))
            }
        }
    }

    // ── Receive dispatch ──

    /**
     * Handle received data from a connected peer.
     *
     * Tries [SyncEnvelope] first (v2 protocol). Falls back to raw [SyncPayload]
     * for backward compatibility with older app versions.
     */
    private suspend fun handleReceivedData(bytes: ByteArray) {
        try {
            val json = String(bytes, Charsets.UTF_8)

            // Try envelope-based protocol first
            val envelope = try {
                gson.fromJson(json, SyncEnvelope::class.java)
            } catch (_: Exception) {
                null
            }

            if (envelope?.mode != null) {
                when (envelope.mode) {
                    SyncMode.SAME_FACILITY -> {
                        val payload = gson.fromJson(envelope.payload, SyncPayload::class.java)
                        handleSameFacilityPayload(payload)
                    }
                    SyncMode.CROSS_FACILITY -> {
                        val payload = gson.fromJson(envelope.payload, CrossFacilitySyncPayload::class.java)
                        handleCrossFacilityPayload(payload)
                    }
                }
            } else {
                // Backward compatibility: raw SyncPayload from older app version
                val payload = gson.fromJson(json, SyncPayload::class.java)
                handleSameFacilityPayload(payload)
            }
        } catch (e: Exception) {
            _state.value = SyncState.ERROR
            _errorMessage.value = "Failed to process received data: ${e.message}"
            auditLogger?.log("SYNC_ERROR", targetType = "SYNC",
                details = AuditLogger.buildDetails("phase" to "receive", "error" to e.message?.take(100)))
        }
    }

    /**
     * Handle a same-facility sync payload (existing behavior).
     * Rejects cross-facility payloads to prevent accidental PHI mixing.
     */
    private suspend fun handleSameFacilityPayload(payload: SyncPayload) {
        val localFacilityId = appConfig.facilityId.trim()
        val isCrossFacility = !sameFacility(payload.facilityId, localFacilityId)
        if (isCrossFacility) {
            auditLogger?.log("SYNC_CROSS_FACILITY_WARNING", targetType = "SYNC",
                details = AuditLogger.buildDetails(
                    "localFacility" to localFacilityId.take(20),
                    "remoteFacility" to payload.facilityId.take(20),
                    "patients" to payload.patients.size,
                    "encounters" to payload.encounters.size
                ))
            _state.value = SyncState.ERROR
            _errorMessage.value = "Sync blocked: facility mismatch (${payload.facilityId.take(20)})"
            return
        }

        // Suppress sync trigger to prevent echo loop
        suppressTrigger = true
        try {
            var mergedUpdates = 0

            // Merge patients: insert new, update if remote is newer (last-write-wins).
            for (remotePatient in payload.patients) {
                val local = patientRepository.getById(remotePatient.id)
                if (local == null) {
                    patientRepository.register(remotePatient)
                } else if (remotePatient.updatedAt > local.updatedAt) {
                    patientRepository.mergeFromSync(remotePatient)
                    mergedUpdates++
                }
            }

            // Merge encounters: insert new, skip if already exists (encounters are immutable)
            for (remoteEncounter in payload.encounters) {
                val local = encounterRepository.getById(remoteEncounter.id)
                if (local == null) {
                    encounterRepository.insertEntity(remoteEncounter)
                }
            }

            // Merge visits: insert new, update if remote is newer (last-write-wins).
            for (remoteVisit in payload.visits) {
                val local = visitRepository.getById(remoteVisit.id)
                if (local == null) {
                    visitRepository.mergeFromSync(remoteVisit)
                } else if (remoteVisit.updatedAt > local.updatedAt) {
                    visitRepository.mergeFromSync(remoteVisit)
                    mergedUpdates++
                }
            }

            _syncResult.value = _syncResult.value?.copy(
                patientsReceived = payload.patients.size,
                encountersReceived = payload.encounters.size,
                visitsReceived = payload.visits.size,
                conflicts = mergedUpdates
            ) ?: SyncResult(
                patientsReceived = payload.patients.size,
                encountersReceived = payload.encounters.size,
                patientsSent = 0,
                encountersSent = 0,
                visitsSent = 0,
                visitsReceived = payload.visits.size,
                conflicts = mergedUpdates,
                durationMs = 0
            )

            _state.value = SyncState.COMPLETED

            // Record sync timestamp for incremental sync on next round
            appConfig.lastSyncTimestamp = System.currentTimeMillis()

            auditLogger?.log("SYNC_RECEIVE", targetType = "SYNC",
                details = AuditLogger.buildDetails(
                    "patients" to payload.patients.size,
                    "encounters" to payload.encounters.size,
                    "visits" to payload.visits.size,
                    "merged" to mergedUpdates,
                    "from" to payload.facilityId.take(20)
                ))
        } finally {
            suppressTrigger = false
        }
    }

    /**
     * Handle a cross-facility sync payload — store it and wait for user confirmation.
     * Does NOT merge any data until [acceptCrossFacilitySync] is called.
     */
    private fun handleCrossFacilityPayload(payload: CrossFacilitySyncPayload) {
        _pendingCrossFacilityPayload.value = payload
        _state.value = SyncState.AWAITING_CROSS_FACILITY_CONFIRMATION

        Log.i(TAG, "Cross-facility sync received from ${payload.sourceFacilityName} " +
            "(${payload.sourceFacilityId}): ${payload.patients.size} patients, " +
            "${payload.encounters.size} encounters, ${payload.visits.size} visits")
    }

    /** Cancel all coroutines launched by this engine. Call on app shutdown. */
    fun close() {
        disconnect()
        scope.cancel()
    }

    fun reset() {
        disconnect()
        sendOnConnect = SendOnConnect.NONE
        crossFacilityOutboundPatientIds = emptyList()
        peerCrossFacilityEndpoints.clear()
        _state.value = SyncState.IDLE
        _discoveredDevices.value = emptyList()
        _syncResult.value = null
        _crossFacilityResult.value = null
        _pendingCrossFacilityPayload.value = null
        _errorMessage.value = null
    }

    /**
     * Build a connection name that encodes the send intent.
     * The [CROSS_FACILITY_TAG] suffix is detected by the peer in [onConnectionInitiated]
     * (which fires before [onConnectionResult]), giving deterministic cross-facility
     * detection with no timing dependency.
     */
    private fun getTaggedConnectionName(): String {
        val base = "ChartLite-${appConfig.facilityId.take(8)}"
        return if (sendOnConnect == SendOnConnect.CROSS_FACILITY) "$base$CROSS_FACILITY_TAG" else base
    }

    private fun sameFacility(left: String, right: String): Boolean {
        return left.trim().equals(right.trim(), ignoreCase = true)
    }

    // ── Callbacks ──

    private val endpointDiscoveryCallback = object : EndpointDiscoveryCallback() {
        override fun onEndpointFound(endpointId: String, info: DiscoveredEndpointInfo) {
            val device = DiscoveredDevice(endpointId, info.endpointName)
            _discoveredDevices.value = _discoveredDevices.value
                .filter { it.name != info.endpointName } + device

            // In continuous mode, auto-connect to discovered peers
            if (autoAcceptConnections && endpointId !in _connectedEndpoints.value) {
                connectionsClient.requestConnection(
                    "ChartLite-${appConfig.facilityId.take(8)}",
                    endpointId,
                    connectionLifecycleCallback
                ).addOnFailureListener { e ->
                    Log.w(TAG, "Auto-connect failed to $endpointId: ${e.message}")
                }
            }
        }

        override fun onEndpointLost(endpointId: String) {
            _discoveredDevices.value = _discoveredDevices.value.filter { it.endpointId != endpointId }
        }
    }

    /**
     * Accept a pending connection after user verifies the authentication code.
     */
    fun acceptPendingConnection() {
        val pending = _pendingConnection.value ?: return
        connectionsClient.acceptConnection(pending.endpointId, payloadCallback)
        _pendingConnection.value = null
    }

    /**
     * Reject a pending connection.
     */
    fun rejectPendingConnection() {
        val pending = _pendingConnection.value ?: return
        connectionsClient.rejectConnection(pending.endpointId)
        _pendingConnection.value = null
        _state.value = SyncState.IDLE
    }

    private val connectionLifecycleCallback = object : ConnectionLifecycleCallback() {
        override fun onConnectionInitiated(endpointId: String, info: ConnectionInfo) {
            // Detect cross-facility intent from the peer's connection name.
            // This fires BEFORE onConnectionResult, so by the time we decide
            // whether to auto-send, we already know the peer's intent — no race.
            if (info.endpointName.endsWith(CROSS_FACILITY_TAG)) {
                peerCrossFacilityEndpoints.add(endpointId)
                Log.d(TAG, "Peer $endpointId declared cross-facility intent")
            }
            val displayName = info.endpointName.removeSuffix(CROSS_FACILITY_TAG)

            if (autoAcceptConnections) {
                // Continuous mode: auto-accept same-facility peers
                connectionsClient.acceptConnection(endpointId, payloadCallback)
                Log.d(TAG, "Auto-accepted connection from $displayName")
            } else {
                // Manual mode: require user verification
                _pendingConnection.value = PendingConnection(
                    endpointId = endpointId,
                    deviceName = displayName,
                    authenticationDigits = info.authenticationDigits
                )
            }
        }

        override fun onConnectionResult(endpointId: String, result: ConnectionResolution) {
            if (result.status.isSuccess) {
                _connectedEndpoints.update { it + endpointId }
                lastPushTimestamps[endpointId] = 0L
                _state.value = SyncState.SYNCING
                Log.d(TAG, "Connected to $endpointId (${_connectedEndpoints.value.size} peers), sendOnConnect=$sendOnConnect")

                // In continuous mode, do an initial full sync with the new peer
                if (autoAcceptConnections) {
                    scope.launch {
                        sendSyncData(fullSync = true, targetEndpointId = endpointId)
                    }
                } else {
                    // Manual mode: execute the send intent declared by the UI.
                    // The peer's cross-facility intent was already detected in
                    // onConnectionInitiated (via the CROSS_FACILITY_TAG in the
                    // connection name), so we can make a deterministic decision
                    // here with no timing dependency.
                    val peerIsCrossFacility = endpointId in peerCrossFacilityEndpoints
                    when (sendOnConnect) {
                        SendOnConnect.CROSS_FACILITY -> {
                            scope.launch {
                                sendCrossFacilityData(crossFacilityOutboundPatientIds, endpointId)
                            }
                        }
                        SendOnConnect.SAME_FACILITY -> {
                            if (peerIsCrossFacility) {
                                // Peer declared cross-facility intent — suppress our
                                // same-facility send. The peer will push a cross-facility
                                // payload; we handle it in handleCrossFacilityPayload().
                                Log.d(TAG, "Suppressing same-facility send: peer $endpointId is cross-facility")
                            } else {
                                scope.launch { sendSyncData(fullSync = true, targetEndpointId = endpointId) }
                            }
                        }
                        SendOnConnect.NONE -> {
                            Log.d(TAG, "No send intent — waiting for inbound data")
                        }
                    }
                }
            } else {
                if (_connectedEndpoints.value.isEmpty()) {
                    _state.value = SyncState.ERROR
                    _errorMessage.value = "Connection rejected"
                }
            }
        }

        override fun onDisconnected(endpointId: String) {
            _connectedEndpoints.update { it - endpointId }
            lastPushTimestamps.remove(endpointId)
            peerCrossFacilityEndpoints.remove(endpointId)
            Log.d(TAG, "Disconnected from $endpointId (${_connectedEndpoints.value.size} peers left)")

            if (_connectedEndpoints.value.isEmpty()) {
                if (_state.value == SyncState.SYNCING) {
                    _state.value = SyncState.ERROR
                    _errorMessage.value = "Disconnected during sync"
                }
            }
        }
    }

    private val payloadCallback = object : PayloadCallback() {
        override fun onPayloadReceived(endpointId: String, payload: Payload) {
            payload.asBytes()?.let { bytes ->
                scope.launch {
                    handleReceivedData(bytes)
                }
            }
        }

        override fun onPayloadTransferUpdate(endpointId: String, update: PayloadTransferUpdate) {
            // Could track transfer progress for large payloads
        }
    }

    companion object {
        private const val TAG = "SyncEngine"

        /**
         * Suffix appended to the Nearby Connections name when this device intends to
         * send cross-facility data. The peer detects this in [onConnectionInitiated]
         * (which fires before [onConnectionResult]) and suppresses its own same-facility
         * auto-send deterministically — no timing window or delay heuristic.
         */
        private const val CROSS_FACILITY_TAG = "#XF"
    }
}
