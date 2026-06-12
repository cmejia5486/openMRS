package com.chartlite.app.agent

import com.chartlite.app.auth.AuditLogger
import com.chartlite.app.database.entity.*
import com.chartlite.app.database.repository.AppointmentRepository
import com.chartlite.app.database.repository.LabOrderRepository
import com.chartlite.app.database.repository.ReferralRepository
import com.chartlite.app.database.PatientRepository
import com.chartlite.app.database.EncounterRepository

/**
 * Unified data service for AI agent access to clinical data.
 *
 * This is the primary interface AI agents use to interact with ChartLite data.
 * Every method:
 * 1. Checks permissions via AgentContext
 * 2. Performs the operation through the appropriate repository
 * 3. Logs the action to the audit trail
 *
 * Design principles:
 * - All actions are permission-gated (no backdoor access)
 * - All actions are audit-logged with agent + user provenance
 * - Return types are structured data (entities) — easily serializable to JSON
 * - Errors are explicit (sealed results, not silent nulls)
 * - Stateless — agents don't maintain connection state
 *
 * Future extensions:
 * - Batch operations for bulk data import/export
 * - Streaming/subscription for real-time updates (Flow-based)
 * - FHIR resource mapping for interoperability
 * - Rate limiting per agent per time window
 */
class ClinicalDataService(
    private val patientRepository: PatientRepository,
    private val encounterRepository: EncounterRepository,
    private val labOrderRepository: LabOrderRepository,
    private val appointmentRepository: AppointmentRepository,
    private val referralRepository: ReferralRepository,
    private val auditLogger: AuditLogger
) {

    // ── Patient Operations ──────────────────────────────────────────────

    suspend fun getPatient(ctx: AgentContext, patientId: String): AgentResult<PatientEntity> {
        ctx.requirePermission(AgentPermission.PATIENT_READ)
        val patient = patientRepository.getById(patientId)
            ?: return AgentResult.NotFound("Patient", patientId)
        auditLog(ctx, "AGENT_READ_PATIENT", "PATIENT", patientId)
        return AgentResult.Success(patient)
    }

    suspend fun searchPatients(ctx: AgentContext, query: String): AgentResult<List<PatientEntity>> {
        ctx.requirePermission(AgentPermission.PATIENT_SEARCH)
        val results = patientRepository.search(query)
        auditLog(ctx, "AGENT_SEARCH_PATIENTS", details = AuditLogger.buildDetails("query" to query, "count" to results.size))
        return AgentResult.Success(results)
    }

    // ── Lab Order Operations ────────────────────────────────────────────

    suspend fun getLabOrders(ctx: AgentContext, visitId: String): AgentResult<List<LabOrderEntity>> {
        ctx.requirePermission(AgentPermission.LAB_ORDER_READ)
        val orders = labOrderRepository.getByVisitId(visitId)
        auditLog(ctx, "AGENT_READ_LAB_ORDERS", "VISIT", visitId)
        return AgentResult.Success(orders)
    }

    suspend fun getPatientLabOrders(ctx: AgentContext, patientId: String): AgentResult<List<LabOrderEntity>> {
        ctx.requirePermission(AgentPermission.LAB_ORDER_READ)
        val orders = labOrderRepository.getByPatientId(patientId)
        auditLog(ctx, "AGENT_READ_PATIENT_LABS", "PATIENT", patientId)
        return AgentResult.Success(orders)
    }

    suspend fun createLabOrder(
        ctx: AgentContext,
        visitId: String,
        patientId: String,
        testCode: String,
        testName: String,
        priority: String = "ROUTINE",
        notes: String? = null
    ): AgentResult<LabOrderEntity> {
        ctx.requirePermission(AgentPermission.LAB_ORDER_CREATE)
        val order = labOrderRepository.createOrder(
            visitId = visitId,
            patientId = patientId,
            testCode = testCode,
            testName = testName,
            orderedBy = ctx.userId,
            priority = priority,
            notes = notes
        )
        auditLog(ctx, "AGENT_CREATE_LAB_ORDER", "LAB_ORDER", order.id,
            """{"testCode":"$testCode","priority":"$priority","agent":"${ctx.agentId}"}""")
        return AgentResult.Success(order)
    }

    suspend fun enterLabResult(
        ctx: AgentContext,
        orderId: String,
        resultValue: String,
        resultUnit: String? = null,
        referenceRange: String? = null,
        isAbnormal: Boolean? = null,
        notes: String? = null
    ): AgentResult<Boolean> {
        ctx.requirePermission(AgentPermission.LAB_RESULT_ENTER)
        val success = labOrderRepository.enterResult(
            orderId = orderId,
            resultValue = resultValue,
            resultUnit = resultUnit,
            referenceRange = referenceRange,
            isAbnormal = isAbnormal,
            resultedBy = ctx.userId,
            notes = notes
        )
        if (!success) return AgentResult.NotFound("LabOrder", orderId)
        auditLog(ctx, "AGENT_ENTER_LAB_RESULT", "LAB_ORDER", orderId,
            """{"abnormal":$isAbnormal,"agent":"${ctx.agentId}"}""")
        return AgentResult.Success(true)
    }

    // ── Appointment Operations ──────────────────────────────────────────

    suspend fun getAppointments(
        ctx: AgentContext,
        facilityId: String,
        date: Long
    ): AgentResult<List<AppointmentEntity>> {
        ctx.requirePermission(AgentPermission.APPOINTMENT_READ)
        val appts = appointmentRepository.getByDate(facilityId, date)
        auditLog(ctx, "AGENT_READ_APPOINTMENTS", "FACILITY", facilityId,
            """{"date":$date,"count":${appts.size}}""")
        return AgentResult.Success(appts)
    }

    suspend fun scheduleAppointment(
        ctx: AgentContext,
        patientId: String,
        facilityId: String,
        scheduledDate: Long,
        type: String,
        scheduledTime: String? = null,
        durationMinutes: Int = 30,
        notes: String? = null
    ): AgentResult<AppointmentEntity> {
        ctx.requirePermission(AgentPermission.APPOINTMENT_CREATE)
        val appt = appointmentRepository.schedule(
            patientId = patientId,
            facilityId = facilityId,
            scheduledDate = scheduledDate,
            type = type,
            createdBy = ctx.userId,
            scheduledTime = scheduledTime,
            durationMinutes = durationMinutes,
            notes = notes
        )
        auditLog(ctx, "AGENT_CREATE_APPOINTMENT", "APPOINTMENT", appt.id,
            """{"type":"$type","agent":"${ctx.agentId}"}""")
        return AgentResult.Success(appt)
    }

    // ── Referral Operations ─────────────────────────────────────────────

    suspend fun getPendingReferrals(ctx: AgentContext, facilityId: String): AgentResult<List<ReferralEntity>> {
        ctx.requirePermission(AgentPermission.REFERRAL_READ)
        val referrals = referralRepository.getPending(facilityId)
        auditLog(ctx, "AGENT_READ_REFERRALS", details = """{"filter":"pending","count":${referrals.size}}""")
        return AgentResult.Success(referrals)
    }

    suspend fun createReferral(
        ctx: AgentContext,
        visitId: String,
        patientId: String,
        fromFacilityId: String,
        toFacility: String,
        urgency: String,
        reason: String,
        toDepartment: String? = null,
        clinicalNotes: String? = null
    ): AgentResult<ReferralEntity> {
        ctx.requirePermission(AgentPermission.REFERRAL_CREATE)
        val referral = referralRepository.createReferral(
            visitId = visitId,
            patientId = patientId,
            fromProviderId = ctx.userId,
            fromFacilityId = fromFacilityId,
            toFacility = toFacility,
            urgency = urgency,
            reason = reason,
            toDepartment = toDepartment,
            clinicalNotes = clinicalNotes
        )
        auditLog(ctx, "AGENT_CREATE_REFERRAL", "REFERRAL", referral.id,
            """{"urgency":"$urgency","agent":"${ctx.agentId}"}""")
        return AgentResult.Success(referral)
    }

    // ── Summary / Dashboard (read-only aggregates) ──────────────────────

    suspend fun getDashboardSummary(ctx: AgentContext, facilityId: String, date: Long): AgentResult<DashboardSummary> {
        ctx.requirePermission(AgentPermission.ANALYTICS_READ)
        val pendingLabs = labOrderRepository.getPendingCount()
        val appointmentCount = appointmentRepository.getCountForDate(facilityId, date)
        val pendingReferrals = referralRepository.getPendingCount(facilityId)
        auditLog(ctx, "AGENT_READ_DASHBOARD", "FACILITY", facilityId)
        return AgentResult.Success(
            DashboardSummary(
                pendingLabOrders = pendingLabs,
                todayAppointments = appointmentCount,
                pendingReferrals = pendingReferrals,
                date = date
            )
        )
    }

    // ── Helpers ─────────────────────────────────────────────────────────

    private suspend fun auditLog(
        ctx: AgentContext,
        action: String,
        targetType: String? = null,
        targetId: String? = null,
        details: String? = null
    ) {
        val enrichedDetails = buildString {
            append("""{"agentId":"${ctx.agentId}"""")
            ctx.intent?.let { append(""","intent":"$it"""") }
            ctx.sessionId?.let { append(""","sessionId":"$it"""") }
            details?.let {
                // Merge with existing details JSON
                val inner = it.trimStart('{').trimEnd('}')
                if (inner.isNotBlank()) append(",$inner")
            }
            append("}")
        }
        auditLogger.log(
            action = action,
            targetType = targetType,
            targetId = targetId,
            details = enrichedDetails,
            userId = ctx.userId
        )
    }
}

/**
 * Structured result type for agent operations.
 * Provides clear success/failure semantics without exceptions.
 */
sealed class AgentResult<out T> {
    data class Success<T>(val data: T) : AgentResult<T>()
    data class NotFound(val entityType: String, val entityId: String) : AgentResult<Nothing>()
    data class Error(val message: String, val cause: Throwable? = null) : AgentResult<Nothing>()
    data class PermissionDenied(val permission: String) : AgentResult<Nothing>()
}

/**
 * Aggregate dashboard data for agent consumption.
 */
data class DashboardSummary(
    val pendingLabOrders: Int,
    val todayAppointments: Int,
    val pendingReferrals: Int,
    val date: Long
)
