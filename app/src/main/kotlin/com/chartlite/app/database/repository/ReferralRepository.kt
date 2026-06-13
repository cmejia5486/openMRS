package com.chartlite.app.database.repository

import com.chartlite.app.database.dao.ReferralDao
import com.chartlite.app.database.entity.ReferralEntity
import com.chartlite.app.database.entity.hasMeaningfulDestination
import com.chartlite.app.model.ReferralStatus
import java.util.UUID
import kotlinx.coroutines.flow.map

/**
 * Business logic for referral tracking and status management.
 * Can auto-create referrals from encounter extraction data.
 */
class ReferralRepository(private val referralDao: ReferralDao) {

    suspend fun createReferral(
        visitId: String,
        patientId: String,
        fromProviderId: String,
        fromFacilityId: String,
        toFacility: String,
        urgency: String,
        reason: String,
        toDepartment: String? = null,
        clinicalNotes: String? = null,
        patientInstructions: String? = null,
        timeframeDays: Int? = null,
        smsText: String? = null
    ): ReferralEntity {
        val now = System.currentTimeMillis()
        val referral = ReferralEntity(
            id = UUID.randomUUID().toString(),
            visitId = visitId,
            patientId = patientId,
            fromProviderId = fromProviderId,
            fromFacilityId = fromFacilityId,
            toFacility = toFacility,
            toDepartment = toDepartment,
            urgency = urgency,
            reason = reason,
            clinicalNotes = clinicalNotes,
            status = ReferralStatus.PENDING.name,
            referredAt = now,
            updatedAt = now,
            patientInstructions = patientInstructions,
            timeframeDays = timeframeDays,
            smsText = smsText
        )
        referralDao.insert(referral)
        return referral
    }

    suspend fun updateStatus(referralId: String, newStatus: String): Boolean {
        // Validate the status is a known ReferralStatus
        val validStatus = try { ReferralStatus.valueOf(newStatus); true } catch (_: IllegalArgumentException) { false }
        if (!validStatus) return false

        val referral = referralDao.getById(referralId) ?: return false

        // Don't allow going back from terminal states
        if (referral.status == ReferralStatus.COMPLETED.name || referral.status == ReferralStatus.CANCELLED.name) return false

        referralDao.update(referral.copy(
            status = newStatus,
            updatedAt = System.currentTimeMillis()
        ))
        return true
    }

    suspend fun getByPatient(patientId: String) = referralDao.getByPatient(patientId).filter { it.hasMeaningfulDestination() }
    suspend fun getPending(facilityId: String) = referralDao.getPending(facilityId).filter { it.hasMeaningfulDestination() }
    suspend fun getByFacility(facilityId: String) = referralDao.getByFacility(facilityId).filter { it.hasMeaningfulDestination() }
    suspend fun getByVisitId(visitId: String) = referralDao.getByVisitId(visitId)
    suspend fun getPendingCount(facilityId: String) = getPending(facilityId).size
    fun observePending(facilityId: String) =
        referralDao.observePending(facilityId).map { referrals ->
            referrals.filter { it.hasMeaningfulDestination() }
        }
}
