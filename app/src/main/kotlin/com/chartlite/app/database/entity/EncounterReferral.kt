package com.chartlite.app.database.entity

import com.chartlite.app.model.Referral
import com.chartlite.app.model.normalizedOrNull

fun EncounterEntity.normalizedReferralOrNull(): Referral? =
    referralType?.let {
        Referral(
            type = it,
            specialty = referralSpecialty,
            urgency = referralUrgency ?: "routine",
            reason = referralReason
        ).normalizedOrNull()
    }
