package com.chartlite.app.database.entity

import com.chartlite.app.model.normalizeReferralValue

fun ReferralEntity.hasMeaningfulDestination(): Boolean =
    normalizeReferralValue(toFacility) != null || normalizeReferralValue(toDepartment) != null
