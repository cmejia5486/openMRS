package com.chartlite.app.model

private val INVALID_REFERRAL_VALUES = setOf(
    "",
    "null",
    "none",
    "nil",
    "n a",
    "n/a",
    "unknown",
    "not stated",
    "not mentioned"
)

fun normalizeReferralValue(raw: String?): String? {
    val value = raw?.trim()
        ?.trim('"')
        ?.replace(Regex("""\s+"""), " ")
        ?: return null
    if (value.isBlank()) return null
    return value.takeUnless { it.lowercase() in INVALID_REFERRAL_VALUES }
}

fun Referral?.normalizedOrNull(): Referral? {
    if (this == null) return null

    val specialty = normalizeReferralValue(specialty)
    val reason = normalizeReferralValue(reason)
    val type = normalizeReferralType(type, specialty) ?: return null
    val urgency = normalizeReferralUrgency(urgency)

    return Referral(
        type = type,
        specialty = specialty,
        urgency = urgency,
        reason = reason
    )
}

fun Referral.destinationLabel(): String = when (type.lowercase()) {
    "specialist" -> "Specialist referral"
    "hospital" -> "Hospital"
    "lab" -> "Laboratory"
    else -> specialty ?: type
}

private fun normalizeReferralType(rawType: String?, specialty: String?): String? {
    val normalized = normalizeReferralValue(rawType)?.lowercase()
    return when {
        normalized == null && specialty != null -> "specialist"
        normalized in setOf("specialist", "hospital", "lab") -> normalized
        normalized != null -> normalized
        else -> null
    }
}

private fun normalizeReferralUrgency(rawUrgency: String?): String {
    return when (normalizeReferralValue(rawUrgency)?.lowercase()) {
        "emergency", "emergent" -> "emergency"
        "urgent", "stat", "immediate" -> "urgent"
        else -> "routine"
    }
}
