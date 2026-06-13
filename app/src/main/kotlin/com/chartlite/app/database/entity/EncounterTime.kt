package com.chartlite.app.database.entity

fun EncounterEntity.effectiveEncounterTimeMillis(): Long? = when {
    timestamp > 0L -> timestamp
    createdAt > 0L -> createdAt
    else -> null
}

fun EncounterEntity.effectiveEncounterSortTimeMillis(): Long =
    effectiveEncounterTimeMillis() ?: Long.MIN_VALUE
