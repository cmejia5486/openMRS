package com.lyecdevelopers.worklist.domain.mapper

import com.lyecdevelopers.core.data.local.entity.EncounterEntity
import com.lyecdevelopers.core.data.local.entity.VitalsEntity
import com.lyecdevelopers.worklist.domain.model.Encounter
import com.lyecdevelopers.worklist.domain.model.Vitals
import java.time.Instant
import java.util.UUID


// Encounters
fun EncounterEntity.toDomain(): Encounter = Encounter(
    uuid = id,
    encounterTypeUuid = encounterTypeUuid,
    encounterDatetime = Instant.parse(encounterDatetime),
    patientUuid = patientUuid,
    locationUuid = locationUuid,
    providerUuid = providerUuid,
    obs = obs,
    orders = orders,
    formUuid = formUuid,
    visitUuid = visitUuid,
    voided = voided,
    synced = synced,
    createdAt = Instant.parse(createdAt)
)


fun Encounter.toEntity(): EncounterEntity = EncounterEntity(
    id = uuid,
    encounterTypeUuid = encounterTypeUuid,
    encounterDatetime = encounterDatetime.toString(),
    patientUuid = patientUuid,
    locationUuid = locationUuid,
    providerUuid = providerUuid,
    obs = obs,
    orders = orders,
    formUuid = formUuid,
    visitUuid = visitUuid,
    voided = voided,
    synced = synced,
    createdAt = createdAt.toString()
)


// Vitals
fun VitalsEntity.toDomain(): Vitals {
    return Vitals(
        temperature = temperature?.toString() ?: "",
        bloodPressureSystolic = bloodPressureSystolic?.toString() ?: "",
        bloodPressureDiastolic = bloodPressureDiastolic?.toString() ?: "",
        heartRate = heartRate?.toString() ?: "",
        respirationRate = respirationRate?.toString() ?: "",
        spo2 = spo2?.toString() ?: "",
        notes = notes.orEmpty(),
        weight = weight?.toString() ?: "",
        height = height?.toString() ?: "",
        bmi = bmi?.toString() ?: "",
        muac = muac?.toString() ?: ""
    )
}


fun Vitals.toEntity(
    visitUuid: String,
    patientId: String,
    id: String = UUID.randomUUID().toString(),
    dateRecorded: Long = System.currentTimeMillis(),
): VitalsEntity {
    return VitalsEntity(
        id = id,
        visitUuid = visitUuid,
        patientUuid = patientId,
        dateRecorded = dateRecorded,
        temperature = temperature.trim().toDoubleOrNull(),
        bloodPressureSystolic = bloodPressureSystolic.trim().toIntOrNull(),
        bloodPressureDiastolic = bloodPressureDiastolic.trim().toIntOrNull(),
        heartRate = heartRate.trim().toIntOrNull(),
        respirationRate = respirationRate.trim().toIntOrNull(),
        spo2 = spo2.trim().toIntOrNull(),
        notes = notes.takeIf { it.isNotBlank() },
        weight = weight.trim().toDoubleOrNull(),
        height = height.trim().toDoubleOrNull(),
        bmi = bmi.trim().toDoubleOrNull(),
        muac = muac.trim().toDoubleOrNull(),
    )
}


