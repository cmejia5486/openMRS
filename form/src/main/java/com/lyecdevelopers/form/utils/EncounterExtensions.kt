package com.lyecdevelopers.form.utils

import com.lyecdevelopers.core.data.local.entity.EncounterEntity
import com.lyecdevelopers.core.model.OpenmrsEncounter
import com.lyecdevelopers.form.domain.mapper.FormMapper.extractObsFromResponse
import org.hl7.fhir.r4.model.Questionnaire
import org.hl7.fhir.r4.model.QuestionnaireResponse
import java.time.Instant
import java.util.UUID

object EncounterExtensions {

    fun buildOpenmrsEncounter(
        response: QuestionnaireResponse,
        questionnaireItems: List<Questionnaire.QuestionnaireItemComponent>,
        patientUuid: String,
        encounterTypeUuid: String,
        locationUuid: String,
        encounterDateTime: String = Instant.now().toString(),
    ): OpenmrsEncounter {
        val obs = extractObsFromResponse(
            response = response,
            questionnaireItems = questionnaireItems,
            patientUuid = patientUuid,
            encounterDateTime = encounterDateTime
        )
        return OpenmrsEncounter(
            patient = patientUuid,
            encounterType = encounterTypeUuid,
            location = locationUuid,
            encounterDatetime = encounterDateTime,
            obs = obs
        )
    }

    fun QuestionnaireResponse.toOpenmrsEncounter(
        questionnaireItems: List<Questionnaire.QuestionnaireItemComponent>,
        patientUuid: String,
        encounterTypeUuid: String,
        locationUuid: String,
    ): OpenmrsEncounter = buildOpenmrsEncounter(
        this, questionnaireItems, patientUuid, encounterTypeUuid, locationUuid
    )

    fun OpenmrsEncounter.toEncounterEntity(
        visitUuid: String,
        formUuid: String,
        synced: Boolean = false,
        createdAt: String,
    ): EncounterEntity {
        return EncounterEntity(
            id = UUID.randomUUID().toString(),
            visitUuid = visitUuid,
            encounterTypeUuid = this.encounterType,
            encounterDatetime = this.encounterDatetime,
            obs = this.obs,
            createdAt = createdAt,
            patientUuid = this.patient,
            locationUuid = this.location,
            synced = synced,
            providerUuid = "",
            orders = emptyList(),
            formUuid = formUuid,
            voided = false,
        )
    }



}
