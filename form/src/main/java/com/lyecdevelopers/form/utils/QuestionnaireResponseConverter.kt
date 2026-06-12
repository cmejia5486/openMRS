package com.lyecdevelopers.form.utils

import org.hl7.fhir.r4.model.Address
import org.hl7.fhir.r4.model.Enumerations
import org.hl7.fhir.r4.model.Extension
import org.hl7.fhir.r4.model.Identifier
import org.hl7.fhir.r4.model.Patient
import org.hl7.fhir.r4.model.QuestionnaireResponse
import org.hl7.fhir.r4.model.StringType

object QuestionnaireResponseConverter {

    fun toPatient(response: QuestionnaireResponse): Patient {
        val patient = Patient()
        val identifierList = mutableListOf<Identifier>()
        val address = Address()

        response.item?.forEach {
            when (it.linkId) {
                "first_name" -> patient.addName().addGiven(it.answerFirst()?.valueStringType?.value)
                "last_name" -> patient.nameFirstRep.family =
                    it.answerFirst()?.valueStringType?.value

                "gender" -> patient.gender = when (it.answerFirst()?.valueCoding?.code) {
                    "male" -> Enumerations.AdministrativeGender.MALE
                    "female" -> Enumerations.AdministrativeGender.FEMALE
                    else -> Enumerations.AdministrativeGender.UNKNOWN
                }

                "birth_date" -> patient.birthDate = it.answerFirst()?.valueDateType?.value

                "nin" -> {
                    identifierList.add(
                        Identifier().apply {
                            system = "http://health.go.ug/identifiers/nin"
                            value = it.answerFirst()?.valueStringType?.value
                        }
                    )
                }

                "art_number" -> {
                    identifierList.add(
                        Identifier().apply {
                            system = "http://health.go.ug/identifiers/art"
                            value = it.answerFirst()?.valueStringType?.value
                        }
                    )
                }

                "address" -> {
                    it.item?.forEach { addrItem ->
                        when (addrItem.linkId) {
                            "village" -> address.line = listOf(
                                StringType(
                                    addrItem.answerFirst()?.valueStringType?.value ?: ""
                                )
                            )

                            "parish" -> address.addExtension(
                                Extension(
                                    "http://health.go.ug/fhir/StructureDefinition/parish",
                                    StringType(addrItem.answerFirst()?.valueStringType?.value)
                                )
                            )

                            "sub_county" -> address.addExtension(
                                Extension(
                                    "http://health.go.ug/fhir/StructureDefinition/subcounty",
                                    StringType(addrItem.answerFirst()?.valueStringType?.value)
                                )
                            )

                            "district" -> address.city =
                                addrItem.answerFirst()?.valueStringType?.value
                        }
                    }
                }
            }
        }

        if (identifierList.isNotEmpty()) {
            patient.identifier = identifierList
        }

        if (!address.isEmpty) {
            patient.address = listOf(address)
        }

        return patient
    }


    private fun QuestionnaireResponse.QuestionnaireResponseItemComponent.answerFirst() =
        this.answer?.firstOrNull()

}