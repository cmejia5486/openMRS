package com.lyecdevelopers.form.utils


import com.lyecdevelopers.core.data.local.entity.PatientEntity
import com.lyecdevelopers.core.model.VisitStatus
import org.hl7.fhir.r4.model.Address
import org.hl7.fhir.r4.model.CodeableConcept
import org.hl7.fhir.r4.model.Coding
import org.hl7.fhir.r4.model.ContactPoint
import org.hl7.fhir.r4.model.Enumerations
import org.hl7.fhir.r4.model.HumanName
import org.hl7.fhir.r4.model.Identifier
import org.hl7.fhir.r4.model.Patient
import java.text.SimpleDateFormat
import java.util.Locale

/**
 * -------------------------------
 * FHIR Patient <-> Local PatientEntity
 * FHIR Patient <-> Questionnaire Answers Map
 * -------------------------------
 */

/** ✅ FHIR ➜ Flat Map (Questionnaire answers) */
fun Patient.toQuestionnaireAnswers(): Map<String, Any?> = buildMap {
    this["first_name"] = nameFirst()
    this["last_name"] = nameLast()
    this["gender"] = gender?.toCode()
    this["birth_date"] = birthDateElement?.valueAsString
    this["nin"] = getIdentifier("http://health.go.ug/nin")

    address?.firstOrNull()?.let { addr ->
        this["village"] = addr.city
        this["parish"] = addr.district
        this["sub_county"] = addr.state
        this["district"] = addr.country
    }
}

/** ✅ Map ➜ FHIR Patient */
fun Map<String, Any?>.toPatient(existingId: String? = null): Patient {
    return Patient().apply {
        id = existingId

        val firstName = this@toPatient["first_name"] as? String
        val lastName = this@toPatient["last_name"] as? String

        if (!firstName.isNullOrBlank() || !lastName.isNullOrBlank()) {
            addName(
                HumanName().apply {
                    family = lastName ?: ""
                    if (!firstName.isNullOrBlank()) addGiven(firstName)
                    use = HumanName.NameUse.OFFICIAL
                })
        }

        gender = (this@toPatient["gender"] as? String)?.let {
            runCatching { Enumerations.AdministrativeGender.fromCode(it) }.getOrElse { Enumerations.AdministrativeGender.UNKNOWN }
        }

        birthDate = (this@toPatient["birth_date"] as? String)?.let {
            runCatching {
                SimpleDateFormat("yyyy-MM-dd", Locale.getDefault()).parse(it)
            }.getOrNull()
        }

        val nin = this@toPatient["nin"] as? String
        if (!nin.isNullOrBlank()) {
            addIdentifier(
                Identifier().apply {
                    system = "http://health.go.ug/nin"
                    value = nin
                })
        }


        val address = Address().apply {
            city = this@toPatient["village"] as? String
            district = this@toPatient["parish"] as? String
            state = this@toPatient["sub_county"] as? String
            country = this@toPatient["district"] as? String
        }
        if (!address.isEmpty) addAddress(address)
    }
}

/** ✅ Local ➜ FHIR Patient */
fun PatientEntity.toFhirPatient(): Patient = Patient().apply {
    id = this@toFhirPatient.id

    addName(
        HumanName().apply {
            family = lastName
            addGiven(firstName)
            use = HumanName.NameUse.OFFICIAL
        }
    )

    gender = runCatching {
        Enumerations.AdministrativeGender.fromCode(this@toFhirPatient.gender)
    }.getOrElse { Enumerations.AdministrativeGender.UNKNOWN }

    birthDate = runCatching {
        if (dateOfBirth.isNotBlank()) {
            SimpleDateFormat("yyyy-MM-dd", Locale.getDefault()).parse(dateOfBirth)
        } else null
    }.getOrNull()

    if (patientIdentifier.isNotBlank()) {
        val identifier = Identifier().apply {
            use = Identifier.IdentifierUse.OFFICIAL
            type = CodeableConcept().apply {
                coding = listOf(
                    Coding().apply {
                        code = "05a29f94-c0ed-11e2-94be-8c13b969e334"
                    }
                )
                text = "OpenMRS ID"
            }
            value = patientIdentifier
        }
        addIdentifier(identifier)
    }

    if (!phoneNumber.isNullOrBlank()) {
        addTelecom(
            ContactPoint().apply {
                system = ContactPoint.ContactPointSystem.PHONE
                value = phoneNumber
                use = ContactPoint.ContactPointUse.MOBILE
            }
        )
    }

    if (!address.isNotEmpty()) {
        val fhirAddress = Address().apply {
            city = city
            district = district
            state = state
            postalCode = postalCode
            country = country
        }
        addAddress(fhirAddress)
    }
}


/** ✅ FHIR ➜ Local PatientEntity */
fun Patient.toPatientEntity(): PatientEntity {
    val name = this.nameFirstRep ?: HumanName()
    val firstName = name.given?.joinToString(" ") ?: ""
    val lastName = name.family ?: ""

    val identifier = this.identifier.firstOrNull()?.value ?: this.idElement.idPart
    val phone =
        this.telecom.firstOrNull { it.system == ContactPoint.ContactPointSystem.PHONE }?.value

    val genderCode = this.gender?.toCode() ?: "unknown"

    val dob = this.birthDate?.let {
        SimpleDateFormat("yyyy-MM-dd", Locale.getDefault()).format(it)
    } ?: ""

    val addressStr = this.addressFirstRep?.let { addr ->
        buildList {
            addr.line?.forEach { line -> add(line.value) }
            addr.city?.let { add(it) }
            addr.district?.let { add(it) }
            addr.state?.let { add(it) }
            addr.country?.let { add(it) }
        }.joinToString(", ")
    }

    return PatientEntity(
        id = this.idElement.idPart.ifBlank { java.util.UUID.randomUUID().toString() },
        patientIdentifier = identifier,
        firstName = firstName,
        lastName = lastName,
        gender = genderCode,
        dateOfBirth = dob,
        phoneNumber = phone,
        address = addressStr,
        status = VisitStatus.PENDING,
        synced = false
    )

}

/** ✅ Small FHIR helpers */
fun Patient.nameFirst(): String? = name.firstOrNull()?.given?.firstOrNull()?.value
fun Patient.nameLast(): String? = name.firstOrNull()?.family
fun Patient.getIdentifier(system: String): String? =
    identifier.firstOrNull { it.system == system }?.value
