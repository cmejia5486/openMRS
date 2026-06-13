package com.lyecdevelopers.core.model.cohort

object IndicatorRepository {

    private val personNameAttributes = listOf(
        Attribute("givenName", "Given Name", "PersonName", 1, false),
        Attribute("middleName", "Middle Name", "PersonName", 1, false),
        Attribute("familyName", "Family Name", "PersonName", 1, false),
        Attribute("familyName2", "Family Name 2", "PersonName", 1, false)
    )

    private val demographicsAttributes = listOf(
        Attribute("uuid", "UUID", "Demographics", 1, false),
        Attribute("gender", "Gender", "Demographics", 1, false),
        Attribute("birthdate", "Birthdate", "Demographics", 1, false),
        Attribute("Age", "Age", "Demographics", 1, false),
        Attribute("birthdateEstimated", "Birth Date estimated", "Demographics", 1, false),
        Attribute("dead", "Deceased", "Demographics", 1, false),
        Attribute("deathDate", "Date of death", "Demographics", 1, false)
    )

    private val addressAttributes = listOf(
        Attribute("country", "Country", "Address", 1, false),
        Attribute("countyDistrict", "District", "Address", 1, false),
        Attribute("stateProvince", "County", "Address", 1, false),
        Attribute("address3", "Sub County", "Address", 1, false),
        Attribute("address4", "Parish", "Address", 1, false),
        Attribute("address5", "Village", "Address", 1, false)
    )

    private val appointmentAttributes = listOf(
        Attribute("startDate", "Appointment Scheduled", "Appointment", 1, false)
    )

    val reportIndicators: List<Indicator> = listOf(
        Indicator(
            id = "IDN", label = "Identifiers", type = "PatientIdentifier", attributes = emptyList()
        ), Indicator(
            id = "PEN",
            label = "Person Names",
            type = "PersonName",
            attributes = personNameAttributes
        ), Indicator(
            id = "DEM",
            label = "Demographics",
            type = "Demographics",
            attributes = demographicsAttributes
        ), Indicator(
            id = "ADD", label = "Address", type = "Address", attributes = addressAttributes
        ), Indicator(
            id = "PAT",
            label = "Person Attributes",
            type = "PersonAttribute",
            attributes = emptyList()
        ), Indicator(
            id = "CON", label = "Conditions", type = "Condition", attributes = emptyList()
        ), Indicator(
            id = "APP",
            label = "Appointments",
            type = "Appointment",
            attributes = appointmentAttributes
        )
    )
}
