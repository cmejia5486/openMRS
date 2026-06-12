package com.lyecdevelopers.core.model.cohort

import com.squareup.moshi.Json

data class DataDefinition(
    @Json(name = "cohort") val cohort: CohortResponse,
    @Json(name = "columns") val columns: List<ReportParamItem>,
)

data class CohortResponse(
    @Json(name = "type") val type: String?,
    @Json(name = "clazz") val clazz: String?,
    @Json(name = "uuid") val uuid: String?,
    @Json(name = "name") val name: String?,
    @Json(name = "description") val description: String?,
    @Json(name = "parameters") val parameters: List<Parameters>?,
)

data class Parameters(
    @Json(name = "startDate") val startdate: String?,
    @Json(name = "endDate") val enddate: String?,
)
