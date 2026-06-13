package com.lyecdevelopers.core.model.cohort

import com.squareup.moshi.Json
import com.squareup.moshi.JsonClass

@JsonClass(generateAdapter = true)
data class ReportRequest(
    @Json(name = "uuid") val uuid: String,
    @Json(name = "startDate") val startDate: String,
    @Json(name = "endDate") val endDate: String,
    @Json(name = "type") val type: String,
    @Json(name = "reportCategory") val reportCategory: ReportCategoryWrapper? = null,
    @Json(name = "reportIndicators") val reportIndicators: List<Attribute>? = null,
    @Json(name = "reportType") val reportType: ReportType,
    @Json(name = "reportingCohort") val reportingCohort: CQIReportingCohort? = null,
)

@JsonClass(generateAdapter = true)
data class ReportCategoryWrapper(
    @Json(name = "category") val category: ReportCategory,
    @Json(name = "renderType") val renderType: RenderType? = null,
)

enum class ReportCategory(val value: String) {
    FACILITY("facility"), NATIONAL("national"), CQI("cqi"), DONOR("donor"), INTEGRATION("integration");

    override fun toString(): String = value

    companion object {
        fun from(value: String): ReportCategory? =
            values().firstOrNull { it.value.equals(value, ignoreCase = true) }
    }
}


enum class RenderType(val value: String) {
    LIST("list"), JSON("json"), HTML("html");

    override fun toString(): String = value

    companion object {
        fun from(value: String): RenderType? =
            values().firstOrNull { it.value.equals(value, ignoreCase = true) }
    }
}


enum class ReportType(val value: String) {
    FIXED("fixed"), DYNAMIC("dynamic");

    override fun toString(): String = value

    companion object {
        fun from(value: String): ReportType? =
            values().firstOrNull { it.value.equals(value, ignoreCase = true) }
    }
}


enum class CQIReportingCohort(val value: String) {
    PATIENTS_WITH_ENCOUNTERS("Patients with encounters"), PATIENTS_ON_APPOINTMENT("Patients on appointment");

    override fun toString(): String = value

    companion object {
        fun from(value: String): CQIReportingCohort? =
            values().firstOrNull { it.value.equals(value, ignoreCase = true) }
    }
}
