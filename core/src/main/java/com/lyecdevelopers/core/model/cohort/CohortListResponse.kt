package com.lyecdevelopers.core.model.cohort

import com.squareup.moshi.Json

data class CohortListResponse(
    @Json(name = "results") val results: List<Cohort>,
)

data class Cohort(
    @Json(name = "uuid") val uuid: String,
    @Json(name = "display") val display: String?,
    @Json(name = "name") val name: String?,
    @Json(name = "description") val description: String?,
    @Json(name = "voided") val voided: Boolean,
    @Json(name = "size") val size: Int,
    @Json(name = "auditInfo") val auditinfo: Auditinfo?,
    @Json(name = "links") val links: List<Links>,
    @Json(name = "resourceVersion") val resourceversion: String,
)


data class Auditinfo(
    @Json(name = "creator") val creator: Creator,
    @Json(name = "dateCreated") val datecreated: String?,
    @Json(name = "changedBy") val changedby: String?,
    @Json(name = "dateChanged") val datechanged: String?,
)

data class Creator(
    @Json(name = "uuid") val uuid: String,
    @Json(name = "display") val display: String?,
    @Json(name = "links") val links: List<Links>,
)

data class Links(
    @Json(name = "rel") val rel: String,
    @Json(name = "uri") val uri: String,
    @Json(name = "resourceAlias") val resourcealias: String,
)

