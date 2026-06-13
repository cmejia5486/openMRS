package com.lyecdevelopers.core.model.reports

import com.squareup.moshi.Json

data class Definition(
    @Json(name = "Given Name") val givenName: String?,
    @Json(name = "Middle Name") val middleName: String?,
    @Json(name = "Family Name") val familyName: String?,
    @Json(name = "Family Name 2") val familyName2: String?,
)
