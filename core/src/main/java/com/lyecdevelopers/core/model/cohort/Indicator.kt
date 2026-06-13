package com.lyecdevelopers.core.model.cohort

import com.squareup.moshi.Json

data class Indicator(
    @Json(name = "id") val id: String,
    @Json(name = "label") val label: String,
    @Json(name = "type") val type: String,
    @Json(name = "attributes") val attributes: List<Attribute>,
)
