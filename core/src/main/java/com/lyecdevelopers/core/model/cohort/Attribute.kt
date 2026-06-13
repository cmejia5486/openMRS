package com.lyecdevelopers.core.model.cohort

import com.squareup.moshi.Json
import com.squareup.moshi.JsonClass

@JsonClass(generateAdapter = true)
data class Attribute(
    @Json(name = "id") val id: String,
    @Json(name = "label") val label: String,
    @Json(name = "type") val type: String,
    @Json(name = "modifier") val modifier: Int,
    @Json(name = "showModifierPanel") val showModifierPanel: Boolean,
    @Json(name = "extras") val extras: List<String> = emptyList(),
    @Json(name = "attributes") val attributes: List<String> = emptyList(),
)