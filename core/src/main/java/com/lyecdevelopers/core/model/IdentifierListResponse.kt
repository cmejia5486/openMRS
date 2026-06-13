package com.lyecdevelopers.core.model

import com.lyecdevelopers.core.model.cohort.Attribute
import com.lyecdevelopers.core.model.cohort.Indicator
import com.squareup.moshi.Json

data class IdentifierListResponse(
    @Json(name = "results") val results: List<Identifier>,
)

data class Identifier(
    @Json(name = "uuid") val uuid: String,
    @Json(name = "display") val display: String,
    @Json(name = "links") val links: List<Links>,
)

fun Identifier.toAttribute(): Attribute {
    return Attribute(
        id = this.uuid,
        label = this.display,
        type = "PatientIdentifier",
        modifier = 0,
        showModifierPanel = false,
        extras = emptyList(),
        attributes = emptyList()
    )
}

fun Identifier.toIndicator(): Indicator {
    return Indicator(
        id = this.uuid, label = this.display, type = "PatientIdentifier", attributes = emptyList()
    )
}


fun Attribute.toIdentifier(): Identifier {
    return Identifier(
        uuid = this.id, display = this.label, links = emptyList()
    )
}

fun List<Identifier>.toIndicators(): List<Indicator> {
    return this.map { it.toIndicator() }
}


fun List<Identifier>.toAttributes(): List<Attribute> = map { it.toAttribute() }

fun List<Attribute>.toIdentifiers(): List<Identifier> = map { it.toIdentifier() }


