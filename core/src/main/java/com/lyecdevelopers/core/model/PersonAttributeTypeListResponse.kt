package com.lyecdevelopers.core.model

import com.lyecdevelopers.core.model.cohort.Attribute
import com.lyecdevelopers.core.model.cohort.Indicator
import com.squareup.moshi.Json

data class PersonAttributeTypeListResponse(
    @Json(name = "results") val results: List<PersonAttributeType>,
)

data class PersonAttributeType(
    @Json(name = "uuid") val uuid: String,
    @Json(name = "display") val display: String,
    @Json(name = "links") val links: List<Links>,
)


fun PersonAttributeType.toAttribute(): Attribute {
    return Attribute(
        id = this.uuid,
        label = this.display,
        type = "PersonAttribute",
        modifier = 0,
        showModifierPanel = false,
        extras = emptyList(),
        attributes = emptyList()
    )
}

fun PersonAttributeType.toIndicator(): Indicator {
    return Indicator(
        id = this.uuid, label = this.display, type = "PersonAttribute", attributes = emptyList()
    )

}

fun List<PersonAttributeType>.toIndicators(): List<Indicator> {
    return this.map { it.toIndicator() }
}


fun Attribute.toPersonAttributeType(): PersonAttributeType {
    return PersonAttributeType(
        uuid = this.id, display = this.label, links = emptyList()
    )
}


fun List<PersonAttributeType>.toAttributes(): List<Attribute> {
    return this.map { it.toAttribute() }
}

fun List<Attribute>.toPersonAttributeTypes(): List<PersonAttributeType> {
    return this.map { it.toPersonAttributeType() }
}