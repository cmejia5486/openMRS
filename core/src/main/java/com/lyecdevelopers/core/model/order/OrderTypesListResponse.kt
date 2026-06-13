package com.lyecdevelopers.core.model.order

import com.lyecdevelopers.core.model.cohort.Attribute
import com.lyecdevelopers.core.model.cohort.Indicator
import com.squareup.moshi.Json


data class OrderTypeListResponse(
    @Json(name = "results") val results: List<OrderType>,
)

data class OrderType(
    @Json(name = "uuid") val uuid: String,
    @Json(name = "display") val display: String?,
    @Json(name = "name") val name: String?,
)

fun OrderType.toAttribute(): Attribute {
    return Attribute(
        id = this.uuid,
        label = this.display ?: this.name.orEmpty(),
        type = "OrderType",
        modifier = 0,
        showModifierPanel = false,
        extras = emptyList(),
        attributes = emptyList()
    )
}

fun OrderType.toIndicator(): Indicator {
    return Indicator(
        id = this.uuid,
        label = this.display ?: this.name.orEmpty(),
        type = "orderType",
        attributes = emptyList()
    )
}



fun Attribute.toOrderType(): OrderType {
    return OrderType(
        uuid = this.id,
        display = this.label,
        name = this.label
    )
}

fun List<OrderType>.toIndicators(): List<Indicator> {
    return this.map { it.toIndicator() }
}


fun List<OrderType>.toAttributes(): List<Attribute> = map { it.toAttribute() }

fun List<Attribute>.toOrderTypes(): List<OrderType> = map { it.toOrderType() }
