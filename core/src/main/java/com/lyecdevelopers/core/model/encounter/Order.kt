package com.lyecdevelopers.core.model.encounter

data class Order(
    val uuid: String,
    val orderType: String,
    val conceptUuid: String,
    val value: String,
)