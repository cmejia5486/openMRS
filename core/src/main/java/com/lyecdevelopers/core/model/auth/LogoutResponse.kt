package com.lyecdevelopers.core.model.auth

import com.squareup.moshi.Json

data class LogoutResponse (
    @Json(name = "authenticated")
    val authenticated:Boolean,
    @Json(name = "locale")
    val locale:String,
    @Json(name = "allowedLocales")
    val allowedlocales:List<String>,
)
