package com.lyecdevelopers.core.model.auth

import com.squareup.moshi.Json

data class LoginResponse (
    @Json(name = "authenticated")
    val authenticated:Boolean,
    @Json(name = "locale")
    val locale:String,
    @Json(name = "allowedLocales")
    val allowedlocales:List<String>,
    @Json(name = "user")
    val user: User,
    @Json(name = "sessionLocation")
    val sessionlocation: Sessionlocation?,
    @Json(name = "currentProvider")
    val currentprovider: Currentprovider,
)

data class Currentprovider (
    @Json(name = "uuid")
    val uuid:String,
    @Json(name = "display")
    val display:String,
    @Json(name = "links")
    val links:List<Links>,
)

data class Sessionlocation (
    @Json(name = "uuid")
    val uuid:String,
    @Json(name = "display")
    val display:String,
    @Json(name = "links")
    val links:List<Links>,
)
data class User (
    @Json(name = "uuid")
    val uuid:String,
    @Json(name = "display")
    val display:String,
    @Json(name = "username")
    val username:String,
    @Json(name = "systemId")
    val systemid:String,
    @Json(name = "userProperties")
    val userproperties: Userproperties,
    @Json(name = "person")
    val person: Person,
    @Json(name = "privileges") val privileges: List<Privilege>,
    @Json(name = "roles")
    val roles:List<Roles>,
    @Json(name = "links")
    val links:List<Links>,
)
data class Links (
    @Json(name = "rel")
    val rel:String,
    @Json(name = "uri")
    val uri:String,
    @Json(name = "resourceAlias")
    val resourcealias:String,
)

data class Roles (
    @Json(name = "uuid")
    val uuid:String,
    @Json(name = "display")
    val display:String,
    @Json(name = "name")
    val name:String,
)

data class Privilege(
    @Json(name = "uuid") val uuid: String,
    @Json(name = "display") val display: String,
    @Json(name = "name") val name: String,
)


data class Person (
    @Json(name = "uuid")
    val uuid:String,
    @Json(name = "display")
    val display:String,
)

data class Userproperties (
    @Json(name = "loginAttempts")
    val loginattempts:String,
    @Json(name = "patientsVisited")
    val patientsvisited:String
)


