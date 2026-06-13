package com.lyecdevelopers.core.model

import com.squareup.moshi.Json
import com.squareup.moshi.JsonClass

@JsonClass(generateAdapter = true)
data class Form(
    @Json(name = "uuid")
    val uuid: String,
    @Json(name = "display") val display: String,
    @Json(name = "name") val name: String?,
    @Json(name = "description") val description: String?,
    @Json(name = "encounterType") val encountertype: Encountertype?,
    @Json(name = "version") val version: String?,
    @Json(name = "build") val build: String?,
    @Json(name = "published") val published: Boolean,
    @Json(name = "retired") val retired: Boolean,
    @Json(name = "auditInfo") val auditinfo: Auditinfo,
    @Json(name = "resources") val resources: List<Resources>,
    @Json(name = "links") val links: List<Links>,
    @Json(name = "resourceVersion") val resourceversion: String?,
) {
    companion object {
        fun empty() = Form(
            uuid = "",
            display = "",
            name = "",
            description = "",
            encountertype = Encountertype.empty(),
            version = "",
            build = "",
            published = false,
            retired = false,
            auditinfo = Auditinfo.empty(),
            resources = emptyList(),
            links = emptyList(),
            resourceversion = ""
        )
    }
}

@JsonClass(generateAdapter = true)
data class Encountertype(
    @Json(name = "uuid")
    val uuid: String,
    @Json(name = "display") val display: String?,
    @Json(name = "name") val name: String?,
    @Json(name = "description") val description: String?,
    @Json(name = "retired") val retired: Boolean,
    @Json(name = "links") val links: List<Links>,
    @Json(name = "resourceVersion") val resourceversion: String?,
) {
    companion object {
        fun empty() = Encountertype(
            uuid = "",
            display = "",
            name = "",
            description = "",
            retired = false,
            links = emptyList(),
            resourceversion = ""
        )
    }
}


@JsonClass(generateAdapter = true)
data class Links(
    @Json(name = "rel") val rel: String?,
    @Json(name = "uri") val uri: String?,
    @Json(name = "resourceAlias") val resourcealias: String?,
) {
    companion object {
        fun empty() = Links(
            rel = "",
            uri = "",
            resourcealias = ""
        )
    }
}

@JsonClass(generateAdapter = true)
data class Auditinfo(
    @Json(name = "creator") val creator: Creator,
    @Json(name = "dateCreated") val datecreated: String,
    @Json(name = "changedBy") val changedby: Changedby?,
    @Json(name = "dateChanged") val datechanged: String?,
) {
    companion object {
        fun empty() = Auditinfo(
            creator = Creator.empty(),
            datecreated = "",
            changedby = Changedby.empty(),
            datechanged = ""
        )
    }
}

@JsonClass(generateAdapter = true)
data class Creator(
    @Json(name = "uuid")
    val uuid: String,
    @Json(name = "display")
    val display: String,
    @Json(name = "links")
    val links: List<Links>,
) {
    companion object {
        fun empty() = Creator(
            uuid = "",
            display = "",
            links = emptyList()
        )
    }
}


@JsonClass(generateAdapter = true)
data class Changedby(
    @Json(name = "uuid") val uuid: String,
    @Json(name = "display") val display: String,
    @Json(name = "links") val links: List<Links>,
) {
    companion object {
        fun empty() = Changedby(
            uuid = "", display = "", links = emptyList()
        )
    }
}


@JsonClass(generateAdapter = true)
data class Resources(
    @Json(name = "uuid") val uuid: String,
    @Json(name = "name") val name: String,
    @Json(name = "valueReference") val valuereference: String,
    @Json(name = "display") val display: String,
    @Json(name = "links") val links: List<Links>,
    @Json(name = "resourceVersion") val resourceversion: String,
) {
    companion object {
        fun empty() = Resources(
            uuid = "",
            name = "",
            valuereference = "",
            display = "",
            links = emptyList(),
            resourceversion = ""
        )
    }
}

@JsonClass(generateAdapter = true)
data class FormsListResponse(
    @Json(name = "results") val results: List<Form>,
)