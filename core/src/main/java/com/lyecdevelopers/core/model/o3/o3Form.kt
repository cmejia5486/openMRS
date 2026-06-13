package com.lyecdevelopers.core.model.o3

import com.lyecdevelopers.core.model.FieldType
import com.squareup.moshi.Json

data class o3Form(
    @Json(name = "name") val name: String?,
    @Json(name = "version") val version: String?,
    @Json(name = "description") val description: String?,
    @Json(name = "encounterType") val encountertype: Encountertype?,
    @Json(name = "encounter") val encounter: String?,
    @Json(name = "uuid") val uuid: String?,
    @Json(name = "processor") val processor: String?,
    @Json(name = "published") val published: Boolean?,
    @Json(name = "retired") val retired: Boolean?,
    @Json(name = "referencedForms") val referencedforms: List<String>?,
    @Json(name = "pages") val pages: List<Pages>?,
) {
    companion object {
        fun empty() = o3Form(
            name = "",
            version = "",
            description = "",
            encountertype = Encountertype.empty(),
            encounter = "",
            uuid = "",
            processor = "",
            published = false,
            retired = false,
            referencedforms = emptyList(),
            pages = emptyList(),
        )
    }
}


data class Encountertype(
    @Json(name = "uuid") val uuid: String,
    @Json(name = "display") val display: String?,
    @Json(name = "name") val name: String?,
    @Json(name = "description") val description: String?,
    @Json(name = "retired") val retired: Boolean?,
    @Json(name = "links") val links: List<Links>?,
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


data class Links(
    @Json(name = "rel") val rel: String?,
    @Json(name = "uri") val uri: String?,
    @Json(name = "resourceAlias") val resourcealias: String?,
) {
    companion object {
        fun empty() = Links(
            rel = "", uri = "", resourcealias = ""
        )
    }
}


data class Pages(
    @Json(name = "label") val label: String,
    @Json(name = "sections") val sections: List<Sections>,
) {
    companion object {
        fun empty() = Pages(
            label = "", sections = emptyList()
        )
    }
}

data class Sections(
    @Json(name = "label") val label: String,
    @Json(name = "isExpanded") val isexpanded: String,
    @Json(name = "questions") val questions: List<Questions>,
) {
    companion object {
        fun empty() = Sections(
            label = "", isexpanded = "false", questions = emptyList()
        )
    }
}

data class Questions(
    @Json(name = "label") val label: String?,
    @Json(name = "type") val type: String?,
    @Json(name = "required") val required: String?,
    @Json(name = "id") val id: String?,
    @Json(name = "questionOptions") val questionoptions: Questionoptions,
    @Json(name = "questions") val questions: List<Questions>? = null,
) {
    companion object {
        fun empty() = Questions(
            label = "",
            type = "",
            id = "",
            questionoptions = Questionoptions.empty(),
            required = "false",
            questions = emptyList(), // ✅ Correct type!
        )
    }

}


data class Questionoptions(
    @Json(name = "rendering") val rendering: FieldType?,

    @Json(name = "concept") val concept: String?,

    @Json(name = "answers") val answers: List<Answers>?,
) {
    companion object {
        fun empty() = Questionoptions(
            rendering = null, concept = "", answers = emptyList()
        )
    }
}


data class Answers(
    @Json(name = "concept") val concept: String?,
    @Json(name = "label") val label: String?,
) {
    companion object {
        fun empty() = Answers(
            concept = "", label = ""
        )
    }
}


data class Meta(
    @Json(name = "programs") val programs: Programs,
) {
    companion object {
        fun empty() = Meta(
            programs = Programs.empty()
        )
    }
}

data class Programs(
    @Json(name = "uuid") val uuid: String,
    @Json(name = "isEnrollment") val isenrollment: Boolean,
    @Json(name = "discontinuationDateQuestionId") val discontinuationdatequestionid: String,
) {
    companion object {
        fun empty() = Programs(
            uuid = "", isenrollment = false, discontinuationdatequestionid = ""
        )
    }
}
