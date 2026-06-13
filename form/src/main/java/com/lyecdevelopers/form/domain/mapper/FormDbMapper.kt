package com.lyecdevelopers.form.domain.mapper

import com.lyecdevelopers.core.data.local.entity.FormEntity
import com.lyecdevelopers.core.model.o3.Encountertype
import com.lyecdevelopers.core.model.o3.o3Form

fun o3Form.toEntity(): FormEntity {
    return FormEntity(
        uuid = this.uuid.toString(),
        name = this.name,
        version = this.version,
        description = this.description,
        encounterTypeUuid = this.encountertype?.uuid,
        encounterTypeDisplay = this.encountertype?.display,
        encounter = this.encounter,
        processor = this.processor,
        published = this.published == true,
        retired = this.retired == true,
        pages = this.pages // This will be handled by Room converter
    )
}

fun FormEntity.o3Form(): o3Form {
    return o3Form(
        uuid = uuid,
        name = name,
        version = version,
        description = description,
        encountertype = encounterTypeUuid?.let {
            Encountertype(
                it,
                encounterTypeDisplay,
                name = "",
                description = "",
                retired = false,
                links = emptyList(),
                resourceversion = ""
            )
        },
        encounter = encounter,
        processor = processor,
        published = published,
        retired = retired,
        pages = pages ?: emptyList(),
        referencedforms = emptyList()
    )
}

