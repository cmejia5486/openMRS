package com.lyecdevelopers.core.data.local.entity

import androidx.room.Entity
import androidx.room.PrimaryKey
import androidx.room.TypeConverters
import com.lyecdevelopers.core.data.local.db.FormTypeConverters
import com.lyecdevelopers.core.model.o3.Pages
import com.lyecdevelopers.core.model.o3.o3Form
import java.util.UUID

@Entity(tableName = "forms")
@TypeConverters(FormTypeConverters::class)
data class FormEntity(
    @PrimaryKey val uuid: String = UUID.randomUUID().toString(),
    val name: String?,
    val version: String?,
    val description: String?,
    val encounterTypeUuid: String?,
    val encounterTypeDisplay: String?,
    val encounter: String?,
    val processor: String?,
    val published: Boolean,
    val retired: Boolean,
    val pages: List<Pages>?,
) {
    companion object {
        fun from(form: o3Form): FormEntity {
            return FormEntity(
                uuid = form.uuid.toString(),
                name = form.name,
                version = form.version,
                description = form.description,
                encounterTypeUuid = form.encountertype?.uuid,
                encounterTypeDisplay = form.encountertype?.display,
                encounter = form.encounter,
                processor = form.processor,
                published = form.published == true,
                retired = form.retired == true,
                pages = form.pages
            )
        }
    }

}



