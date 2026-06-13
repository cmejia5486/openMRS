package com.lyecdevelopers.core.data.local.db

import androidx.room.Database
import androidx.room.RoomDatabase
import androidx.room.TypeConverters
import com.lyecdevelopers.core.data.local.dao.EncounterDao
import com.lyecdevelopers.core.data.local.dao.FormDao
import com.lyecdevelopers.core.data.local.dao.PatientDao
import com.lyecdevelopers.core.data.local.dao.VisitDao
import com.lyecdevelopers.core.data.local.dao.VitalsDao
import com.lyecdevelopers.core.data.local.entity.EncounterEntity
import com.lyecdevelopers.core.data.local.entity.FormEntity
import com.lyecdevelopers.core.data.local.entity.PatientEntity
import com.lyecdevelopers.core.data.local.entity.VisitEntity
import com.lyecdevelopers.core.data.local.entity.VitalsEntity

@Database(
    entities = [FormEntity::class, PatientEntity::class, VisitEntity::class, VitalsEntity::class, EncounterEntity::class],
    version = 1,
    exportSchema = false
)
@TypeConverters(
    FormTypeConverters::class, DateTimeTypeConverters::class, VisitStatusConverter::class,
)
abstract class AppDatabase : RoomDatabase() {
    abstract fun visitDao(): VisitDao
    abstract fun formDao(): FormDao
    abstract fun patientDao(): PatientDao
    abstract fun encounterDao(): EncounterDao

    abstract fun vitalsDao(): VitalsDao
}
