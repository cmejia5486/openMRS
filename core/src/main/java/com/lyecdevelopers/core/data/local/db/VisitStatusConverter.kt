package com.lyecdevelopers.core.data.local.db

import androidx.room.TypeConverter
import com.lyecdevelopers.core.model.VisitStatus

class VisitStatusConverter {

    @TypeConverter
    fun fromVisitStatus(status: VisitStatus): String {
        return status.name
    }

    @TypeConverter
    fun toVisitStatus(value: String): VisitStatus {
        return try {
            VisitStatus.valueOf(value)
        } catch (e: IllegalArgumentException) {
            VisitStatus.PENDING
        }
    }
}
