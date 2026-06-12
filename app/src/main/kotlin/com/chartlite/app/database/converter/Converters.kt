package com.chartlite.app.database.converter

import android.util.Log
import androidx.room.TypeConverter
import com.chartlite.app.model.*
import com.google.gson.Gson
import com.google.gson.reflect.TypeToken

class Converters {
    private val gson = Gson()

    @TypeConverter
    fun fromMedicationList(value: String): List<Medication> {
        return try {
            val type = object : TypeToken<List<Medication>>() {}.type
            gson.fromJson<List<Medication>>(value, type) ?: emptyList()
        } catch (e: Exception) {
            Log.e(TAG, "Failed to deserialize medication list (${value.length} chars)", e)
            emptyList()
        }
    }

    @TypeConverter
    fun toMedicationList(list: List<Medication>): String = gson.toJson(list)

    @TypeConverter
    fun fromDiagnosisList(value: String): List<Diagnosis> {
        return try {
            val type = object : TypeToken<List<Diagnosis>>() {}.type
            gson.fromJson<List<Diagnosis>>(value, type) ?: emptyList()
        } catch (e: Exception) {
            Log.e(TAG, "Failed to deserialize diagnosis list (${value.length} chars)", e)
            emptyList()
        }
    }

    @TypeConverter
    fun toDiagnosisList(list: List<Diagnosis>): String = gson.toJson(list)

    @TypeConverter
    fun fromStringList(value: String): List<String> {
        return try {
            val type = object : TypeToken<List<String>>() {}.type
            gson.fromJson<List<String>>(value, type) ?: emptyList()
        } catch (e: Exception) {
            Log.e(TAG, "Failed to deserialize string list (${value.length} chars)", e)
            emptyList()
        }
    }

    @TypeConverter
    fun toStringList(list: List<String>): String = gson.toJson(list)

    @TypeConverter
    fun fromVitalSigns(value: String?): VitalSigns? {
        return try {
            value?.let { gson.fromJson(it, VitalSigns::class.java) }
        } catch (e: Exception) {
            Log.e(TAG, "Failed to deserialize vital signs (${value?.length ?: 0} chars)", e)
            null
        }
    }

    @TypeConverter
    fun toVitalSigns(vitals: VitalSigns?): String? = vitals?.let { gson.toJson(it) }

    @TypeConverter
    fun fromCDSSAlertList(value: String): List<CDSSAlert> {
        return try {
            val type = object : TypeToken<List<CDSSAlert>>() {}.type
            gson.fromJson<List<CDSSAlert>>(value, type) ?: emptyList()
        } catch (e: Exception) {
            Log.e(TAG, "Failed to deserialize CDSS alert list (${value.length} chars)", e)
            emptyList()
        }
    }

    @TypeConverter
    fun toCDSSAlertList(list: List<CDSSAlert>): String = gson.toJson(list)

    companion object {
        private const val TAG = "Converters"
    }
}
