package com.chartlite.app.config

import android.content.Context
import com.chartlite.app.model.CountryConfig
import com.chartlite.app.model.Formulary
import com.chartlite.app.model.ICD10Index
import com.google.gson.Gson

class CountryConfigLoader(private val context: Context) {

    private val gson = Gson()

    fun loadCountryConfig(countryCode: String): CountryConfig {
        val json = readAsset("config/country_$countryCode.json")
        return gson.fromJson(json, CountryConfig::class.java)
    }

    fun loadFormulary(path: String): Formulary {
        val json = readAsset(path)
        return gson.fromJson(json, Formulary::class.java)
    }

    fun loadICD10(path: String): ICD10Index {
        val json = readAsset(path)
        return gson.fromJson(json, ICD10Index::class.java)
    }

    fun listAvailableCountries(): List<String> {
        return context.assets.list("config")
            ?.filter { it.startsWith("country_") && it.endsWith(".json") }
            ?.map { it.removePrefix("country_").removeSuffix(".json") }
            ?: emptyList()
    }

    private fun readAsset(path: String): String {
        return context.assets.open(path).bufferedReader().use { it.readText() }
    }
}
