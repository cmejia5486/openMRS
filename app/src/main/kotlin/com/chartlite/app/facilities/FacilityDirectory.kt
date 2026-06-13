package com.chartlite.app.facilities

import android.content.Context
import android.util.Log
import com.google.gson.Gson
import kotlin.math.*

/**
 * Offline Facility Directory — searchable registry of health facilities
 * for referrals with distance estimation.
 *
 * Features:
 * - Search by name, type, service, district
 * - Distance calculation from current facility (Haversine formula)
 * - Filter by facility type (hospital, CHC, clinic)
 * - Filter by available services
 * - Sort by distance or name
 */
class FacilityDirectory(
    private val context: Context,
    private val countryCodeProvider: () -> String
) {

    @Volatile private var facilities: List<Facility> = emptyList()
    private val gson = Gson()
    @Volatile private var loadedCountryCode: String? = null

    /** Load facilities from bundled asset file for the given country. */
    @Synchronized
    fun loadFacilities(countryCode: String, forceReload: Boolean = false) {
        if (!forceReload && loadedCountryCode == countryCode && facilities.isNotEmpty()) return
        try {
            val filename = "facilities/${countryCode}_facilities.json"
            val json = context.assets.open(filename)
                .bufferedReader().use { it.readText() }
            val wrapper = gson.fromJson(json, FacilitiesWrapper::class.java)
            facilities = wrapper?.facilities ?: emptyList()
        } catch (e: Exception) {
            Log.w(TAG, "Failed to load facilities", e)
            facilities = emptyList()
        }
        loadedCountryCode = countryCode
    }

    @Synchronized
    fun invalidate() {
        facilities = emptyList()
        loadedCountryCode = null
    }

    private fun ensureLoaded() {
        val countryCode = countryCodeProvider().trim().lowercase()
        if (loadedCountryCode != countryCode) {
            loadFacilities(countryCode, forceReload = true)
        }
    }

    fun preloadCurrentCountry() {
        ensureLoaded()
    }

    /** Load from raw JSON string (useful for testing). */
    @Synchronized
    fun loadFromJson(json: String) {
        val wrapper = gson.fromJson(json, FacilitiesWrapper::class.java)
        facilities = wrapper?.facilities ?: emptyList()
        loadedCountryCode = countryCodeProvider().trim().lowercase()
    }

    /** Get all loaded facilities. */
    fun getAll(): List<Facility> {
        ensureLoaded()
        return facilities
    }

    /** Get facility by ID. */
    fun getById(id: String): Facility? {
        ensureLoaded()
        return facilities.find { it.id == id }
    }

    /** Get all unique facility types. */
    fun getTypes(): List<String> {
        ensureLoaded()
        return facilities.map { it.type }.distinct().sorted()
    }

    /** Get all unique services across all facilities. */
    fun getAvailableServices(): List<String> {
        ensureLoaded()
        return facilities.flatMap { it.services }.distinct().sorted()
    }

    /** Get all unique provinces/regions. */
    fun getProvinces(): List<String> {
        ensureLoaded()
        return facilities.map { it.province }.distinct().sorted()
    }

    /** Get all unique districts. */
    fun getDistricts(): List<String> {
        ensureLoaded()
        return facilities.map { it.district }.distinct().sorted()
    }

    /** Filter by facility type. */
    fun filterByType(type: String): List<Facility> {
        ensureLoaded()
        return facilities.filter { it.type.equals(type, ignoreCase = true) }
    }

    /** Filter by available service. */
    fun filterByService(service: String): List<Facility> {
        ensureLoaded()
        return facilities.filter { facility ->
            facility.services.any { it.equals(service, ignoreCase = true) }
        }
    }

    /** Filter by province. */
    fun filterByProvince(province: String): List<Facility> {
        ensureLoaded()
        return facilities.filter { it.province.equals(province, ignoreCase = true) }
    }

    /** Filter by district. */
    fun filterByDistrict(district: String): List<Facility> {
        ensureLoaded()
        return facilities.filter { it.district.equals(district, ignoreCase = true) }
    }

    /**
     * Search facilities by keyword (matches name, district, subDistrict, services).
     */
    fun search(query: String): List<Facility> {
        ensureLoaded()
        val q = query.lowercase().trim()
        if (q.isBlank()) return emptyList()
        return facilities.filter { facility ->
            facility.name.lowercase().contains(q) ||
            facility.district.lowercase().contains(q) ||
            facility.subDistrict.lowercase().contains(q) ||
            facility.province.lowercase().contains(q) ||
            facility.services.any { it.lowercase().contains(q) }
        }
    }

    /**
     * Combined filter — apply multiple criteria at once.
     */
    fun filter(
        query: String? = null,
        type: String? = null,
        service: String? = null,
        province: String? = null,
        district: String? = null
    ): List<Facility> {
        ensureLoaded()
        return facilities.filter { facility ->
            (query == null || facility.name.lowercase().contains(query.lowercase()) ||
                facility.district.lowercase().contains(query.lowercase()) ||
                facility.services.any { it.lowercase().contains(query.lowercase()) }) &&
            (type == null || facility.type.equals(type, ignoreCase = true)) &&
            (service == null || facility.services.any { it.equals(service, ignoreCase = true) }) &&
            (province == null || facility.province.equals(province, ignoreCase = true)) &&
            (district == null || facility.district.equals(district, ignoreCase = true))
        }
    }

    /**
     * Get facilities sorted by distance from a reference point.
     * Uses Haversine formula for accurate great-circle distance.
     */
    fun sortByDistance(
        fromLat: Double,
        fromLon: Double,
        facilities: List<Facility>? = null
    ): List<FacilityWithDistance> {
        ensureLoaded()
        val sourceFacilities = facilities ?: this.facilities
        return sourceFacilities.map { facility ->
            val distance = haversineDistanceKm(fromLat, fromLon, facility.latitude, facility.longitude)
            FacilityWithDistance(facility, distance)
        }.sortedBy { it.distanceKm }
    }

    /**
     * Find nearest facilities offering a specific service.
     */
    fun findNearestWithService(
        service: String,
        fromLat: Double,
        fromLon: Double,
        limit: Int = 5
    ): List<FacilityWithDistance> {
        val matching = filterByService(service)
        return sortByDistance(fromLat, fromLon, matching).take(limit)
    }

    /**
     * Find nearest referral facility (hospital level) from a PHC clinic.
     */
    fun findNearestReferralFacility(
        fromLat: Double,
        fromLon: Double,
        urgency: String = "routine"
    ): List<FacilityWithDistance> {
        val hospitalTypes = when (urgency.lowercase()) {
            "emergency" -> listOf("TERTIARY_HOSPITAL", "REGIONAL_HOSPITAL")
            "urgent" -> listOf("TERTIARY_HOSPITAL", "REGIONAL_HOSPITAL", "DISTRICT_HOSPITAL")
            else -> listOf("TERTIARY_HOSPITAL", "REGIONAL_HOSPITAL", "DISTRICT_HOSPITAL", "CHC")
        }
        val hospitals = facilities.filter { it.type in hospitalTypes }
        return sortByDistance(fromLat, fromLon, hospitals).take(5)
    }

    companion object {
        private const val TAG = "FacilityDirectory"

        /**
         * Haversine formula — calculate great-circle distance between two points.
         * Returns distance in kilometers.
         */
        fun haversineDistanceKm(
            lat1: Double, lon1: Double,
            lat2: Double, lon2: Double
        ): Double {
            val earthRadiusKm = 6371.0

            val dLat = Math.toRadians(lat2 - lat1)
            val dLon = Math.toRadians(lon2 - lon1)

            val a = sin(dLat / 2).pow(2) +
                    cos(Math.toRadians(lat1)) * cos(Math.toRadians(lat2)) *
                    sin(dLon / 2).pow(2)

            val c = 2 * atan2(sqrt(a), sqrt(1 - a))

            return earthRadiusKm * c
        }
    }
}

// ── Data Models ──

data class FacilitiesWrapper(
    val version: String,
    val country: String,
    val source: String,
    val facilities: List<Facility>
)

data class Facility(
    val id: String,
    val name: String,
    val type: String,
    val province: String,
    val district: String,
    val subDistrict: String,
    val latitude: Double,
    val longitude: Double,
    val phone: String,
    val services: List<String>,
    val beds: Int = 0,
    val operatingHours: String = ""
)

data class FacilityWithDistance(
    val facility: Facility,
    val distanceKm: Double
)
