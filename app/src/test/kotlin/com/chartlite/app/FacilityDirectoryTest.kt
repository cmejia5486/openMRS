package com.chartlite.app

import com.chartlite.app.facilities.FacilityDirectory
import io.mockk.mockk
import org.junit.Assert.*
import org.junit.Before
import org.junit.Test

class FacilityDirectoryTest {

    private lateinit var directory: FacilityDirectory

    private val testJson = """
    {
        "version": "1.0",
        "country": "ZA",
        "source": "Test",
        "facilities": [
            {
                "id": "ZA-GP-001",
                "name": "Chris Hani Baragwanath Hospital",
                "type": "TERTIARY_HOSPITAL",
                "province": "Gauteng",
                "district": "Johannesburg",
                "subDistrict": "Soweto",
                "latitude": -26.2609,
                "longitude": 27.9387,
                "phone": "+27 11 933 8000",
                "services": ["Emergency", "Surgery", "ICU", "Maternity", "Pediatrics"],
                "beds": 3200,
                "operatingHours": "24/7"
            },
            {
                "id": "ZA-GP-002",
                "name": "Charlotte Maxeke Hospital",
                "type": "TERTIARY_HOSPITAL",
                "province": "Gauteng",
                "district": "Johannesburg",
                "subDistrict": "Parktown",
                "latitude": -26.1749,
                "longitude": 28.0437,
                "phone": "+27 11 488 4911",
                "services": ["Emergency", "Surgery", "ICU", "Oncology"],
                "beds": 1088,
                "operatingHours": "24/7"
            },
            {
                "id": "ZA-GP-020",
                "name": "Diepsloot CHC",
                "type": "CHC",
                "province": "Gauteng",
                "district": "Johannesburg",
                "subDistrict": "Diepsloot",
                "latitude": -25.9316,
                "longitude": 28.0143,
                "phone": "+27 11 840 1100",
                "services": ["Primary Care", "TB/HIV", "Pharmacy", "Immunization"],
                "beds": 0,
                "operatingHours": "Mon-Fri 07:00-19:00"
            },
            {
                "id": "ZA-KZN-001",
                "name": "Inkosi Albert Luthuli Hospital",
                "type": "TERTIARY_HOSPITAL",
                "province": "KwaZulu-Natal",
                "district": "eThekwini",
                "subDistrict": "Durban",
                "latitude": -29.8097,
                "longitude": 30.9652,
                "phone": "+27 31 240 1000",
                "services": ["Emergency", "Surgery", "ICU", "Cardiology"],
                "beds": 846,
                "operatingHours": "24/7"
            },
            {
                "id": "ZA-GP-030",
                "name": "Stretford Clinic",
                "type": "PHC_CLINIC",
                "province": "Gauteng",
                "district": "Ekurhuleni",
                "subDistrict": "Orange Farm",
                "latitude": -26.4757,
                "longitude": 27.8687,
                "phone": "+27 11 850 0300",
                "services": ["Primary Care", "TB/HIV", "Immunization"],
                "beds": 0,
                "operatingHours": "Mon-Fri 07:00-16:00"
            }
        ]
    }
    """.trimIndent()

    @Before
    fun setUp() {
        directory = FacilityDirectory(mockk(relaxed = true)) { "za" }
        directory.loadFromJson(testJson)
    }

    @Test
    fun `getAll returns all loaded facilities`() {
        assertEquals(5, directory.getAll().size)
    }

    @Test
    fun `getById returns correct facility`() {
        val facility = directory.getById("ZA-GP-001")
        assertNotNull(facility)
        assertEquals("Chris Hani Baragwanath Hospital", facility!!.name)
    }

    @Test
    fun `getById returns null for nonexistent ID`() {
        assertNull(directory.getById("NONEXISTENT"))
    }

    @Test
    fun `getTypes returns unique types`() {
        val types = directory.getTypes()
        assertEquals(3, types.size)
        assertTrue(types.contains("TERTIARY_HOSPITAL"))
        assertTrue(types.contains("CHC"))
        assertTrue(types.contains("PHC_CLINIC"))
    }

    @Test
    fun `getAvailableServices returns unique services`() {
        val services = directory.getAvailableServices()
        assertTrue(services.contains("Emergency"))
        assertTrue(services.contains("Primary Care"))
        assertTrue(services.contains("TB/HIV"))
    }

    @Test
    fun `getProvinces returns unique provinces`() {
        val provinces = directory.getProvinces()
        assertEquals(2, provinces.size)
        assertTrue(provinces.contains("Gauteng"))
        assertTrue(provinces.contains("KwaZulu-Natal"))
    }

    @Test
    fun `filterByType filters correctly`() {
        val hospitals = directory.filterByType("TERTIARY_HOSPITAL")
        assertEquals(3, hospitals.size)
        assertTrue(hospitals.all { it.type == "TERTIARY_HOSPITAL" })
    }

    @Test
    fun `filterByType is case-insensitive`() {
        val hospitals = directory.filterByType("tertiary_hospital")
        assertEquals(3, hospitals.size)
    }

    @Test
    fun `filterByService filters correctly`() {
        val withEmergency = directory.filterByService("Emergency")
        assertEquals(3, withEmergency.size)
    }

    @Test
    fun `filterByProvince filters correctly`() {
        val gauteng = directory.filterByProvince("Gauteng")
        assertEquals(4, gauteng.size) // 2 tertiary + 1 CHC + 1 PHC
    }

    @Test
    fun `filterByDistrict filters correctly`() {
        val jhb = directory.filterByDistrict("Johannesburg")
        assertEquals(3, jhb.size)
    }

    @Test
    fun `search matches name`() {
        val results = directory.search("baragwanath")
        assertEquals(1, results.size)
        assertEquals("ZA-GP-001", results[0].id)
    }

    @Test
    fun `search matches district`() {
        val results = directory.search("johannesburg")
        assertEquals(3, results.size)
    }

    @Test
    fun `search matches services`() {
        val results = directory.search("oncology")
        assertEquals(1, results.size)
        assertEquals("ZA-GP-002", results[0].id)
    }

    @Test
    fun `search returns empty for blank query`() {
        assertTrue(directory.search("").isEmpty())
        assertTrue(directory.search("   ").isEmpty())
    }

    @Test
    fun `combined filter works`() {
        val results = directory.filter(
            type = "TERTIARY_HOSPITAL",
            province = "Gauteng"
        )
        assertEquals(2, results.size)
    }

    @Test
    fun `combined filter with service`() {
        val results = directory.filter(
            service = "ICU",
            province = "Gauteng"
        )
        assertEquals(2, results.size) // Both GP tertiary hospitals have ICU
    }

    @Test
    fun `sortByDistance orders correctly`() {
        // From Soweto coordinates
        val sorted = directory.sortByDistance(-26.2609, 27.9387)
        // Chris Hani (Soweto) should be first (distance 0)
        assertEquals("ZA-GP-001", sorted[0].facility.id)
        // Durban should be last (furthest from Soweto)
        assertEquals("ZA-KZN-001", sorted.last().facility.id)
    }

    @Test
    fun `sortByDistance calculates non-negative distances`() {
        val sorted = directory.sortByDistance(-26.0, 28.0)
        assertTrue(sorted.all { it.distanceKm >= 0 })
    }

    @Test
    fun `findNearestWithService filters and sorts`() {
        val nearest = directory.findNearestWithService("Oncology", -26.2609, 27.9387, limit = 3)
        assertEquals(1, nearest.size) // Only Charlotte Maxeke has Oncology
        assertEquals("ZA-GP-002", nearest[0].facility.id)
    }

    @Test
    fun `findNearestReferralFacility for emergency returns hospitals only`() {
        val nearest = directory.findNearestReferralFacility(-26.2609, 27.9387, urgency = "emergency")
        assertTrue(nearest.all {
            it.facility.type == "TERTIARY_HOSPITAL" || it.facility.type == "REGIONAL_HOSPITAL"
        })
    }

    @Test
    fun `findNearestReferralFacility for routine includes CHC`() {
        val nearest = directory.findNearestReferralFacility(-26.2609, 27.9387, urgency = "routine")
        assertTrue(nearest.any { it.facility.type == "CHC" })
    }

    @Test
    fun `haversine distance calculation is accurate`() {
        // Johannesburg to Durban is approximately 570 km
        val distance = FacilityDirectory.haversineDistanceKm(
            -26.2041, 28.0473, // JHB
            -29.8587, 31.0218  // Durban
        )
        assertTrue("Expected ~570km, got ${distance}km", distance in 500.0..650.0)
    }

    @Test
    fun `haversine distance zero for same point`() {
        val distance = FacilityDirectory.haversineDistanceKm(
            -26.2041, 28.0473,
            -26.2041, 28.0473
        )
        assertEquals(0.0, distance, 0.001)
    }
}
