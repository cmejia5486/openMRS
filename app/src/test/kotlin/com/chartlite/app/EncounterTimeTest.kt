package com.chartlite.app

import com.chartlite.app.database.entity.EncounterEntity
import com.chartlite.app.database.entity.effectiveEncounterSortTimeMillis
import com.chartlite.app.database.entity.effectiveEncounterTimeMillis
import org.junit.Assert.assertEquals
import org.junit.Assert.assertNull
import org.junit.Test

class EncounterTimeTest {

    @Test
    fun `effective encounter time prefers timestamp when present`() {
        val encounter = testEncounter(timestamp = 1_710_000_000_000L, createdAt = 1_700_000_000_000L)

        assertEquals(1_710_000_000_000L, encounter.effectiveEncounterTimeMillis())
    }

    @Test
    fun `effective encounter time falls back to createdAt when timestamp missing`() {
        val encounter = testEncounter(timestamp = 0L, createdAt = 1_700_000_000_000L)

        assertEquals(1_700_000_000_000L, encounter.effectiveEncounterTimeMillis())
    }

    @Test
    fun `effective encounter time is null when both fields are invalid`() {
        val encounter = testEncounter(timestamp = 0L, createdAt = 0L)

        assertNull(encounter.effectiveEncounterTimeMillis())
        assertEquals(Long.MIN_VALUE, encounter.effectiveEncounterSortTimeMillis())
    }

    private fun testEncounter(timestamp: Long, createdAt: Long) = EncounterEntity(
        id = "enc-1",
        patientId = "patient-1",
        providerId = "provider-1",
        facilityId = "facility-1",
        timestamp = timestamp,
        transcript = "test",
        createdAt = createdAt
    )
}
