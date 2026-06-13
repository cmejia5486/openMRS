package com.chartlite.app

import com.chartlite.app.database.dao.GrowthDao
import com.chartlite.app.database.entity.GrowthMeasurementEntity
import com.chartlite.app.database.repository.GrowthRepository
import kotlinx.coroutines.flow.Flow
import kotlinx.coroutines.flow.flowOf
import kotlinx.coroutines.runBlocking
import org.junit.Assert.*
import org.junit.Before
import org.junit.Test

class GrowthRepositoryTest {

    private lateinit var repo: GrowthRepository
    private lateinit var fakeDao: FakeGrowthDao

    @Before
    fun setup() {
        fakeDao = FakeGrowthDao()
        repo = GrowthRepository(fakeDao)
    }

    @Test
    fun `recordMeasurement stores weight and height`() = runBlocking {
        val m = repo.recordMeasurement("p1", "user1", weight = 10.5f, height = 76.0f)
        assertEquals(10.5f, m.weight!!, 0.01f)
        assertEquals(76.0f, m.height!!, 0.01f)
        assertEquals("p1", m.patientId)
        assertNotNull(m.id)
        assertTrue(m.measuredAt > 0)
    }

    @Test
    fun `recordMeasurement computes Z-scores when age provided`() = runBlocking {
        val m = repo.recordMeasurement("p1", "user1", weight = 10.0f, height = 76.0f, ageInMonths = 12)
        assertNotNull(m.weightForAgeZ)
        assertNotNull(m.heightForAgeZ)
        assertNotNull(m.bmiForAgeZ)
    }

    @Test
    fun `recordMeasurement without age has null Z-scores`() = runBlocking {
        val m = repo.recordMeasurement("p1", "user1", weight = 10.0f, height = 76.0f)
        assertNull(m.weightForAgeZ)
        assertNull(m.heightForAgeZ)
        assertNull(m.bmiForAgeZ)
    }

    @Test
    fun `recordMeasurement with only weight`() = runBlocking {
        val m = repo.recordMeasurement("p1", "user1", weight = 8.0f, ageInMonths = 6)
        assertNotNull(m.weightForAgeZ)
        assertNull(m.heightForAgeZ)
        assertNull(m.bmiForAgeZ) // Need both weight and height for BMI
    }

    @Test
    fun `recordMeasurement with MUAC and head circumference`() = runBlocking {
        val m = repo.recordMeasurement("p1", "user1", weight = 5.0f, height = 55.0f, headCircumference = 35.0f, muac = 13.0f)
        assertEquals(35.0f, m.headCircumference!!, 0.01f)
        assertEquals(13.0f, m.muac!!, 0.01f)
    }

    @Test
    fun `normal weight produces positive Z-score near 0`() = runBlocking {
        // ~9.6 kg at 12 months is near median
        val m = repo.recordMeasurement("p1", "user1", weight = 9.6f, ageInMonths = 12)
        val z = m.weightForAgeZ!!
        assertTrue("Z-score should be near 0 for median weight, was $z", z > -1.0f && z < 1.0f)
    }

    @Test
    fun `very low weight produces negative Z-score`() = runBlocking {
        // ~5 kg at 12 months is severely underweight
        val m = repo.recordMeasurement("p1", "user1", weight = 5.0f, ageInMonths = 12)
        val z = m.weightForAgeZ!!
        assertTrue("Z-score should be very negative for low weight, was $z", z < -2.0f)
    }

    @Test
    fun `recordMeasurement validates against negative and zero values`() = runBlocking {
        // Negative weight should be sanitized to null
        val m = repo.recordMeasurement("p1", "user1", weight = -5.0f, height = 0.0f, ageInMonths = 12)
        assertNull("Negative weight should be null", m.weight)
        assertNull("Zero height should be null", m.height)
        assertNull("Z-scores should be null when measurements are invalid", m.weightForAgeZ)
        assertNull(m.bmiForAgeZ)
    }

    @Test
    fun `recordMeasurement with age over 60 months returns null Z-scores`() = runBlocking {
        val m = repo.recordMeasurement("p1", "user1", weight = 25.0f, height = 120.0f, ageInMonths = 72)
        assertNull("WAZ should be null for age > 60 months", m.weightForAgeZ)
        assertNull("HAZ should be null for age > 60 months", m.heightForAgeZ)
    }

    @Test
    fun `female weight Z-scores differ from male`() = runBlocking {
        val male = repo.recordMeasurement("p1", "user1", weight = 9.0f, ageInMonths = 12, isMale = true)
        val female = repo.recordMeasurement("p2", "user1", weight = 9.0f, ageInMonths = 12, isMale = false)
        // Same weight at same age should produce different Z-scores
        assertNotEquals(male.weightForAgeZ, female.weightForAgeZ)
    }

    @Test
    fun `Z-score thresholds are correctly defined`() {
        assertEquals(-2.0f, GrowthRepository.Z_MODERATE_MALNUTRITION)
        assertEquals(-3.0f, GrowthRepository.Z_SEVERE_MALNUTRITION)
        assertEquals(2.0f, GrowthRepository.Z_OVERWEIGHT)
        assertEquals(3.0f, GrowthRepository.Z_OBESE)
    }

    @Test
    fun `getByPatient returns all measurements`() = runBlocking {
        repo.recordMeasurement("p1", "user1", weight = 5.0f)
        repo.recordMeasurement("p1", "user1", weight = 7.0f)
        repo.recordMeasurement("p2", "user1", weight = 8.0f)
        assertEquals(2, repo.getByPatient("p1").size)
    }

    @Test
    fun `getLatest returns most recent measurement`() = runBlocking {
        repo.recordMeasurement("p1", "user1", weight = 5.0f)
        Thread.sleep(10) // ensure different timestamp
        repo.recordMeasurement("p1", "user1", weight = 7.0f)
        val latest = repo.getLatest("p1")
        assertNotNull(latest)
        assertEquals(7.0f, latest!!.weight!!, 0.01f)
    }

    private class FakeGrowthDao : GrowthDao {
        private val measurements = mutableMapOf<String, GrowthMeasurementEntity>()

        override suspend fun insert(measurement: GrowthMeasurementEntity) { measurements[measurement.id] = measurement }
        override suspend fun update(measurement: GrowthMeasurementEntity) { measurements[measurement.id] = measurement }
        override suspend fun getById(id: String) = measurements[id]
        override suspend fun getByPatient(patientId: String) = measurements.values.filter { it.patientId == patientId }.sortedByDescending { it.measuredAt }
        override suspend fun getLatest(patientId: String) = getByPatient(patientId).firstOrNull()
        override fun observeByPatient(patientId: String): Flow<List<GrowthMeasurementEntity>> = flowOf(emptyList())
    }
}
