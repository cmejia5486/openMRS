package com.chartlite.app

import com.chartlite.app.patientid.PatientIdGenerator
import kotlinx.coroutines.runBlocking
import org.junit.Assert.*
import org.junit.Test

class PatientIdGeneratorTest {

    @Test
    fun `generated ID has correct format XXXX-XXXX`() {
        val id = PatientIdGenerator.generate()
        assertTrue("ID should match XXXX-XXXX format: $id",
            id.matches(Regex("[A-Z2-7]{4}-[A-Z2-7]{4}")))
    }

    @Test
    fun `generated ID has 8 chars excluding dash`() {
        val id = PatientIdGenerator.generate()
        val cleaned = id.replace("-", "")
        assertEquals(8, cleaned.length)
    }

    @Test
    fun `generated ID uses only base28 alphabet`() {
        val alphabet = "ABCDEFGHJKMNPQRTUVWXYZ234567"
        repeat(50) {
            val id = PatientIdGenerator.generate()
            for (c in id.replace("-", "")) {
                assertTrue("Char '$c' not in alphabet", c in alphabet)
            }
        }
    }

    @Test
    fun `excluded chars I L O S never appear`() {
        repeat(100) {
            val id = PatientIdGenerator.generate()
            assertFalse("Should not contain I", 'I' in id)
            assertFalse("Should not contain L", 'L' in id)
            assertFalse("Should not contain O", 'O' in id)
            assertFalse("Should not contain S", 'S' in id)
        }
    }

    @Test
    fun `isValid accepts correct IDs`() {
        assertTrue(PatientIdGenerator.isValid("KFMT-4WRN"))
        assertTrue(PatientIdGenerator.isValid("ABCD-2345"))
        assertTrue(PatientIdGenerator.isValid("ZZZZ-7777"))
    }

    @Test
    fun `isValid rejects invalid IDs`() {
        assertFalse(PatientIdGenerator.isValid(""))
        assertFalse(PatientIdGenerator.isValid("ABCD"))
        assertFalse(PatientIdGenerator.isValid("ABCD-123"))  // too short
        assertFalse(PatientIdGenerator.isValid("ABCD-12345")) // too long
        assertFalse(PatientIdGenerator.isValid("ABCI-1234"))  // contains I
        assertFalse(PatientIdGenerator.isValid("ABCL-1234"))  // contains L
        assertFalse(PatientIdGenerator.isValid("ABCO-1234"))  // contains O
        assertFalse(PatientIdGenerator.isValid("ABCS-1234"))  // contains S
        assertFalse(PatientIdGenerator.isValid("ABC0-1234"))  // contains 0
        assertFalse(PatientIdGenerator.isValid("ABC1-1234"))  // contains 1
        assertFalse(PatientIdGenerator.isValid("ABC8-1234"))  // contains 8
        assertFalse(PatientIdGenerator.isValid("ABC9-1234"))  // contains 9
    }

    @Test
    fun `isValid works without dash`() {
        assertTrue(PatientIdGenerator.isValid("KFMT4WRN"))
    }

    @Test
    fun `isValid is case insensitive`() {
        assertTrue(PatientIdGenerator.isValid("kfmt-4wrn"))
        assertTrue(PatientIdGenerator.isValid("Kfmt-4Wrn"))
    }

    @Test
    fun `normalize formats with dash`() {
        assertEquals("KFMT-4WRN", PatientIdGenerator.normalize("kfmt4wrn"))
        assertEquals("KFMT-4WRN", PatientIdGenerator.normalize("KFMT4WRN"))
        assertEquals("KFMT-4WRN", PatientIdGenerator.normalize("kfmt 4wrn"))
    }

    @Test
    fun `generated IDs are unique`() {
        val ids = (1..1000).map { PatientIdGenerator.generate() }.toSet()
        assertEquals("Expected 1000 unique IDs", 1000, ids.size)
    }

    @Test
    fun `generated ID validates itself`() {
        repeat(100) {
            val id = PatientIdGenerator.generate()
            assertTrue("Generated ID should be valid: $id", PatientIdGenerator.isValid(id))
        }
    }

    @Test
    fun `generateUnique returns ID not in existing set`() = runBlocking {
        val existingIds = mutableSetOf<String>()
        // Generate a few IDs and add them to the "existing" set
        repeat(5) { existingIds.add(PatientIdGenerator.generate()) }

        val newId = PatientIdGenerator.generateUnique { id -> id in existingIds }
        assertFalse("New ID should not be in existing set", newId in existingIds)
        assertTrue("New ID should be valid", PatientIdGenerator.isValid(newId))
    }

    @Test
    fun `generateUnique retries on collision`() = runBlocking {
        var attempts = 0
        val newId = PatientIdGenerator.generateUnique { _ ->
            attempts++
            attempts <= 3 // First 3 attempts "collide", 4th succeeds
        }
        assertTrue("Should have retried", attempts > 3)
        assertTrue("Final ID should be valid", PatientIdGenerator.isValid(newId))
    }
}
