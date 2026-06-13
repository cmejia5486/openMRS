package com.chartlite.app

import com.chartlite.app.extraction.PatientDemographicsExtractor
import org.junit.Assert.*
import org.junit.Before
import org.junit.Test

class PatientDemographicsExtractorTest {

    private lateinit var extractor: PatientDemographicsExtractor

    @Before
    fun setup() {
        extractor = PatientDemographicsExtractor()
    }

    // ── First Name ──

    @Test
    fun `extracts first name from name is pattern`() {
        val result = extractor.extract("name is John Smith")
        assertEquals("John", result.firstName)
    }

    @Test
    fun `extracts first name from alternative patterns`() {
        assertEquals("John", extractor.extract("first name John").firstName)
        assertEquals("John", extractor.extract("patient name John").firstName)
        assertEquals("John", extractor.extract("called John").firstName)
    }

    @Test
    fun `first name is capitalized`() {
        val result = extractor.extract("name is john smith")
        assertEquals("John", result.firstName)
    }

    // ── Last Name ──

    @Test
    fun `extracts last name from name is pattern`() {
        val result = extractor.extract("name is John Smith")
        assertEquals("Smith", result.lastName)
    }

    @Test
    fun `extracts last name from surname and last name patterns`() {
        assertEquals("Nkosi", extractor.extract("surname Nkosi").lastName)
        assertEquals("Doe", extractor.extract("last name Doe").lastName)
    }

    @Test
    fun `last name is capitalized`() {
        val result = extractor.extract("surname nkosi")
        assertEquals("Nkosi", result.lastName)
    }

    // ── Age ──

    @Test
    fun `extracts age from age N and years old and aged patterns`() {
        assertEquals(45, extractor.extract("age 45").ageYears)
        assertEquals(45, extractor.extract("45 years old").ageYears)
        assertEquals(30, extractor.extract("aged 30").ageYears)
    }

    @Test
    fun `extracts age from pronoun he is N`() {
        val result = extractor.extract("he is 28")
        assertEquals(28, result.ageYears)
    }

    @Test
    fun `rejects age above 150`() {
        val result = extractor.extract("age 200")
        assertNull("Age 200 exceeds range 0-150", result.ageYears)
    }

    // ── Date of Birth ──

    @Test
    fun `extracts DOB from slash notation`() {
        val result = extractor.extract("born on 15/03/1985")
        assertEquals("15/03/1985", result.dateOfBirth)
    }

    @Test
    fun `extracts DOB from day month year words`() {
        val result = extractor.extract("born 15 january 1985")
        assertEquals("15/01/1985", result.dateOfBirth)
    }

    @Test
    fun `extracts DOB from month day year words`() {
        val result = extractor.extract("born january 15 1985")
        assertEquals("15/01/1985", result.dateOfBirth)
    }

    // ── Gender ──

    @Test
    fun `extracts male gender from keyword and pronoun`() {
        assertEquals("male", extractor.extract("patient is male").gender)
        assertEquals("male", extractor.extract("he is 45 years old").gender)
    }

    @Test
    fun `extracts female gender from keyword and pronoun`() {
        assertEquals("female", extractor.extract("patient is a woman").gender)
        assertEquals("female", extractor.extract("she is 30 years old").gender)
    }

    // ── Phone Number ──

    @Test
    fun `extracts phone number and strips formatting`() {
        val result = extractor.extract("phone number is 072 123 4567")
        assertNotNull("Should extract phone number", result.phoneNumber)
        assertFalse("Phone should not contain spaces", result.phoneNumber!!.contains(" "))
        assertTrue("Phone should be digits only",
            result.phoneNumber!!.all { it.isDigit() || it == '+' })
        assertTrue("Phone length should be 7-15 digits",
            result.phoneNumber!!.length in 7..15)
    }

    // ── Allergies ──

    @Test
    fun `extracts allergy from allergic to pattern`() {
        val result = extractor.extract("allergic to penicillin")
        assertTrue("Should contain penicillin",
            result.allergies.any { it.contains("penicillin") })
    }

    @Test
    fun `no known allergies returns empty list`() {
        val result = extractor.extract("no known allergies")
        assertTrue("Should return empty list for no known allergies",
            result.allergies.isEmpty())
    }

    // ── Address ──

    @Test
    fun `extracts address from lives in pattern`() {
        val result = extractor.extract("lives in Johannesburg")
        assertNotNull("Should extract address", result.address)
        assertTrue("Address should contain Johannesburg",
            result.address!!.contains("Johannesburg"))
    }

    @Test
    fun `address words are capitalized`() {
        val result = extractor.extract("lives in johannesburg")
        assertNotNull(result.address)
        assertTrue("Each word should be capitalized",
            result.address!!.split(" ").all { it[0].isUpperCase() })
    }

    // ── Edge Cases ──

    @Test
    fun `empty transcript returns all nulls and empty lists`() {
        val result = extractor.extract("")
        assertNull(result.firstName)
        assertNull(result.lastName)
        assertNull(result.ageYears)
        assertNull(result.dateOfBirth)
        assertNull(result.gender)
        assertNull(result.phoneNumber)
        assertTrue(result.allergies.isEmpty())
        assertNull(result.address)
    }

    @Test
    fun `full transcript extracts multiple fields`() {
        val transcript = "name is John Smith he is 45 years old born on 15/03/1979 " +
            "male phone number is 0721234567 allergic to penicillin. lives in Johannesburg"
        val result = extractor.extract(transcript)
        assertEquals("John", result.firstName)
        assertEquals("Smith", result.lastName)
        assertEquals(45, result.ageYears)
        assertEquals("15/03/1979", result.dateOfBirth)
        assertEquals("male", result.gender)
        assertNotNull(result.phoneNumber)
        assertTrue(result.allergies.isNotEmpty())
        assertNotNull(result.address)
    }

    @Test
    fun `ignores stop words as first name`() {
        val result = extractor.extract("called the")
        assertNull("Stop word 'the' should not be captured as first name", result.firstName)
    }
}
