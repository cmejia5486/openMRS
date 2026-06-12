package com.chartlite.app

import com.chartlite.app.auth.PinHasher
import org.junit.Assert.*
import org.junit.Test

/**
 * Tests for PBKDF2-HMAC-SHA256 PIN hashing.
 * Covers: salt generation, hash determinism, verification, constant-time comparison, edge cases.
 */
class PinHasherTest {

    // ── Salt Generation ──────────────────────────────────────────────

    @Test
    fun `generateSalt returns non-empty base64 string`() {
        val salt = PinHasher.generateSalt()
        assertTrue("Salt should not be blank", salt.isNotBlank())
    }

    @Test
    fun `generateSalt returns unique salts`() {
        val salts = (1..10).map { PinHasher.generateSalt() }.toSet()
        assertEquals("10 generated salts should all be unique", 10, salts.size)
    }

    @Test
    fun `generateSalt returns valid base64`() {
        val salt = PinHasher.generateSalt()
        // Should not throw — Base64 decoder accepts the output
        val decoded = java.util.Base64.getDecoder().decode(salt)
        assertEquals("Decoded salt should be 16 bytes", 16, decoded.size)
    }

    // ── Hash Determinism ─────────────────────────────────────────────

    @Test
    fun `hash produces same output for same PIN and salt`() {
        val salt = PinHasher.generateSalt()
        val hash1 = PinHasher.hash("1234", salt)
        val hash2 = PinHasher.hash("1234", salt)
        assertEquals("Same PIN + salt should produce same hash", hash1, hash2)
    }

    @Test
    fun `hash produces different output for different PINs`() {
        val salt = PinHasher.generateSalt()
        val hash1 = PinHasher.hash("1234", salt)
        val hash2 = PinHasher.hash("5678", salt)
        assertNotEquals("Different PINs should produce different hashes", hash1, hash2)
    }

    @Test
    fun `hash produces different output for different salts`() {
        val salt1 = PinHasher.generateSalt()
        val salt2 = PinHasher.generateSalt()
        val hash1 = PinHasher.hash("1234", salt1)
        val hash2 = PinHasher.hash("1234", salt2)
        assertNotEquals("Same PIN with different salts should produce different hashes", hash1, hash2)
    }

    @Test
    fun `hash returns valid base64 of 256-bit key`() {
        val salt = PinHasher.generateSalt()
        val hash = PinHasher.hash("1234", salt)
        val decoded = java.util.Base64.getDecoder().decode(hash)
        assertEquals("Hash should be 32 bytes (256 bits)", 32, decoded.size)
    }

    // ── PIN Verification ─────────────────────────────────────────────

    @Test
    fun `verify returns true for correct PIN`() {
        val salt = PinHasher.generateSalt()
        val hash = PinHasher.hash("1234", salt)
        assertTrue("Correct PIN should verify", PinHasher.verify("1234", hash, salt))
    }

    @Test
    fun `verify returns false for incorrect PIN`() {
        val salt = PinHasher.generateSalt()
        val hash = PinHasher.hash("1234", salt)
        assertFalse("Wrong PIN should not verify", PinHasher.verify("5678", hash, salt))
    }

    @Test
    fun `verify returns false for wrong salt`() {
        val salt1 = PinHasher.generateSalt()
        val salt2 = PinHasher.generateSalt()
        val hash = PinHasher.hash("1234", salt1)
        assertFalse("Correct PIN with wrong salt should not verify", PinHasher.verify("1234", hash, salt2))
    }

    @Test(expected = IllegalArgumentException::class)
    fun `hash rejects empty PIN`() {
        val salt = PinHasher.generateSalt()
        PinHasher.hash("", salt) // Should throw
    }

    @Test(expected = IllegalArgumentException::class)
    fun `verify rejects empty PIN`() {
        val salt = PinHasher.generateSalt()
        val hash = PinHasher.hash("1234", salt)
        PinHasher.verify("", hash, salt) // Should throw
    }

    // ── Various PIN Lengths ──────────────────────────────────────────

    @Test
    fun `hash and verify works with 4-digit PIN`() {
        val salt = PinHasher.generateSalt()
        val hash = PinHasher.hash("0000", salt)
        assertTrue(PinHasher.verify("0000", hash, salt))
        assertFalse(PinHasher.verify("0001", hash, salt))
    }

    @Test
    fun `hash and verify works with 6-digit PIN`() {
        val salt = PinHasher.generateSalt()
        val hash = PinHasher.hash("123456", salt)
        assertTrue(PinHasher.verify("123456", hash, salt))
        assertFalse(PinHasher.verify("123457", hash, salt))
    }

    @Test
    fun `hash and verify works with single digit PIN`() {
        val salt = PinHasher.generateSalt()
        val hash = PinHasher.hash("7", salt)
        assertTrue(PinHasher.verify("7", hash, salt))
        assertFalse(PinHasher.verify("8", hash, salt))
    }

    // ── Constant-Time Comparison ─────────────────────────────────────

    @Test
    fun `verify rejects hash of different length`() {
        val salt = PinHasher.generateSalt()
        val hash = PinHasher.hash("1234", salt)
        // Append extra characters to make length differ
        assertFalse("Modified-length hash should not verify", PinHasher.verify("1234", hash + "A", salt))
    }

    @Test
    fun `verify rejects truncated hash`() {
        val salt = PinHasher.generateSalt()
        val hash = PinHasher.hash("1234", salt)
        assertFalse("Truncated hash should not verify", PinHasher.verify("1234", hash.dropLast(1), salt))
    }

    // ── Edge Cases ───────────────────────────────────────────────────

    @Test
    fun `hash works with special character PINs`() {
        // Even though we restrict to digits in UI, the hasher should handle any string
        val salt = PinHasher.generateSalt()
        val hash = PinHasher.hash("abc!", salt)
        assertTrue(PinHasher.verify("abc!", hash, salt))
        assertFalse(PinHasher.verify("abc?", hash, salt))
    }

    @Test
    fun `hash works with very long input`() {
        val salt = PinHasher.generateSalt()
        val longPin = "1".repeat(100)
        val hash = PinHasher.hash(longPin, salt)
        assertTrue(PinHasher.verify(longPin, hash, salt))
    }
}
