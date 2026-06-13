package com.chartlite.app

import com.chartlite.app.sms.SMSEncryption
import org.junit.Assert.*
import org.junit.Test
import java.util.Base64
import javax.crypto.AEADBadTagException

class SMSEncryptionTest {

    // ── Key Derivation ──────────────────────────────────────────────

    @Test
    fun `deriveKey produces same key for same inputs`() {
        val key1 = SMSEncryption.deriveKey("9001015009087", "1234")
        val key2 = SMSEncryption.deriveKey("9001015009087", "1234")
        assertArrayEquals(key1.encoded, key2.encoded)
    }

    @Test
    fun `deriveKey produces different key for different nationalId`() {
        val key1 = SMSEncryption.deriveKey("9001015009087", "1234")
        val key2 = SMSEncryption.deriveKey("8501015009087", "1234")
        assertFalse(
            "Keys should differ for different national IDs",
            key1.encoded.contentEquals(key2.encoded)
        )
    }

    @Test
    fun `deriveKey produces different key for different PIN`() {
        val key1 = SMSEncryption.deriveKey("9001015009087", "1234")
        val key2 = SMSEncryption.deriveKey("9001015009087", "5678")
        assertFalse(
            "Keys should differ for different PINs",
            key1.encoded.contentEquals(key2.encoded)
        )
    }

    @Test
    fun `deriveKey returns 256-bit AES key`() {
        val key = SMSEncryption.deriveKey("9001015009087", "1234")
        assertEquals("AES", key.algorithm)
        assertEquals(32, key.encoded.size) // 256 bits = 32 bytes
    }

    // ── Encrypt-Decrypt Round Trip ──────────────────────────────────

    @Test
    fun `encrypt-decrypt round trip preserves payload`() {
        val key = SMSEncryption.deriveKey("9001015009087", "1234")
        val payload = ByteArray(92) { it.toByte() }
        val encrypted = SMSEncryption.encrypt(payload, key)
        val decrypted = SMSEncryption.decrypt(encrypted, key)
        assertArrayEquals(payload, decrypted)
    }

    @Test
    fun `encrypt-decrypt with small payload`() {
        val key = SMSEncryption.deriveKey("9001015009087", "1234")
        val payload = ByteArray(10) { (it * 3).toByte() }
        val encrypted = SMSEncryption.encrypt(payload, key)
        val decrypted = SMSEncryption.decrypt(encrypted, key)
        assertArrayEquals(payload, decrypted)
    }

    @Test
    fun `encrypt produces different ciphertext each time`() {
        val key = SMSEncryption.deriveKey("9001015009087", "1234")
        val payload = ByteArray(92) { 0x42 }
        val encrypted1 = SMSEncryption.encrypt(payload, key)
        val encrypted2 = SMSEncryption.encrypt(payload, key)
        assertNotEquals(
            "Two encryptions of the same payload should differ (random nonce)",
            encrypted1,
            encrypted2
        )
    }

    @Test
    fun `encrypted output is valid base64`() {
        val key = SMSEncryption.deriveKey("9001015009087", "1234")
        val payload = ByteArray(92) { it.toByte() }
        val encrypted = SMSEncryption.encrypt(payload, key)
        // Should not throw; Base64 decoder accepts without-padding output
        val decoded = Base64.getDecoder().decode(encrypted)
        assertTrue("Decoded bytes should be non-empty", decoded.isNotEmpty())
    }

    // ── Decryption Failures ─────────────────────────────────────────

    @Test(expected = AEADBadTagException::class)
    fun `decrypt with wrong key throws exception`() {
        val correctKey = SMSEncryption.deriveKey("9001015009087", "1234")
        val wrongKey = SMSEncryption.deriveKey("9001015009087", "9999")
        val payload = ByteArray(50) { it.toByte() }
        val encrypted = SMSEncryption.encrypt(payload, correctKey)
        SMSEncryption.decrypt(encrypted, wrongKey)
    }

    @Test
    fun `decrypt with tampered ciphertext throws`() {
        val key = SMSEncryption.deriveKey("9001015009087", "1234")
        val payload = ByteArray(50) { it.toByte() }
        val encrypted = SMSEncryption.encrypt(payload, key)

        // Decode, flip a byte in the ciphertext portion, re-encode
        val raw = Base64.getDecoder().decode(encrypted)
        raw[raw.size - 1] = (raw[raw.size - 1].toInt() xor 0xFF).toByte()
        val tampered = Base64.getEncoder().withoutPadding().encodeToString(raw)

        try {
            SMSEncryption.decrypt(tampered, key)
            fail("Expected exception for tampered ciphertext")
        } catch (_: AEADBadTagException) {
            // expected
        }
    }

    @Test(expected = IllegalArgumentException::class)
    fun `decrypt with too-short input throws`() {
        val key = SMSEncryption.deriveKey("9001015009087", "1234")
        // 20 bytes < 28 minimum (12 nonce + 16 tag)
        val shortData = ByteArray(20) { it.toByte() }
        val encoded = Base64.getEncoder().withoutPadding().encodeToString(shortData)
        SMSEncryption.decrypt(encoded, key)
    }

    @Test(expected = IllegalArgumentException::class)
    fun `encrypt rejects payload over 92 bytes`() {
        val key = SMSEncryption.deriveKey("9001015009087", "1234")
        val oversized = ByteArray(93) { it.toByte() }
        SMSEncryption.encrypt(oversized, key)
    }

    // ── Clinical SMS Detection ──────────────────────────────────────

    @Test
    fun `looksLikeClinicalSMS true for valid encrypted SMS`() {
        val key = SMSEncryption.deriveKey("9001015009087", "1234")
        val payload = ByteArray(92) { it.toByte() }
        val encrypted = SMSEncryption.encrypt(payload, key)
        assertTrue(
            "Encrypted 92-byte payload should be recognized as clinical SMS",
            SMSEncryption.looksLikeClinicalSMS(encrypted)
        )
    }

    @Test
    fun `looksLikeClinicalSMS false for short text`() {
        assertFalse(SMSEncryption.looksLikeClinicalSMS("hello"))
    }

    @Test
    fun `looksLikeClinicalSMS false for plain English`() {
        val text = "Please pick up your prescription from the pharmacy on Main Street tomorrow morning."
        assertFalse(SMSEncryption.looksLikeClinicalSMS(text))
    }

    @Test
    fun `looksLikeClinicalSMS false for very long text`() {
        val text = "A".repeat(300)
        assertFalse(SMSEncryption.looksLikeClinicalSMS(text))
    }
}
