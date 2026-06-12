package com.chartlite.app.sms

import java.security.SecureRandom
import java.util.Base64
import javax.crypto.Cipher
import javax.crypto.SecretKey
import javax.crypto.SecretKeyFactory
import javax.crypto.spec.GCMParameterSpec
import javax.crypto.spec.PBEKeySpec
import javax.crypto.spec.SecretKeySpec

/**
 * Key derivation mode for SMS encryption.
 *
 * PHONE_NUMBER (default) — patient's phone number is the key. Simple, practical,
 * everyone knows their own number. Already a massive upgrade over paper records
 * (which have zero encryption). If someone finds the SMS, they still need the
 * patient's phone number to decrypt it.
 *
 * PHONE_WITH_PIN — for shared-phone households. Phone number + optional 4-digit
 * PIN chosen by the patient. Protects privacy between family members sharing
 * a device. PIN is patient-initiated, never forced.
 *
 * NATIONAL_ID_PIN — for countries that require stronger consent
 * (e.g., South Africa with National IDs). Uses National ID + 4-digit PIN.
 */
enum class KeyMode {
    PHONE_NUMBER,
    PHONE_WITH_PIN,
    NATIONAL_ID_PIN
}

object SMSEncryption {

    private const val STATIC_SALT = "ChartLite-PHR-v1"
    @Deprecated("Use STATIC_SALT") private const val LEGACY_SALT = "AfriMedASR-v1"
    private const val PBKDF2_ITERATIONS = 100_000
    private const val KEY_LENGTH = 256
    private const val SALT_LENGTH = 16
    private const val GCM_NONCE_LENGTH = 12
    private const val GCM_TAG_LENGTH = 128

    /**
     * Derive AES-256 key using a random salt (new format) or legacy static salt.
     */
    private fun deriveKeyWithSalt(password: String, salt: ByteArray): SecretKey {
        val spec = PBEKeySpec(password.toCharArray(), salt, PBKDF2_ITERATIONS, KEY_LENGTH)
        val factory = SecretKeyFactory.getInstance("PBKDF2WithHmacSHA256")
        val keyBytes = factory.generateSecret(spec).encoded
        return SecretKeySpec(keyBytes, "AES")
    }

    /**
     * Derive AES-256 key from patient's phone number (default mode).
     * Uses the legacy static salt for backward compatibility with the key-based API.
     * The password-based encrypt() uses random salts internally.
     */
    fun deriveKey(phoneNumber: String): SecretKey =
        deriveKeyWithSalt(phoneNumber, STATIC_SALT.toByteArray())

    /**
     * Derive AES-256 key from phone number + optional PIN (shared-phone mode).
     * When PIN is null/blank, falls back to phone-number-only derivation.
     * Uses the legacy static salt for backward compatibility with the key-based API.
     */
    fun deriveKey(phoneNumber: String, pin: String?): SecretKey {
        val password = if (pin.isNullOrBlank()) phoneNumber else "$phoneNumber:$pin"
        return deriveKeyWithSalt(password, STATIC_SALT.toByteArray())
    }

    /**
     * Derive AES-256 key from patient's national ID and PIN (enhanced mode).
     * For countries requiring stronger consent (e.g., South Africa).
     * Uses the legacy static salt for backward compatibility with the key-based API.
     */
    fun deriveKeyFromNationalId(nationalId: String, pin: String): SecretKey {
        val password = "$nationalId:$pin"
        return deriveKeyWithSalt(password, STATIC_SALT.toByteArray())
    }

    /**
     * Encrypt clinical payload to base64 string suitable for SMS.
     * New format layout: [salt:16][nonce:12][ciphertext+tag:payload_len+16]
     * Output: Base64 encoded string
     *
     * A random 16-byte salt is generated per encryption and prepended to the output.
     * The key is derived from the password and this random salt.
     */
    fun encrypt(payload: ByteArray, password: String): String {
        require(payload.size <= 92) { "Payload exceeds 92 bytes (got ${payload.size})" }

        val salt = ByteArray(SALT_LENGTH)
        SecureRandom().nextBytes(salt)
        val key = deriveKeyWithSalt(password, salt)

        val nonce = ByteArray(GCM_NONCE_LENGTH)
        SecureRandom().nextBytes(nonce)

        val cipher = Cipher.getInstance("AES/GCM/NoPadding")
        cipher.init(Cipher.ENCRYPT_MODE, key, GCMParameterSpec(GCM_TAG_LENGTH, nonce))
        val ciphertext = cipher.doFinal(payload)

        // salt (16) + nonce (12) + ciphertext (payload_len) + GCM tag (16)
        val output = salt + nonce + ciphertext
        return Base64.getEncoder().withoutPadding().encodeToString(output)
    }

    /**
     * V4 encrypt using static salt — no salt prefix in output.
     * Layout: [nonce:12][ciphertext+tag:payload_len+16]
     * For 92-byte payload: 12 + 92 + 16 = 120 bytes → Base64 = 160 chars = 1 SMS.
     */
    fun encryptV4(payload: ByteArray, password: String): String {
        require(payload.size <= 92) { "V4 payload exceeds 92 bytes (got ${payload.size})" }

        val key = deriveKeyWithSalt(password, STATIC_SALT.toByteArray())

        val nonce = ByteArray(GCM_NONCE_LENGTH)
        SecureRandom().nextBytes(nonce)

        val cipher = Cipher.getInstance("AES/GCM/NoPadding")
        cipher.init(Cipher.ENCRYPT_MODE, key, GCMParameterSpec(GCM_TAG_LENGTH, nonce))
        val ciphertext = cipher.doFinal(payload)

        // nonce (12) + ciphertext (payload_len) + GCM tag (16)
        val output = nonce + ciphertext
        return Base64.getEncoder().withoutPadding().encodeToString(output)
    }

    /**
     * Legacy encrypt using a pre-derived key (old format without salt prefix).
     * Layout: [nonce:12][ciphertext+tag:payload_len+16]
     * @deprecated Use encrypt(payload, password) instead for random-salt encryption.
     */
    @Deprecated("Use encrypt(payload, password) for random-salt encryption", ReplaceWith("encrypt(payload, password)"))
    fun encrypt(payload: ByteArray, key: SecretKey): String {
        require(payload.size <= 92) { "Payload exceeds 92 bytes (got ${payload.size})" }

        val nonce = ByteArray(GCM_NONCE_LENGTH)
        SecureRandom().nextBytes(nonce)

        val cipher = Cipher.getInstance("AES/GCM/NoPadding")
        cipher.init(Cipher.ENCRYPT_MODE, key, GCMParameterSpec(GCM_TAG_LENGTH, nonce))
        val ciphertext = cipher.doFinal(payload)

        // nonce (12) + ciphertext (payload_len) + GCM tag (16)
        val output = nonce + ciphertext
        return Base64.getEncoder().withoutPadding().encodeToString(output)
    }

    /**
     * Decrypt SMS content back to clinical payload.
     * Tries new format first (salt:16 + nonce:12 + ciphertext+tag), then falls
     * back to legacy format (nonce:12 + ciphertext+tag with static salt) for
     * backward compatibility with existing encrypted SMS messages.
     */
    fun decrypt(smsContent: String, password: String): ByteArray {
        val raw = Base64.getDecoder().decode(smsContent)
        require(raw.size > GCM_NONCE_LENGTH + 16) { "SMS content too short to be valid" }

        // Try new format first: [salt:16][nonce:12][ciphertext+tag]
        if (raw.size > SALT_LENGTH + GCM_NONCE_LENGTH + 16) {
            try {
                val salt = raw.sliceArray(0 until SALT_LENGTH)
                val nonce = raw.sliceArray(SALT_LENGTH until SALT_LENGTH + GCM_NONCE_LENGTH)
                val ciphertext = raw.sliceArray(SALT_LENGTH + GCM_NONCE_LENGTH until raw.size)
                val key = deriveKeyWithSalt(password, salt)

                val cipher = Cipher.getInstance("AES/GCM/NoPadding")
                cipher.init(Cipher.DECRYPT_MODE, key, GCMParameterSpec(GCM_TAG_LENGTH, nonce))
                return cipher.doFinal(ciphertext)
            } catch (_: Exception) {
                // New format failed, try legacy format below
            }
        }

        // Static-salt format: [nonce:12][ciphertext+tag]
        // Try current salt first, then legacy salt for backward compatibility
        val nonce = raw.sliceArray(0 until GCM_NONCE_LENGTH)
        val ciphertext = raw.sliceArray(GCM_NONCE_LENGTH until raw.size)
        for (saltStr in listOf(STATIC_SALT, LEGACY_SALT)) {
            try {
                val key = deriveKeyWithSalt(password, saltStr.toByteArray(Charsets.UTF_8))
                val cipher = Cipher.getInstance("AES/GCM/NoPadding")
                cipher.init(Cipher.DECRYPT_MODE, key, GCMParameterSpec(GCM_TAG_LENGTH, nonce))
                return cipher.doFinal(ciphertext)
            } catch (_: Exception) { /* try next */ }
        }
        throw javax.crypto.AEADBadTagException("Decryption failed with all salt variants")
    }

    /**
     * Legacy decrypt using a pre-derived key (old format).
     * Kept for backward compatibility with code that already derives keys externally.
     */
    fun decrypt(smsContent: String, key: SecretKey): ByteArray {
        val raw = Base64.getDecoder().decode(smsContent)
        require(raw.size > GCM_NONCE_LENGTH + 16) { "SMS content too short to be valid" }

        val nonce = raw.sliceArray(0 until GCM_NONCE_LENGTH)
        val ciphertext = raw.sliceArray(GCM_NONCE_LENGTH until raw.size)

        val cipher = Cipher.getInstance("AES/GCM/NoPadding")
        cipher.init(Cipher.DECRYPT_MODE, key, GCMParameterSpec(GCM_TAG_LENGTH, nonce))
        return cipher.doFinal(ciphertext)
    }

    /**
     * Check if a string looks like an encrypted clinical SMS.
     */
    fun looksLikeClinicalSMS(text: String): Boolean {
        val trimmed = text.trim()
        if (trimmed.length < 100 || trimmed.length > 200) return false
        // Quick check: clinical SMS is pure Base64 (A-Z, a-z, 0-9, +, /, =)
        if (!trimmed.all { it.isLetterOrDigit() || it == '+' || it == '/' || it == '=' }) return false
        return try {
            // Use MIME decoder which is lenient with padding
            val decoded = Base64.getMimeDecoder().decode(trimmed)
            decoded.size > GCM_NONCE_LENGTH + 16
        } catch (_: Exception) {
            false
        }
    }
}
