package com.chartlite.app.auth

import java.security.SecureRandom
import java.util.Base64
import javax.crypto.SecretKeyFactory
import javax.crypto.spec.PBEKeySpec

/**
 * PBKDF2-HMAC-SHA256 PIN hasher for user authentication.
 * Uses the same security pattern as SMSEncryption but with per-user random salts.
 */
object PinHasher {

    private const val ITERATIONS = 100_000
    private const val KEY_LENGTH = 256
    private const val SALT_LENGTH = 16

    /**
     * Generate a random salt for a new user.
     */
    fun generateSalt(): String {
        val salt = ByteArray(SALT_LENGTH)
        SecureRandom().nextBytes(salt)
        return Base64.getEncoder().encodeToString(salt)
    }

    /**
     * Hash a PIN with the given salt using PBKDF2.
     * Returns Base64-encoded hash.
     */
    fun hash(pin: String, saltBase64: String): String {
        require(pin.isNotEmpty()) { "PIN must not be empty" }
        require(saltBase64.isNotBlank()) { "Salt must not be blank" }
        val salt = Base64.getDecoder().decode(saltBase64)
        val spec = PBEKeySpec(pin.toCharArray(), salt, ITERATIONS, KEY_LENGTH)
        try {
            val factory = SecretKeyFactory.getInstance("PBKDF2WithHmacSHA256")
            val keyBytes = factory.generateSecret(spec).encoded
            return Base64.getEncoder().encodeToString(keyBytes)
        } finally {
            spec.clearPassword()
        }
    }

    /**
     * Verify a PIN against a stored hash+salt.
     */
    fun verify(pin: String, storedHash: String, saltBase64: String): Boolean {
        val computed = hash(pin, saltBase64)
        // Constant-time comparison to prevent timing attacks
        return computed.length == storedHash.length &&
            computed.indices.fold(0) { acc, i ->
                acc or (computed[i].code xor storedHash[i].code)
            } == 0
    }
}
