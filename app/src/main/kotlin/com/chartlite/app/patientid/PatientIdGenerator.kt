package com.chartlite.app.patientid

import java.math.BigInteger
import java.security.SecureRandom

object PatientIdGenerator {

    // 28 chars: A-Z minus I,L,O,S plus 2-7
    private const val ALPHABET = "ABCDEFGHJKMNPQRTUVWXYZ234567"

    /** Max attempts before giving up on finding a unique ID (extremely unlikely to hit). */
    private const val MAX_COLLISION_RETRIES = 10

    fun generate(): String {
        val bytes = ByteArray(5) // 40 bits of entropy
        SecureRandom().nextBytes(bytes)

        val chars = StringBuilder()
        var value = BigInteger(1, bytes)
        val base = BigInteger.valueOf(ALPHABET.length.toLong())

        repeat(8) {
            val (quotient, remainder) = value.divideAndRemainder(base)
            chars.append(ALPHABET[remainder.toInt()])
            value = quotient
        }

        return "${chars.substring(0, 4)}-${chars.substring(4, 8)}"
    }

    /**
     * Generate a unique patient ID, checking against existing IDs.
     * With 28^8 (~550 billion) possible IDs, collisions are extremely rare,
     * but this ensures safety as the patient base grows.
     *
     * @param existsCheck Suspend function that returns true if the ID already exists in the database.
     * @throws IllegalStateException if a unique ID cannot be generated after [MAX_COLLISION_RETRIES] attempts.
     */
    suspend fun generateUnique(existsCheck: suspend (String) -> Boolean): String {
        repeat(MAX_COLLISION_RETRIES) {
            val id = generate()
            if (!existsCheck(id)) return id
        }
        throw IllegalStateException("Failed to generate unique patient ID after $MAX_COLLISION_RETRIES attempts")
    }

    fun isValid(id: String): Boolean {
        val cleaned = id.uppercase().replace("-", "")
        if (cleaned.length != 8) return false
        return cleaned.all { it in ALPHABET }
    }

    fun normalize(id: String): String {
        val cleaned = id.uppercase().replace("-", "").replace(" ", "")
        if (cleaned.length != 8) return id
        return "${cleaned.substring(0, 4)}-${cleaned.substring(4, 8)}"
    }
}
