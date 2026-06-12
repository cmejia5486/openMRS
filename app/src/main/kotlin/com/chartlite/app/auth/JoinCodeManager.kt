package com.chartlite.app.auth

import com.chartlite.app.config.AppConfig
import com.google.gson.Gson
import com.google.gson.reflect.TypeToken
import java.security.SecureRandom

/**
 * Manages facility join codes for self-service user registration.
 *
 * Admin generates a 6-digit code tied to a specific role. New staff enter the code
 * on the login screen to create their own account without needing admin to manually
 * create it. Codes expire after 24 hours and are single-use.
 *
 * Codes are stored device-locally in AppConfig (EncryptedSharedPreferences).
 */
class JoinCodeManager(private val appConfig: AppConfig) {

    private val gson = Gson()
    private val random = SecureRandom()

    data class JoinCode(
        val code: String,
        val role: String,
        val createdBy: String,
        val expiresAt: Long
    )

    /**
     * Generate a new 6-digit join code for the given role.
     * Valid for 24 hours. Returns the code string.
     */
    fun generate(role: UserRole, createdBy: String): String {
        cleanup() // Remove expired codes first

        val code = String.format("%06d", random.nextInt(1_000_000))
        val joinCode = JoinCode(
            code = code,
            role = role.name,
            createdBy = createdBy,
            expiresAt = System.currentTimeMillis() + 24 * 60 * 60 * 1000L
        )

        val codes = loadCodes().toMutableList()
        codes.add(joinCode)
        saveCodes(codes)

        return code
    }

    /**
     * Validate a join code. Returns the role if valid, null if invalid/expired.
     */
    fun validate(code: String): JoinCode? {
        cleanup()
        return loadCodes().find { it.code == code.trim() }
    }

    /**
     * Consume (delete) a join code after successful registration.
     */
    fun consume(code: String) {
        val codes = loadCodes().toMutableList()
        codes.removeAll { it.code == code.trim() }
        saveCodes(codes)
    }

    /**
     * Revoke a specific join code (admin action).
     */
    fun revoke(code: String) = consume(code)

    /**
     * Get all active (non-expired) join codes.
     */
    fun getActiveCodes(): List<JoinCode> {
        cleanup()
        return loadCodes()
    }

    /**
     * Remove expired codes.
     */
    fun cleanup() {
        val now = System.currentTimeMillis()
        val codes = loadCodes().filter { it.expiresAt > now }
        saveCodes(codes)
    }

    private fun loadCodes(): List<JoinCode> {
        return try {
            val type = object : TypeToken<List<JoinCode>>() {}.type
            gson.fromJson<List<JoinCode>>(appConfig.joinCodes, type) ?: emptyList()
        } catch (_: Exception) {
            emptyList()
        }
    }

    private fun saveCodes(codes: List<JoinCode>) {
        appConfig.joinCodes = gson.toJson(codes)
    }
}
