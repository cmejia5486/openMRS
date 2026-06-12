package com.chartlite.app.auth

import android.content.Context
import android.util.Log
import com.chartlite.app.asr.cloud.SharedHttpClient
import com.google.android.play.core.integrity.IntegrityManagerFactory
import com.google.android.play.core.integrity.IntegrityTokenRequest
import kotlinx.coroutines.Dispatchers
import kotlinx.coroutines.suspendCancellableCoroutine
import kotlinx.coroutines.sync.Mutex
import kotlinx.coroutines.sync.withLock
import kotlinx.coroutines.withContext
import okhttp3.MediaType.Companion.toMediaType
import okhttp3.Request
import okhttp3.RequestBody.Companion.toRequestBody
import org.json.JSONObject
import java.security.MessageDigest
import kotlin.coroutines.resume
import kotlin.coroutines.resumeWithException

/**
 * Manages Play Integrity attestation and session tokens for proxy auth.
 *
 * Flow:
 *   1. Request Play Integrity token from Google (proves genuine app + device)
 *   2. Exchange it with our Worker for a short-lived session JWT (1-hour TTL)
 *   3. Use the JWT for all subsequent proxy requests (fast, local validation on Worker)
 *   4. When JWT expires, transparently refresh via new integrity token
 *
 * Non-GMS fallback:
 *   If Play Integrity is unavailable, use a device-bound Android Keystore key
 *   plus one-time server enrollment to mint the same session JWT format.
 */
class PlayIntegrityManager(
    private val context: Context,
    private val deviceId: String,
    deviceEnrollmentCodeProvider: () -> String,
    onDeviceEnrollmentSuccess: () -> Unit = {},
    private val proxyBaseUrl: String = PROXY_BASE_URL
) {

    companion object {
        private const val TAG = "PlayIntegrity"
        private const val PROXY_BASE_URL = "https://api.chartlite.health"
        private const val SESSION_MARGIN_MS = 5 * 60 * 1000L // Refresh 5 min before expiry
    }

    // In-memory session state (not persisted — regenerated on app restart)
    private var sessionToken: String? = null
    private var sessionExpiresAt: Long = 0L
    private val refreshMutex = Mutex() // Prevent concurrent refresh
    private var playIntegrityAvailable: Boolean? = null // Cached availability check
    private val deviceKeyAuthManager = DeviceKeyAuthManager(
        deviceId = deviceId,
        enrollmentCodeProvider = deviceEnrollmentCodeProvider,
        onEnrollmentSuccess = onDeviceEnrollmentSuccess,
        proxyBaseUrl = proxyBaseUrl,
    )

    /**
     * Get auth headers for a proxy request.
     *
     * Returns a session JWT header, refreshing it transparently if needed.
     */
    suspend fun getAuthHeaders(): Map<String, String> {
        // Fast path: valid session token
        val token = sessionToken
        if (token != null && System.currentTimeMillis() < sessionExpiresAt - SESSION_MARGIN_MS) {
            return mapOf("X-Session-Token" to token)
        }

        // Try to get/refresh a session token via Play Integrity or device-key auth
        val refreshed = tryRefreshSession()
        return mapOf("X-Session-Token" to refreshed)
    }

    /**
     * Check if Play Integrity is available on this device.
     */
    private fun isPlayIntegrityAvailable(): Boolean {
        playIntegrityAvailable?.let { return it }
        return try {
            // Check if Google Play Services is available
            val pm = context.packageManager
            pm.getPackageInfo("com.google.android.gms", 0)
            playIntegrityAvailable = true
            true
        } catch (e: Exception) {
            Log.d(TAG, "Play Integrity not available: ${e.message}")
            playIntegrityAvailable = false
            false
        }
    }

    /** Immediately test whether [code] is accepted by the server as an enrollment code. */
    suspend fun testDeviceEnrollment(code: String): DeviceKeyAuthManager.EnrollmentResult =
        deviceKeyAuthManager.testEnrollment(code)

    /**
     * Try to refresh the session token.
     */
    private suspend fun tryRefreshSession(): String = refreshMutex.withLock {
        // Double-check after acquiring lock (another coroutine may have refreshed)
        val token = sessionToken
        if (token != null && System.currentTimeMillis() < sessionExpiresAt - SESSION_MARGIN_MS) {
            return@withLock token
        }

        val session = if (isPlayIntegrityAvailable()) {
            try {
                refreshViaPlayIntegrity()
            } catch (e: ProxyAuthException) {
                // Play Integrity present but failed (debug build, emulator, cloud project not
                // configured) — fall back to device-key auth if an enrollment code is available.
                Log.d(TAG, "Play Integrity failed, trying device-key fallback: ${e.message}")
                deviceKeyAuthManager.refreshSession()
            }
        } else {
            Log.d(TAG, "Play Integrity unavailable, using device-key auth")
            deviceKeyAuthManager.refreshSession()
        }

        sessionToken = session.token
        sessionExpiresAt = session.expiresAt
        Log.d(TAG, "Session refreshed, expires in ${(session.expiresAt - System.currentTimeMillis()) / 1000}s")
        session.token
    }

    private suspend fun refreshViaPlayIntegrity(): SessionInfo {
        try {
            val timestamp = System.currentTimeMillis()
            val integrityToken = requestIntegrityToken(timestamp)
            return exchangeForSession(integrityToken, timestamp)
        } catch (e: Exception) {
            Log.w(TAG, "Play Integrity session refresh failed", e)
            throw ProxyAuthException("Play Integrity verification failed. ChartLite Cloud is unavailable right now.")
        }
    }

    /**
     * Request an integrity token from Google Play Integrity API.
     *
     * @param timestamp The exact timestamp used to generate the nonce. The same
     *   timestamp must be sent to the Worker in the session exchange so the server
     *   can recompute the nonce and verify it matches the verdict.
     */
    private suspend fun requestIntegrityToken(timestamp: Long): String {
        val nonce = generateNonce(timestamp)
        val integrityManager = IntegrityManagerFactory.create(context)

        return suspendCancellableCoroutine { cont ->
            val request = IntegrityTokenRequest.builder()
                .setNonce(nonce)
                .build()

            integrityManager.requestIntegrityToken(request)
                .addOnSuccessListener { response ->
                    cont.resume(response.token())
                }
                .addOnFailureListener { e ->
                    cont.resumeWithException(e)
                }
        }
    }

    /**
     * Exchange a Play Integrity token for a session JWT via the Worker.
     *
     * Sends the same timestamp that was used to generate the nonce, so the
     * Worker can recompute sha256(deviceId + ":" + timestamp) and verify it
     * matches the nonce in Google's verdict — binding the token to this request.
     */
    private suspend fun exchangeForSession(integrityToken: String, timestamp: Long): SessionInfo = withContext(Dispatchers.IO) {
        val body = JSONObject().apply {
            put("integrity_token", integrityToken)
            put("device_id", deviceId)
            put("timestamp", timestamp)
        }.toString()

        val request = Request.Builder()
            .url("$proxyBaseUrl/v1/auth/session")
            .addHeader("Content-Type", "application/json")
            .post(body.toRequestBody("application/json".toMediaType()))
            .build()

        SharedHttpClient.instance.newCall(request).execute().use { response ->
            val responseBody = response.body?.string() ?: throw Exception("Empty response")

            if (!response.isSuccessful) {
                throw Exception("Session exchange failed ${response.code}: ${responseBody.take(200)}")
            }

            val json = JSONObject(responseBody)
            SessionInfo(
                token = json.getString("session_token"),
                expiresAt = json.getLong("expires_at")
            )
        }
    }

    /**
     * Generate a nonce for the integrity token request.
     * base64url(SHA-256(deviceId + ":" + timestamp)) — binds token to device + moment.
     *
     * The Worker recomputes this same hash from the posted device_id + timestamp
     * and verifies it matches the nonce in Google's verdict, preventing replay
     * and device-ID spoofing.
     *
     * Note: Uses NO_PADDING (not NO_WRAP alone) to match Worker's base64url encoding
     * which strips trailing '=' characters.
     */
    private fun generateNonce(timestamp: Long): String {
        val input = "$deviceId:$timestamp"
        val digest = MessageDigest.getInstance("SHA-256").digest(input.toByteArray())
        return android.util.Base64.encodeToString(
            digest,
            android.util.Base64.URL_SAFE or android.util.Base64.NO_PADDING or android.util.Base64.NO_WRAP
        )
    }

    data class SessionInfo(val token: String, val expiresAt: Long)
}
