package com.chartlite.app.auth

import android.security.keystore.KeyGenParameterSpec
import android.security.keystore.KeyProperties
import android.util.Base64
import android.util.Log
import com.chartlite.app.asr.cloud.SharedHttpClient
import kotlinx.coroutines.Dispatchers
import kotlinx.coroutines.withContext
import okhttp3.MediaType.Companion.toMediaType
import okhttp3.Request
import okhttp3.RequestBody.Companion.toRequestBody
import org.json.JSONObject
import java.security.KeyPairGenerator
import java.security.KeyStore
import java.security.Signature
import java.security.spec.ECGenParameterSpec

/**
 * Non-GMS proxy auth flow backed by an Android Keystore device key.
 *
 * The private key never leaves the device. The Worker stores only the public
 * key after a one-time enrollment-code exchange, then issues session tokens
 * after a signed challenge-response.
 */
class DeviceKeyAuthManager(
    private val deviceId: String,
    private val enrollmentCodeProvider: () -> String,
    private val onEnrollmentSuccess: () -> Unit = {},
    private val proxyBaseUrl: String = PROXY_BASE_URL
) {

    companion object {
        private const val TAG = "DeviceKeyAuth"
        private const val PROXY_BASE_URL = "https://api.chartlite.health"
        private const val KEYSTORE_NAME = "AndroidKeyStore"
        private const val KEY_ALIAS_PREFIX = "chartlite_proxy_auth_v1"

        private const val MISSING_CODE_MESSAGE =
            "ChartLite Cloud on this device requires a one-time enrollment code in Settings."
        private const val INVALID_CODE_MESSAGE =
            "ChartLite Cloud enrollment code was rejected. Update it in Settings and try again."
        private const val REENROLL_MESSAGE =
            "ChartLite Cloud device authentication failed. Re-enter the enrollment code and try again."
    }

    /** One-shot enrollment attempt — returns success or a user-readable error. */
    suspend fun testEnrollment(code: String): EnrollmentResult = withContext(Dispatchers.IO) {
        if (code.isBlank()) return@withContext EnrollmentResult.Error("Enter the enrollment code first.")
        return@withContext try {
            enrollDevice(code)
            EnrollmentResult.Success
        } catch (e: ProxyAuthException) {
            EnrollmentResult.Error(e.message ?: "Enrollment failed.")
        } catch (e: Exception) {
            EnrollmentResult.Error("Network error: ${e.message ?: "check your connection."}")
        }
    }

    sealed class EnrollmentResult {
        object Success : EnrollmentResult()
        data class Error(val message: String) : EnrollmentResult()
    }

    suspend fun refreshSession(): PlayIntegrityManager.SessionInfo = withContext(Dispatchers.IO) {
        var challenge = requestChallenge()
        if (challenge == null) {
            enrollDeviceOrThrow()
            challenge = requestChallenge()
                ?: throw ProxyAuthException("ChartLite Cloud device enrollment did not complete.")
        }

        try {
            exchangeSignedChallenge(challenge)
        } catch (e: DeviceAuthHttpException) {
            if ((e.statusCode == 403 || e.statusCode == 404) && enrollmentCodeProvider().trim().isNotBlank()) {
                Log.w(TAG, "Device auth needs re-enrollment: ${e.message}")
                enrollDevice(enrollmentCodeProvider().trim())
                val retryChallenge = requestChallenge()
                    ?: throw ProxyAuthException("ChartLite Cloud device enrollment did not complete.")
                exchangeSignedChallenge(retryChallenge)
            } else {
                throw ProxyAuthException(REENROLL_MESSAGE)
            }
        }
    }

    private suspend fun enrollDeviceOrThrow() {
        val enrollmentCode = enrollmentCodeProvider().trim()
        if (enrollmentCode.isBlank()) {
            throw ProxyAuthException(MISSING_CODE_MESSAGE)
        }
        enrollDevice(enrollmentCode)
    }

    private suspend fun enrollDevice(enrollmentCode: String) {
        val requestBody = JSONObject().apply {
            put("device_id", deviceId)
            put("public_key_spki", getOrCreatePublicKeySpki())
            put("enrollment_code", enrollmentCode)
        }.toString()

        val request = Request.Builder()
            .url("$proxyBaseUrl/v1/auth/device/enroll")
            .addHeader("Content-Type", "application/json")
            .post(requestBody.toRequestBody("application/json".toMediaType()))
            .build()

        SharedHttpClient.instance.newCall(request).execute().use { response ->
            val responseBody = response.body?.string().orEmpty()
            when {
                response.isSuccessful -> onEnrollmentSuccess()
                response.code == 403 -> throw ProxyAuthException(INVALID_CODE_MESSAGE)
                response.code == 503 -> throw ProxyAuthException(
                    "ChartLite Cloud device enrollment is not configured on the server."
                )
                else -> throw ProxyAuthException(
                    "ChartLite Cloud device enrollment failed (${response.code}): ${extractError(responseBody)}"
                )
            }
        }
    }

    private suspend fun requestChallenge(): ChallengeInfo? {
        val requestBody = JSONObject().apply {
            put("device_id", deviceId)
        }.toString()

        val request = Request.Builder()
            .url("$proxyBaseUrl/v1/auth/device/challenge")
            .addHeader("Content-Type", "application/json")
            .post(requestBody.toRequestBody("application/json".toMediaType()))
            .build()

        SharedHttpClient.instance.newCall(request).execute().use { response ->
            val responseBody = response.body?.string().orEmpty()
            if (response.isSuccessful) {
                val json = JSONObject(responseBody)
                return ChallengeInfo(
                    id = json.getString("challenge_id"),
                    challenge = json.getString("challenge"),
                )
            }
            if (response.code == 404) {
                return null
            }
            throw ProxyAuthException(
                "ChartLite Cloud device challenge failed (${response.code}): ${extractError(responseBody)}"
            )
        }
    }

    private suspend fun exchangeSignedChallenge(challenge: ChallengeInfo): PlayIntegrityManager.SessionInfo {
        val requestBody = JSONObject().apply {
            put("device_id", deviceId)
            put("challenge_id", challenge.id)
            put("signature", signChallenge(challenge.challenge))
        }.toString()

        val request = Request.Builder()
            .url("$proxyBaseUrl/v1/auth/device/session")
            .addHeader("Content-Type", "application/json")
            .post(requestBody.toRequestBody("application/json".toMediaType()))
            .build()

        SharedHttpClient.instance.newCall(request).execute().use { response ->
            val responseBody = response.body?.string().orEmpty()
            if (!response.isSuccessful) {
                if (response.code == 403 || response.code == 404) {
                    throw DeviceAuthHttpException(response.code, extractError(responseBody))
                }
                throw ProxyAuthException(
                    "ChartLite Cloud device authentication failed (${response.code}): ${extractError(responseBody)}"
                )
            }

            val json = JSONObject(responseBody)
            return PlayIntegrityManager.SessionInfo(
                token = json.getString("session_token"),
                expiresAt = json.getLong("expires_at"),
            )
        }
    }

    private fun getOrCreatePublicKeySpki(): String {
        val keyStore = loadKeyStore()
        if (!keyStore.containsAlias(keyAlias)) {
            generateKeyPair()
        }

        val certificate = loadKeyStore().getCertificate(keyAlias)
            ?: throw ProxyAuthException("This device could not create a secure ChartLite Cloud key.")
        return Base64.encodeToString(certificate.publicKey.encoded, Base64.NO_WRAP)
    }

    private fun signChallenge(challengeBase64: String): String {
        val keyStore = loadKeyStore()
        val privateKey = keyStore.getKey(keyAlias, null)
            ?: throw ProxyAuthException(REENROLL_MESSAGE)

        val signature = Signature.getInstance("SHA256withECDSA")
        signature.initSign(privateKey as java.security.PrivateKey)
        signature.update(Base64.decode(challengeBase64, Base64.DEFAULT))
        // Android produces DER-encoded ECDSA (ASN.1 SEQUENCE { r, s }).
        // Cloudflare Workers use WebCrypto (SubtleCrypto.verify) which requires raw r‖s
        // (64 bytes for P-256: 32-byte r followed by 32-byte s, no ASN.1 wrapper).
        val rawSignature = ecdsaDerToRaw(signature.sign())
        return Base64.encodeToString(rawSignature, Base64.NO_WRAP)
    }

    /**
     * Convert a DER-encoded ECDSA signature to raw r‖s format.
     *
     * DER layout:  30 [seq-len] 02 [r-len] [r-bytes] 02 [s-len] [s-bytes]
     * Raw layout:  [r padded to componentSize] || [s padded to componentSize]
     *
     * The r/s INTEGERs may carry a leading 0x00 sign byte when the high bit is
     * set; that byte is stripped.  Each component is left-zero-padded to exactly
     * [componentSize] bytes (32 for P-256 / secp256r1).
     */
    private fun ecdsaDerToRaw(der: ByteArray, componentSize: Int = 32): ByteArray {
        var pos = 0
        require(der[pos++].toInt() and 0xFF == 0x30) { "Expected SEQUENCE tag" }
        // Skip sequence length — may be short-form (1 byte) or long-form (0x81 + 1 byte)
        val seqLenByte = der[pos++].toInt() and 0xFF
        if (seqLenByte and 0x80 != 0) pos += seqLenByte and 0x7F

        fun readInteger(): ByteArray {
            require(der[pos++].toInt() and 0xFF == 0x02) { "Expected INTEGER tag" }
            val len = der[pos++].toInt() and 0xFF
            val bytes = der.copyOfRange(pos, pos + len)
            pos += len
            return bytes
        }

        fun normalise(bytes: ByteArray): ByteArray {
            // Strip leading sign byte (0x00) added when high bit is set
            val stripped = if (bytes.isNotEmpty() && bytes[0] == 0x00.toByte())
                bytes.copyOfRange(1, bytes.size) else bytes
            return when {
                stripped.size == componentSize -> stripped
                stripped.size < componentSize -> ByteArray(componentSize - stripped.size) + stripped
                else -> stripped.copyOfRange(stripped.size - componentSize, stripped.size)
            }
        }

        val r = normalise(readInteger())
        val s = normalise(readInteger())
        return r + s
    }

    private fun generateKeyPair() {
        try {
            val keyPairGenerator = KeyPairGenerator.getInstance(
                KeyProperties.KEY_ALGORITHM_EC,
                KEYSTORE_NAME,
            )
            val spec = KeyGenParameterSpec.Builder(
                keyAlias,
                KeyProperties.PURPOSE_SIGN or KeyProperties.PURPOSE_VERIFY,
            )
                .setAlgorithmParameterSpec(ECGenParameterSpec("secp256r1"))
                .setDigests(KeyProperties.DIGEST_SHA256)
                .build()
            keyPairGenerator.initialize(spec)
            keyPairGenerator.generateKeyPair()
        } catch (e: Exception) {
            Log.e(TAG, "Failed to generate device auth key", e)
            throw ProxyAuthException("This device cannot create a secure ChartLite Cloud key.")
        }
    }

    private fun loadKeyStore(): KeyStore = KeyStore.getInstance(KEYSTORE_NAME).apply {
        load(null)
    }

    private fun extractError(responseBody: String): String {
        return try {
            JSONObject(responseBody).optString("error").ifBlank { "Unknown error" }
        } catch (_: Exception) {
            responseBody.take(120).ifBlank { "Unknown error" }
        }
    }

    private val keyAlias: String = buildString {
        append(KEY_ALIAS_PREFIX)
        append('_')
        append(deviceId.replace(Regex("[^A-Za-z0-9_]"), "_"))
    }

    private data class ChallengeInfo(
        val id: String,
        val challenge: String,
    )

    private class DeviceAuthHttpException(
        val statusCode: Int,
        override val message: String,
    ) : Exception(message)
}
