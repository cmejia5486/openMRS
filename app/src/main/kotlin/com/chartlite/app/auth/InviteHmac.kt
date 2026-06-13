package com.chartlite.app.auth

import android.util.Base64
import java.security.MessageDigest
import javax.crypto.Mac
import javax.crypto.spec.SecretKeySpec

/**
 * HMAC-based invite code signing for facility QR invites.
 *
 * The admin device holds a per-facility `inviteSecret` (256-bit random key stored in
 * EncryptedSharedPreferences). When generating a QR invite, the payload is HMAC-signed
 * so that forging a valid invite requires access to the secret.
 *
 * A 4-digit verbal confirmation code is derived from the HMAC tag. The admin reads it
 * aloud to the joining user, who enters it on their device. This provides a second
 * factor of verification beyond scanning the QR.
 */
object InviteHmac {

    private const val ALGORITHM = "HmacSHA256"

    /**
     * Compute HMAC-SHA256 tag over the invite payload fields.
     * @return Base64-encoded (NO_WRAP) HMAC tag
     */
    fun computeTag(
        facilityId: String,
        role: String,
        expires: Long,
        nonce: String,
        secretBase64: String
    ): String {
        val message = "$facilityId:$role:$expires:$nonce"
        val secretBytes = Base64.decode(secretBase64, Base64.NO_WRAP)
        val mac = Mac.getInstance(ALGORITHM)
        mac.init(SecretKeySpec(secretBytes, ALGORITHM))
        val tag = mac.doFinal(message.toByteArray(Charsets.UTF_8))
        return Base64.encodeToString(tag, Base64.NO_WRAP or Base64.URL_SAFE)
    }

    /**
     * Derive a 4-digit confirmation code from an HMAC tag.
     * The admin reads this aloud; the joining device verifies it.
     */
    fun deriveConfirmCode(hmacTagBase64: String): String {
        val bytes = Base64.decode(hmacTagBase64, Base64.NO_WRAP or Base64.URL_SAFE)
        // First 2 bytes → unsigned big-endian int → mod 10000 → zero-padded
        val value = ((bytes[0].toInt() and 0xFF) shl 8) or (bytes[1].toInt() and 0xFF)
        return String.format("%04d", value % 10000)
    }

    /**
     * Verify an HMAC tag by recomputing and constant-time comparing.
     */
    fun verify(
        facilityId: String,
        role: String,
        expires: Long,
        nonce: String,
        hmacTagBase64: String,
        secretBase64: String
    ): Boolean {
        val expected = computeTag(facilityId, role, expires, nonce, secretBase64)
        return MessageDigest.isEqual(
            expected.toByteArray(Charsets.UTF_8),
            hmacTagBase64.toByteArray(Charsets.UTF_8)
        )
    }

    /**
     * Generate a 256-bit (32-byte) random secret, returned as Base64 (NO_WRAP).
     */
    fun generateSecret(): String {
        val bytes = ByteArray(32)
        java.security.SecureRandom().nextBytes(bytes)
        return Base64.encodeToString(bytes, Base64.NO_WRAP)
    }
}
