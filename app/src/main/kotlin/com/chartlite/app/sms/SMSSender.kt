package com.chartlite.app.sms

import android.Manifest
import android.app.PendingIntent
import android.content.BroadcastReceiver
import android.content.Context
import android.content.Intent
import android.content.IntentFilter
import android.content.pm.PackageManager
import android.os.Build
import android.telephony.SmsManager
import android.util.Log
import androidx.core.content.ContextCompat
import com.chartlite.app.config.AppConfig
import com.chartlite.app.database.entity.PatientEntity
import com.chartlite.app.model.SMSStatus
import com.chartlite.app.model.StructuredEncounter
import kotlinx.coroutines.suspendCancellableCoroutine
import kotlin.coroutines.resume

class SMSSender(private val context: Context, private val appConfig: AppConfig) {

    data class SendResult(
        val status: SMSStatus,
        val error: String? = null
    )

    fun hasPermission(): Boolean {
        return ContextCompat.checkSelfPermission(
            context, Manifest.permission.SEND_SMS
        ) == PackageManager.PERMISSION_GRANTED
    }

    /**
     * Encrypt and send encounter as SMS to patient's phone.
     * Uses Twilio if configured, otherwise falls back to native SMS.
     * If Twilio fails and native SMS permission is available, falls back to native.
     *
     * V2 mode: When [allEncounters] and [patientAllergies] are provided, the SMS
     * becomes a "portable health record" containing the current encounter PLUS
     * accumulated significant health history (chronic conditions, abnormal vitals).
     * The patient can store only the latest SMS and have all significant details.
     */
    suspend fun sendEncryptedSMS(
        encounter: StructuredEncounter,
        patient: PatientEntity,
        allEncounters: List<StructuredEncounter>? = null,
        patientAllergies: List<String>? = null,
        growthData: PatientHealthSummaryBuilder.GrowthData? = null,
        immunizationRecords: List<ImmunizationRecord> = emptyList()
    ): SendResult {
        val phoneNumber = patient.phoneNumber
            ?: return SendResult(SMSStatus.FAILED, "No phone number on file")
        val pin = patient.pin  // Optional — for shared-phone privacy

        return try {
            // Encode encounter to binary — v4 (expanded vitals + immunizations + growth + clinical flags)
            // Uses static salt encryption to guarantee 1-SMS fit (160 Base64 chars)
            val payload = if (allEncounters != null) {
                val summary = PatientHealthSummaryBuilder.buildSummary(
                    allEncounters = allEncounters,
                    patientAllergies = patientAllergies ?: emptyList(),
                    growthData = growthData,
                    immunizationRecords = immunizationRecords
                )
                BinaryEncoder.encodeV4(encounter, encounter.patientId, summary)
            } else {
                BinaryEncoder.encode(encounter)
            }

            // Derive password from phone number + optional PIN for encryption.
            // V4 uses static-salt encryption (no salt prefix) for guaranteed 1-SMS fit.
            val password = if (pin.isNullOrBlank()) phoneNumber else "$phoneNumber:$pin"
            val smsContent = if (allEncounters != null) {
                SMSEncryption.encryptV4(payload, password)
            } else {
                @Suppress("DEPRECATION")
                SMSEncryption.encrypt(payload, SMSEncryption.deriveKey(password))
            }

            // Send via configured provider, with native fallback if Twilio fails
            val hasTwilio = appConfig.twilioAccountSid.isNotBlank() &&
                appConfig.twilioAuthToken.isNotBlank() &&
                appConfig.twilioFromNumber.isNotBlank()

            if (hasTwilio) {
                val result = sendViaTwilio(phoneNumber, smsContent)
                if (result.status == SMSStatus.FAILED && hasPermission()) {
                    // Twilio failed — fall back to native SMS
                    sendViaNative(phoneNumber, smsContent)
                } else {
                    result
                }
            } else if (hasPermission()) {
                sendViaNative(phoneNumber, smsContent)
            } else {
                SendResult(SMSStatus.FAILED, "SMS permission not granted and Twilio not configured")
            }
        } catch (e: Exception) {
            SendResult(SMSStatus.FAILED, e.message)
        }
    }

    /**
     * Send a plain-text SMS (e.g., appointment reminders).
     * Handles multipart messages for texts exceeding 160 characters.
     * Pre-checks SMS permission before sending.
     */
    suspend fun sendPlainSMS(to: String, body: String): SendResult {
        if (!hasPermission()) {
            return SendResult(SMSStatus.FAILED, "SMS permission not granted")
        }
        return sendViaNative(to, body)
    }

    private suspend fun sendViaTwilio(to: String, body: String): SendResult {
        val provider = TwilioSMSProvider(
            accountSid = appConfig.twilioAccountSid,
            authToken = appConfig.twilioAuthToken,
            fromNumber = appConfig.twilioFromNumber
        )

        val result = provider.sendSMS(to, body)
        return SendResult(
            status = result.status,
            error = result.error
        )
    }

    private suspend fun sendViaNative(to: String, body: String): SendResult {
        if (!hasPermission()) {
            return SendResult(SMSStatus.FAILED, "SMS permission not granted")
        }

        val smsManager = if (Build.VERSION.SDK_INT >= Build.VERSION_CODES.S) {
            context.getSystemService(SmsManager::class.java)
        } else {
            @Suppress("DEPRECATION")
            SmsManager.getDefault()
        }

        return suspendCancellableCoroutine { cont ->
            val action = "com.chartlite.app.SMS_SENT_${System.nanoTime()}"
            val receiver = object : BroadcastReceiver() {
                override fun onReceive(ctx: Context, intent: Intent) {
                    context.unregisterReceiver(this)
                    when (resultCode) {
                        android.app.Activity.RESULT_OK ->
                            cont.resume(SendResult(SMSStatus.SENT))
                        SmsManager.RESULT_ERROR_NO_SERVICE ->
                            cont.resume(SendResult(SMSStatus.FAILED, "No cellular service — check signal or SIM"))
                        SmsManager.RESULT_ERROR_RADIO_OFF ->
                            cont.resume(SendResult(SMSStatus.FAILED, "Radio off — enable mobile network"))
                        SmsManager.RESULT_ERROR_NULL_PDU ->
                            cont.resume(SendResult(SMSStatus.FAILED, "SMS encoding error — phone number may be invalid"))
                        else ->
                            cont.resume(SendResult(SMSStatus.FAILED, "SMS send failed (error code: $resultCode)"))
                    }
                }
            }

            val flags = if (Build.VERSION.SDK_INT >= Build.VERSION_CODES.TIRAMISU) {
                Context.RECEIVER_NOT_EXPORTED
            } else {
                0
            }
            context.registerReceiver(receiver, IntentFilter(action), flags)

            val sentIntent = PendingIntent.getBroadcast(
                context, 0, Intent(action),
                PendingIntent.FLAG_ONE_SHOT or PendingIntent.FLAG_IMMUTABLE
            )

            cont.invokeOnCancellation {
                runCatching { context.unregisterReceiver(receiver) }
            }

            try {
                val parts = smsManager.divideMessage(body)
                if (parts.size <= 1) {
                    smsManager.sendTextMessage(to, null, body, sentIntent, null)
                } else {
                    val sentIntents = ArrayList(parts.map { sentIntent })
                    smsManager.sendMultipartTextMessage(to, null, parts, sentIntents, null)
                }
                Log.d("SMSSender", "Native SMS queued to $to (${body.length} chars, ${parts.size} part(s))")
            } catch (e: Exception) {
                runCatching { context.unregisterReceiver(receiver) }
                cont.resume(SendResult(SMSStatus.FAILED, "SMS send error: ${e.message}"))
            }
        }
    }

    /**
     * Decrypt SMS messages from a patient.
     * Returns the appropriate [DecryptResult] variant based on the version byte:
     * V4 (expanded vitals + immunizations + growth + clinical flags),
     * V3 (patient ID + health history), V2 (health history), or V1 (encounter only).
     */
    fun decryptSMSWithVersion(
        smsContent: String,
        phoneNumber: String,
        pin: String? = null
    ): DecryptResult? {
        return try {
            // Use password-based decrypt which auto-detects static-salt (v4+)
            // and legacy formats for backward compatibility.
            val password = if (pin.isNullOrBlank()) phoneNumber else "$phoneNumber:$pin"
            val payload = SMSEncryption.decrypt(smsContent, password)
            val version = payload[0].toInt() and 0xFF
            when (version) {
                0x04 -> DecryptResult.V4(BinaryEncoder.decodeV4(payload))
                0x03 -> DecryptResult.V3(BinaryEncoder.decodeV3(payload))
                0x02 -> DecryptResult.V2(BinaryEncoder.decodeV2(payload))
                else -> DecryptResult.V1(BinaryEncoder.decode(payload))
            }
        } catch (_: Exception) {
            null
        }
    }

    /**
     * Decrypt SMS messages from a patient (backward-compatible, returns encounter only).
     */
    fun decryptSMS(
        smsContent: String,
        phoneNumber: String,
        pin: String? = null
    ): DecodedEncounter? {
        return when (val result = decryptSMSWithVersion(smsContent, phoneNumber, pin)) {
            is DecryptResult.V1 -> result.encounter
            is DecryptResult.V2 -> result.data.encounter
            is DecryptResult.V3 -> result.data.encounter
            is DecryptResult.V4 -> result.data.encounter
            null -> null
        }
    }
}
