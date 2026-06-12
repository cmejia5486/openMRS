package com.chartlite.app.sms

import com.chartlite.app.model.SMSStatus
import kotlinx.coroutines.Dispatchers
import kotlinx.coroutines.withContext
import okhttp3.Credentials
import okhttp3.FormBody
import okhttp3.Request
import com.chartlite.app.asr.cloud.SharedHttpClient

/**
 * Sends SMS via Twilio REST API.
 *
 * Uses the Messages resource:
 * POST https://api.twilio.com/2010-04-01/Accounts/{SID}/Messages.json
 */
class TwilioSMSProvider(
    private val accountSid: String,
    private val authToken: String,
    private val fromNumber: String
) {

    data class TwilioResult(
        val status: SMSStatus,
        val messageSid: String? = null,
        val error: String? = null
    )

    private val client = SharedHttpClient.instance

    /**
     * Send an SMS message via Twilio.
     * Must be called from a coroutine (runs on IO dispatcher).
     */
    suspend fun sendSMS(to: String, body: String): TwilioResult = withContext(Dispatchers.IO) {
        val url = "https://api.twilio.com/2010-04-01/Accounts/$accountSid/Messages.json"

        val formBody = FormBody.Builder()
            .add("To", to)
            .add("From", fromNumber)
            .add("Body", body)
            .build()

        val request = Request.Builder()
            .url(url)
            .post(formBody)
            .header("Authorization", Credentials.basic(accountSid, authToken))
            .build()

        try {
            client.newCall(request).execute().use { response ->
                val responseBody = response.body?.string() ?: ""

                if (response.isSuccessful) {
                    // Extract message SID from JSON response
                    val sidRegex = """"sid"\s*:\s*"(SM[a-f0-9]+)"""".toRegex()
                    val messageSid = sidRegex.find(responseBody)?.groupValues?.get(1)

                    TwilioResult(
                        status = SMSStatus.SENT,
                        messageSid = messageSid
                    )
                } else {
                    // Extract error message
                    val errorRegex = """"message"\s*:\s*"([^"]+)"""".toRegex()
                    val errorMsg = errorRegex.find(responseBody)?.groupValues?.get(1)
                        ?: "HTTP ${response.code}"

                    TwilioResult(
                        status = SMSStatus.FAILED,
                        error = errorMsg
                    )
                }
            }
        } catch (e: Exception) {
            TwilioResult(
                status = SMSStatus.FAILED,
                error = e.message ?: "Network error"
            )
        }
    }

    /**
     * Verify credentials by calling the account endpoint.
     */
    suspend fun verifyCredentials(): Boolean = withContext(Dispatchers.IO) {
        val url = "https://api.twilio.com/2010-04-01/Accounts/$accountSid.json"

        val request = Request.Builder()
            .url(url)
            .get()
            .header("Authorization", Credentials.basic(accountSid, authToken))
            .build()

        try {
            client.newCall(request).execute().use { response ->
                response.body?.string() // consume body
                response.isSuccessful
            }
        } catch (_: Exception) {
            false
        }
    }
}
