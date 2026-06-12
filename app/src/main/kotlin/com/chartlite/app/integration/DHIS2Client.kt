package com.chartlite.app.integration

import kotlinx.coroutines.Dispatchers
import kotlinx.coroutines.withContext
import okhttp3.*
import okhttp3.MediaType.Companion.toMediaType
import okhttp3.RequestBody.Companion.toRequestBody
import java.io.IOException
import java.util.concurrent.TimeUnit

/**
 * HTTP client for the DHIS2 Web API.
 *
 * Supports:
 * - Authentication (Basic Auth)
 * - Pushing aggregate dataValueSets
 * - Pushing tracker events
 * - Connectivity testing
 *
 * Uses OkHttp (already in project deps for model downloading).
 * Uses a shared OkHttpClient instance to avoid thread/connection pool leaks.
 */
class DHIS2Client(private val config: DHIS2Config) {

    sealed class DHIS2Result {
        data class Success(val message: String, val importCount: ImportCount? = null) : DHIS2Result()
        data class Error(val message: String, val statusCode: Int? = null) : DHIS2Result()
    }

    data class ImportCount(
        val imported: Int = 0,
        val updated: Int = 0,
        val ignored: Int = 0,
        val deleted: Int = 0
    )

    companion object {
        /** Shared OkHttpClient to avoid creating new thread/connection pools per-instance */
        private val sharedClient = OkHttpClient.Builder()
            .connectTimeout(30, TimeUnit.SECONDS)
            .readTimeout(60, TimeUnit.SECONDS)
            .writeTimeout(60, TimeUnit.SECONDS)
            .build()
    }

    private fun authHeader(): String = Credentials.basic(config.username, config.password)

    /**
     * Test connectivity to the DHIS2 server.
     * Calls /api/system/info to verify auth and reachability.
     */
    suspend fun testConnection(): DHIS2Result = withContext(Dispatchers.IO) {
        if (!config.isConfigured) {
            return@withContext DHIS2Result.Error("DHIS2 not configured")
        }

        try {
            val request = Request.Builder()
                .url("${config.apiUrl}system/info")
                .header("Authorization", authHeader())
                .get()
                .build()

            sharedClient.newCall(request).execute().use { response ->
                if (response.isSuccessful) {
                    DHIS2Result.Success("Connected to DHIS2 server")
                } else {
                    DHIS2Result.Error(
                        "Connection failed: ${response.code} ${response.message}",
                        response.code
                    )
                }
            }
        } catch (e: IOException) {
            DHIS2Result.Error("Network error: ${e.message}")
        } catch (e: IllegalArgumentException) {
            DHIS2Result.Error("Invalid server URL: ${e.message}")
        } catch (e: Exception) {
            DHIS2Result.Error("Unexpected error: ${e.message}")
        }
    }

    /**
     * Push aggregate data values to DHIS2.
     * POST /api/dataValueSets?importStrategy=CREATE_AND_UPDATE
     */
    suspend fun pushDataValueSet(dataValueSet: DHIS2Mapper.DataValueSet): DHIS2Result =
        withContext(Dispatchers.IO) {
            if (!config.isConfigured) {
                return@withContext DHIS2Result.Error("DHIS2 not configured")
            }

            try {
                val json = DHIS2Mapper.toJson(dataValueSet)
                val body = json.toRequestBody("application/json".toMediaType())

                val request = Request.Builder()
                    .url("${config.apiUrl}dataValueSets?importStrategy=CREATE_AND_UPDATE")
                    .header("Authorization", authHeader())
                    .post(body)
                    .build()

                sharedClient.newCall(request).execute().use { response ->
                    val responseBody = response.body?.string() ?: ""
                    if (response.isSuccessful) {
                        val importCount = parseImportCount(responseBody)
                        DHIS2Result.Success(
                            "Data values pushed successfully",
                            importCount
                        )
                    } else {
                        // Don't expose full response body to UI — may contain server internals
                        DHIS2Result.Error(
                            "Push failed: HTTP ${response.code}",
                            response.code
                        )
                    }
                }
            } catch (e: IOException) {
                DHIS2Result.Error("Network error: ${e.message}")
            } catch (e: Exception) {
                DHIS2Result.Error("Unexpected error: ${e.message}")
            }
        }

    /**
     * Push tracker events to DHIS2.
     * POST /api/events
     */
    suspend fun pushEvents(events: List<DHIS2Mapper.TrackerEvent>): DHIS2Result =
        withContext(Dispatchers.IO) {
            if (!config.isConfigured) {
                return@withContext DHIS2Result.Error("DHIS2 not configured")
            }
            if (events.isEmpty()) {
                return@withContext DHIS2Result.Success("No events to push")
            }

            try {
                val json = buildString {
                    appendLine("{\"events\": [")
                    events.forEachIndexed { i, event ->
                        val comma = if (i < events.size - 1) "," else ""
                        // Trim trailing newline from toJson before appending comma
                        append(DHIS2Mapper.toJson(event).trimEnd())
                        appendLine(comma)
                    }
                    appendLine("]}")
                }

                val body = json.toRequestBody("application/json".toMediaType())

                val request = Request.Builder()
                    .url("${config.apiUrl}events")
                    .header("Authorization", authHeader())
                    .post(body)
                    .build()

                sharedClient.newCall(request).execute().use { response ->
                    val responseBody = response.body?.string() ?: ""
                    if (response.isSuccessful) {
                        val importCount = parseImportCount(responseBody)
                        DHIS2Result.Success(
                            "${events.size} events pushed successfully",
                            importCount
                        )
                    } else {
                        DHIS2Result.Error(
                            "Push failed: HTTP ${response.code}",
                            response.code
                        )
                    }
                }
            } catch (e: IOException) {
                DHIS2Result.Error("Network error: ${e.message}")
            } catch (e: Exception) {
                DHIS2Result.Error("Unexpected error: ${e.message}")
            }
        }

    /**
     * Simple JSON parsing for DHIS2 import summary.
     * Avoids adding Gson/Moshi dependency just for this.
     */
    private fun parseImportCount(json: String): ImportCount {
        fun extractInt(key: String): Int {
            val regex = "\"$key\"\\s*:\\s*(\\d+)".toRegex()
            return regex.find(json)?.groupValues?.get(1)?.toIntOrNull() ?: 0
        }
        return ImportCount(
            imported = extractInt("imported"),
            updated = extractInt("updated"),
            ignored = extractInt("ignored"),
            deleted = extractInt("deleted")
        )
    }
}
