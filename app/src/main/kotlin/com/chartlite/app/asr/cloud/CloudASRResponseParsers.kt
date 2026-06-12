package com.chartlite.app.asr.cloud

import com.google.gson.Gson
import com.google.gson.JsonObject

/**
 * Shared response parsers for cloud ASR providers.
 *
 * Used by both direct providers and the ChartLite proxy provider,
 * since the upstream API response format is the same regardless of
 * whether the request went through the proxy or directly.
 */
object CloudASRResponseParsers {

    private val gson = Gson()

    fun parseGoogleResponse(body: String): CloudTranscriptionResult {
        val json = gson.fromJson(body, JsonObject::class.java)
        val results = json.getAsJsonArray("results")
        if (results == null || results.size() == 0) {
            return CloudTranscriptionResult(text = "")
        }

        val transcript = buildString {
            for (result in results) {
                val alternatives = result.asJsonObject.getAsJsonArray("alternatives")
                if (alternatives != null && alternatives.size() > 0) {
                    val text = alternatives[0].asJsonObject.get("transcript")?.asString ?: ""
                    if (text.isNotBlank()) {
                        if (isNotEmpty()) append(" ")
                        append(text)
                    }
                }
            }
        }

        val confidence = try {
            results[0].asJsonObject
                .getAsJsonArray("alternatives")?.get(0)?.asJsonObject
                ?.get("confidence")?.asFloat ?: 0f
        } catch (_: Exception) { 0f }

        val detectedLang = try {
            results[0].asJsonObject.get("languageCode")?.asString
        } catch (_: Exception) { null }

        return CloudTranscriptionResult(
            text = transcript,
            confidence = confidence,
            languageDetected = detectedLang
        )
    }

    fun parseDeepgramResponse(body: String): CloudTranscriptionResult {
        val json = gson.fromJson(body, JsonObject::class.java)
        val results = json.getAsJsonObject("results")
            ?.getAsJsonArray("channels")
            ?.get(0)?.asJsonObject
            ?.getAsJsonArray("alternatives")
            ?.get(0)?.asJsonObject
            ?: return CloudTranscriptionResult(text = "")

        val transcript = results.get("transcript")?.asString ?: ""
        val confidence = results.get("confidence")?.asFloat ?: 0f

        val words = try {
            results.getAsJsonArray("words")?.map { wordJson ->
                val w = wordJson.asJsonObject
                WordTimestamp(
                    word = w.get("word")?.asString ?: "",
                    startMs = ((w.get("start")?.asDouble ?: 0.0) * 1000).toLong(),
                    endMs = ((w.get("end")?.asDouble ?: 0.0) * 1000).toLong(),
                    confidence = w.get("confidence")?.asFloat ?: 0f
                )
            }
        } catch (_: Exception) { null }

        val detectedLang = try {
            json.getAsJsonObject("results")
                ?.getAsJsonArray("channels")
                ?.get(0)?.asJsonObject
                ?.get("detected_language")?.asString
        } catch (_: Exception) { null }

        return CloudTranscriptionResult(
            text = transcript,
            confidence = confidence,
            languageDetected = detectedLang,
            words = words
        )
    }

    fun parseOpenAIResponse(body: String): CloudTranscriptionResult {
        val json = gson.fromJson(body, JsonObject::class.java)
        val text = json.get("text")?.asString ?: ""
        return CloudTranscriptionResult(text = text)
    }

    /**
     * Parse a normalised Gemini proxy response.
     * The worker extracts the transcript and returns: { "transcript": "..." }
     */
    fun parseGeminiResponse(body: String): CloudTranscriptionResult {
        val json = gson.fromJson(body, JsonObject::class.java)
        val text = json.get("transcript")?.asString ?: ""
        return CloudTranscriptionResult(text = text)
    }
}
