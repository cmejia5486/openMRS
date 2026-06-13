package com.chartlite.app.asr.cloud

import okhttp3.OkHttpClient
import java.util.concurrent.TimeUnit

/**
 * Shared OkHttpClient for all cloud ASR providers and extraction strategies.
 *
 * OkHttp manages its own connection pool and thread pool internally.
 * Sharing a single instance avoids creating 6+ separate pools on
 * resource-constrained devices (Galaxy A03 target).
 *
 * Timeout values: connect=15s, read=90s (GPT-4o transcribe is slow), write=60s (large audio uploads).
 */
object SharedHttpClient {

    val instance: OkHttpClient = OkHttpClient.Builder()
        .connectTimeout(15, TimeUnit.SECONDS)
        .readTimeout(90, TimeUnit.SECONDS)
        .writeTimeout(60, TimeUnit.SECONDS)
        .build()
}
