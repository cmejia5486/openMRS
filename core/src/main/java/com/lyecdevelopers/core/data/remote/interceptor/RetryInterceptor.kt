package com.lyecdevelopers.core.data.remote.interceptor

import okhttp3.Interceptor
import okhttp3.Response
import javax.inject.Inject

class RetryInterceptor @Inject constructor(private val maxRetry: Int = 3) : Interceptor {
    override fun intercept(chain: Interceptor.Chain): Response {
        var request = chain.request()
        var response: Response? = null
        var tryCount = 0

        while (tryCount < maxRetry) {
            try {
                response = chain.proceed(request)
                break
            } catch (e: Exception) {
                tryCount++
                if (tryCount >= maxRetry) throw e
            }
        }

        return response!!
    }
}