package com.lyecdevelopers.core.data.remote.interceptor

import okhttp3.Credentials
import okhttp3.Interceptor
import okhttp3.Response
import javax.inject.Inject


class AuthInterceptor @Inject constructor() : Interceptor {

    @Volatile
    private var credentials: String? = null

    fun updateCredentials(username: String, password: String) {
        credentials = Credentials.basic(username, password)
    }

    override fun intercept(chain: Interceptor.Chain): Response {
        val requestBuilder = chain.request().newBuilder()

        credentials?.let {
            requestBuilder.header("Authorization", it)
        }

        return chain.proceed(requestBuilder.build())
    }
}



