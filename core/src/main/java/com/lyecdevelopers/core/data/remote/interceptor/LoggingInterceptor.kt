package com.lyecdevelopers.core.data.remote.interceptor


import okhttp3.logging.HttpLoggingInterceptor

fun provideLoggingInterceptor(): HttpLoggingInterceptor {
    val interceptor = HttpLoggingInterceptor()
    interceptor.level = HttpLoggingInterceptor.Level.BODY
    return interceptor
}