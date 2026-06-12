package com.lyecdevelopers.core.di

import com.lyecdevelopers.core.model.Form
import com.lyecdevelopers.core.model.auth.LoginResponse
import com.lyecdevelopers.core.model.auth.LogoutResponse
import com.squareup.moshi.JsonAdapter
import com.squareup.moshi.Moshi
import com.squareup.moshi.Types
import com.squareup.moshi.kotlin.reflect.KotlinJsonAdapterFactory
import dagger.Module
import dagger.Provides
import dagger.hilt.InstallIn
import dagger.hilt.components.SingletonComponent
import javax.inject.Singleton

@Module
@InstallIn(SingletonComponent::class)
object MoshiModule {

    @Provides
    @Singleton
    fun provideMoshi(): Moshi {
        return Moshi.Builder()
            .addLast(KotlinJsonAdapterFactory())
            .build()
    }

    @Provides
    @Singleton
    fun provideFormAdapter(moshi: Moshi): JsonAdapter<Form> =
        moshi.adapter(Form::class.java)

    @Provides
    @Singleton
    fun provideLoginResponseAdapter(moshi: Moshi): JsonAdapter<LoginResponse> =
        moshi.adapter(LoginResponse::class.java)

    @Provides
    @Singleton
    fun provideLogoutResponseAdapter(moshi: Moshi): JsonAdapter<LogoutResponse> =
        moshi.adapter(LogoutResponse::class.java)

    @Provides
    @Singleton
    fun provideMapAdapter(moshi: Moshi): JsonAdapter<Map<String, Any>> {
        val type = Types.newParameterizedType(
            Map::class.java, String::class.java, Any::class.java
        )
        return moshi.adapter(type)
    }

    @Provides
    @Singleton
    fun provideListOfMapAdapter(moshi: Moshi): JsonAdapter<List<Map<String, Any>>> {
        val mapType = Types.newParameterizedType(
            Map::class.java, String::class.java, Any::class.java
        )
        val listType = Types.newParameterizedType(
            List::class.java, mapType
        )
        return moshi.adapter(listType)
    }
}
