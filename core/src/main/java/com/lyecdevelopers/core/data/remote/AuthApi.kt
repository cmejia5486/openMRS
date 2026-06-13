package com.lyecdevelopers.core.data.remote
import com.lyecdevelopers.core.model.auth.LoginResponse
import com.lyecdevelopers.core.model.auth.LogoutResponse
import retrofit2.Response
import retrofit2.http.DELETE
import retrofit2.http.GET
import retrofit2.http.Header

interface AuthApi {

    @GET("rest/v1/session")
    suspend fun loginWithAuthHeader(
        @Header("Authorization") authHeader: String
    ): Response<LoginResponse>

    @DELETE("rest/v1/session")
    suspend fun logoutWithAuthHeader(@Header("Authorization") authHeader: String): Response<LogoutResponse>
}


