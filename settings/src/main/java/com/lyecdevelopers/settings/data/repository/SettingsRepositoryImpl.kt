package com.lyecdevelopers.settings.data.repository

import com.lyecdevelopers.core.data.remote.AuthApi
import com.lyecdevelopers.core.model.Result
import com.lyecdevelopers.core.utils.AppLogger
import com.lyecdevelopers.settings.domain.repository.SettingsRepository
import kotlinx.coroutines.Dispatchers
import kotlinx.coroutines.flow.Flow
import kotlinx.coroutines.flow.catch
import kotlinx.coroutines.flow.flow
import kotlinx.coroutines.flow.flowOn
import okhttp3.Credentials
import javax.inject.Inject

class SettingsRepositoryImpl @Inject constructor(
    private val authApi: AuthApi,
) : SettingsRepository {
    override fun logout(username: String, password: String): Flow<Result<Boolean>> = flow {
        emit(Result.Loading)

        val credentials = Credentials.basic(username, password)
        val response = authApi.logoutWithAuthHeader(credentials)

        when (response.code()) {
            200 -> {
                val body = response.body()
                emit(Result.Success(true))
                AppLogger.d("Logout successful (200 OK)")
            }

            204 -> {
                // Logout success with no content
                emit(Result.Success(true))
                AppLogger.d("Logout successful (204 No Content)")
            }

            401 -> {
                // Unauthorized — maybe credentials were invalid
                emit(Result.Error("Unauthorized. Please login again."))
                AppLogger.d("Logout failed: Unauthorized (401)")
            }

            else -> {
                // Other unexpected status
                emit(Result.Error("Logout failed with code: ${response.code()}"))
                AppLogger.d("Logout failed with code: ${response.code()}, message: ${response.message()}")
            }
        }

    }.catch { e ->
        emit(Result.Error("Logout failed: ${e.localizedMessage ?: "Unknown error"}"))
        AppLogger.d("Logout exception: ${e.localizedMessage ?: "Unknown error"}")
    }.flowOn(Dispatchers.IO)


}