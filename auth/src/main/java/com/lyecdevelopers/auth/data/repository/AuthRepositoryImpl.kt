package com.lyecdevelopers.auth.data.repository

import com.lyecdevelopers.auth.domain.repository.AuthRepository
import com.lyecdevelopers.core.common.scheduler.SchedulerProvider
import com.lyecdevelopers.core.data.remote.AuthApi
import com.lyecdevelopers.core.model.Result
import com.lyecdevelopers.core.utils.AppLogger
import kotlinx.coroutines.flow.Flow
import kotlinx.coroutines.flow.catch
import kotlinx.coroutines.flow.flow
import kotlinx.coroutines.flow.flowOn
import okhttp3.Credentials
import javax.inject.Inject

class AuthRepositoryImpl @Inject constructor(
    private val authApi: AuthApi,
    private val schedulerProvider: SchedulerProvider,
) : AuthRepository {

    override fun login(username: String, password: String): Flow<Result<Boolean>> = flow {
        emit(Result.Loading)

        val credentials = Credentials.basic(username, password)
        val response = try {
            authApi.loginWithAuthHeader(credentials)
        } catch (e: Exception) {
            AppLogger.e("Network request failed", e)
            emit(Result.Error("Network error: ${e.localizedMessage ?: "Unknown error"}"))
            return@flow
        }

        if (!response.isSuccessful) {
            val errorMsg = "Login failed with code: ${response.code()}"
            AppLogger.d(errorMsg)
            emit(Result.Error(errorMsg))
            return@flow
        }

        val body = response.body()
        if (body?.authenticated == true) {
            emit(Result.Success(true))
        } else {
            val errorMsg = "Invalid credentials"
            AppLogger.d(errorMsg)
            emit(Result.Error(errorMsg))
        }
    }.catch { e ->
        val msg = "Login failed: ${e.localizedMessage ?: "Unknown error"}"
        AppLogger.e(msg, e)
        emit(Result.Error(msg))
    }.flowOn(schedulerProvider.io)
}



