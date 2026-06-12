package com.lyecdevelopers.auth.domain.repository

import com.lyecdevelopers.core.model.Result
import kotlinx.coroutines.flow.Flow

interface AuthRepository {
    fun login(username: String, password: String): Flow<Result<Boolean>>
}
