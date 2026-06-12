package com.lyecdevelopers.settings.domain.repository

import com.lyecdevelopers.core.model.Result
import kotlinx.coroutines.flow.Flow

interface SettingsRepository {
    // logout
    fun logout(username: String, password: String): Flow<Result<Boolean>>
}