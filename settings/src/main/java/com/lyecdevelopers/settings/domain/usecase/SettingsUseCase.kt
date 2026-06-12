package com.lyecdevelopers.settings.domain.usecase

import com.lyecdevelopers.core.model.Result
import com.lyecdevelopers.settings.domain.repository.SettingsRepository
import kotlinx.coroutines.flow.Flow
import javax.inject.Inject

class SettingsUseCase @Inject constructor(
    private val repository: SettingsRepository,
) {
    // logout
    fun logout(username: String, password: String): Flow<Result<Boolean>> {
        return repository.logout(username, password)
    }
}