package com.lyecdevelopers.auth.domain.usecase

import com.lyecdevelopers.auth.domain.repository.AuthRepository
import com.lyecdevelopers.core.model.Result
import kotlinx.coroutines.flow.Flow
import javax.inject.Inject

class LoginUseCase @Inject constructor(
    private val repository: AuthRepository
) {
     operator fun invoke(username: String, password: String): Flow<Result<Boolean>> {
        return repository.login(username, password)
    }
}

