package com.lyecdevelopers.core.data.preference

import android.content.Context
import kotlinx.coroutines.flow.Flow


interface PreferenceManager {

    // auth
    suspend fun saveAuthToken(token: String)
    fun getAuthToken(): Flow<String?>

    suspend fun setIsLoggedIn (loggedIn: Boolean)
    fun isLoggedIn() : Flow<Boolean>

    suspend fun saveUserRole(role: String)
    fun getUserRole(): Flow<String?>

    suspend fun saveUsername(username: String)
    fun getUsername(): Flow<String?>

    suspend fun savePassword(password: String)
    fun getPassword(): Flow<String?>

    // remember
    suspend fun setRememberMe(enabled: Boolean)
    fun isRememberMeEnabled(): Flow<Boolean>

    // dark theme
    suspend fun setDarkModeEnabled(enabled: Boolean)
    fun isDarkModeEnabled(): Flow<Boolean>

    // selected forms
    suspend fun saveSelectedForms(context: Context, ids: Set<String>)

    suspend fun loadSelectedForms(context: Context): Set<String>


    // sync
    suspend fun saveAutoSyncEnabled(enabled: Boolean)

    suspend fun loadAutoSyncEnabled(): Boolean

    suspend fun saveAutoSyncInterval(hours: Int)

    suspend fun loadAutoSyncInterval(): Int

    suspend fun loadServerUrl(): String

    suspend fun saveServerUrl(url: String)

    // clear data
    suspend fun clear()

}

