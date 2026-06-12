package com.lyecdevelopers.auth.presentation.event

sealed  class LoginEvent {
    data class Login(val username: String, val password : String) : LoginEvent()
    object Submit : LoginEvent()
}