package com.lyecdevelopers.auth.presentation.login

import androidx.compose.foundation.clickable
import androidx.compose.foundation.layout.Column
import androidx.compose.foundation.layout.Spacer
import androidx.compose.foundation.layout.fillMaxWidth
import androidx.compose.foundation.layout.height
import androidx.compose.foundation.layout.padding
import androidx.compose.foundation.shape.RoundedCornerShape
import androidx.compose.foundation.text.KeyboardActions
import androidx.compose.foundation.text.KeyboardOptions
import androidx.compose.material.icons.Icons
import androidx.compose.material.icons.filled.Lock
import androidx.compose.material.icons.filled.Person
import androidx.compose.material3.ButtonDefaults
import androidx.compose.material3.MaterialTheme
import androidx.compose.material3.Text
import androidx.compose.runtime.Composable
import androidx.compose.runtime.collectAsState
import androidx.compose.runtime.getValue
import androidx.compose.runtime.remember
import androidx.compose.ui.Alignment
import androidx.compose.ui.Modifier
import androidx.compose.ui.focus.FocusRequester
import androidx.compose.ui.focus.focusRequester
import androidx.compose.ui.text.font.FontWeight
import androidx.compose.ui.text.input.ImeAction
import androidx.compose.ui.unit.dp
import androidx.compose.ui.unit.sp
import androidx.hilt.navigation.compose.hiltViewModel
import com.lyecdevelopers.auth.presentation.AuthViewModel
import com.lyecdevelopers.auth.presentation.event.LoginEvent
import com.lyecdevelopers.core.ui.components.SectionTitle
import com.lyecdevelopers.core.ui.components.SubmitButton
import com.lyecdevelopers.core.ui.components.TextInputField


@Composable
fun LoginScreen(
) {
    val viewModel: AuthViewModel = hiltViewModel()
    val state by viewModel.uiState.collectAsState()
    val passwordFocusRequester = remember { FocusRequester() }

    Column(
        modifier = Modifier
            .fillMaxWidth()
            .padding(16.dp),
        horizontalAlignment = Alignment.CenterHorizontally
    ) {
        Spacer(modifier = Modifier.height(24.dp))

        SectionTitle(
            text = "Login".uppercase(),
            fontSize = 30.sp,
            fontWeight = FontWeight.SemiBold,
            color = MaterialTheme.colorScheme.onPrimary
        )

        Spacer(modifier = Modifier.height(24.dp))

        TextInputField(
            value = state.username,
            onValueChange = { viewModel.onEvent(LoginEvent.Login(it, state.password)) },
            label = "Username",
            leadingIcon = Icons.Default.Person,
            modifier = Modifier.fillMaxWidth(),
            error = if (state.hasSubmitted && state.username.isBlank()) "Username required" else null,
            keyboardOptions = KeyboardOptions.Default.copy(imeAction = ImeAction.Next),
            keyboardActions = KeyboardActions(onNext = { passwordFocusRequester.requestFocus() })
        )

        Spacer(modifier = Modifier.height(16.dp))

        TextInputField(
            value = state.password,
            onValueChange = { viewModel.onEvent(LoginEvent.Login(state.username, it)) },
            label = "Password",
            leadingIcon = Icons.Default.Lock,
            isPassword = true,
            modifier = Modifier
                .fillMaxWidth()
                .focusRequester(passwordFocusRequester),
            error = if (state.hasSubmitted && state.password.isBlank()) "Password required" else null,
            keyboardOptions = KeyboardOptions.Default.copy(imeAction = ImeAction.Done),
            keyboardActions = KeyboardActions(onDone = { viewModel.onEvent(LoginEvent.Submit) })
        )

        Spacer(modifier = Modifier.height(8.dp))

        Text(
            text = "Forgot password?",
            style = MaterialTheme.typography.labelLarge,
            color = MaterialTheme.colorScheme.primary,
            modifier = Modifier
                .align(Alignment.End)
                .clickable {
                    // TODO
                })

        Spacer(modifier = Modifier.height(24.dp))

        SubmitButton(
            text = "Submit",
            onClick = { viewModel.onEvent(LoginEvent.Submit) },
            iconContentDescription = "Login icon",
            colors = ButtonDefaults.buttonColors(
                containerColor = MaterialTheme.colorScheme.primary,
                contentColor = MaterialTheme.colorScheme.onPrimary
            ),
            shape = RoundedCornerShape(12.dp)
        )

    }
}













