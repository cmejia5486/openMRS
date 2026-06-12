package com.lyecdevelopers.core.ui.components

import androidx.compose.foundation.layout.Box
import androidx.compose.foundation.layout.fillMaxSize
import androidx.compose.runtime.Composable
import androidx.compose.runtime.LaunchedEffect
import androidx.compose.runtime.getValue
import androidx.compose.runtime.mutableStateOf
import androidx.compose.runtime.remember
import androidx.compose.runtime.setValue
import androidx.compose.ui.Alignment
import androidx.compose.ui.Modifier
import androidx.navigation.NavController
import androidx.navigation.compose.rememberNavController
import com.lyecdevelopers.core.ui.event.UiEvent
import kotlinx.coroutines.flow.Flow
import kotlinx.coroutines.flow.collectLatest

@Composable
fun BaseScreen(
    uiEventFlow: Flow<UiEvent>,
    navController: NavController = rememberNavController(),
    isLoading: Boolean = false,
    showLoading: (Boolean) -> Unit = {},
    content: @Composable () -> Unit,
) {
    var snackbarEvent by remember { mutableStateOf<UiEvent.Snackbar?>(null) }

    LaunchedEffect(Unit) {
        uiEventFlow.collectLatest { event ->
            when (event) {
                is UiEvent.Snackbar -> snackbarEvent = event
                is UiEvent.Navigate -> navController.navigate(event.route)
                is UiEvent.PopBackStack -> navController.popBackStack()
                is UiEvent.ShowLoading -> showLoading(true)
                is UiEvent.HideLoading -> showLoading(false)
                else -> Unit
            }
        }
    }

    Box(modifier = Modifier.fillMaxSize()) {
        content()

        UiEventHandler(
            uiEventFlow = uiEventFlow, showLoading = showLoading, navController = navController
        )

        Box(
            modifier = Modifier.fillMaxSize(), contentAlignment = Alignment.BottomCenter
        ) {
            snackbarEvent?.let { event ->
                CustomSnackbar(
                    message = event.message,
                    actionLabel = event.actionLabel,
                    onAction = {
                        event.onAction?.invoke()
                        snackbarEvent = null
                    },
                    onDismiss = {
                        snackbarEvent = null
                    })
            }
        }

        if (isLoading) {
            CustomLoadingIndicator()
        }
    }
}




