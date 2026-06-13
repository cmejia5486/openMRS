package com.lyecdevelopers.core.ui.components

import androidx.compose.runtime.Composable
import androidx.compose.runtime.LaunchedEffect
import androidx.compose.runtime.getValue
import androidx.compose.runtime.mutableStateOf
import androidx.compose.runtime.remember
import androidx.compose.runtime.setValue
import androidx.navigation.NavController
import com.lyecdevelopers.core.model.NotificationType
import com.lyecdevelopers.core.ui.event.UiEvent
import kotlinx.coroutines.flow.Flow

@Composable
fun UiEventHandler(
    uiEventFlow: Flow<UiEvent>,
    showLoading: (Boolean) -> Unit = {},
    navController: NavController,
    onEventHandled: (() -> Unit)? = null,
) {
    var dialogData by remember { mutableStateOf<Triple<String, String, NotificationType>?>(null) }

    LaunchedEffect(Unit) {
        uiEventFlow.collect { event ->
            when (event) {
                is UiEvent.Success -> {
                    dialogData = Triple(
                        event.title, event.message, NotificationType.SUCCESS
                    )
                }

                is UiEvent.Error -> {
                    dialogData = Triple(
                        event.title, event.message, NotificationType.ERROR
                    )
                }

                is UiEvent.Snackbar -> {
                }

                UiEvent.ShowLoading -> showLoading(true)
                UiEvent.HideLoading -> showLoading(false)
                is UiEvent.Navigate -> {
                    navController.navigate(event.route)
                    onEventHandled?.invoke()
                }

                is UiEvent.PopBackStack -> {
                    navController.popBackStack()
                    onEventHandled?.invoke()
                }
            }
        }
    }

    dialogData?.let { (title, message, type) ->
        NotificationDialog(
            title = title, message = message, type = type,
            onDismiss = {
                dialogData = null
                onEventHandled?.invoke()
            },
        )
    }
}

