package com.lyecdevelopers.worklist.presentation.worklist

import androidx.compose.material3.AlertDialog
import androidx.compose.material3.Button
import androidx.compose.material3.OutlinedButton
import androidx.compose.material3.Text
import androidx.compose.runtime.Composable
import androidx.compose.runtime.collectAsState
import androidx.compose.runtime.getValue
import androidx.hilt.navigation.compose.hiltViewModel
import com.lyecdevelopers.worklist.presentation.patient.StartVisitScreen
import com.lyecdevelopers.worklist.presentation.worklist.event.WorklistEvent

@Composable
fun StartVisitDialog(
    isVisible: Boolean,
    onDismissRequest: () -> Unit,
    viewModel: WorklistViewModel = hiltViewModel(),
) {
    if (!isVisible) return

    val uiState by viewModel.uiState.collectAsState()

    AlertDialog(onDismissRequest = onDismissRequest, confirmButton = {
        Button(
            onClick = {
                viewModel.onEvent(WorklistEvent.StartVisit)
                onDismissRequest()
            }, enabled = uiState.visitType.isNotEmpty()
            ) {
            Text("Start Visit")
            }
    }, dismissButton = {
        OutlinedButton(onClick = onDismissRequest) {
            Text("Cancel")
        }
    }, text = {
        StartVisitScreen(
            viewModel = viewModel
        )
    })
}


