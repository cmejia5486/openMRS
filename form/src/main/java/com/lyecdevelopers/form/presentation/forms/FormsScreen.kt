package com.lyecdevelopers.form.presentation.forms

import android.annotation.SuppressLint
import androidx.compose.foundation.clickable
import androidx.compose.foundation.layout.Arrangement
import androidx.compose.foundation.layout.Column
import androidx.compose.foundation.layout.PaddingValues
import androidx.compose.foundation.layout.Spacer
import androidx.compose.foundation.layout.fillMaxSize
import androidx.compose.foundation.layout.fillMaxWidth
import androidx.compose.foundation.layout.height
import androidx.compose.foundation.layout.padding
import androidx.compose.foundation.lazy.LazyColumn
import androidx.compose.foundation.lazy.items
import androidx.compose.foundation.shape.RoundedCornerShape
import androidx.compose.material.icons.Icons
import androidx.compose.material.icons.filled.Search
import androidx.compose.material3.Icon
import androidx.compose.material3.MaterialTheme
import androidx.compose.material3.OutlinedTextField
import androidx.compose.material3.Scaffold
import androidx.compose.material3.Surface
import androidx.compose.material3.Text
import androidx.compose.runtime.Composable
import androidx.compose.runtime.LaunchedEffect
import androidx.compose.runtime.collectAsState
import androidx.compose.runtime.getValue
import androidx.compose.runtime.mutableStateOf
import androidx.compose.runtime.remember
import androidx.compose.runtime.setValue
import androidx.compose.ui.Modifier
import androidx.compose.ui.unit.dp
import androidx.hilt.navigation.compose.hiltViewModel
import com.lyecdevelopers.core.model.o3.o3Form
import com.lyecdevelopers.core.ui.components.BaseScreen
import com.lyecdevelopers.core.ui.components.EmptyStateView
import com.lyecdevelopers.form.presentation.event.FormsEvent


@SuppressLint("UnusedMaterial3ScaffoldPaddingParameter")
@Composable
fun FormsScreen(
    patientId: String?,
    onFormClick: (o3Form) -> Unit = {},
) {
    val viewModel: FormsViewModel = hiltViewModel()
    val state by viewModel.uiState.collectAsState()
    var isLoading by remember { mutableStateOf(false) }

    val forms = state.filteredForms
    val searchQuery = state.searchQuery

    // Optional: Automatically sync loading with ViewModel state if needed
    LaunchedEffect(state.isLoading) {
        isLoading = state.isLoading
    }

    BaseScreen(
        uiEventFlow = viewModel.uiEvent,
        isLoading = isLoading,
        showLoading = { isLoading = it },
    ) {
        Scaffold {
            Column(modifier = Modifier.fillMaxSize()) {
                OutlinedTextField(
                    value = searchQuery,
                    onValueChange = { viewModel.onEvent(FormsEvent.SearchQueryChanged(it)) },
                    modifier = Modifier
                        .fillMaxWidth()
                        .padding(16.dp),
                    placeholder = { Text("Search forms...") },
                    singleLine = true,
                    leadingIcon = {
                        Icon(
                            imageVector = Icons.Default.Search, contentDescription = "Search Icon"
                        )
                    })

                if (forms.isEmpty()) {
                    EmptyStateView("No Forms Available ")
                } else {
                    LazyColumn(
                        modifier = Modifier.fillMaxSize(),
                        contentPadding = PaddingValues(16.dp),
                        verticalArrangement = Arrangement.spacedBy(12.dp)
                    ) {
                        items(
                            forms,
                            key = { it.uuid ?: it.name ?: it.hashCode().toString() }) { form ->
                            form.name?.let {
                                Surface(
                                    modifier = Modifier
                                        .fillMaxWidth()
                                        .clickable { onFormClick(form) },
                                    tonalElevation = 4.dp,
                                    shape = RoundedCornerShape(12.dp),
                                    color = MaterialTheme.colorScheme.surface,
                                    shadowElevation = 4.dp
                                ) {
                                    Column(modifier = Modifier.padding(16.dp)) {
                                        // Title
                                        Text(
                                            text = form.name.orEmpty(),
                                            style = MaterialTheme.typography.bodyLarge,
                                            color = MaterialTheme.colorScheme.onSurface
                                        )


                                        // Description Subtitle (if available)
                                        form.description?.takeIf { it.isNotBlank() }
                                            ?.let { description ->
                                                Spacer(modifier = Modifier.height(2.dp))
                                                Text(
                                                    text = description,
                                                    style = MaterialTheme.typography.bodySmall,
                                                    color = MaterialTheme.colorScheme.onSurfaceVariant
                                                )
                                            }

                                        // Version Subtitle (if available)
                                        form.version?.takeIf { it.isNotBlank() }?.let { version ->
                                            Spacer(modifier = Modifier.height(4.dp))
                                            Text(
                                                text = "Version: $version",
                                                style = MaterialTheme.typography.bodySmall,
                                                color = MaterialTheme.colorScheme.onSurfaceVariant
                                            )
                                        }

                                    }
                                }


                            }
                        }
                    }
                }
            }

        }
    }
}


