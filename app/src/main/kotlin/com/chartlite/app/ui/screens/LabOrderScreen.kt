package com.chartlite.app.ui.screens

import androidx.compose.foundation.layout.*
import androidx.compose.foundation.lazy.LazyColumn
import androidx.compose.foundation.lazy.items
import androidx.compose.foundation.shape.RoundedCornerShape
import androidx.compose.material.icons.Icons
import androidx.compose.material.icons.automirrored.filled.ArrowBack
import androidx.compose.material.icons.filled.Add
import androidx.compose.material.icons.filled.Science
import androidx.compose.material3.*
import androidx.compose.runtime.*
import androidx.compose.ui.Alignment
import androidx.compose.ui.Modifier
import androidx.compose.ui.platform.LocalContext
import androidx.compose.ui.res.stringResource
import androidx.compose.ui.text.font.FontWeight
import androidx.compose.ui.unit.dp
import com.chartlite.app.App
import com.chartlite.app.R
import com.chartlite.app.auth.AuditLogger
import com.chartlite.app.database.entity.LabOrderEntity
import com.chartlite.app.model.LabOrderStatus
import com.chartlite.app.model.LabPriority
import com.chartlite.app.model.LabTestCatalogEntry
import com.google.gson.Gson
import com.google.gson.reflect.TypeToken
import android.util.Log
import kotlinx.coroutines.launch
import java.text.SimpleDateFormat
import java.util.Date
import java.util.Locale

@OptIn(ExperimentalMaterial3Api::class)
@Composable
fun LabOrderScreen(
    visitId: String,
    patientId: String,
    onBack: () -> Unit
) {
    val context = LocalContext.current
    val app = context.applicationContext as App
    val scope = rememberCoroutineScope()

    var orders by remember { mutableStateOf<List<LabOrderEntity>>(emptyList()) }
    var isLoading by remember { mutableStateOf(true) }
    var showCreateDialog by remember { mutableStateOf(false) }
    var selectedOrder by remember { mutableStateOf<LabOrderEntity?>(null) }
    var labCatalog by remember { mutableStateOf<List<LabTestCatalogEntry>>(emptyList()) }

    // Load lab catalog from assets
    LaunchedEffect(Unit) {
        try {
            val json = context.assets.open("lab/common_lab_tests.json")
                .bufferedReader().use { it.readText() }
            val parsed = Gson().fromJson<Map<String, Any>>(json, object : TypeToken<Map<String, Any>>() {}.type)
            @Suppress("UNCHECKED_CAST")
            val testsList = parsed["tests"] as? List<Map<String, Any?>> ?: emptyList()
            labCatalog = testsList.map { test ->
                LabTestCatalogEntry(
                    code = test["code"] as? String ?: "",
                    name = test["name"] as? String ?: "",
                    category = test["category"] as? String ?: "",
                    defaultUnit = test["defaultUnit"] as? String,
                    referenceRange = test["referenceRange"] as? String,
                    criticalRange = test["criticalRange"] as? String
                )
            }
        } catch (e: Exception) {
            Log.w("LabOrderScreen", "Failed to load lab catalog", e)
        }
    }

    // Load existing orders
    LaunchedEffect(visitId) {
        orders = app.labOrderRepository.getByVisitId(visitId)
        isLoading = false
    }

    Scaffold(
        topBar = {
            TopAppBar(
                title = { Text(stringResource(R.string.lab_orders)) },
                navigationIcon = {
                    IconButton(onClick = onBack) {
                        Icon(Icons.AutoMirrored.Filled.ArrowBack, stringResource(R.string.back))
                    }
                }
            )
        },
        floatingActionButton = {
            FloatingActionButton(
                onClick = { showCreateDialog = true }
            ) {
                Icon(Icons.Default.Add, stringResource(R.string.new_order))
            }
        }
    ) { padding ->
        if (isLoading) {
            Box(Modifier.fillMaxSize().padding(padding), contentAlignment = Alignment.Center) {
                CircularProgressIndicator()
            }
        } else if (orders.isEmpty()) {
            Box(Modifier.fillMaxSize().padding(padding), contentAlignment = Alignment.Center) {
                Column(horizontalAlignment = Alignment.CenterHorizontally) {
                    Icon(
                        Icons.Default.Science,
                        contentDescription = null,
                        modifier = Modifier.size(64.dp),
                        tint = MaterialTheme.colorScheme.outline
                    )
                    Spacer(Modifier.height(16.dp))
                    Text(stringResource(R.string.no_lab_orders_yet), style = MaterialTheme.typography.titleMedium)
                    Text(
                        stringResource(R.string.tap_plus_to_create_order),
                        style = MaterialTheme.typography.bodyMedium,
                        color = MaterialTheme.colorScheme.outline
                    )
                }
            }
        } else {
            LazyColumn(
                modifier = Modifier.fillMaxSize().padding(padding),
                contentPadding = PaddingValues(16.dp),
                verticalArrangement = Arrangement.spacedBy(12.dp)
            ) {
                items(orders, key = { it.id }) { order ->
                    LabOrderCard(
                        order = order,
                        onStatusUpdate = { newStatus ->
                            scope.launch {
                                when (newStatus) {
                                    LabOrderStatus.COLLECTED.name ->
                                        app.labOrderRepository.markCollected(order.id)
                                    LabOrderStatus.CANCELLED.name ->
                                        app.labOrderRepository.cancelOrder(order.id)
                                }
                                orders = app.labOrderRepository.getByVisitId(visitId)
                            }
                        },
                        onEnterResult = { selectedOrder = it }
                    )
                }
            }
        }
    }

    if (showCreateDialog) {
        CreateLabOrderDialog(
            catalog = labCatalog,
            onDismiss = { showCreateDialog = false },
            onConfirm = { testCode, testName, priority, notes ->
                scope.launch {
                    val userId = app.sessionManager.currentSession?.userId ?: "system"
                    app.labOrderRepository.createOrder(
                        visitId = visitId,
                        patientId = patientId,
                        testCode = testCode,
                        testName = testName,
                        orderedBy = userId,
                        priority = priority,
                        notes = notes
                    )
                    app.auditLogger.log(
                        action = "ORDER_LAB",
                        targetType = "LAB_ORDER",
                        targetId = visitId,
                        details = AuditLogger.buildDetails("testCode" to testCode, "priority" to priority)
                    )
                    orders = app.labOrderRepository.getByVisitId(visitId)
                    showCreateDialog = false
                }
            }
        )
    }

    selectedOrder?.let { order ->
        EnterResultDialog(
            order = order,
            onDismiss = { selectedOrder = null },
            onConfirm = { resultValue, resultUnit, referenceRange, isAbnormal, notes ->
                scope.launch {
                    val userId = app.sessionManager.currentSession?.userId ?: "system"
                    app.labOrderRepository.enterResult(
                        orderId = order.id,
                        resultValue = resultValue,
                        resultUnit = resultUnit,
                        referenceRange = referenceRange,
                        isAbnormal = isAbnormal,
                        resultedBy = userId,
                        notes = notes
                    )
                    app.auditLogger.log(
                        action = "ENTER_LAB_RESULT",
                        targetType = "LAB_ORDER",
                        targetId = order.id,
                        details = AuditLogger.buildDetails("testCode" to order.testCode, "abnormal" to isAbnormal)
                    )
                    orders = app.labOrderRepository.getByVisitId(visitId)
                    selectedOrder = null
                }
            }
        )
    }
}

@Composable
private fun LabOrderCard(
    order: LabOrderEntity,
    onStatusUpdate: (String) -> Unit,
    onEnterResult: (LabOrderEntity) -> Unit
) {
    val dateFormat = remember { SimpleDateFormat("dd MMM yyyy HH:mm", Locale.getDefault()) }
    val statusColor = when (order.status) {
        LabOrderStatus.ORDERED.name -> MaterialTheme.colorScheme.primary
        LabOrderStatus.COLLECTED.name -> MaterialTheme.colorScheme.tertiary
        LabOrderStatus.RESULTED.name -> MaterialTheme.colorScheme.secondary
        LabOrderStatus.CANCELLED.name -> MaterialTheme.colorScheme.error
        else -> MaterialTheme.colorScheme.outline
    }

    Card(
        modifier = Modifier.fillMaxWidth(),
        shape = RoundedCornerShape(12.dp)
    ) {
        Column(Modifier.padding(16.dp)) {
            Row(
                modifier = Modifier.fillMaxWidth(),
                horizontalArrangement = Arrangement.SpaceBetween,
                verticalAlignment = Alignment.CenterVertically
            ) {
                Column(Modifier.weight(1f)) {
                    Text(order.testName, fontWeight = FontWeight.Bold)
                    Text(
                        order.testCode,
                        style = MaterialTheme.typography.bodySmall,
                        color = MaterialTheme.colorScheme.outline
                    )
                }
                Surface(
                    shape = MaterialTheme.shapes.small,
                    color = statusColor.copy(alpha = 0.12f)
                ) {
                    Text(
                        order.status,
                        modifier = Modifier.padding(horizontal = 12.dp, vertical = 6.dp),
                        style = MaterialTheme.typography.labelLarge,
                        color = statusColor
                    )
                }
            }

            Spacer(Modifier.height(8.dp))

            Row(horizontalArrangement = Arrangement.spacedBy(16.dp)) {
                Text(
                    stringResource(R.string.priority_format, order.priority),
                    style = MaterialTheme.typography.bodySmall
                )
                Text(
                    stringResource(R.string.ordered_format, dateFormat.format(Date(order.orderedAt))),
                    style = MaterialTheme.typography.bodySmall,
                    color = MaterialTheme.colorScheme.outline
                )
            }

            if (order.status == LabOrderStatus.RESULTED.name && order.resultValue != null) {
                Spacer(Modifier.height(8.dp))
                Card(
                    colors = CardDefaults.cardColors(
                        containerColor = if (order.isAbnormal == true)
                            MaterialTheme.colorScheme.errorContainer
                        else MaterialTheme.colorScheme.secondaryContainer
                    ),
                    shape = RoundedCornerShape(8.dp)
                ) {
                    Column(Modifier.padding(12.dp)) {
                        Text(
                            if (order.resultUnit != null)
                                stringResource(R.string.result_with_unit_format, order.resultValue!!, order.resultUnit!!)
                            else
                                stringResource(R.string.result_format, order.resultValue!!),
                            fontWeight = FontWeight.SemiBold
                        )
                        order.referenceRange?.let {
                            Text(stringResource(R.string.reference_format, it), style = MaterialTheme.typography.bodySmall)
                        }
                        if (order.isAbnormal == true) {
                            Text(
                                stringResource(R.string.abnormal_label),
                                color = MaterialTheme.colorScheme.error,
                                fontWeight = FontWeight.Bold,
                                style = MaterialTheme.typography.labelSmall
                            )
                        }
                    }
                }
            }

            // Action buttons based on status
            if (order.status == LabOrderStatus.ORDERED.name ||
                order.status == LabOrderStatus.COLLECTED.name) {
                Spacer(Modifier.height(8.dp))
                Row(horizontalArrangement = Arrangement.spacedBy(8.dp)) {
                    if (order.status == LabOrderStatus.ORDERED.name) {
                        OutlinedButton(
                            onClick = { onStatusUpdate(LabOrderStatus.COLLECTED.name) },
                            modifier = Modifier.weight(1f)
                        ) { Text(stringResource(R.string.mark_collected)) }
                    }
                    if (order.status == LabOrderStatus.ORDERED.name ||
                        order.status == LabOrderStatus.COLLECTED.name) {
                        Button(
                            onClick = { onEnterResult(order) },
                            modifier = Modifier.weight(1f)
                        ) { Text(stringResource(R.string.enter_result)) }
                    }
                    OutlinedButton(
                        onClick = { onStatusUpdate(LabOrderStatus.CANCELLED.name) },
                        colors = ButtonDefaults.outlinedButtonColors(
                            contentColor = MaterialTheme.colorScheme.error
                        )
                    ) { Text(stringResource(R.string.cancel)) }
                }
            }
        }
    }
}

@OptIn(ExperimentalMaterial3Api::class)
@Composable
private fun CreateLabOrderDialog(
    catalog: List<LabTestCatalogEntry>,
    onDismiss: () -> Unit,
    onConfirm: (testCode: String, testName: String, priority: String, notes: String?) -> Unit
) {
    var selectedTest by remember { mutableStateOf<LabTestCatalogEntry?>(null) }
    var searchQuery by remember { mutableStateOf("") }
    var priority by remember { mutableStateOf(LabPriority.ROUTINE.name) }
    var notes by remember { mutableStateOf("") }
    var expanded by remember { mutableStateOf(false) }

    val filteredTests = remember(searchQuery, catalog) {
        if (searchQuery.isBlank()) catalog
        else catalog.filter {
            it.name.contains(searchQuery, ignoreCase = true) ||
                    it.code.contains(searchQuery, ignoreCase = true) ||
                    it.category.contains(searchQuery, ignoreCase = true)
        }
    }

    AlertDialog(
        onDismissRequest = onDismiss,
        title = { Text(stringResource(R.string.order_lab_test)) },
        text = {
            Column(verticalArrangement = Arrangement.spacedBy(12.dp)) {
                // Test search
                OutlinedTextField(
                    value = searchQuery,
                    onValueChange = { searchQuery = it; selectedTest = null },
                    label = { Text(stringResource(R.string.search_tests)) },
                    modifier = Modifier.fillMaxWidth(),
                    singleLine = true
                )

                // Test list (scrollable, max 4 visible)
                if (selectedTest == null && filteredTests.isNotEmpty()) {
                    Card(
                        modifier = Modifier.fillMaxWidth().heightIn(max = 200.dp)
                    ) {
                        LazyColumn {
                            items(filteredTests.take(20)) { test ->
                                Surface(
                                    onClick = {
                                        selectedTest = test
                                        searchQuery = test.name
                                    },
                                    modifier = Modifier.fillMaxWidth()
                                ) {
                                    Column(Modifier.padding(12.dp)) {
                                        Text(test.name, fontWeight = FontWeight.Medium)
                                        Text(
                                            "${test.code} - ${test.category}",
                                            style = MaterialTheme.typography.bodySmall,
                                            color = MaterialTheme.colorScheme.outline
                                        )
                                    }
                                }
                            }
                        }
                    }
                }

                if (selectedTest != null) {
                    Text(
                        stringResource(R.string.selected_test_format, selectedTest?.name ?: "", selectedTest?.code ?: ""),
                        style = MaterialTheme.typography.bodySmall,
                        color = MaterialTheme.colorScheme.primary
                    )
                }

                // Priority selector
                Text(stringResource(R.string.priority), fontWeight = FontWeight.Medium)
                Row(horizontalArrangement = Arrangement.spacedBy(8.dp)) {
                    LabPriority.entries.forEach { p ->
                        FilterChip(
                            selected = priority == p.name,
                            onClick = { priority = p.name },
                            label = { Text(p.name) }
                        )
                    }
                }

                // Notes
                OutlinedTextField(
                    value = notes,
                    onValueChange = { notes = it },
                    label = { Text(stringResource(R.string.notes_optional)) },
                    modifier = Modifier.fillMaxWidth(),
                    minLines = 2
                )
            }
        },
        confirmButton = {
            Button(
                onClick = {
                    selectedTest?.let {
                        onConfirm(it.code, it.name, priority, notes.ifBlank { null })
                    }
                },
                enabled = selectedTest != null
            ) { Text(stringResource(R.string.order)) }
        },
        dismissButton = {
            TextButton(onClick = onDismiss) { Text(stringResource(R.string.cancel)) }
        }
    )
}

@Composable
private fun EnterResultDialog(
    order: LabOrderEntity,
    onDismiss: () -> Unit,
    onConfirm: (resultValue: String, resultUnit: String?, referenceRange: String?, isAbnormal: Boolean?, notes: String?) -> Unit
) {
    var resultValue by remember { mutableStateOf("") }
    var resultUnit by remember { mutableStateOf("") }
    var referenceRange by remember { mutableStateOf("") }
    var isAbnormal by remember { mutableStateOf(false) }
    var notes by remember { mutableStateOf("") }
    var showErrors by remember { mutableStateOf(false) }

    AlertDialog(
        onDismissRequest = onDismiss,
        title = { Text(stringResource(R.string.enter_result_format, order.testName)) },
        text = {
            Column(verticalArrangement = Arrangement.spacedBy(12.dp)) {
                OutlinedTextField(
                    value = resultValue,
                    onValueChange = { resultValue = it },
                    label = { Text(stringResource(R.string.result_value)) },
                    modifier = Modifier.fillMaxWidth(),
                    isError = showErrors && resultValue.isBlank(),
                    supportingText = if (showErrors && resultValue.isBlank()) {{ Text(stringResource(R.string.required)) }} else null
                )
                OutlinedTextField(
                    value = resultUnit,
                    onValueChange = { resultUnit = it },
                    label = { Text(stringResource(R.string.unit_optional)) },
                    modifier = Modifier.fillMaxWidth()
                )
                OutlinedTextField(
                    value = referenceRange,
                    onValueChange = { referenceRange = it },
                    label = { Text(stringResource(R.string.reference_range_optional)) },
                    modifier = Modifier.fillMaxWidth()
                )
                Row(
                    verticalAlignment = Alignment.CenterVertically,
                    horizontalArrangement = Arrangement.spacedBy(8.dp)
                ) {
                    Checkbox(
                        checked = isAbnormal,
                        onCheckedChange = { isAbnormal = it }
                    )
                    Text(stringResource(R.string.abnormal_result))
                }
                OutlinedTextField(
                    value = notes,
                    onValueChange = { notes = it },
                    label = { Text(stringResource(R.string.notes_optional)) },
                    modifier = Modifier.fillMaxWidth(),
                    minLines = 2
                )
            }
        },
        confirmButton = {
            Button(
                onClick = {
                    if (resultValue.isBlank()) { showErrors = true; return@Button }
                    showErrors = false
                    onConfirm(
                        resultValue,
                        resultUnit.ifBlank { null },
                        referenceRange.ifBlank { null },
                        isAbnormal,
                        notes.ifBlank { null }
                    )
                }
            ) { Text(stringResource(R.string.save_result)) }
        },
        dismissButton = {
            TextButton(onClick = onDismiss) { Text(stringResource(R.string.cancel)) }
        }
    )
}
