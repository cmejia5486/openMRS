package com.chartlite.app.ui.screens

import androidx.compose.foundation.layout.*
import androidx.compose.foundation.lazy.LazyColumn
import androidx.compose.foundation.lazy.items
import androidx.compose.foundation.shape.RoundedCornerShape
import androidx.compose.material.icons.Icons
import androidx.compose.material.icons.automirrored.filled.ArrowBack
import androidx.compose.material.icons.filled.Add
import androidx.compose.material.icons.filled.Inventory2
import androidx.compose.material.icons.filled.Warning
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
import com.chartlite.app.database.entity.StockItemEntity
import kotlinx.coroutines.launch
import java.text.SimpleDateFormat
import java.util.Date
import java.util.Locale

@OptIn(ExperimentalMaterial3Api::class)
@Composable
fun StockManagementScreen(
    onBack: () -> Unit
) {
    val context = LocalContext.current
    val app = context.applicationContext as App
    val scope = rememberCoroutineScope()
    val facilityId = app.appConfig.facilityId

    var stockItems by remember { mutableStateOf<List<StockItemEntity>>(emptyList()) }
    var isLoading by remember { mutableStateOf(true) }
    var showFilter by remember { mutableStateOf("all") } // all, low, expiring
    var showAddDialog by remember { mutableStateOf(false) }
    var selectedItem by remember { mutableStateOf<StockItemEntity?>(null) }

    fun loadStock() {
        scope.launch {
            isLoading = true
            stockItems = when (showFilter) {
                "low" -> app.stockRepository.getLowStock(facilityId)
                "expiring" -> app.stockRepository.getExpiringSoon(facilityId, 30)
                else -> app.stockRepository.getByFacility(facilityId)
            }
            isLoading = false
        }
    }

    LaunchedEffect(showFilter) { loadStock() }

    Scaffold(
        topBar = {
            TopAppBar(
                title = { Text(stringResource(R.string.stock_management)) },
                navigationIcon = {
                    IconButton(onClick = onBack) {
                        Icon(Icons.AutoMirrored.Filled.ArrowBack, stringResource(R.string.back))
                    }
                }
            )
        },
        floatingActionButton = {
            FloatingActionButton(onClick = { showAddDialog = true }) {
                Icon(Icons.Default.Add, stringResource(R.string.add_stock_item))
            }
        }
    ) { padding ->
        Column(Modifier.fillMaxSize().padding(padding)) {
            // Filter chips
            Row(
                modifier = Modifier.fillMaxWidth().padding(horizontal = 16.dp, vertical = 8.dp),
                horizontalArrangement = Arrangement.spacedBy(8.dp)
            ) {
                FilterChip(selected = showFilter == "all", onClick = { showFilter = "all" }, label = { Text(stringResource(R.string.all)) })
                FilterChip(selected = showFilter == "low", onClick = { showFilter = "low" }, label = { Text(stringResource(R.string.low_stock)) })
                FilterChip(selected = showFilter == "expiring", onClick = { showFilter = "expiring" }, label = { Text(stringResource(R.string.expiring)) })
            }

            if (isLoading) {
                Box(Modifier.fillMaxSize(), contentAlignment = Alignment.Center) { CircularProgressIndicator() }
            } else if (stockItems.isEmpty()) {
                Box(Modifier.fillMaxSize(), contentAlignment = Alignment.Center) {
                    Column(horizontalAlignment = Alignment.CenterHorizontally) {
                        Icon(Icons.Default.Inventory2, null, Modifier.size(64.dp), tint = MaterialTheme.colorScheme.outline)
                        Spacer(Modifier.height(16.dp))
                        Text(stringResource(R.string.no_stock_items), style = MaterialTheme.typography.titleMedium)
                        Text(stringResource(R.string.tap_plus_to_add_inventory), style = MaterialTheme.typography.bodyMedium, color = MaterialTheme.colorScheme.outline)
                    }
                }
            } else {
                LazyColumn(
                    contentPadding = PaddingValues(16.dp),
                    verticalArrangement = Arrangement.spacedBy(12.dp)
                ) {
                    items(stockItems, key = { it.id }) { item ->
                        StockItemCard(
                            item = item,
                            onReceive = { selectedItem = item },
                            onAdjust = { qty, reason ->
                                scope.launch {
                                    val userId = app.sessionManager.currentSession?.userId ?: "system"
                                    app.stockRepository.adjustStock(item.id, qty, userId, reason)
                                    app.auditLogger.log("ADJUST_STOCK", "STOCK", item.id,
                                        AuditLogger.buildDetails("drugCode" to item.drugCode, "newQty" to qty, "reason" to reason))
                                    loadStock()
                                }
                            }
                        )
                    }
                }
            }
        }
    }

    if (showAddDialog) {
        AddStockItemDialog(
            onDismiss = { showAddDialog = false },
            onConfirm = { drugCode, drugName, qty, reorderLevel, unit, batchNumber ->
                scope.launch {
                    val userId = app.sessionManager.currentSession?.userId ?: "system"
                    app.stockRepository.addStockItem(
                        facilityId = facilityId, drugCode = drugCode, drugName = drugName,
                        initialQuantity = qty, reorderLevel = reorderLevel, unit = unit,
                        batchNumber = batchNumber, performedBy = userId
                    )
                    app.auditLogger.log("ADD_STOCK", "STOCK", details = AuditLogger.buildDetails("drugCode" to drugCode, "qty" to qty))
                    loadStock()
                    showAddDialog = false
                }
            }
        )
    }

    selectedItem?.let { item ->
        ReceiveStockDialog(
            item = item,
            onDismiss = { selectedItem = null },
            onConfirm = { qty, notes ->
                scope.launch {
                    val userId = app.sessionManager.currentSession?.userId ?: "system"
                    app.stockRepository.receiveStock(item.id, qty, userId, notes)
                    app.auditLogger.log("RECEIVE_STOCK", "STOCK", item.id,
                        AuditLogger.buildDetails("drugCode" to item.drugCode, "qty" to qty))
                    loadStock()
                    selectedItem = null
                }
            }
        )
    }
}

@Composable
private fun StockItemCard(
    item: StockItemEntity,
    onReceive: () -> Unit,
    onAdjust: (Int, String) -> Unit
) {
    val dateFormat = remember { SimpleDateFormat("dd MMM yyyy", Locale.getDefault()) }
    val isLow = item.quantityOnHand <= item.reorderLevel
    val isExpiring = item.expiryDate != null &&
            item.expiryDate <= System.currentTimeMillis() + 30L * 86400000L

    Card(
        modifier = Modifier.fillMaxWidth(),
        shape = RoundedCornerShape(12.dp),
        colors = CardDefaults.cardColors(
            containerColor = when {
                item.quantityOnHand == 0 -> MaterialTheme.colorScheme.errorContainer
                isLow -> MaterialTheme.colorScheme.tertiaryContainer
                else -> MaterialTheme.colorScheme.surfaceVariant
            }
        )
    ) {
        Column(Modifier.padding(16.dp)) {
            Row(Modifier.fillMaxWidth(), horizontalArrangement = Arrangement.SpaceBetween) {
                Column(Modifier.weight(1f)) {
                    Text(item.drugName, fontWeight = FontWeight.Bold)
                    Text(item.drugCode, style = MaterialTheme.typography.bodySmall, color = MaterialTheme.colorScheme.outline)
                }
                Column(horizontalAlignment = Alignment.End) {
                    Text("${item.quantityOnHand}", style = MaterialTheme.typography.headlineSmall, fontWeight = FontWeight.Bold)
                    Text(item.unit, style = MaterialTheme.typography.bodySmall)
                }
            }

            if (isLow) {
                Spacer(Modifier.height(4.dp))
                Row(verticalAlignment = Alignment.CenterVertically) {
                    Icon(Icons.Default.Warning, null, Modifier.size(16.dp), tint = MaterialTheme.colorScheme.error)
                    Spacer(Modifier.width(4.dp))
                    Text(
                        if (item.quantityOnHand == 0) stringResource(R.string.out_of_stock_label) else stringResource(R.string.low_stock_reorder_format, item.reorderLevel),
                        style = MaterialTheme.typography.labelSmall,
                        color = MaterialTheme.colorScheme.error
                    )
                }
            }

            item.batchNumber?.let { Text(stringResource(R.string.batch_format, it), style = MaterialTheme.typography.bodySmall) }
            item.expiryDate?.let {
                Text(
                    stringResource(R.string.expires_format, dateFormat.format(Date(it))),
                    style = MaterialTheme.typography.bodySmall,
                    color = if (isExpiring) MaterialTheme.colorScheme.error else MaterialTheme.colorScheme.outline
                )
            }

            Spacer(Modifier.height(8.dp))
            Row(horizontalArrangement = Arrangement.spacedBy(8.dp)) {
                OutlinedButton(onClick = onReceive, modifier = Modifier.weight(1f)) { Text(stringResource(R.string.receive)) }
            }
        }
    }
}

@Composable
private fun AddStockItemDialog(
    onDismiss: () -> Unit,
    onConfirm: (drugCode: String, drugName: String, qty: Int, reorderLevel: Int, unit: String, batchNumber: String?) -> Unit
) {
    var drugCode by remember { mutableStateOf("") }
    var drugName by remember { mutableStateOf("") }
    var qty by remember { mutableStateOf("") }
    var reorderLevel by remember { mutableStateOf("10") }
    var unit by remember { mutableStateOf("tablets") }
    var batchNumber by remember { mutableStateOf("") }
    var showErrors by remember { mutableStateOf(false) }

    AlertDialog(
        onDismissRequest = onDismiss,
        title = { Text(stringResource(R.string.add_stock_item)) },
        text = {
            Column(verticalArrangement = Arrangement.spacedBy(8.dp)) {
                OutlinedTextField(value = drugCode, onValueChange = { drugCode = it }, label = { Text(stringResource(R.string.drug_code)) }, modifier = Modifier.fillMaxWidth(),
                    isError = showErrors && drugCode.isBlank(),
                    supportingText = if (showErrors && drugCode.isBlank()) {{ Text(stringResource(R.string.required)) }} else null)
                OutlinedTextField(value = drugName, onValueChange = { drugName = it }, label = { Text(stringResource(R.string.drug_name)) }, modifier = Modifier.fillMaxWidth(),
                    isError = showErrors && drugName.isBlank(),
                    supportingText = if (showErrors && drugName.isBlank()) {{ Text(stringResource(R.string.required)) }} else null)
                OutlinedTextField(value = qty, onValueChange = { qty = it.filter { c -> c.isDigit() } }, label = { Text(stringResource(R.string.initial_quantity)) }, modifier = Modifier.fillMaxWidth())
                OutlinedTextField(value = reorderLevel, onValueChange = { reorderLevel = it.filter { c -> c.isDigit() } }, label = { Text(stringResource(R.string.reorder_level)) }, modifier = Modifier.fillMaxWidth())
                OutlinedTextField(value = unit, onValueChange = { unit = it }, label = { Text(stringResource(R.string.unit)) }, modifier = Modifier.fillMaxWidth())
                OutlinedTextField(value = batchNumber, onValueChange = { batchNumber = it }, label = { Text(stringResource(R.string.batch_number_optional)) }, modifier = Modifier.fillMaxWidth())
            }
        },
        confirmButton = {
            Button(
                onClick = {
                    if (drugCode.isBlank() || drugName.isBlank()) { showErrors = true; return@Button }
                    showErrors = false
                    onConfirm(drugCode, drugName, qty.toIntOrNull() ?: 0, reorderLevel.toIntOrNull() ?: 10, unit, batchNumber.ifBlank { null })
                }
            ) { Text(stringResource(R.string.add)) }
        },
        dismissButton = { TextButton(onClick = onDismiss) { Text(stringResource(R.string.cancel)) } }
    )
}

@Composable
private fun ReceiveStockDialog(
    item: StockItemEntity,
    onDismiss: () -> Unit,
    onConfirm: (quantity: Int, notes: String?) -> Unit
) {
    var qty by remember { mutableStateOf("") }
    var notes by remember { mutableStateOf("") }

    AlertDialog(
        onDismissRequest = onDismiss,
        title = { Text(stringResource(R.string.receive_drug_format, item.drugName)) },
        text = {
            Column(verticalArrangement = Arrangement.spacedBy(8.dp)) {
                Text(stringResource(R.string.current_stock_format, item.quantityOnHand, item.unit))
                OutlinedTextField(value = qty, onValueChange = { qty = it.filter { c -> c.isDigit() } }, label = { Text(stringResource(R.string.quantity_received)) }, modifier = Modifier.fillMaxWidth())
                OutlinedTextField(value = notes, onValueChange = { notes = it }, label = { Text(stringResource(R.string.notes_optional)) }, modifier = Modifier.fillMaxWidth())
            }
        },
        confirmButton = {
            Button(
                onClick = { onConfirm(qty.toIntOrNull() ?: 0, notes.ifBlank { null }) },
                enabled = (qty.toIntOrNull() ?: 0) > 0
            ) { Text(stringResource(R.string.receive)) }
        },
        dismissButton = { TextButton(onClick = onDismiss) { Text(stringResource(R.string.cancel)) } }
    )
}
