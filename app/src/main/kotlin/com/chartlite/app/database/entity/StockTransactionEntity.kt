package com.chartlite.app.database.entity

import androidx.room.Entity
import androidx.room.Index
import androidx.room.PrimaryKey

@Entity(
    tableName = "stock_transactions",
    indices = [
        Index("stockItemId"),
        Index("transactionType"),
        Index("timestamp")
    ]
)
data class StockTransactionEntity(
    @PrimaryKey val id: String,
    val stockItemId: String,
    val transactionType: String,  // RECEIVED, DISPENSED, ADJUSTED, EXPIRED, RETURNED
    val quantity: Int,            // Positive for in, negative for out
    val referenceId: String?,     // visitId for DISPENSED
    val performedBy: String,
    val notes: String?,
    val timestamp: Long,
    // Forward-compatible fields
    val metadata: String? = null,
    val sourceAgentId: String? = null
)
