package com.chartlite.app.database.entity

import androidx.room.Entity
import androidx.room.Index
import androidx.room.PrimaryKey

@Entity(
    tableName = "stock_items",
    indices = [
        Index("facilityId"),
        Index("drugCode"),
        Index("expiryDate"),
        Index(value = ["facilityId", "drugCode"]),
        Index(value = ["facilityId", "quantityOnHand"])
    ]
)
data class StockItemEntity(
    @PrimaryKey val id: String,
    val facilityId: String,
    val drugCode: String,         // Links to formulary
    val drugName: String,
    val quantityOnHand: Int,
    val reorderLevel: Int,
    val unit: String,             // "tablets", "capsules", "vials", "bottles"
    val batchNumber: String?,
    val expiryDate: Long?,
    val lastUpdatedBy: String,
    val lastUpdatedAt: Long,
    // Forward-compatible fields
    val metadata: String? = null,
    val sourceAgentId: String? = null,
    val syncStatus: String? = null,
    val fhirResourceId: String? = null
)
