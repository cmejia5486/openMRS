package com.chartlite.app.model

/**
 * Lab order status lifecycle: ORDERED → COLLECTED → RESULTED (or CANCELLED at any point).
 */
enum class LabOrderStatus {
    ORDERED, COLLECTED, RESULTED, CANCELLED
}

enum class LabPriority {
    ROUTINE, URGENT, STAT
}

/**
 * Catalog entry for a common lab test available at PHC level.
 */
data class LabTestCatalogEntry(
    val code: String,
    val name: String,
    val category: String,
    val defaultUnit: String?,
    val referenceRange: String?,
    val criticalRange: String?
)
