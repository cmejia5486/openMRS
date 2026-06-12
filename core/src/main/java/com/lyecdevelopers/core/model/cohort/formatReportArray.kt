package com.lyecdevelopers.core.model.cohort

fun formatReportArray(selectedItems: List<Attribute>?): List<ReportParamItem> {
    val arrayToReturn = mutableListOf<ReportParamItem>()

    selectedItems?.forEach { item ->
        arrayToReturn.add(
            ReportParamItem(
                label = item.label,
                type = item.type,
                expression = item.id,
                modifier = 1,
                extras = emptyList()
            )
        )
    }

    return arrayToReturn
}
