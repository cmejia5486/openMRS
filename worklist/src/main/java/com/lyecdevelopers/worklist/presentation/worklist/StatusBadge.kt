package com.lyecdevelopers.worklist.presentation.worklist

import androidx.compose.foundation.background
import androidx.compose.foundation.layout.Box
import androidx.compose.foundation.layout.padding
import androidx.compose.foundation.shape.RoundedCornerShape
import androidx.compose.material3.MaterialTheme
import androidx.compose.material3.Text
import androidx.compose.runtime.Composable
import androidx.compose.ui.Modifier
import androidx.compose.ui.graphics.Color
import androidx.compose.ui.unit.dp
import com.lyecdevelopers.core.model.VisitStatus

@Composable
fun StatusBadge(status: VisitStatus) {
    val color = when (status) {
        VisitStatus.PENDING -> Color(0xFFFFC107)
        VisitStatus.IN_PROGRESS -> Color(0xFF2196F3)
        VisitStatus.COMPLETED -> Color(0xFF4CAF50)
        VisitStatus.FOLLOW_UP -> Color(0xFF9C27B0)
    }

    val backgroundColor = color.copy(alpha = 0.1f)

    Box(
        modifier = Modifier
            .background(backgroundColor, shape = RoundedCornerShape(50))
            .padding(horizontal = 12.dp, vertical = 4.dp)
    ) {
        Text(
            text = status.name.replace("_", " ")
                .lowercase()
                .replaceFirstChar { it.uppercase() },
            color = color,
            style = MaterialTheme.typography.labelMedium
        )
    }
}

