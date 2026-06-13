package com.lyecdevelopers.core.ui.components

import androidx.compose.foundation.BorderStroke
import androidx.compose.foundation.background
import androidx.compose.foundation.border
import androidx.compose.foundation.clickable
import androidx.compose.foundation.layout.Arrangement
import androidx.compose.foundation.layout.Column
import androidx.compose.foundation.layout.Spacer
import androidx.compose.foundation.layout.fillMaxSize
import androidx.compose.foundation.layout.fillMaxWidth
import androidx.compose.foundation.layout.height
import androidx.compose.foundation.layout.padding
import androidx.compose.foundation.layout.size
import androidx.compose.foundation.lazy.LazyColumn
import androidx.compose.foundation.lazy.items
import androidx.compose.foundation.shape.RoundedCornerShape
import androidx.compose.material.icons.Icons
import androidx.compose.material.icons.filled.Info
import androidx.compose.material3.HorizontalDivider
import androidx.compose.material3.Icon
import androidx.compose.material3.MaterialTheme
import androidx.compose.material3.Surface
import androidx.compose.material3.Text
import androidx.compose.runtime.Composable
import androidx.compose.ui.Alignment
import androidx.compose.ui.Modifier
import androidx.compose.ui.text.font.FontWeight
import androidx.compose.ui.unit.dp
import com.lyecdevelopers.core.model.cohort.Attribute


@Composable
fun ParameterList(
    title: String,
    parameters: List<Attribute>,
    highlighted: List<Attribute>,
    onItemClick: (Attribute) -> Unit,
    labelSelector: (Attribute) -> String = { it.label },
    modifier: Modifier = Modifier,
) {
    val colors = MaterialTheme.colorScheme

    Column(
        modifier = modifier
            .border(1.dp, colors.outline, RoundedCornerShape(8.dp))
            .background(colors.surfaceVariant, RoundedCornerShape(8.dp))
            .height(320.dp)
    ) {
        Text(
            text = title,
            style = MaterialTheme.typography.titleMedium.copy(fontWeight = FontWeight.Medium),
            color = colors.onSurface,
            modifier = Modifier
                .fillMaxWidth()
                .background(colors.surface, RoundedCornerShape(topStart = 8.dp, topEnd = 8.dp))
                .padding(horizontal = 16.dp, vertical = 12.dp)
        )

        HorizontalDivider(thickness = 1.dp, color = colors.outline)

        if (parameters.isEmpty()) {
            // Better empty state with subtle icon
            Column(
                modifier = Modifier
                    .fillMaxSize()
                    .padding(16.dp),
                verticalArrangement = Arrangement.Center,
                horizontalAlignment = Alignment.CenterHorizontally
            ) {
                Icon(
                    imageVector = Icons.Default.Info,
                    contentDescription = null,
                    tint = colors.outline,
                    modifier = Modifier.size(32.dp)
                )
                Spacer(Modifier.height(8.dp))
                Text(
                    text = "No ${title.lowercase().removeSuffix("s")} available.",
                    style = MaterialTheme.typography.bodyMedium,
                    color = colors.onSurface.copy(alpha = 0.7f)
                )
            }
        } else {
            LazyColumn(
                modifier = Modifier
                    .fillMaxSize()
                    .padding(8.dp),
                verticalArrangement = Arrangement.spacedBy(4.dp)
            ) {
                items(parameters, key = labelSelector) { param ->
                    val isHighlighted = param in highlighted
                    val label = labelSelector(param)

                    Surface(
                        shape = RoundedCornerShape(6.dp),
                        tonalElevation = if (isHighlighted) 1.dp else 0.dp,
                        color = if (isHighlighted) colors.primary.copy(alpha = 0.1f) else colors.surfaceVariant,
                        border = if (isHighlighted) BorderStroke(
                            1.dp,
                            colors.primary.copy(alpha = 0.4f)
                        ) else null,
                        modifier = Modifier
                            .fillMaxWidth()
                            .clickable { onItemClick(param) }
                    ) {
                        Text(
                            text = label,
                            color = if (isHighlighted) colors.primary else colors.onSurface,
                            style = MaterialTheme.typography.bodyMedium.copy(
                                fontWeight = if (isHighlighted) FontWeight.SemiBold else FontWeight.Normal
                            ),
                            modifier = Modifier.padding(horizontal = 12.dp, vertical = 8.dp)
                        )
                    }
                }
            }
        }
    }
}

