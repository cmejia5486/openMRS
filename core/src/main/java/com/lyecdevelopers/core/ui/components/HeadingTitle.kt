package com.lyecdevelopers.core.ui.components

import androidx.compose.foundation.layout.PaddingValues
import androidx.compose.foundation.layout.fillMaxWidth
import androidx.compose.foundation.layout.padding
import androidx.compose.material3.MaterialTheme
import androidx.compose.material3.Text
import androidx.compose.runtime.Composable
import androidx.compose.ui.Modifier
import androidx.compose.ui.graphics.Color
import androidx.compose.ui.text.TextStyle
import androidx.compose.ui.text.font.FontWeight
import androidx.compose.ui.text.style.TextAlign
import androidx.compose.ui.text.style.TextOverflow
import androidx.compose.ui.unit.TextUnit
import androidx.compose.ui.unit.dp

@Composable
fun HeadlineText(
    text: String,
    modifier: Modifier = Modifier,
    color: Color = MaterialTheme.colorScheme.primary,
    style: TextStyle = MaterialTheme.typography.titleLarge,
    textAlign: TextAlign = TextAlign.Center,
    maxLines: Int = Int.MAX_VALUE,
    overflow: TextOverflow = TextOverflow.Clip,
    fontWeight: FontWeight? = FontWeight.SemiBold,
    fontSize: TextUnit? = null,
    padding: PaddingValues = PaddingValues(horizontal = 16.dp, vertical = 8.dp)
) {
    Text(
        text = text,
        color = color,
        modifier = modifier
            .padding(padding)
            .fillMaxWidth(),
        style = style.merge(
            TextStyle(
                fontWeight = fontWeight,
                fontSize = fontSize ?: style.fontSize
            )
        ),
        textAlign = textAlign,
        maxLines = maxLines,
        overflow = overflow
    )
}
