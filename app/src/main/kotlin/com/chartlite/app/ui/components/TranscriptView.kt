package com.chartlite.app.ui.components

import androidx.compose.animation.animateContentSize
import androidx.compose.foundation.background
import androidx.compose.foundation.layout.*
import androidx.compose.foundation.shape.RoundedCornerShape
import androidx.compose.material3.MaterialTheme
import androidx.compose.material3.Text
import androidx.compose.runtime.Composable
import androidx.compose.ui.Modifier
import androidx.compose.ui.draw.clip
import androidx.compose.ui.text.SpanStyle
import androidx.compose.ui.text.buildAnnotatedString
import androidx.compose.ui.text.font.FontWeight
import androidx.compose.ui.text.style.TextDecoration
import androidx.compose.ui.text.withStyle
import androidx.compose.ui.unit.dp
import com.chartlite.app.model.WordResult
import com.chartlite.app.ui.theme.WarningAmber
import com.chartlite.app.ui.theme.AlertRed

@Composable
fun TranscriptView(
    text: String,
    words: List<WordResult> = emptyList(),
    modifier: Modifier = Modifier,
    isStreaming: Boolean = false
) {
    val shape = RoundedCornerShape(12.dp)

    Box(
        modifier = modifier
            .fillMaxWidth()
            .clip(shape)
            .background(MaterialTheme.colorScheme.surfaceVariant.copy(alpha = 0.5f))
            .animateContentSize()
            .padding(16.dp)
    ) {
        if (words.isNotEmpty()) {
            // Confidence-colored transcript
            // Color + decoration for color-blind safety:
            // Low confidence: red + bold + underline
            // Medium confidence: amber + medium weight + dashed underline
            // High confidence: normal
            val annotated = buildAnnotatedString {
                for (word in words) {
                    val style = when {
                        word.confidence < 0.5f -> SpanStyle(
                            color = AlertRed,
                            fontWeight = FontWeight.Bold,
                            textDecoration = TextDecoration.Underline
                        )
                        word.confidence < 0.7f -> SpanStyle(
                            color = WarningAmber,
                            fontWeight = FontWeight.Medium
                        )
                        else -> SpanStyle(
                            color = MaterialTheme.colorScheme.onSurface
                        )
                    }
                    withStyle(style) { append(word.word) }
                    append(" ")
                }
                if (isStreaming) {
                    withStyle(SpanStyle(color = MaterialTheme.colorScheme.primary)) {
                        append("\u2588") // Blinking cursor
                    }
                }
            }
            Text(annotated, style = MaterialTheme.typography.bodyLarge)
        } else if (text.isNotBlank()) {
            Text(
                text + if (isStreaming) " \u2588" else "",
                style = MaterialTheme.typography.bodyLarge,
                color = MaterialTheme.colorScheme.onSurface
            )
        } else if (isStreaming) {
            Text(
                "Listening...",
                style = MaterialTheme.typography.bodyLarge,
                color = MaterialTheme.colorScheme.onSurfaceVariant
            )
        }
    }
}
