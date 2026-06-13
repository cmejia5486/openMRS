package com.chartlite.app.ui.components

import androidx.compose.animation.core.*
import androidx.compose.foundation.Canvas
import androidx.compose.foundation.background
import androidx.compose.foundation.layout.*
import androidx.compose.foundation.shape.CircleShape
import androidx.compose.material.icons.Icons
import androidx.compose.material.icons.filled.Mic
import androidx.compose.material.icons.filled.Stop
import androidx.compose.material3.CircularProgressIndicator
import androidx.compose.material3.Icon
import androidx.compose.material3.MaterialTheme
import androidx.compose.runtime.*
import androidx.compose.ui.Alignment
import androidx.compose.ui.Modifier
import androidx.compose.ui.draw.clip
import androidx.compose.ui.draw.scale
import androidx.compose.ui.draw.shadow
import androidx.compose.ui.graphics.Brush
import androidx.compose.ui.graphics.Color
import androidx.compose.ui.graphics.drawscope.Stroke
import androidx.compose.foundation.gestures.detectTapGestures
import androidx.compose.ui.input.pointer.pointerInput
import androidx.compose.ui.unit.dp
import com.chartlite.app.ui.theme.BrandGreen
import com.chartlite.app.ui.theme.BrandGreenLight
import com.chartlite.app.ui.theme.AlertRed

private val EaseOut = CubicBezierEasing(0f, 0f, 0.2f, 1f)

/** Hold threshold in ms — finger must be down this long before it counts as "hold" */
private const val HOLD_THRESHOLD_MS = 300L

@Composable
fun RecordButton(
    isRecording: Boolean,
    amplitude: Float,
    onClick: () -> Unit,
    enabled: Boolean = true,
    isPreparing: Boolean = false,
    isHolding: Boolean = false,
    onHoldStart: () -> Unit = {},
    onHoldEnd: () -> Unit = {},
    modifier: Modifier = Modifier
) {
    // Pulse animation — single shared transition, only active when recording
    val isAnimating = isRecording && !isPreparing
    val transition = rememberInfiniteTransition(label = "record_pulse")
    val animatedScale by transition.animateFloat(
        initialValue = 1f,
        targetValue = 1.4f,
        animationSpec = infiniteRepeatable(
            animation = tween(1000, easing = EaseOut),
            repeatMode = RepeatMode.Restart
        ),
        label = "ringScale"
    )
    val animatedAlpha by transition.animateFloat(
        initialValue = 0.5f,
        targetValue = 0f,
        animationSpec = infiniteRepeatable(
            animation = tween(1000, easing = EaseOut),
            repeatMode = RepeatMode.Restart
        ),
        label = "ringAlpha"
    )
    // Only use animated values when recording — avoids unnecessary recomposition
    val ringScale = if (isAnimating) animatedScale else 1f
    val ringAlpha = if (isAnimating) animatedAlpha else 0f

    // Hold mode uses amber, ambient uses red, idle is green
    val buttonColor = when {
        isHolding -> Color(0xFFFF9800) // amber for hold-to-dictate
        isRecording -> AlertRed
        else -> BrandGreen
    }
    val buttonGradient = when {
        isPreparing -> Brush.radialGradient(listOf(MaterialTheme.colorScheme.surfaceVariant, MaterialTheme.colorScheme.outlineVariant))
        isHolding -> Brush.radialGradient(listOf(Color(0xFFFFA726), Color(0xFFFF9800)))
        isRecording -> Brush.radialGradient(listOf(Color(0xFFEF5350), AlertRed))
        else -> Brush.radialGradient(listOf(BrandGreenLight, BrandGreen))
    }

    val ringColor = if (isHolding) Color(0xFFFF9800) else AlertRed

    // Amplitude-driven scale
    val effectiveScale = if (isRecording && !isPreparing) 1f + amplitude.coerceIn(0f, 1f) * 0.15f else 1f

    Box(
        modifier = modifier.size(160.dp),
        contentAlignment = Alignment.Center
    ) {
        // Outer pulsing ring (recording only)
        if (isRecording && !isPreparing) {
            Canvas(modifier = Modifier.size(160.dp).scale(ringScale)) {
                drawCircle(
                    color = ringColor.copy(alpha = ringAlpha),
                    radius = size.minDimension / 2,
                    style = Stroke(width = 3.dp.toPx())
                )
            }

            // Audio level ring
            Canvas(modifier = Modifier.size(140.dp)) {
                drawCircle(
                    color = ringColor.copy(alpha = 0.15f + amplitude * 0.2f),
                    radius = size.minDimension / 2 * (1f + amplitude * 0.1f)
                )
            }
        }

        // Main button — with tap + hold gesture detection
        Box(
            modifier = Modifier
                .size(96.dp)
                .scale(effectiveScale)
                .shadow(
                    elevation = if (isRecording) 12.dp else 6.dp,
                    shape = CircleShape,
                    ambientColor = buttonColor.copy(alpha = 0.3f),
                    spotColor = buttonColor.copy(alpha = 0.3f)
                )
                .clip(CircleShape)
                .background(buttonGradient)
                .pointerInput(enabled, isRecording) {
                    if (!enabled) return@pointerInput
                    detectTapGestures(
                        onPress = { _ ->
                            val pressStart = System.currentTimeMillis()
                            val released = tryAwaitRelease()
                            val pressDuration = System.currentTimeMillis() - pressStart

                            if (released) {
                                if (pressDuration >= HOLD_THRESHOLD_MS) {
                                    // Hold gesture — fire both start and end so the
                                    // caller sees a complete hold cycle
                                    onHoldStart()
                                    onHoldEnd()
                                } else {
                                    onClick()
                                }
                            }
                        },
                        onLongPress = {
                            // Triggers after viewConfiguration.longPressTimeoutMillis (~400ms).
                            // Provides immediate visual feedback for long holds (finger still down).
                            onHoldStart()
                        }
                    )
                },
            contentAlignment = Alignment.Center
        ) {
            if (isPreparing) {
                CircularProgressIndicator(
                    modifier = Modifier.size(34.dp),
                    strokeWidth = 3.dp,
                    color = MaterialTheme.colorScheme.onSurfaceVariant
                )
            } else {
                Icon(
                    imageVector = if (isRecording) Icons.Default.Stop else Icons.Default.Mic,
                    contentDescription = when {
                        isHolding -> "Release to capture"
                        isRecording -> "Stop recording"
                        else -> "Tap to scribe, hold to dictate"
                    },
                    modifier = Modifier.size(40.dp),
                    tint = Color.White
                )
            }
        }
    }
}
