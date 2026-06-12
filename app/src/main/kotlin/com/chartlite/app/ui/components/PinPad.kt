package com.chartlite.app.ui.components

import androidx.compose.foundation.layout.*
import androidx.compose.foundation.shape.CircleShape
import androidx.compose.material.icons.Icons
import androidx.compose.material.icons.automirrored.filled.Backspace
import androidx.compose.material.icons.filled.Check
import androidx.compose.material3.*
import androidx.compose.runtime.Composable
import androidx.compose.ui.Alignment
import androidx.compose.ui.Modifier
import androidx.compose.ui.semantics.contentDescription
import androidx.compose.ui.semantics.semantics
import androidx.compose.ui.text.font.FontWeight
import androidx.compose.ui.unit.dp
import androidx.compose.ui.unit.sp

/**
 * Reusable numeric PIN pad with 48dp+ touch targets.
 * Designed for clinical use — large buttons work with gloves and on low-res screens.
 *
 * Supports variable-length PINs (4-6 digits): shows a submit button in the bottom-right
 * once the minimum length is reached, and auto-submits at maxLength.
 *
 * @param pin Current PIN value
 * @param minLength Minimum PIN length required to enable submit (default 4)
 * @param maxLength Maximum PIN length (default 6)
 * @param onPinChange Called when PIN changes (digit added or removed)
 * @param onSubmit Called when PIN is submitted (via button or auto at maxLength)
 * @param enabled Whether the pad is interactive
 */
@Composable
fun PinPad(
    pin: String,
    minLength: Int = 4,
    maxLength: Int = 6,
    onPinChange: (String) -> Unit,
    onSubmit: (String) -> Unit,
    enabled: Boolean = true
) {
    Column(
        horizontalAlignment = Alignment.CenterHorizontally,
        verticalArrangement = Arrangement.spacedBy(8.dp)
    ) {
        // PIN dots indicator — show filled dots for entered digits + one empty dot as prompt
        // Don't show all maxLength dots, since PINs can be 4-6 digits and showing 6
        // empty dots misleads users with shorter PINs into thinking 6 digits are required.
        PinDots(filled = pin.length, showNext = pin.length < maxLength)

        Spacer(Modifier.height(16.dp))

        // Number grid: 1-9, then (backspace, 0, submit) — standard phone keypad layout
        val rows = listOf(
            listOf("1", "2", "3"),
            listOf("4", "5", "6"),
            listOf("7", "8", "9"),
            listOf("⌫", "0", "✓")
        )

        rows.forEach { row ->
            Row(
                horizontalArrangement = Arrangement.spacedBy(16.dp),
                verticalAlignment = Alignment.CenterVertically
            ) {
                row.forEach { key ->
                    when (key) {
                        "✓" -> {
                            // Submit button — visible once minLength reached
                            val canSubmit = enabled && pin.length >= minLength
                            FilledIconButton(
                                onClick = { onSubmit(pin) },
                                enabled = canSubmit,
                                modifier = Modifier.size(72.dp),
                                shape = CircleShape,
                                colors = IconButtonDefaults.filledIconButtonColors(
                                    containerColor = MaterialTheme.colorScheme.primary,
                                    contentColor = MaterialTheme.colorScheme.onPrimary,
                                    disabledContainerColor = MaterialTheme.colorScheme.surfaceVariant,
                                    disabledContentColor = MaterialTheme.colorScheme.onSurfaceVariant.copy(alpha = 0.38f)
                                )
                            ) {
                                Icon(
                                    Icons.Default.Check,
                                    contentDescription = "Submit PIN",
                                    modifier = Modifier.size(28.dp)
                                )
                            }
                        }
                        "⌫" -> {
                            // Backspace button
                            FilledTonalIconButton(
                                onClick = {
                                    if (pin.isNotEmpty()) {
                                        onPinChange(pin.dropLast(1))
                                    }
                                },
                                enabled = enabled && pin.isNotEmpty(),
                                modifier = Modifier.size(72.dp),
                                shape = CircleShape
                            ) {
                                Icon(
                                    Icons.AutoMirrored.Filled.Backspace,
                                    contentDescription = "Delete",
                                    modifier = Modifier.size(28.dp)
                                )
                            }
                        }
                        else -> {
                            // Digit button
                            FilledTonalButton(
                                onClick = {
                                    if (pin.length < maxLength) {
                                        val newPin = pin + key
                                        onPinChange(newPin)
                                        if (newPin.length == maxLength) {
                                            onSubmit(newPin)
                                        }
                                    }
                                },
                                enabled = enabled && pin.length < maxLength,
                                modifier = Modifier.size(72.dp),
                                shape = CircleShape,
                                contentPadding = PaddingValues(0.dp)
                            ) {
                                Text(
                                    text = key,
                                    fontSize = 24.sp,
                                    fontWeight = FontWeight.Medium
                                )
                            }
                        }
                    }
                }
            }
        }
    }
}

/**
 * Row of dots showing PIN entry progress.
 * Shows one filled dot per entered digit, plus one empty dot as a visual prompt
 * for the next digit (if more can be entered). This avoids implying a fixed PIN length.
 */
@Composable
fun PinDots(filled: Int, showNext: Boolean = true) {
    Row(
        horizontalArrangement = Arrangement.spacedBy(16.dp),
        verticalAlignment = Alignment.CenterVertically,
        modifier = Modifier.semantics { contentDescription = "$filled digits entered" }
    ) {
        // Filled dots for entered digits
        repeat(filled) {
            Surface(
                modifier = Modifier.size(16.dp),
                shape = CircleShape,
                color = MaterialTheme.colorScheme.primary
            ) {}
        }
        // One empty dot to show "you can type more"
        if (showNext) {
            Surface(
                modifier = Modifier.size(16.dp),
                shape = CircleShape,
                color = MaterialTheme.colorScheme.outlineVariant
            ) {}
        }
    }
}
