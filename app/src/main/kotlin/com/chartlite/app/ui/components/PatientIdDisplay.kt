package com.chartlite.app.ui.components

import android.widget.Toast
import androidx.compose.foundation.background
import androidx.compose.foundation.border
import androidx.compose.foundation.clickable
import androidx.compose.foundation.layout.*
import androidx.compose.foundation.shape.RoundedCornerShape
import androidx.compose.material.icons.Icons
import androidx.compose.material.icons.filled.ContentCopy
import androidx.compose.material3.*
import androidx.compose.runtime.*
import androidx.compose.ui.Alignment
import androidx.compose.ui.Modifier
import androidx.compose.ui.draw.clip
import androidx.compose.ui.graphics.Brush
import androidx.compose.ui.graphics.Color
import androidx.compose.ui.platform.LocalClipboardManager
import androidx.compose.ui.platform.LocalContext
import androidx.compose.ui.text.AnnotatedString
import androidx.compose.ui.text.font.FontFamily
import androidx.compose.ui.text.font.FontWeight
import androidx.compose.ui.text.style.TextAlign
import androidx.compose.ui.text.style.TextOverflow
import androidx.compose.ui.unit.dp
import androidx.compose.ui.unit.sp
import com.chartlite.app.ui.theme.BrandGreen
import com.chartlite.app.ui.theme.BrandGreenDark
import com.chartlite.app.ui.theme.BrandGreenSurface

@Composable
fun PatientIdDisplay(
    patientId: String,
    modifier: Modifier = Modifier,
    showCopyHint: Boolean = true,
    size: PatientIdSize = PatientIdSize.LARGE
) {
    val shape = RoundedCornerShape(16.dp)
    val clipboardManager = LocalClipboardManager.current
    val context = LocalContext.current

    Column(
        modifier = modifier,
        horizontalAlignment = Alignment.CenterHorizontally
    ) {
        BoxWithConstraints {
            // Auto-downsize on narrow screens to prevent wrapping
            val effectiveSize = when {
                size == PatientIdSize.LARGE && maxWidth <= 360.dp -> PatientIdSize.MEDIUM
                else -> size
            }
            val horizontalPad = when (effectiveSize) {
                PatientIdSize.LARGE -> 20.dp
                PatientIdSize.MEDIUM -> 16.dp
                PatientIdSize.SMALL -> 12.dp
            }

            Box(
                modifier = Modifier
                    .clip(shape)
                    .background(
                        Brush.verticalGradient(
                            listOf(BrandGreenSurface, Color.White)
                        )
                    )
                    .border(2.dp, BrandGreen.copy(alpha = 0.3f), shape)
                    .clickable {
                        clipboardManager.setText(AnnotatedString(patientId))
                        Toast.makeText(context, "Patient ID copied", Toast.LENGTH_SHORT).show()
                    }
                    .padding(horizontal = horizontalPad, vertical = 20.dp),
                contentAlignment = Alignment.Center
            ) {
                Column(horizontalAlignment = Alignment.CenterHorizontally) {
                    Text(
                        "PATIENT ID",
                        style = MaterialTheme.typography.labelMedium,
                        color = BrandGreenDark.copy(alpha = 0.85f),
                        letterSpacing = 3.sp
                    )
                    Spacer(Modifier.height(8.dp))
                    Text(
                        patientId,
                        fontSize = when (effectiveSize) {
                            PatientIdSize.LARGE -> 44.sp
                            PatientIdSize.MEDIUM -> 28.sp
                            PatientIdSize.SMALL -> 18.sp
                        },
                        fontWeight = FontWeight.Bold,
                        fontFamily = FontFamily.Monospace,
                        color = BrandGreenDark,
                        letterSpacing = when (effectiveSize) {
                            PatientIdSize.LARGE -> 3.sp
                            PatientIdSize.MEDIUM -> 2.sp
                            PatientIdSize.SMALL -> 1.sp
                        },
                        textAlign = TextAlign.Center,
                        maxLines = 1,
                        overflow = TextOverflow.Ellipsis
                    )
                }
            }
        }

        if (showCopyHint && size == PatientIdSize.LARGE) {
            Spacer(Modifier.height(12.dp))
            Text(
                "Tap to copy \u2022 Write this ID on the patient\u2019s booklet",
                style = MaterialTheme.typography.bodySmall,
                color = MaterialTheme.colorScheme.onSurfaceVariant
            )
        }
    }
}

enum class PatientIdSize { LARGE, MEDIUM, SMALL }
