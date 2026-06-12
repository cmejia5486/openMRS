package com.lyecdevelopers.core.ui.theme
import android.os.Build
import androidx.compose.foundation.isSystemInDarkTheme
import androidx.compose.material3.MaterialTheme
import androidx.compose.material3.darkColorScheme
import androidx.compose.material3.dynamicDarkColorScheme
import androidx.compose.material3.dynamicLightColorScheme
import androidx.compose.material3.lightColorScheme
import androidx.compose.runtime.Composable
import androidx.compose.ui.graphics.Color
import androidx.compose.ui.platform.LocalContext
import androidx.compose.ui.res.colorResource
import com.lyecdevelopers.core.R
import com.lyecdevelopers.core.model.BrandColors


@Composable
fun UgandaEMRMobileTheme(
    darkTheme: Boolean = isSystemInDarkTheme(),
    dynamicColor: Boolean = true,
    content: @Composable () -> Unit,
) {
    val brandColors = provideBrandColors()

    val colorScheme = when {
        dynamicColor && Build.VERSION.SDK_INT >= Build.VERSION_CODES.S -> {
            val context = LocalContext.current
            if (darkTheme) dynamicDarkColorScheme(context) else dynamicLightColorScheme(context)
        }
        darkTheme -> darkColorScheme(
            primary = brandColors.primary,
            primaryContainer = brandColors.primaryVariant,
            secondary = brandColors.secondary,
            secondaryContainer = brandColors.secondaryVariant,
            tertiary = brandColors.accent,
            tertiaryContainer = brandColors.accentVariant,
            background = brandColors.background,
            surface = brandColors.surface,
            error = brandColors.error,
            onPrimary = Color.White,
            onSecondary = Color.Black,
            onBackground = Color.Black,
            onSurface = Color.Black,
            onError = Color.White,
        )
        else -> lightColorScheme(
            primary = brandColors.primary,
            primaryContainer = brandColors.primaryVariant,
            secondary = brandColors.secondary,
            secondaryContainer = brandColors.secondaryVariant,
            tertiary = brandColors.accent,
            tertiaryContainer = brandColors.accentVariant,
            background = brandColors.background,
            surface = brandColors.surface,
            error = brandColors.error,
            onPrimary = Color.White,
            onSecondary = Color.Black,
            onBackground = Color.Black,
            onSurface = Color.Black,
            onError = Color.White,
        )
    }

    MaterialTheme(
        colorScheme = colorScheme,
        typography = Typography,
        content = content
    )
}

@Composable
fun provideBrandColors(): BrandColors {
    return BrandColors(
        primary = colorResource(id = R.color.colorPrimary),
        primaryVariant = colorResource(id = R.color.colorPrimaryVariant),
        secondary = colorResource(id = R.color.colorSecondary),
        secondaryVariant = colorResource(id = R.color.colorSecondaryVariant),
        accent = colorResource(id = R.color.colorAccent),
        accentVariant = colorResource(id = R.color.colorAccentVariant),
        surface = colorResource(id = R.color.colorSurface),
        background = colorResource(id = R.color.colorBackground),
        error = colorResource(id = R.color.colorError),
        success = colorResource(id = R.color.colorSuccess),
        warning = colorResource(id = R.color.colorWarning),
        info = colorResource(id = R.color.colorInfo),
        neutral = colorResource(id = R.color.colorNeutral),
        primaryDark = colorResource(id = R.color.colorPrimaryDark),
        secondaryDark = colorResource(id = R.color.colorSecondaryDark),
        accentDark = colorResource(id = R.color.colorAccentDark),
    )
}
