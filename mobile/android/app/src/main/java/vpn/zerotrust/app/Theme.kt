package vpn.zerotrust.app

import androidx.compose.foundation.isSystemInDarkTheme
import androidx.compose.material3.MaterialTheme
import androidx.compose.material3.darkColorScheme
import androidx.compose.material3.lightColorScheme
import androidx.compose.runtime.Composable
import androidx.compose.ui.graphics.Color
import androidx.compose.ui.text.TextStyle
import androidx.compose.ui.text.font.FontFamily
import androidx.compose.ui.text.font.FontWeight
import androidx.compose.ui.unit.sp

// Palette matches the 0trust web design system (web/index.html :root vars):
//   --bg #0c0c0a   --ink #f4ede0    --amber #d4a574
//   --terra #c44536    --moss #7d8f5a    --line #2a2820
val ZT_Bg     = Color(0xFF0C0C0A)
val ZT_BgElev = Color(0xFF14140F)
val ZT_Ink    = Color(0xFFF4EDE0)
val ZT_InkDim = Color(0xFFA8A094)
val ZT_InkFnt = Color(0xFF6B6359)
val ZT_Line   = Color(0xFF2A2820)
val ZT_Amber  = Color(0xFFD4A574)
val ZT_Terra  = Color(0xFFC44536)
val ZT_Moss   = Color(0xFF7D8F5A)

private val ZeroTrustDarkColors = darkColorScheme(
    primary           = ZT_Amber,
    onPrimary         = ZT_Bg,
    primaryContainer  = ZT_BgElev,
    onPrimaryContainer = ZT_Ink,

    secondary         = ZT_Moss,
    onSecondary       = ZT_Bg,
    tertiary          = ZT_Terra,
    onTertiary        = ZT_Ink,

    background        = ZT_Bg,
    onBackground      = ZT_Ink,
    surface           = ZT_BgElev,
    onSurface         = ZT_Ink,
    surfaceVariant    = ZT_BgElev,
    onSurfaceVariant  = ZT_InkDim,

    outline           = ZT_Line,
    outlineVariant    = ZT_Line,
    error             = ZT_Terra,
)

/**
 * Custom typography — we'd ideally load Instrument Serif / JetBrains Mono /
 * IBM Plex Sans from the bundled fonts, but to keep the APK small we fall
 * back to system serif + monospace + sans-serif. Add the WOFF2 fonts to
 * res/font/ later and reference them here for the final brand match.
 */
private val ZeroTrustTypography = androidx.compose.material3.Typography(
    displayLarge = TextStyle(
        fontFamily = FontFamily.Serif,
        fontWeight = FontWeight.Normal,
        fontSize = 48.sp, lineHeight = 52.sp, letterSpacing = (-0.5).sp,
    ),
    headlineMedium = TextStyle(
        fontFamily = FontFamily.Serif,
        fontWeight = FontWeight.Normal,
        fontSize = 28.sp, lineHeight = 34.sp,
    ),
    labelSmall = TextStyle(
        fontFamily = FontFamily.Monospace,
        fontWeight = FontWeight.Medium,
        fontSize = 11.sp, lineHeight = 14.sp, letterSpacing = 1.4.sp,
    ),
    bodyLarge = TextStyle(
        fontFamily = FontFamily.SansSerif,
        fontSize = 16.sp, lineHeight = 24.sp,
    ),
    bodyMedium = TextStyle(
        fontFamily = FontFamily.SansSerif,
        fontSize = 14.sp, lineHeight = 20.sp,
    ),
)

@Composable
fun ZeroTrustTheme(content: @Composable () -> Unit) {
    // Always dark — 0trust is a dark-only product
    @Suppress("UNUSED_VARIABLE") val dark = isSystemInDarkTheme()
    MaterialTheme(
        colorScheme = ZeroTrustDarkColors,
        typography  = ZeroTrustTypography,
        content     = content,
    )
}
