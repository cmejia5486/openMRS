package com.chartlite.app.ui.components

import androidx.compose.material3.MaterialTheme
import androidx.compose.material3.Text
import androidx.compose.runtime.Composable
import androidx.compose.runtime.remember
import androidx.compose.ui.Modifier
import androidx.compose.ui.text.AnnotatedString
import androidx.compose.ui.text.SpanStyle
import androidx.compose.ui.text.TextStyle
import androidx.compose.ui.text.buildAnnotatedString
import androidx.compose.ui.text.font.FontStyle
import androidx.compose.ui.text.font.FontWeight
import androidx.compose.ui.text.withStyle
import androidx.compose.ui.unit.sp

/**
 * Renders a subset of Markdown as styled text using [buildAnnotatedString].
 *
 * Supported syntax:
 *   # Heading 1          → bold, +4sp
 *   ## Heading 2         → bold, +2sp
 *   ### Heading 3        → bold, same size
 *   **bold**             → bold inline spans
 *   *italic*             → italic inline spans
 *   - bullet / • bullet  → indented with •
 *   1. numbered list     → rendered with number prefix
 *   --- / ***            → blank line (section divider)
 *   **Bold:** on own line → treated as heading (bold, +2sp)
 *   Blank lines          → paragraph spacing
 */
@Composable
fun MarkdownText(
    text: String,
    modifier: Modifier = Modifier,
    style: TextStyle = MaterialTheme.typography.bodyMedium,
) {
    val annotated = remember(text, style) { parseMarkdown(text, style) }
    Text(annotated, modifier = modifier, style = style)
}

/** Regex for numbered list items like "1. ", "2. ", "10. " */
private val NUMBERED_LIST_REGEX = Regex("""^(\d+)\.\s""")

/** Regex for horizontal rules */
private val HORIZONTAL_RULE_REGEX = Regex("""^[-*_]{3,}\s*$""")

/** Regex for bold-colon header on its own line: **Something:** */
private val BOLD_HEADER_LINE_REGEX = Regex("""^\*\*(.+?):\*\*\s*$""")

private fun parseMarkdown(text: String, baseStyle: TextStyle): AnnotatedString {
    val baseFontSize = baseStyle.fontSize.let { if (it.isSp) it else 14.sp }

    return buildAnnotatedString {
        val lines = text.split('\n')
        var prevWasBlank = false

        for ((i, rawLine) in lines.withIndex()) {
            val line = rawLine.trimEnd()

            when {
                // Blank line → paragraph spacing
                line.isBlank() -> {
                    if (!prevWasBlank && i > 0 && i < lines.lastIndex) {
                        append('\n')
                    }
                    prevWasBlank = true
                    continue
                }

                // Horizontal rule (--- or *** or ___)
                HORIZONTAL_RULE_REGEX.matches(line) -> {
                    append('\n')
                    prevWasBlank = true
                    continue
                }

                // ### Heading 3
                line.startsWith("### ") -> {
                    if (prevWasBlank && length > 0) append('\n')
                    withStyle(SpanStyle(fontWeight = FontWeight.Bold)) {
                        appendInlineStyles(line.removePrefix("### "))
                    }
                }
                // ## Heading 2
                line.startsWith("## ") -> {
                    if (prevWasBlank && length > 0) append('\n')
                    withStyle(SpanStyle(fontWeight = FontWeight.Bold, fontSize = baseFontSize * 1.15f)) {
                        appendInlineStyles(line.removePrefix("## "))
                    }
                }
                // # Heading 1
                line.startsWith("# ") -> {
                    if (prevWasBlank && length > 0) append('\n')
                    withStyle(SpanStyle(fontWeight = FontWeight.Bold, fontSize = baseFontSize * 1.3f)) {
                        appendInlineStyles(line.removePrefix("# "))
                    }
                }

                // **Bold Header:** on its own line → treat as heading
                BOLD_HEADER_LINE_REGEX.matches(line) -> {
                    if (prevWasBlank && length > 0) append('\n')
                    val headerText = BOLD_HEADER_LINE_REGEX.find(line)!!.groupValues[1]
                    withStyle(SpanStyle(fontWeight = FontWeight.Bold, fontSize = baseFontSize * 1.15f)) {
                        append(headerText)
                    }
                }

                // Bullet list (top level)
                line.startsWith("- ") || line.startsWith("• ") || line.startsWith("* ") -> {
                    append("  • ")
                    appendInlineStyles(line.drop(2))
                }

                // Indented bullet (  - item)
                line.trimStart().let { it.startsWith("- ") || it.startsWith("• ") || it.startsWith("* ") } &&
                        line.startsWith("  ") -> {
                    append("    • ")
                    appendInlineStyles(line.trimStart().drop(2))
                }

                // Numbered list (1. item, 2. item, etc.)
                NUMBERED_LIST_REGEX.containsMatchIn(line) -> {
                    val match = NUMBERED_LIST_REGEX.find(line)!!
                    val number = match.groupValues[1]
                    append("  $number. ")
                    appendInlineStyles(line.substring(match.range.last + 1))
                }

                // Plain line — still parse inline styles
                else -> {
                    if (prevWasBlank && length > 0) append('\n')
                    appendInlineStyles(line)
                }
            }

            prevWasBlank = false
            if (i < lines.lastIndex) append('\n')
        }
    }
}

/**
 * Appends [text] while converting `**bold**` and `*italic*` spans to styled text.
 */
private fun AnnotatedString.Builder.appendInlineStyles(text: String) {
    var cursor = 0
    while (cursor < text.length) {
        // Check for ** (bold)
        val boldStart = text.indexOf("**", cursor)
        // Check for * (italic) — but not **
        val italicStart = findSingleAsterisk(text, cursor)

        // Determine which comes first
        val nextBold = if (boldStart >= 0) boldStart else Int.MAX_VALUE
        val nextItalic = if (italicStart >= 0) italicStart else Int.MAX_VALUE

        when {
            nextBold <= nextItalic && nextBold != Int.MAX_VALUE -> {
                // Bold match
                val end = text.indexOf("**", boldStart + 2)
                if (end == -1) {
                    append(text.substring(cursor))
                    return
                }
                append(text.substring(cursor, boldStart))
                withStyle(SpanStyle(fontWeight = FontWeight.Bold)) {
                    append(text.substring(boldStart + 2, end))
                }
                cursor = end + 2
            }
            nextItalic < nextBold && nextItalic != Int.MAX_VALUE -> {
                // Italic match
                val end = findSingleAsterisk(text, italicStart + 1)
                if (end == -1) {
                    append(text.substring(cursor))
                    return
                }
                append(text.substring(cursor, italicStart))
                withStyle(SpanStyle(fontStyle = FontStyle.Italic)) {
                    append(text.substring(italicStart + 1, end))
                }
                cursor = end + 1
            }
            else -> {
                append(text.substring(cursor))
                return
            }
        }
    }
}

/**
 * Find index of a single `*` (not `**`) starting from [startIndex].
 * Returns -1 if not found.
 */
private fun findSingleAsterisk(text: String, startIndex: Int): Int {
    var i = startIndex
    while (i < text.length) {
        if (text[i] == '*') {
            val isDouble = (i + 1 < text.length && text[i + 1] == '*') ||
                    (i > 0 && text[i - 1] == '*')
            if (!isDouble) return i
            // Skip the pair
            if (i + 1 < text.length && text[i + 1] == '*') i += 2 else i++
        } else {
            i++
        }
    }
    return -1
}
