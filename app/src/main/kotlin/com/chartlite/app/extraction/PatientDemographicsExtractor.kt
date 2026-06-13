package com.chartlite.app.extraction

/**
 * Extracts patient demographic information from a voice transcript.
 *
 * Follows the same regex-based pattern as VitalsExtractor.
 * Returns a map of field name → extracted value for pre-filling the
 * registration form. The clinician reviews and corrects before saving.
 */
class PatientDemographicsExtractor {

    companion object {
        /** Map spoken number words to digits — ASR often outputs "three" instead of "3". */
        private val WORD_TO_NUMBER = mapOf(
            "zero" to 0, "one" to 1, "two" to 2, "three" to 3, "four" to 4,
            "five" to 5, "six" to 6, "seven" to 7, "eight" to 8, "nine" to 9,
            "ten" to 10, "eleven" to 11, "twelve" to 12, "thirteen" to 13,
            "fourteen" to 14, "fifteen" to 15, "sixteen" to 16, "seventeen" to 17,
            "eighteen" to 18, "nineteen" to 19, "twenty" to 20, "thirty" to 30,
            "forty" to 40, "fifty" to 50, "sixty" to 60, "seventy" to 70,
            "eighty" to 80, "ninety" to 90, "hundred" to 100
        )

        /** Convert a number word or compound ("twenty three") to Int, or parse digits. */
        fun parseSpokenNumber(text: String): Int? {
            // Try direct digit parse first
            text.trim().toIntOrNull()?.let { return it }

            // Try single word
            WORD_TO_NUMBER[text.trim().lowercase()]?.let { return it }

            // Try compound: "twenty three" → 23, "one hundred" → 100
            val words = text.trim().lowercase().split(Regex("[\\s-]+"))
            if (words.isEmpty()) return null

            var result = 0
            for (w in words) {
                val n = WORD_TO_NUMBER[w] ?: return null
                if (n == 100) {
                    result = if (result == 0) 100 else result * 100
                } else {
                    result += n
                }
            }
            return if (result > 0) result else null
        }

        // Pre-compiled regex for compound number matching (e.g., "twenty three")
        private val TENS = listOf("twenty", "thirty", "forty", "fifty", "sixty", "seventy", "eighty", "ninety")
        private val ONES = listOf("one", "two", "three", "four", "five", "six", "seven", "eight", "nine")
        private val COMPOUND_REGEX = Regex(
            "\\b(${TENS.joinToString("|")})\\s+(${ONES.joinToString("|")})\\b"
        )
        private val SINGLE_WORD_REGEX = Regex(
            "\\b(${WORD_TO_NUMBER.keys.joinToString("|")})\\b"
        )

        /**
         * Replace all spoken number words in text with digit equivalents.
         * Handles compounds ("twenty three" → "23") and singles ("three" → "3").
         * Applied as preprocessing so all downstream regex patterns work with digits.
         */
        fun normalizeNumberWords(text: String): String {
            // First pass: compounds like "twenty three" → "23"
            var result = COMPOUND_REGEX.replace(text) { match ->
                val tens = WORD_TO_NUMBER[match.groupValues[1]] ?: 0
                val ones = WORD_TO_NUMBER[match.groupValues[2]] ?: 0
                (tens + ones).toString()
            }
            // Second pass: remaining single words like "three" → "3"
            result = SINGLE_WORD_REGEX.replace(result) { match ->
                val n = WORD_TO_NUMBER[match.groupValues[1]]
                n?.toString() ?: match.value
            }
            return result
        }
    }

    data class Demographics(
        val firstName: String? = null,
        val lastName: String? = null,
        val ageYears: Int? = null,
        val dateOfBirth: String? = null,
        val gender: String? = null,
        val phoneNumber: String? = null,
        val allergies: List<String> = emptyList(),
        val address: String? = null
    )

    fun extract(transcript: String): Demographics {
        // Preprocess: replace spoken number words with digits so all regex patterns
        // work regardless of whether ASR outputs "three" or "3".
        val lower = normalizeNumberWords(transcript.lowercase())

        return Demographics(
            firstName = extractFirstName(lower),
            lastName = extractLastName(lower),
            ageYears = extractAge(lower),
            dateOfBirth = extractDOB(lower),
            gender = extractGender(lower),
            phoneNumber = extractPhone(transcript), // keep original case for digits
            allergies = extractAllergies(lower),
            address = extractAddress(lower)
        )
    }

    private fun extractFirstName(text: String): String? {
        val patterns = listOf(
            // "name is John Smith" or "my name is John Smith"
            Regex("""(?:my\s+)?name\s+is\s+(\w+)(?:\s+(\w+))?"""),
            // "first name John"
            Regex("""first\s+name\s+(?:is\s+)?(\w+)"""),
            // "patient name John Smith"
            Regex("""patient(?:'s)?\s+name\s+(?:is\s+)?(\w+)"""),
            // "called John" / "named John"
            Regex("""(?:called|named)\s+(\w+)""")
        )
        for (p in patterns) {
            val match = p.find(text) ?: continue
            val name = match.groupValues[1]
            if (name.isNotBlank() && name.length >= 2 && !isStopWord(name)) {
                return name.replaceFirstChar { it.uppercase() }
            }
        }
        return null
    }

    private fun extractLastName(text: String): String? {
        val patterns = listOf(
            // "name is John Smith" → captures Smith
            Regex("""(?:my\s+)?name\s+is\s+\w+\s+(\w+)"""),
            // "last name Smith" / "surname Smith"
            Regex("""(?:last\s+name|surname|family\s+name)\s+(?:is\s+)?(\w+)"""),
            // "patient name John Smith" → captures Smith
            Regex("""patient(?:'s)?\s+name\s+(?:is\s+)?\w+\s+(\w+)""")
        )
        for (p in patterns) {
            val match = p.find(text) ?: continue
            val name = match.groupValues[1]
            if (name.isNotBlank() && name.length >= 2 && !isStopWord(name)) {
                return name.replaceFirstChar { it.uppercase() }
            }
        }
        return null
    }

    private fun extractAge(text: String): Int? {
        // Text is already preprocessed by normalizeNumberWords() — "three" → "3" etc.
        val patterns = listOf(
            Regex("""(?:age|aged)\s+(?:is\s+)?(\d{1,3})(?:\s+years?)?"""),
            Regex("""(\d{1,3})\s+years?\s+old"""),
            Regex("""(\d{1,3})\s*(?:year|yr)s?\s*(?:of\s+age)?"""),
            Regex("""(?:he|she|patient)\s+is\s+(\d{1,3})""")
        )
        for (p in patterns) {
            val match = p.find(text) ?: continue
            val age = match.groupValues[1].toIntOrNull()
            if (age != null && age in 0..150) return age
        }
        return null
    }

    private fun extractDOB(text: String): String? {
        val patterns = listOf(
            // "born on 15/03/1985" or "date of birth 15/03/1985"
            Regex("""(?:born|date\s+of\s+birth|dob)\s+(?:is\s+|on\s+)?(\d{1,2})\s*/\s*(\d{1,2})\s*/\s*(\d{4})"""),
            // "born January 15 1985" / "born 15 January 1985"
            Regex("""(?:born|dob)\s+(?:on\s+)?(\d{1,2})\s+(january|february|march|april|may|june|july|august|september|october|november|december)\s+(\d{4})"""),
            Regex("""(?:born|dob)\s+(?:on\s+)?(january|february|march|april|may|june|july|august|september|october|november|december)\s+(\d{1,2})\s*,?\s*(\d{4})""")
        )

        // Try DD/MM/YYYY format first
        patterns[0].find(text)?.let { match ->
            val day = match.groupValues[1].padStart(2, '0')
            val month = match.groupValues[2].padStart(2, '0')
            val year = match.groupValues[3]
            return "$day/$month/$year"
        }

        // Try "15 January 1985"
        patterns[1].find(text)?.let { match ->
            val day = match.groupValues[1].padStart(2, '0')
            val month = monthToNumber(match.groupValues[2])
            val year = match.groupValues[3]
            if (month != null) return "$day/$month/$year"
        }

        // Try "January 15, 1985"
        patterns[2].find(text)?.let { match ->
            val month = monthToNumber(match.groupValues[1])
            val day = match.groupValues[2].padStart(2, '0')
            val year = match.groupValues[3]
            if (month != null) return "$day/$month/$year"
        }

        return null
    }

    private fun extractGender(text: String): String? {
        return when {
            Regex("""(?:^|\s)(?:male|man|boy|he\s+is|gender\s+(?:is\s+)?male)""").containsMatchIn(text) -> "male"
            Regex("""(?:^|\s)(?:female|woman|girl|she\s+is|gender\s+(?:is\s+)?female)""").containsMatchIn(text) -> "female"
            else -> null
        }
    }

    private fun extractPhone(text: String): String? {
        val patterns = listOf(
            // "phone number is 072 123 4567" or "phone 0721234567"
            Regex("""(?:phone|cell|mobile|contact|number)\s+(?:number\s+)?(?:is\s+)?([\d\s\-+()]{7,15})"""),
            // "call 072 123 4567"
            Regex("""call\s+(?:at\s+)?([\d\s\-+()]{7,15})""")
        )
        for (p in patterns) {
            val match = p.find(text.lowercase()) ?: continue
            val phone = match.groupValues[1].replace(Regex("[\\s\\-()]"), "")
            if (phone.length in 7..15) {
                // Find the phone number in original text to preserve formatting
                return phone
            }
        }
        return null
    }

    private fun extractAllergies(text: String): List<String> {
        val allergies = mutableListOf<String>()
        val patterns = listOf(
            Regex("""allerg(?:ic|y)\s+to\s+([\w\s,]+?)(?:\.|and\s+no|$)"""),
            Regex("""([\w]+)\s+allergy"""),
            Regex("""known\s+allerg(?:ic|y)\s+(?:to\s+)?([\w\s,]+?)(?:\.|$)""")
        )

        for (pattern in patterns) {
            pattern.findAll(text).forEach { match ->
                val allergenStr = match.groupValues[1].trim()
                // Split comma-separated allergies
                allergenStr.split(",", " and ").forEach { a ->
                    val allergen = a.trim()
                    if (allergen.isNotBlank() && allergen.length in 2..30) {
                        allergies.add(allergen)
                    }
                }
            }
        }

        // Check for "no known allergies"
        if (Regex("""no\s+(?:known\s+)?allergies""").containsMatchIn(text)) {
            return emptyList()
        }

        return allergies.distinct()
    }

    private fun extractAddress(text: String): String? {
        val patterns = listOf(
            Regex("""(?:lives?\s+(?:in|at)|address\s+(?:is)?|from)\s+([\w\s,]+?)(?:\.|$)"""),
            Regex("""(?:staying|residing)\s+(?:in|at)\s+([\w\s,]+?)(?:\.|$)""")
        )
        for (p in patterns) {
            val match = p.find(text) ?: continue
            val address = match.groupValues[1].trim()
            if (address.isNotBlank() && address.length in 3..100) {
                return address.split(" ").joinToString(" ") { word ->
                    word.replaceFirstChar { it.uppercase() }
                }
            }
        }
        return null
    }

    private fun monthToNumber(month: String): String? = when (month.lowercase()) {
        "january" -> "01"; "february" -> "02"; "march" -> "03"
        "april" -> "04"; "may" -> "05"; "june" -> "06"
        "july" -> "07"; "august" -> "08"; "september" -> "09"
        "october" -> "10"; "november" -> "11"; "december" -> "12"
        else -> null
    }

    private fun isStopWord(word: String): Boolean =
        word in setOf("the", "a", "an", "is", "was", "are", "his", "her", "and", "or", "has", "had", "with")
}
