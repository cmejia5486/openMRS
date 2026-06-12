package com.chartlite.app.extraction

import com.chartlite.app.model.StructuredEncounter
import kotlinx.coroutines.Dispatchers
import kotlinx.coroutines.withContext

/**
 * Wraps the existing ClinicalExtractor as an ExtractionStrategy.
 * Always available — serves as the last-resort fallback.
 */
class RegexExtractionStrategy(
    private val extractor: ClinicalExtractor
) : ExtractionStrategy {

    override val name = "Regex (offline)"
    override val isLlmBased = false

    override suspend fun isAvailable() = true

    override suspend fun extract(
        transcript: String,
        patientId: String,
        providerId: String,
        facilityId: String
    ): StructuredEncounter = withContext(Dispatchers.Default) {
        extractor.extract(transcript, patientId, providerId, facilityId)
    }
}
