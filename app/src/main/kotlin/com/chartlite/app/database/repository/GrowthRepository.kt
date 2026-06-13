package com.chartlite.app.database.repository

import com.chartlite.app.database.dao.GrowthDao
import com.chartlite.app.database.entity.GrowthMeasurementEntity
import java.util.UUID

/**
 * Business logic for pediatric growth measurements and Z-score computation.
 * Z-scores are computed against simplified WHO growth standards (0-5 years).
 *
 * NOTE: Z-score computations use simplified linear approximations of WHO medians.
 * For production accuracy, replace with full WHO LMS (Lambda-Mu-Sigma) tables
 * loaded from who_standards.json. Current approximations are suitable for
 * screening-level alerts but should not be used for precise nutritional diagnosis.
 */
class GrowthRepository(private val growthDao: GrowthDao) {

    /**
     * @param isMale true for boys, false for girls. Defaults to true (male reference)
     *        when sex is unknown — this may over-flag malnutrition in girls.
     */
    suspend fun recordMeasurement(
        patientId: String,
        measuredBy: String,
        weight: Float? = null,
        height: Float? = null,
        headCircumference: Float? = null,
        muac: Float? = null,
        visitId: String? = null,
        ageInMonths: Int? = null,
        isMale: Boolean = true
    ): GrowthMeasurementEntity {
        // Validate measurements
        val validWeight = weight?.takeIf { it > 0f && it < 200f }
        val validHeight = height?.takeIf { it > 0f && it < 250f }
        val validAge = ageInMonths?.takeIf { it in 0..240 }

        // Compute Z-scores if we have valid age data (only reliable for 0-60 months)
        val waz = if (validWeight != null && validAge != null && validAge <= 60)
            computeWeightForAgeZ(validWeight, validAge, isMale) else null
        val haz = if (validHeight != null && validAge != null && validAge <= 60)
            computeHeightForAgeZ(validHeight, validAge, isMale) else null
        val baz = if (validWeight != null && validHeight != null && validHeight > 0f && validAge != null && validAge <= 60) {
            val bmi = validWeight / ((validHeight / 100f) * (validHeight / 100f))
            if (bmi.isFinite()) computeBMIForAgeZ(bmi, validAge) else null
        } else null

        val measurement = GrowthMeasurementEntity(
            id = UUID.randomUUID().toString(),
            patientId = patientId,
            visitId = visitId,
            weight = validWeight,
            height = validHeight,
            headCircumference = headCircumference?.takeIf { it > 0f && it < 100f },
            muac = muac?.takeIf { it > 0f && it < 50f },
            measuredAt = System.currentTimeMillis(),
            measuredBy = measuredBy,
            weightForAgeZ = waz,
            heightForAgeZ = haz,
            bmiForAgeZ = baz
        )
        growthDao.insert(measurement)
        return measurement
    }

    suspend fun getByPatient(patientId: String) = growthDao.getByPatient(patientId)
    suspend fun getLatest(patientId: String) = growthDao.getLatest(patientId)
    fun observeByPatient(patientId: String) = growthDao.observeByPatient(patientId)

    /**
     * Simplified WHO Z-score approximation for weight-for-age.
     * Uses sex-differentiated medians (boys are ~5% heavier on average).
     */
    internal fun computeWeightForAgeZ(weight: Float, ageMonths: Int, isMale: Boolean = true): Float {
        // Sex-specific adjustment: girls' median is ~5% lower than boys' on average
        val sexFactor = if (isMale) 1.0f else 0.95f
        val median = when {
            ageMonths <= 0 -> 3.3f
            ageMonths <= 6 -> 3.3f + ageMonths * 0.8f
            ageMonths <= 12 -> 7.5f + (ageMonths - 6) * 0.35f
            ageMonths <= 24 -> 9.6f + (ageMonths - 12) * 0.2f
            ageMonths <= 60 -> 12.0f + (ageMonths - 24) * 0.15f
            else -> return 0f // Not reliable above 5 years without full LMS tables
        } * sexFactor
        val sd = median * 0.12f // ~12% CV
        return if (sd > 0) (weight - median) / sd else 0f
    }

    internal fun computeHeightForAgeZ(height: Float, ageMonths: Int, isMale: Boolean = true): Float {
        val sexFactor = if (isMale) 1.0f else 0.98f
        val median = when {
            ageMonths <= 0 -> 49.9f
            ageMonths <= 12 -> 49.9f + ageMonths * 2.1f
            ageMonths <= 24 -> 75.0f + (ageMonths - 12) * 1.0f
            ageMonths <= 60 -> 87.0f + (ageMonths - 24) * 0.6f
            else -> return 0f
        } * sexFactor
        val sd = median * 0.04f // ~4% CV for height
        return if (sd > 0) (height - median) / sd else 0f
    }

    internal fun computeBMIForAgeZ(bmi: Float, ageMonths: Int): Float {
        // BMI-for-age medians are very similar between sexes at young ages
        val median = when {
            ageMonths <= 6 -> 17.0f
            ageMonths <= 12 -> 17.5f
            ageMonths <= 24 -> 16.5f
            ageMonths <= 60 -> 15.5f
            else -> return 0f
        }
        val sd = 1.3f
        return (bmi - median) / sd
    }

    companion object {
        /** Z-score thresholds for malnutrition classification (WHO standards) */
        const val Z_MODERATE_MALNUTRITION = -2.0f
        const val Z_SEVERE_MALNUTRITION = -3.0f
        const val Z_OVERWEIGHT = 2.0f
        const val Z_OBESE = 3.0f
    }
}
