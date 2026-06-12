package com.chartlite.app.sms

import com.chartlite.app.model.*
import java.nio.ByteBuffer
import java.security.MessageDigest
import java.time.Instant
import java.time.LocalDate
import java.time.ZoneOffset
import java.time.temporal.ChronoUnit

/**
 * Encodes a StructuredEncounter into a compact binary format (exactly 92 bytes)
 * for transmission via a single SMS.
 *
 * Fixed-layout wire format (all fields at fixed byte offsets):
 *   Byte  0:      Version + message type
 *   Bytes 1-2:    Encounter date (days since 2024-01-01)
 *   Bytes 3-5:    Provider hash (12b) + Facility hash (12b)
 *   Bytes 6-9:    Patient ID hash (first 4 bytes of SHA-256)
 *   Byte  10:     Flags (numDx:2 | numMeds:2 | urgency:2 | followUpType:2)
 *   Bytes 11-14:  Diagnoses — 3 × 9-bit ICD-10 indices, packed (always 4 bytes)
 *   Bytes 15-20:  Medications — 3 × 16-bit packed (always 6 bytes)
 *   Bytes 21-25:  Vitals — systolic, diastolic, temp, weight, pulse (5 bytes)
 *   Byte  26:     Allergy flags (1 byte)
 *   Byte  27:     Follow-up value (1 byte)
 *   Bytes 28-90:  Free-text note (63 bytes, truncated ASCII, zero-padded)
 *   Byte  91:     CRC-8/MAXIM checksum (poly 0x31, reflected)
 */
object BinaryEncoder {

    private val EPOCH = LocalDate.of(2024, 1, 1)

    // Fixed field sizes — always written regardless of actual count
    private const val MAX_DIAGNOSES = 3
    private const val MAX_MEDICATIONS = 3
    private const val DX_PACKED_BYTES = 4   // ceil(3 × 9 / 8) = 4 bytes
    private const val MEDS_PACKED_BYTES = 6 // 3 × 2 bytes

    // Dose code table (4 bits)
    private val DOSE_CODES = mapOf(
        50f to 0x1, 100f to 0x2, 125f to 0x3, 250f to 0x4,
        500f to 0x5, 1000f to 0x6, 5f to 0x7, 10f to 0x8,
        20f to 0x9, 25f to 0xA, 40f to 0xB, 2.5f to 0xC
    )

    // Frequency code table (3 bits)
    private val FREQ_CODES = mapOf(
        "OD" to 1, "BD" to 2, "TDS" to 3, "QDS" to 4,
        "PRN" to 5, "STAT" to 6, "WEEKLY" to 7
    )

    // Common allergy flags (1 byte)
    private val ALLERGY_FLAGS = mapOf(
        "penicillin" to 7, "sulfa" to 6, "nsaid" to 5, "latex" to 4,
        "contrast" to 3, "opioid" to 2, "ace inhibitor" to 1
    )

    fun encode(encounter: StructuredEncounter): ByteArray {
        val buffer = ByteBuffer.allocate(92)

        // Byte 0: Version + message type
        buffer.put(0x01.toByte())

        // Bytes 1-2: Encounter date (days since 2024-01-01)
        val encounterDate = encounter.timestamp.atZone(ZoneOffset.UTC).toLocalDate()
        val daysSinceEpoch = ChronoUnit.DAYS.between(EPOCH, encounterDate).toInt()
            .coerceIn(0, 65535)  // Guard: negative days (timestamp=0 → 1970) wraps to ~2149
        buffer.putShort(daysSinceEpoch.toShort())

        // Bytes 3-5: Provider (12 bits) + Facility (12 bits)
        val providerHash = encounter.providerId.hashCode() and 0xFFF
        val facilityHash = encounter.facilityId.hashCode() and 0xFFF
        val combined = (providerHash shl 12) or facilityHash
        buffer.put(((combined shr 16) and 0xFF).toByte())
        buffer.put(((combined shr 8) and 0xFF).toByte())
        buffer.put((combined and 0xFF).toByte())

        // Bytes 6-9: Patient ID hash (first 4 bytes of SHA-256)
        val patientHash = MessageDigest.getInstance("SHA-256")
            .digest(encounter.patientId.toByteArray())
        buffer.put(patientHash, 0, 4)

        // Byte 10: Flags
        val numDx = encounter.diagnoses.size.coerceAtMost(MAX_DIAGNOSES)
        val numMeds = encounter.medications.size.coerceAtMost(MAX_MEDICATIONS)
        val urgency = when (encounter.referral?.urgency) {
            "soon" -> 1; "urgent" -> 2; "emergency" -> 3; else -> 0
        }
        val followUpType = when {
            encounter.followUp == null -> 0
            (encounter.followUp.days) <= 31 -> 1
            (encounter.followUp.days) <= 210 -> 2
            else -> 3
        }
        val flags = ((numDx and 3) shl 6) or ((numMeds and 3) shl 4) or
                ((urgency and 3) shl 2) or (followUpType and 3)
        buffer.put(flags.toByte())

        // Bytes 11-14: Diagnoses — always 3 slots × 9 bits = 27 bits → 4 bytes (fixed layout)
        val dxValues = IntArray(MAX_DIAGNOSES) // zero-padded for unused slots
        for (i in 0 until numDx) {
            dxValues[i] = codeToIndex(encounter.diagnoses[i].icd10Code)
        }
        writeFixedBitPacked(buffer, dxValues, 9, DX_PACKED_BYTES)

        // Bytes 15-20: Medications — always 3 slots × 16 bits = 6 bytes (fixed layout)
        for (i in 0 until MAX_MEDICATIONS) {
            if (i < numMeds) {
                val med = encounter.medications[i]
                val drugIndex = med.formularyCode.filter { it.isDigit() }.toIntOrNull() ?: 0
                val doseCode = med.dose?.let { DOSE_CODES[it] } ?: 0
                val freqCode = med.frequency?.let { FREQ_CODES[it] } ?: 0
                val packed = ((drugIndex and 0x1FF) shl 7) or
                        ((doseCode and 0xF) shl 3) or (freqCode and 0x7)
                buffer.putShort(packed.toShort())
            } else {
                buffer.putShort(0) // zero-pad unused medication slots
            }
        }

        // Bytes 21-25: Vitals (5 bytes, fixed position)
        val v = encounter.vitals
        buffer.put(((v?.systolicBP ?: 120) - 60).coerceIn(0, 255).toByte())
        buffer.put(((v?.diastolicBP ?: 80) - 30).coerceIn(0, 255).toByte())
        buffer.put(((((v?.temperature ?: 37.0f) - 35.0f) * 10).toInt()).coerceIn(0, 255).toByte())
        buffer.put((v?.weight?.toInt() ?: 0).coerceIn(0, 255).toByte())
        buffer.put((v?.pulse ?: 0).coerceIn(0, 255).toByte())

        // Byte 26: Allergy flags (1 byte, fixed position)
        var allergyByte = 0
        for (allergy in encounter.allergies) {
            val lower = allergy.lowercase()
            for ((name, bit) in ALLERGY_FLAGS) {
                if (lower.contains(name)) {
                    allergyByte = allergyByte or (1 shl bit)
                }
            }
            // "other" flag at bit 0 for unrecognized allergies
            if (ALLERGY_FLAGS.none { (name, _) -> lower.contains(name) }) {
                allergyByte = allergyByte or 1
            }
        }
        buffer.put(allergyByte.toByte())

        // Byte 27: Follow-up (1 byte, fixed position)
        val followUpValue = when (followUpType) {
            1 -> encounter.followUp?.days ?: 0
            2 -> (encounter.followUp?.days ?: 0) / 7
            3 -> (encounter.followUp?.days ?: 0) / 30
            else -> 0
        }
        buffer.put(followUpValue.coerceIn(0, 255).toByte())

        // Bytes 28-90: Free-text note (63 bytes, truncated ASCII, zero-padded)
        val noteSpace = 91 - buffer.position() // should be 63
        if (encounter.freeTextNote.isNotBlank()) {
            val noteBytes = encounter.freeTextNote
                .take(noteSpace)
                .toByteArray(Charsets.US_ASCII)
            buffer.put(noteBytes, 0, minOf(noteBytes.size, noteSpace))
        }

        // Zero-pad to position 91
        while (buffer.position() < 91) buffer.put(0)

        // Byte 91: CRC-8/MAXIM checksum
        val data = ByteArray(91)
        buffer.position(0)
        buffer.get(data)
        buffer.put(crc8maxim(data))

        return buffer.array().copyOf(92)
    }

    /**
     * Encode encounter + patient health history into a v2 binary payload.
     * V2 includes current encounter data (same as v1 bytes 1-27) plus a
     * health history section with chronic conditions, abnormal vitals,
     * and cumulative allergy flags. Fixed 92 bytes (same as v1) — fits
     * in a single SMS after encryption + Base64. The note space is reduced
     * to make room for health history (30-60 bytes depending on history size).
     *
     * This makes each SMS a "portable health record" — the patient can
     * store only the latest SMS and have all significant clinical details.
     */
    fun encodeWithHistory(encounter: StructuredEncounter, summary: PatientHealthSummary): ByteArray {
        val numChronicDx = summary.chronicConditions.size.coerceAtMost(5)
        val numAbnormalVitals = summary.abnormalVitals.size.coerceAtMost(5)

        // Calculate total payload size
        val historyHeaderBytes = 3  // flags + cumAllergyFlags + totalVisits
        val chronicBytes = numChronicDx * 2
        val abnormalVitalBytes = numAbnormalVitals * 4
        val structuredBytes = 28 + historyHeaderBytes + chronicBytes + abnormalVitalBytes
        val noteSpace = (MAX_V2_PAYLOAD - structuredBytes - 1).coerceAtLeast(0) // -1 for CRC
        val totalSize = structuredBytes + noteSpace + 1 // +1 for CRC

        val buffer = ByteBuffer.allocate(totalSize)

        // ── Byte 0: Version (0x02 for v2) ──
        buffer.put(0x02.toByte())

        // ── Bytes 1-27: Current encounter (same encoding as v1) ──
        encodeEncounterSection(buffer, encounter)

        // ── Byte 28: History flags ──
        // numChronicDx(3b) | numAbnormalVitals(3b) | reserved(2b)
        val histFlags = ((numChronicDx and 7) shl 5) or ((numAbnormalVitals and 7) shl 2)
        buffer.put(histFlags.toByte())

        // ── Byte 29: Cumulative allergy flags ──
        buffer.put(summary.cumulativeAllergyFlags.toByte())

        // ── Byte 30: Total visit count ──
        buffer.put(summary.totalVisits.coerceAtMost(255).toByte())

        // ── Chronic conditions: 2 bytes each (9-bit ICD hash + 7-bit count) ──
        for (i in 0 until numChronicDx) {
            val cc = summary.chronicConditions[i]
            val icdIndex = codeToIndex(cc.icd10Code)
            val count = cc.occurrenceCount.coerceAtMost(127)
            val packed = ((icdIndex and 0x1FF) shl 7) or (count and 0x7F)
            buffer.putShort(packed.toShort())
        }

        // ── Abnormal vitals: 4 bytes each (date:2 + type:1 + value:1) ──
        for (i in 0 until numAbnormalVitals) {
            val av = summary.abnormalVitals[i]
            val daysSinceEpoch = java.time.temporal.ChronoUnit.DAYS.between(EPOCH, av.date).toInt()
            buffer.putShort(daysSinceEpoch.toShort())
            buffer.put(av.type.ordinal.toByte())
            buffer.put(av.rawValue.coerceIn(0, 255).toByte())
        }

        // ── Free-text note (truncated to remaining space before CRC) ──
        val remainingForNote = totalSize - buffer.position() - 1 // -1 for CRC
        if (encounter.freeTextNote.isNotBlank() && remainingForNote > 0) {
            val noteBytes = encounter.freeTextNote
                .take(remainingForNote)
                .toByteArray(Charsets.US_ASCII)
            buffer.put(noteBytes, 0, minOf(noteBytes.size, remainingForNote))
        }

        // Zero-pad to position totalSize - 1
        while (buffer.position() < totalSize - 1) buffer.put(0)

        // ── Last byte: CRC-8/MAXIM checksum ──
        val data = ByteArray(totalSize - 1)
        buffer.position(0)
        buffer.get(data)
        buffer.put(crc8maxim(data))

        return buffer.array().copyOf(totalSize)
    }

    /**
     * Encode encounter + patient health history into a v3 binary payload.
     * V3 is like V2 but includes the raw 8-char patient ID (ASCII) instead of
     * a 4-byte SHA-256 hash, enabling cross-facility patient linkage.
     *
     * Byte layout change vs v2:
     *   Bytes 6-13: raw patient ID (8 ASCII bytes) — was 4-byte hash in v1/v2
     *   All subsequent fields shift +4 bytes; note space is 4 bytes smaller.
     */
    fun encodeV3(encounter: StructuredEncounter, patientId: String, summary: PatientHealthSummary): ByteArray {
        val numChronicDx = summary.chronicConditions.size.coerceAtMost(5)
        val numAbnormalVitals = summary.abnormalVitals.size.coerceAtMost(5)

        val historyHeaderBytes = 3
        val chronicBytes = numChronicDx * 2
        val abnormalVitalBytes = numAbnormalVitals * 4
        // +4 for the expanded patient ID field (8 bytes instead of 4)
        val structuredBytes = 32 + historyHeaderBytes + chronicBytes + abnormalVitalBytes
        val noteSpace = (MAX_V2_PAYLOAD - structuredBytes - 1).coerceAtLeast(0)
        val totalSize = structuredBytes + noteSpace + 1

        val buffer = ByteBuffer.allocate(totalSize)

        // Byte 0: Version 0x03
        buffer.put(0x03.toByte())

        // Bytes 1-5: date + provider/facility (same as v1/v2)
        val encounterDate = encounter.timestamp.atZone(ZoneOffset.UTC).toLocalDate()
        val daysSinceEpoch = ChronoUnit.DAYS.between(EPOCH, encounterDate).toInt()
            .coerceIn(0, 65535)
        buffer.putShort(daysSinceEpoch.toShort())

        val providerHash = encounter.providerId.hashCode() and 0xFFF
        val facilityHash = encounter.facilityId.hashCode() and 0xFFF
        val combined = (providerHash shl 12) or facilityHash
        buffer.put(((combined shr 16) and 0xFF).toByte())
        buffer.put(((combined shr 8) and 0xFF).toByte())
        buffer.put((combined and 0xFF).toByte())

        // Bytes 6-13: Raw patient ID (8 ASCII bytes, zero-padded)
        val idBytes = patientId.replace("-", "").uppercase().toByteArray(Charsets.US_ASCII)
        for (i in 0 until 8) {
            buffer.put(if (i < idBytes.size) idBytes[i] else 0)
        }

        // Bytes 14-31: Flags + Dx + Meds + Vitals + Allergy + FollowUp (same encoding as v1/v2 bytes 10-27)
        encodeEncounterFieldsAfterPatientId(buffer, encounter)

        // History section (same as v2)
        val histFlags = ((numChronicDx and 7) shl 5) or ((numAbnormalVitals and 7) shl 2)
        buffer.put(histFlags.toByte())
        buffer.put(summary.cumulativeAllergyFlags.toByte())
        buffer.put(summary.totalVisits.coerceAtMost(255).toByte())

        for (i in 0 until numChronicDx) {
            val cc = summary.chronicConditions[i]
            val icdIndex = codeToIndex(cc.icd10Code)
            val count = cc.occurrenceCount.coerceAtMost(127)
            val packed = ((icdIndex and 0x1FF) shl 7) or (count and 0x7F)
            buffer.putShort(packed.toShort())
        }

        for (i in 0 until numAbnormalVitals) {
            val av = summary.abnormalVitals[i]
            val vitalDays = ChronoUnit.DAYS.between(EPOCH, av.date).toInt()
            buffer.putShort(vitalDays.toShort())
            buffer.put(av.type.ordinal.toByte())
            buffer.put(av.rawValue.coerceIn(0, 255).toByte())
        }

        // Note
        val remainingForNote = totalSize - buffer.position() - 1
        if (encounter.freeTextNote.isNotBlank() && remainingForNote > 0) {
            val noteBytes = encounter.freeTextNote
                .take(remainingForNote)
                .toByteArray(Charsets.US_ASCII)
            buffer.put(noteBytes, 0, minOf(noteBytes.size, remainingForNote))
        }

        while (buffer.position() < totalSize - 1) buffer.put(0)

        val data = ByteArray(totalSize - 1)
        buffer.position(0)
        buffer.get(data)
        buffer.put(crc8maxim(data))

        return buffer.array().copyOf(totalSize)
    }

    /**
     * Encode flags + diagnoses + medications + vitals + allergy + follow-up.
     * Shared between v3 and the standard encounter section.
     */
    private fun encodeEncounterFieldsAfterPatientId(buffer: ByteBuffer, encounter: StructuredEncounter) {
        val numDx = encounter.diagnoses.size.coerceAtMost(MAX_DIAGNOSES)
        val numMeds = encounter.medications.size.coerceAtMost(MAX_MEDICATIONS)
        val urgency = when (encounter.referral?.urgency) {
            "soon" -> 1; "urgent" -> 2; "emergency" -> 3; else -> 0
        }
        val followUpType = when {
            encounter.followUp == null -> 0
            (encounter.followUp.days) <= 31 -> 1
            (encounter.followUp.days) <= 210 -> 2
            else -> 3
        }
        val flags = ((numDx and 3) shl 6) or ((numMeds and 3) shl 4) or
                ((urgency and 3) shl 2) or (followUpType and 3)
        buffer.put(flags.toByte())

        val dxValues = IntArray(MAX_DIAGNOSES)
        for (i in 0 until numDx) {
            dxValues[i] = codeToIndex(encounter.diagnoses[i].icd10Code)
        }
        writeFixedBitPacked(buffer, dxValues, 9, DX_PACKED_BYTES)

        for (i in 0 until MAX_MEDICATIONS) {
            if (i < numMeds) {
                val med = encounter.medications[i]
                val drugIndex = med.formularyCode.filter { it.isDigit() }.toIntOrNull() ?: 0
                val doseCode = med.dose?.let { DOSE_CODES[it] } ?: 0
                val freqCode = med.frequency?.let { FREQ_CODES[it] } ?: 0
                val packed = ((drugIndex and 0x1FF) shl 7) or
                        ((doseCode and 0xF) shl 3) or (freqCode and 0x7)
                buffer.putShort(packed.toShort())
            } else {
                buffer.putShort(0)
            }
        }

        val v = encounter.vitals
        buffer.put(((v?.systolicBP ?: 120) - 60).coerceIn(0, 255).toByte())
        buffer.put(((v?.diastolicBP ?: 80) - 30).coerceIn(0, 255).toByte())
        buffer.put(((((v?.temperature ?: 37.0f) - 35.0f) * 10).toInt()).coerceIn(0, 255).toByte())
        buffer.put((v?.weight?.toInt() ?: 0).coerceIn(0, 255).toByte())
        buffer.put((v?.pulse ?: 0).coerceIn(0, 255).toByte())

        var allergyByte = 0
        for (allergy in encounter.allergies) {
            val lower = allergy.lowercase()
            for ((name, bit) in ALLERGY_FLAGS) {
                if (lower.contains(name)) {
                    allergyByte = allergyByte or (1 shl bit)
                }
            }
            if (ALLERGY_FLAGS.none { (name, _) -> lower.contains(name) }) {
                allergyByte = allergyByte or 1
            }
        }
        buffer.put(allergyByte.toByte())

        val followUpValue = when (followUpType) {
            1 -> encounter.followUp?.days ?: 0
            2 -> (encounter.followUp?.days ?: 0) / 7
            3 -> (encounter.followUp?.days ?: 0) / 30
            else -> 0
        }
        buffer.put(followUpValue.coerceIn(0, 255).toByte())
    }

    /**
     * Decode a v3 payload — includes raw patient ID + encounter + health history.
     */
    fun decodeV3(data: ByteArray): DecodedEncounterV3 {
        require(data.size >= 36) { "V3 payload too small: ${data.size}" }

        val expectedCrc = crc8maxim(data.sliceArray(0 until data.size - 1))
        require(data.last() == expectedCrc) { "CRC mismatch" }

        val buffer = ByteBuffer.wrap(data)
        val version = buffer.get().toInt() and 0xFF
        require(version == 0x03) { "Expected v3, got v$version" }

        // Bytes 1-2: Date
        val daysSinceEpoch = buffer.short.toInt() and 0xFFFF
        val encounterDate = EPOCH.plusDays(daysSinceEpoch.toLong())

        // Bytes 3-5: Skip provider/facility hash
        buffer.position(buffer.position() + 3)

        // Bytes 6-13: Raw patient ID (8 ASCII bytes)
        val patientIdBytes = ByteArray(8)
        buffer.get(patientIdBytes)
        val rawPatientId = String(patientIdBytes, Charsets.US_ASCII).trimEnd('\u0000')
        val patientId = if (rawPatientId.length == 8) {
            "${rawPatientId.substring(0, 4)}-${rawPatientId.substring(4, 8)}"
        } else rawPatientId

        // Bytes 14-31: Flags + Dx + Meds + Vitals + Allergy + FollowUp
        val flags = buffer.get().toInt() and 0xFF
        val numDx = (flags shr 6) and 3
        val numMeds = (flags shr 4) and 3
        val urgencyCode = (flags shr 2) and 3
        val followUpType = flags and 3

        val allDxIndices = readFixedBitPacked(buffer, MAX_DIAGNOSES, 9, DX_PACKED_BYTES)
        val dxIndices = allDxIndices.take(numDx)

        val medications = (0 until MAX_MEDICATIONS).mapNotNull { i ->
            val packed = buffer.short.toInt() and 0xFFFF
            if (i < numMeds) {
                DecodedMedication(
                    (packed shr 7) and 0x1FF,
                    (packed shr 3) and 0xF,
                    packed and 0x7
                )
            } else null
        }

        val systolic = (buffer.get().toInt() and 0xFF) + 60
        val diastolic = (buffer.get().toInt() and 0xFF) + 30
        val temp = (buffer.get().toInt() and 0xFF) / 10f + 35.0f
        val weight = buffer.get().toInt() and 0xFF
        val pulse = buffer.get().toInt() and 0xFF
        val allergyByte = buffer.get().toInt() and 0xFF
        val followUpValue = buffer.get().toInt() and 0xFF

        val followUpDays = when (followUpType) {
            1 -> followUpValue; 2 -> followUpValue * 7; 3 -> followUpValue * 30; else -> null
        }

        val encounter = DecodedEncounter(
            date = encounterDate,
            diagnosisIndices = dxIndices,
            medications = medications,
            systolicBP = systolic,
            diastolicBP = diastolic,
            temperature = temp,
            weight = weight,
            pulse = pulse,
            allergyFlags = allergyByte,
            followUpDays = followUpDays,
            urgency = urgencyCode
        )

        // History section (same layout as v2)
        val histFlags = buffer.get().toInt() and 0xFF
        val numChronicDx = (histFlags shr 5) and 7
        val numAbnormalVitals = (histFlags shr 2) and 7
        val cumulativeAllergyFlags = buffer.get().toInt() and 0xFF
        val totalVisits = buffer.get().toInt() and 0xFF

        val chronicConditions = (0 until numChronicDx).map {
            val packed = buffer.short.toInt() and 0xFFFF
            DecodedChronicCondition((packed shr 7) and 0x1FF, packed and 0x7F)
        }

        val abnormalVitals = (0 until numAbnormalVitals).map {
            val vitalDays = buffer.short.toInt() and 0xFFFF
            val vitalDate = EPOCH.plusDays(vitalDays.toLong())
            val vitalType = buffer.get().toInt() and 0xFF
            val rawValue = buffer.get().toInt() and 0xFF
            DecodedAbnormalVital(vitalDate, vitalType, rawValue)
        }

        return DecodedEncounterV3(
            encounter = encounter,
            patientId = patientId,
            totalVisits = totalVisits,
            chronicConditions = chronicConditions,
            abnormalVitals = abnormalVitals,
            cumulativeAllergyFlags = cumulativeAllergyFlags
        )
    }

    /**
     * Encode the current encounter section (bytes 1-27), shared between v1 and v2.
     */
    private fun encodeEncounterSection(buffer: ByteBuffer, encounter: StructuredEncounter) {
        // Bytes 1-2: Encounter date
        val encounterDate = encounter.timestamp.atZone(ZoneOffset.UTC).toLocalDate()
        val daysSinceEpoch = java.time.temporal.ChronoUnit.DAYS.between(EPOCH, encounterDate).toInt()
            .coerceIn(0, 65535)
        buffer.putShort(daysSinceEpoch.toShort())

        // Bytes 3-5: Provider + Facility hash
        val providerHash = encounter.providerId.hashCode() and 0xFFF
        val facilityHash = encounter.facilityId.hashCode() and 0xFFF
        val combined = (providerHash shl 12) or facilityHash
        buffer.put(((combined shr 16) and 0xFF).toByte())
        buffer.put(((combined shr 8) and 0xFF).toByte())
        buffer.put((combined and 0xFF).toByte())

        // Bytes 6-9: Patient ID hash
        val patientHash = java.security.MessageDigest.getInstance("SHA-256")
            .digest(encounter.patientId.toByteArray())
        buffer.put(patientHash, 0, 4)

        // Byte 10: Flags
        val numDx = encounter.diagnoses.size.coerceAtMost(MAX_DIAGNOSES)
        val numMeds = encounter.medications.size.coerceAtMost(MAX_MEDICATIONS)
        val urgency = when (encounter.referral?.urgency) {
            "soon" -> 1; "urgent" -> 2; "emergency" -> 3; else -> 0
        }
        val followUpType = when {
            encounter.followUp == null -> 0
            (encounter.followUp.days) <= 31 -> 1
            (encounter.followUp.days) <= 210 -> 2
            else -> 3
        }
        val flags = ((numDx and 3) shl 6) or ((numMeds and 3) shl 4) or
                ((urgency and 3) shl 2) or (followUpType and 3)
        buffer.put(flags.toByte())

        // Bytes 11-14: Diagnoses
        val dxValues = IntArray(MAX_DIAGNOSES)
        for (i in 0 until numDx) {
            dxValues[i] = codeToIndex(encounter.diagnoses[i].icd10Code)
        }
        writeFixedBitPacked(buffer, dxValues, 9, DX_PACKED_BYTES)

        // Bytes 15-20: Medications
        for (i in 0 until MAX_MEDICATIONS) {
            if (i < numMeds) {
                val med = encounter.medications[i]
                val drugIndex = med.formularyCode.filter { it.isDigit() }.toIntOrNull() ?: 0
                val doseCode = med.dose?.let { DOSE_CODES[it] } ?: 0
                val freqCode = med.frequency?.let { FREQ_CODES[it] } ?: 0
                val packed = ((drugIndex and 0x1FF) shl 7) or
                        ((doseCode and 0xF) shl 3) or (freqCode and 0x7)
                buffer.putShort(packed.toShort())
            } else {
                buffer.putShort(0)
            }
        }

        // Bytes 21-25: Vitals
        val v = encounter.vitals
        buffer.put(((v?.systolicBP ?: 120) - 60).coerceIn(0, 255).toByte())
        buffer.put(((v?.diastolicBP ?: 80) - 30).coerceIn(0, 255).toByte())
        buffer.put(((((v?.temperature ?: 37.0f) - 35.0f) * 10).toInt()).coerceIn(0, 255).toByte())
        buffer.put((v?.weight?.toInt() ?: 0).coerceIn(0, 255).toByte())
        buffer.put((v?.pulse ?: 0).coerceIn(0, 255).toByte())

        // Byte 26: Allergy flags
        var allergyByte = 0
        for (allergy in encounter.allergies) {
            val lower = allergy.lowercase()
            for ((name, bit) in ALLERGY_FLAGS) {
                if (lower.contains(name)) {
                    allergyByte = allergyByte or (1 shl bit)
                }
            }
            if (ALLERGY_FLAGS.none { (name, _) -> lower.contains(name) }) {
                allergyByte = allergyByte or 1
            }
        }
        buffer.put(allergyByte.toByte())

        // Byte 27: Follow-up
        val followUpValue = when (followUpType) {
            1 -> encounter.followUp?.days ?: 0
            2 -> (encounter.followUp?.days ?: 0) / 7
            3 -> (encounter.followUp?.days ?: 0) / 30
            else -> 0
        }
        buffer.put(followUpValue.coerceIn(0, 255).toByte())
    }

    // Maximum payload size — 92 bytes so encrypted Base64 fits in a single SMS
    // (92 bytes → AES-256-GCM [+12 nonce +16 tag] → 120 bytes → Base64 → 160 chars = 1 SMS)
    private const val MAX_V2_PAYLOAD = 92

    // ── EPI Vaccine Index Table (uint8) ──
    // Shared between encode/decode for immunization history in v4
    private val EPI_VACCINE_INDEX = mapOf(
        "BCG" to 1, "OPV" to 2, "PENTA" to 3, "PCV" to 4, "ROTA" to 5,
        "MEASLES" to 6, "HPV" to 7, "TT" to 8, "HEP_B" to 9,
        "YELLOW_FEVER" to 10, "TYPHOID" to 11, "INFLUENZA" to 12,
        "COVID" to 13, "RUBELLA" to 14, "MUMPS" to 15, "VARICELLA" to 16
    )
    private val EPI_INDEX_TO_VACCINE = EPI_VACCINE_INDEX.entries.associate { (k, v) -> v to k }

    /**
     * Resolve a vaccine code to its EPI index, with fuzzy matching for common variants.
     * ASR/LLM may output "PCV13", "Pcv-13", "pentavalent", "Hep B" etc.
     */
    private fun resolveVaccineIndex(code: String): Int {
        val upper = code.uppercase().replace(Regex("[\\s_-]"), "")
        // Exact match first
        EPI_VACCINE_INDEX[upper]?.let { return it }
        // Strip trailing digits: "PCV13" → "PCV", "OPV3" → "OPV", "PENTA3" → "PENTA"
        val stripped = upper.replace(Regex("\\d+$"), "")
        EPI_VACCINE_INDEX[stripped]?.let { return it }
        // Common aliases
        return when {
            upper.startsWith("PNEUMO") || upper.contains("PCV") -> EPI_VACCINE_INDEX["PCV"] ?: 0
            upper.startsWith("PENTA") || upper.contains("DPT") || upper.contains("DTAP") -> EPI_VACCINE_INDEX["PENTA"] ?: 0
            upper.startsWith("ROTA") -> EPI_VACCINE_INDEX["ROTA"] ?: 0
            upper.startsWith("MEASLE") || upper.startsWith("MR") || upper == "MMR" -> EPI_VACCINE_INDEX["MEASLES"] ?: 0
            upper.startsWith("HEP") && upper.contains("B") -> EPI_VACCINE_INDEX["HEP_B"] ?: 0
            upper.startsWith("HEPB") -> EPI_VACCINE_INDEX["HEP_B"] ?: 0
            upper.startsWith("YF") || upper.contains("YELLOW") -> EPI_VACCINE_INDEX["YELLOW_FEVER"] ?: 0
            upper.startsWith("TT") || upper.startsWith("TETANUS") -> EPI_VACCINE_INDEX["TT"] ?: 0
            upper.startsWith("COVID") || upper.contains("SARS") -> EPI_VACCINE_INDEX["COVID"] ?: 0
            upper.startsWith("FLU") || upper.startsWith("INFLUEN") -> EPI_VACCINE_INDEX["INFLUENZA"] ?: 0
            upper.startsWith("VARICELLA") || upper.startsWith("CHICKEN") -> EPI_VACCINE_INDEX["VARICELLA"] ?: 0
            else -> 0
        }
    }

    // ── RR Coding Table (3 bits) ──
    // 0=unknown, 1=<12, 2=12-15, 3=16-19, 4=20-24(normal), 5=25-29, 6=30-39, 7=≥40
    private fun encodeRR(rr: Int?): Int = when {
        rr == null -> 0
        rr < 12 -> 1
        rr <= 15 -> 2
        rr <= 19 -> 3
        rr <= 24 -> 4
        rr <= 29 -> 5
        rr <= 39 -> 6
        else -> 7
    }

    private fun decodeRR(code: Int): String = when (code) {
        0 -> "—"
        1 -> "<12"
        2 -> "12-15"
        3 -> "16-19"
        4 -> "20-24"
        5 -> "25-29"
        6 -> "30-39"
        7 -> "≥40"
        else -> "—"
    }

    /**
     * Encode encounter + health history into a v4 binary payload (exactly 92 bytes).
     *
     * V4 adds: expanded vitals (height, SpO2, RR), immunization history,
     * growth summary (weight, height, z-scores), and clinical status flags
     * (HIV, TB, pregnancy, syphilis, HepB, malaria, anemia, blood group, etc.).
     *
     * Fixed 92-byte layout:
     *   Bytes 0-33:  Current encounter (34 bytes)
     *   Bytes 34-71: Health history (38 bytes)
     *   Bytes 72-90: Free text (19 bytes)
     *   Byte 91:     CRC-8/MAXIM checksum
     */
    fun encodeV4(encounter: StructuredEncounter, patientId: String, summary: PatientHealthSummary): ByteArray {
        val buffer = ByteBuffer.allocate(92)

        // ═══ CURRENT ENCOUNTER (bytes 0-33) ═══

        // Byte 0: Version 0x04
        buffer.put(0x04.toByte())

        // Bytes 1-2: Encounter date (days since 2024-01-01, uint16)
        val encounterDate = encounter.timestamp.atZone(ZoneOffset.UTC).toLocalDate()
        val rawDays = ChronoUnit.DAYS.between(EPOCH, encounterDate).toInt()
        // If encounter timestamp is epoch-zero (1970) or otherwise before 2024,
        // use today's date as fallback — prevents date showing as 2024-01-01.
        val daysSinceEpoch = if (rawDays <= 0) {
            ChronoUnit.DAYS.between(EPOCH, java.time.LocalDate.now()).toInt().coerceIn(1, 65535)
        } else {
            rawDays.coerceIn(0, 65535)
        }
        buffer.putShort(daysSinceEpoch.toShort())

        // Bytes 3-5: Provider hash (12b) + Facility hash (12b)
        val providerHash = encounter.providerId.hashCode() and 0xFFF
        val facilityHash = encounter.facilityId.hashCode() and 0xFFF
        val combined = (providerHash shl 12) or facilityHash
        buffer.put(((combined shr 16) and 0xFF).toByte())
        buffer.put(((combined shr 8) and 0xFF).toByte())
        buffer.put((combined and 0xFF).toByte())

        // Bytes 6-13: Patient ID (8 ASCII bytes, zero-padded)
        val idBytes = patientId.replace("-", "").uppercase().toByteArray(Charsets.US_ASCII)
        for (i in 0 until 8) {
            buffer.put(if (i < idBytes.size) idBytes[i] else 0)
        }

        // Byte 14: Flags: numDx(2b) | numMeds(2b) | urgency(2b) | followUpType(2b)
        val numDx = encounter.diagnoses.size.coerceAtMost(MAX_DIAGNOSES)
        val numMeds = encounter.medications.size.coerceAtMost(MAX_MEDICATIONS)
        val urgency = when (encounter.referral?.urgency?.lowercase()) {
            "soon" -> 1; "urgent" -> 2; "emergency" -> 3; else -> 0
        }
        val followUpType = when {
            encounter.followUp == null -> 0
            encounter.followUp.days <= 31 -> 1
            encounter.followUp.days <= 210 -> 2
            else -> 3
        }
        val flags = ((numDx and 3) shl 6) or ((numMeds and 3) shl 4) or
                ((urgency and 3) shl 2) or (followUpType and 3)
        buffer.put(flags.toByte())

        // Bytes 15-18: Diagnoses (3 × 9-bit, bit-packed → 4 bytes)
        val dxValues = IntArray(MAX_DIAGNOSES)
        for (i in 0 until numDx) {
            dxValues[i] = codeToIndex(encounter.diagnoses[i].icd10Code)
        }
        writeFixedBitPacked(buffer, dxValues, 9, DX_PACKED_BYTES)

        // Bytes 19-24: Medications (3 × 16-bit → 6 bytes)
        for (i in 0 until MAX_MEDICATIONS) {
            if (i < numMeds) {
                val med = encounter.medications[i]
                val drugIndex = med.formularyCode.filter { it.isDigit() }.toIntOrNull() ?: 0
                val doseCode = med.dose?.let { DOSE_CODES[it] } ?: 0
                val freqCode = med.frequency?.let { FREQ_CODES[it] } ?: 0
                val packed = ((drugIndex and 0x1FF) shl 7) or
                        ((doseCode and 0xF) shl 3) or (freqCode and 0x7)
                buffer.putShort(packed.toShort())
            } else {
                buffer.putShort(0)
            }
        }

        // Bytes 25-31: Vitals EXPANDED (7 bytes)
        val v = encounter.vitals
        buffer.put(((v?.systolicBP ?: 120) - 60).coerceIn(0, 255).toByte())       // [0] systolic
        buffer.put(((v?.diastolicBP ?: 80) - 30).coerceIn(0, 255).toByte())       // [1] diastolic
        buffer.put(((((v?.temperature ?: 37.0f) - 35.0f) * 10).toInt()).coerceIn(0, 255).toByte()) // [2] temp
        buffer.put((v?.weight?.toInt() ?: 0).coerceIn(0, 255).toByte())           // [3] weight kg
        buffer.put((v?.pulse ?: 0).coerceIn(0, 255).toByte())                     // [4] pulse bpm
        buffer.put((v?.height?.toInt() ?: 0).coerceIn(0, 255).toByte())           // [5] height cm

        // [6] packed: SpO2 upper 5b (offset 70) | RR lower 3b (coded)
        val spo2Raw = ((v?.oxygenSaturation ?: 0) - 70).coerceIn(0, 31)
        val rrCoded = encodeRR(v?.respiratoryRate)
        val packedSpO2RR = ((spo2Raw and 0x1F) shl 3) or (rrCoded and 0x07)
        buffer.put(packedSpO2RR.toByte())

        // Byte 32: Allergy flags
        var allergyByte = 0
        for (allergy in encounter.allergies) {
            val lower = allergy.lowercase()
            for ((name, bit) in ALLERGY_FLAGS) {
                if (lower.contains(name)) allergyByte = allergyByte or (1 shl bit)
            }
            if (ALLERGY_FLAGS.none { (name, _) -> lower.contains(name) }) {
                allergyByte = allergyByte or 1
            }
        }
        buffer.put(allergyByte.toByte())

        // Byte 33: Follow-up value
        val followUpValue = when (followUpType) {
            1 -> encounter.followUp?.days ?: 0
            2 -> (encounter.followUp?.days ?: 0) / 7
            3 -> (encounter.followUp?.days ?: 0) / 30
            else -> 0
        }
        buffer.put(followUpValue.coerceIn(0, 255).toByte())

        // ═══ HEALTH HISTORY (bytes 34-71) ═══

        val numChronicDx = summary.chronicConditions.size.coerceAtMost(5)
        val numAbnormalVitals = summary.abnormalVitals.size.coerceAtMost(3)
        val hasGrowth = summary.hasGrowth
        val hasImmunizations = summary.recentImmunizations.isNotEmpty()

        // Byte 34: History flags: numChronicDx(3b) | numAbnormalVitals(3b) | hasGrowth(1b) | hasImmunizations(1b)
        val histFlags = ((numChronicDx and 7) shl 5) or
                ((numAbnormalVitals and 7) shl 2) or
                (if (hasGrowth) 0x02 else 0) or
                (if (hasImmunizations) 0x01 else 0)
        buffer.put(histFlags.toByte())

        // Byte 35: Cumulative allergy flags
        buffer.put(summary.cumulativeAllergyFlags.toByte())

        // Byte 36: Total visit count
        buffer.put(summary.totalVisits.coerceAtMost(255).toByte())

        // Bytes 37-46: Chronic conditions: 5 × 2 bytes (fixed, zero-padded)
        for (i in 0 until 5) {
            if (i < numChronicDx) {
                val cc = summary.chronicConditions[i]
                val icdIndex = codeToIndex(cc.icd10Code)
                val count = cc.occurrenceCount.coerceAtMost(127)
                val packed = ((icdIndex and 0x1FF) shl 7) or (count and 0x7F)
                buffer.putShort(packed.toShort())
            } else {
                buffer.putShort(0)
            }
        }

        // Bytes 47-58: Abnormal vitals: 3 × 4 bytes (fixed, zero-padded)
        for (i in 0 until 3) {
            if (i < numAbnormalVitals) {
                val av = summary.abnormalVitals[i]
                val vitalDays = ChronoUnit.DAYS.between(EPOCH, av.date).toInt()
                buffer.putShort(vitalDays.toShort())
                buffer.put(av.type.ordinal.toByte())
                buffer.put(av.rawValue.coerceIn(0, 255).toByte())
            } else {
                buffer.putShort(0)
                buffer.put(0)
                buffer.put(0)
            }
        }

        // Bytes 59-62: Growth summary (4 bytes, all zero if !hasGrowth)
        if (hasGrowth) {
            buffer.put(summary.latestWeight.coerceIn(0, 255).toByte())
            buffer.put(summary.latestHeight.coerceIn(0, 255).toByte())
            buffer.put((summary.weightZScore * 10).toInt().coerceIn(-128, 127).toByte()) // signed int8
            buffer.put((summary.heightZScore * 10).toInt().coerceIn(-128, 127).toByte()) // signed int8
        } else {
            buffer.putInt(0)
        }

        // Byte 63: Immunization header: numVaccines(3b) | reserved(5b)
        val numImmunizations = summary.recentImmunizations.size.coerceAtMost(3)
        buffer.put(((numImmunizations and 7) shl 5).toByte())

        // Bytes 64-69: Immunizations (HISTORY): 3 × 2 bytes (fixed, zero-padded)
        for (i in 0 until 3) {
            if (i < numImmunizations) {
                val imm = summary.recentImmunizations[i]
                val vaccineIndex = resolveVaccineIndex(imm.vaccineCode)
                buffer.put(vaccineIndex.toByte())
                buffer.put(((imm.doseNumber and 0xF) shl 4).toByte())
            } else {
                buffer.put(0)
                buffer.put(0)
            }
        }

        // Byte 70: Clinical status flags 1 (infectious/reproductive)
        buffer.put(summary.clinicalStatusFlags1.toByte())

        // Byte 71: Clinical status flags 2 (lab/risk)
        buffer.put(summary.clinicalStatusFlags2.toByte())

        // ═══ FREE TEXT + CRC (bytes 72-91) ═══

        // Bytes 72-90: Abbreviated visit summary (19 ASCII bytes, zero-padded)
        // Prefer concise smsSummary (LLM-generated or algorithmic), fall back to freeTextNote
        val noteSpace = 19
        val summaryText = encounter.smsSummary?.takeIf { it.isNotBlank() }
            ?: encounter.freeTextNote
        if (summaryText.isNotBlank()) {
            val noteBytes = summaryText
                .take(noteSpace)
                .toByteArray(Charsets.US_ASCII)
            buffer.put(noteBytes, 0, minOf(noteBytes.size, noteSpace))
        }
        // Zero-pad to position 91
        while (buffer.position() < 91) buffer.put(0)

        // Byte 91: CRC-8/MAXIM checksum
        val data = ByteArray(91)
        buffer.position(0)
        buffer.get(data)
        buffer.put(crc8maxim(data))

        return buffer.array().copyOf(92)
    }

    /**
     * Decode a v4 payload — fixed 92-byte layout with expanded vitals,
     * immunization history, growth summary, and clinical status flags.
     */
    fun decodeV4(data: ByteArray): DecodedEncounterV4 {
        require(data.size == 92) { "V4 payload must be exactly 92 bytes, got ${data.size}" }

        val expectedCrc = crc8maxim(data.sliceArray(0 until 91))
        require(data[91] == expectedCrc) { "CRC mismatch" }

        val buffer = ByteBuffer.wrap(data)

        // Byte 0: Version
        val version = buffer.get().toInt() and 0xFF
        require(version == 0x04) { "Expected v4, got v$version" }

        // Bytes 1-2: Date
        val daysSinceEpoch = buffer.short.toInt() and 0xFFFF
        val encounterDate = EPOCH.plusDays(daysSinceEpoch.toLong())

        // Bytes 3-5: Provider/Facility hash (skip)
        buffer.position(buffer.position() + 3)

        // Bytes 6-13: Raw patient ID
        val patientIdBytes = ByteArray(8)
        buffer.get(patientIdBytes)
        val rawPatientId = String(patientIdBytes, Charsets.US_ASCII).trimEnd('\u0000')
        val patientId = if (rawPatientId.length == 8) {
            "${rawPatientId.substring(0, 4)}-${rawPatientId.substring(4, 8)}"
        } else rawPatientId

        // Byte 14: Flags
        val flags = buffer.get().toInt() and 0xFF
        val numDx = (flags shr 6) and 3
        val numMeds = (flags shr 4) and 3
        val urgencyCode = (flags shr 2) and 3
        val followUpType = flags and 3

        // Bytes 15-18: Diagnoses
        val allDxIndices = readFixedBitPacked(buffer, MAX_DIAGNOSES, 9, DX_PACKED_BYTES)
        val dxIndices = allDxIndices.take(numDx)

        // Bytes 19-24: Medications
        val medications = (0 until MAX_MEDICATIONS).mapNotNull { i ->
            val packed = buffer.short.toInt() and 0xFFFF
            if (i < numMeds) DecodedMedication(
                (packed shr 7) and 0x1FF,
                (packed shr 3) and 0xF,
                packed and 0x7
            ) else null
        }

        // Bytes 25-31: Vitals EXPANDED (7 bytes)
        val systolic = (buffer.get().toInt() and 0xFF) + 60
        val diastolic = (buffer.get().toInt() and 0xFF) + 30
        val temp = (buffer.get().toInt() and 0xFF) / 10f + 35.0f
        val weight = buffer.get().toInt() and 0xFF
        val pulse = buffer.get().toInt() and 0xFF
        val height = buffer.get().toInt() and 0xFF
        val packedSpO2RR = buffer.get().toInt() and 0xFF
        val spo2 = ((packedSpO2RR shr 3) and 0x1F) + 70
        val rrCode = packedSpO2RR and 0x07

        // Byte 32: Allergy flags
        val allergyByte = buffer.get().toInt() and 0xFF

        // Byte 33: Follow-up
        val followUpValue = buffer.get().toInt() and 0xFF
        val followUpDays = when (followUpType) {
            1 -> followUpValue; 2 -> followUpValue * 7; 3 -> followUpValue * 30; else -> null
        }

        // ═══ HEALTH HISTORY (bytes 34-71) ═══

        // Byte 34: History flags
        val histFlags = buffer.get().toInt() and 0xFF
        val numChronicDx = (histFlags shr 5) and 7
        val numAbnormalVitals = (histFlags shr 2) and 7
        val hasGrowth = (histFlags and 0x02) != 0
        val hasImmunizations = (histFlags and 0x01) != 0

        // Byte 35: Cumulative allergy flags
        val cumulativeAllergyFlags = buffer.get().toInt() and 0xFF

        // Byte 36: Total visits
        val totalVisits = buffer.get().toInt() and 0xFF

        // Bytes 37-46: Chronic conditions (5 × 2 bytes)
        val chronicConditions = mutableListOf<DecodedChronicCondition>()
        for (i in 0 until 5) {
            val packed = buffer.short.toInt() and 0xFFFF
            if (i < numChronicDx && packed != 0) {
                chronicConditions.add(DecodedChronicCondition(
                    (packed shr 7) and 0x1FF,
                    packed and 0x7F
                ))
            }
        }

        // Bytes 47-58: Abnormal vitals (3 × 4 bytes)
        val abnormalVitals = mutableListOf<DecodedAbnormalVital>()
        for (i in 0 until 3) {
            val vitalDays = buffer.short.toInt() and 0xFFFF
            val vitalType = buffer.get().toInt() and 0xFF
            val rawValue = buffer.get().toInt() and 0xFF
            if (i < numAbnormalVitals) {
                abnormalVitals.add(DecodedAbnormalVital(
                    EPOCH.plusDays(vitalDays.toLong()),
                    vitalType,
                    rawValue
                ))
            }
        }

        // Bytes 59-62: Growth summary
        val growthWeight = buffer.get().toInt() and 0xFF
        val growthHeight = buffer.get().toInt() and 0xFF
        val weightZx10 = buffer.get().toInt()  // signed byte
        val heightZx10 = buffer.get().toInt()  // signed byte
        val growth = if (hasGrowth) DecodedGrowth(
            weightKg = growthWeight,
            heightCm = growthHeight,
            weightZScore = weightZx10 / 10f,
            heightZScore = heightZx10 / 10f
        ) else null

        // Byte 63: Immunization header
        val immHeader = buffer.get().toInt() and 0xFF
        val numImmunizations = (immHeader shr 5) and 7

        // Bytes 64-69: Immunizations (3 × 2 bytes)
        val immunizations = mutableListOf<DecodedImmunization>()
        for (i in 0 until 3) {
            val vaccineIndex = buffer.get().toInt() and 0xFF
            val dosePacked = buffer.get().toInt() and 0xFF
            if (i < numImmunizations && vaccineIndex > 0) {
                immunizations.add(DecodedImmunization(
                    vaccineCode = EPI_INDEX_TO_VACCINE[vaccineIndex] ?: "UNKNOWN",
                    doseNumber = (dosePacked shr 4) and 0xF
                ))
            }
        }

        // Byte 70-71: Clinical status flags
        val clinicalFlags1 = buffer.get().toInt() and 0xFF
        val clinicalFlags2 = buffer.get().toInt() and 0xFF

        // Bytes 72-90: Free text (19 bytes)
        val noteBytes = ByteArray(19)
        buffer.get(noteBytes)
        val freeText = String(noteBytes, Charsets.US_ASCII).trimEnd('\u0000')

        val encounter = DecodedEncounter(
            date = encounterDate,
            diagnosisIndices = dxIndices,
            medications = medications,
            systolicBP = systolic,
            diastolicBP = diastolic,
            temperature = temp,
            weight = weight,
            pulse = pulse,
            allergyFlags = allergyByte,
            followUpDays = followUpDays,
            urgency = urgencyCode
        )

        return DecodedEncounterV4(
            encounter = encounter,
            patientId = patientId,
            height = height,
            spo2 = spo2,
            respiratoryRateCode = rrCode,
            respiratoryRateLabel = decodeRR(rrCode),
            totalVisits = totalVisits,
            chronicConditions = chronicConditions,
            abnormalVitals = abnormalVitals,
            cumulativeAllergyFlags = cumulativeAllergyFlags,
            growth = growth,
            immunizations = immunizations,
            clinicalStatusFlags1 = clinicalFlags1,
            clinicalStatusFlags2 = clinicalFlags2,
            freeText = freeText
        )
    }

    fun decode(data: ByteArray): DecodedEncounter {
        val version = data[0].toInt() and 0xFF
        if (version == 0x04) {
            return decodeV4(data).encounter
        }
        if (version == 0x03) {
            return decodeV3(data).encounter
        }
        if (version == 0x02) {
            // V2 format — decode via v2 path, return the encounter portion
            return decodeV2(data).encounter
        }

        require(data.size == 92) { "Invalid payload size: ${data.size}" }

        // Verify CRC-8/MAXIM
        val expectedCrc = crc8maxim(data.sliceArray(0 until 91))
        require(data[91] == expectedCrc) { "CRC mismatch" }

        val buffer = ByteBuffer.wrap(data)

        @Suppress("UNUSED_VARIABLE")
        val versionByte = buffer.get().toInt() and 0xFF

        val daysSinceEpoch = buffer.short.toInt() and 0xFFFF
        val encounterDate = EPOCH.plusDays(daysSinceEpoch.toLong())

        // Skip provider/facility hash (3 bytes) and patient hash (4 bytes)
        buffer.position(buffer.position() + 7)

        val flags = buffer.get().toInt() and 0xFF
        val numDx = (flags shr 6) and 3
        val numMeds = (flags shr 4) and 3
        val urgencyCode = (flags shr 2) and 3
        val followUpType = flags and 3

        // Read diagnoses — always read 4 bytes (3 × 9-bit slots, fixed layout)
        val allDxIndices = readFixedBitPacked(buffer, MAX_DIAGNOSES, 9, DX_PACKED_BYTES)
        val dxIndices = allDxIndices.take(numDx) // only first numDx are meaningful

        // Read medications — always read 6 bytes (3 × 16-bit slots, fixed layout)
        val medications = (0 until MAX_MEDICATIONS).mapNotNull { i ->
            val packed = buffer.short.toInt() and 0xFFFF
            if (i < numMeds) {
                val drugIndex = (packed shr 7) and 0x1FF
                val doseCode = (packed shr 3) and 0xF
                val freqCode = packed and 0x7
                DecodedMedication(drugIndex, doseCode, freqCode)
            } else null // skip zero-padded slots
        }

        // Read vitals (5 bytes, fixed position)
        val systolic = (buffer.get().toInt() and 0xFF) + 60
        val diastolic = (buffer.get().toInt() and 0xFF) + 30
        val temp = (buffer.get().toInt() and 0xFF) / 10f + 35.0f
        val weight = buffer.get().toInt() and 0xFF
        val pulse = buffer.get().toInt() and 0xFF

        val allergyByte = buffer.get().toInt() and 0xFF
        val followUpValue = buffer.get().toInt() and 0xFF

        val followUpDays = when (followUpType) {
            1 -> followUpValue
            2 -> followUpValue * 7
            3 -> followUpValue * 30
            else -> null
        }

        return DecodedEncounter(
            date = encounterDate,
            diagnosisIndices = dxIndices,
            medications = medications,
            systolicBP = systolic,
            diastolicBP = diastolic,
            temperature = temp,
            weight = weight,
            pulse = pulse,
            allergyFlags = allergyByte,
            followUpDays = followUpDays,
            urgency = urgencyCode
        )
    }

    private fun codeToIndex(icd10Code: String): Int {
        // Simple hash to map ICD-10 code to a 9-bit index (0-511)
        return (icd10Code.hashCode() and 0x1FF)
    }

    /**
     * Write bit-packed values into exactly [totalBytes] bytes.
     * Unused bits are zero-padded on the right.
     */
    private fun writeFixedBitPacked(buffer: ByteBuffer, values: IntArray, bitsPerValue: Int, totalBytes: Int) {
        var accumulator = 0L
        var bitsInAccum = 0
        val outputBytes = mutableListOf<Byte>()

        for (value in values) {
            accumulator = (accumulator shl bitsPerValue) or (value.toLong() and ((1L shl bitsPerValue) - 1))
            bitsInAccum += bitsPerValue
            while (bitsInAccum >= 8) {
                bitsInAccum -= 8
                outputBytes.add(((accumulator shr bitsInAccum) and 0xFF).toByte())
            }
        }
        // Flush remaining bits (zero-padded on right)
        if (bitsInAccum > 0) {
            outputBytes.add(((accumulator shl (8 - bitsInAccum)) and 0xFF).toByte())
        }

        // Write exactly totalBytes (pad with 0 if needed)
        for (i in 0 until totalBytes) {
            buffer.put(if (i < outputBytes.size) outputBytes[i] else 0)
        }
    }

    /**
     * Read bit-packed values from exactly [totalBytes] bytes.
     */
    private fun readFixedBitPacked(buffer: ByteBuffer, count: Int, bitsPerValue: Int, totalBytes: Int): List<Int> {
        val bytes = ByteArray(totalBytes)
        buffer.get(bytes)

        var bits = 0L
        for (b in bytes) bits = (bits shl 8) or (b.toLong() and 0xFF)

        val totalBitsAvailable = totalBytes * 8
        val result = mutableListOf<Int>()
        for (i in 0 until count) {
            val shift = totalBitsAvailable - (i + 1) * bitsPerValue
            result.add(((bits shr shift) and ((1L shl bitsPerValue) - 1)).toInt())
        }

        return result
    }

    /**
     * CRC-8/MAXIM — reflected (LSB-first) with polynomial 0x31.
     *
     * Parameters: init=0x00, poly=0x31, refin=true, refout=true, xorout=0x00
     * Check value for ASCII "123456789": 0xA1
     */
    private fun crc8maxim(data: ByteArray): Byte {
        var crc = 0
        for (b in data) {
            crc = crc xor (b.toInt() and 0xFF)
            repeat(8) {
                // Reflected: test LSB, shift right, XOR with reflected poly 0x8C
                crc = if (crc and 0x01 != 0) (crc ushr 1) xor 0x8C else crc ushr 1
            }
        }
        return crc.toByte()
    }

    /**
     * Decode a v2 payload that includes current encounter + health history.
     */
    fun decodeV2(data: ByteArray): DecodedEncounterV2 {
        require(data.size >= 32) { "V2 payload too small: ${data.size}" }

        // Verify CRC-8/MAXIM (last byte)
        val expectedCrc = crc8maxim(data.sliceArray(0 until data.size - 1))
        require(data.last() == expectedCrc) { "CRC mismatch" }

        val buffer = ByteBuffer.wrap(data)

        val version = buffer.get().toInt() and 0xFF
        require(version == 0x02) { "Expected v2, got v$version" }

        // ── Decode encounter section (bytes 1-27, same as v1) ──
        val daysSinceEpoch = buffer.short.toInt() and 0xFFFF
        val encounterDate = EPOCH.plusDays(daysSinceEpoch.toLong())

        // Skip provider/facility hash (3 bytes) and patient hash (4 bytes)
        buffer.position(buffer.position() + 7)

        val flags = buffer.get().toInt() and 0xFF
        val numDx = (flags shr 6) and 3
        val numMeds = (flags shr 4) and 3
        val urgencyCode = (flags shr 2) and 3
        val followUpType = flags and 3

        val allDxIndices = readFixedBitPacked(buffer, MAX_DIAGNOSES, 9, DX_PACKED_BYTES)
        val dxIndices = allDxIndices.take(numDx)

        val medications = (0 until MAX_MEDICATIONS).mapNotNull { i ->
            val packed = buffer.short.toInt() and 0xFFFF
            if (i < numMeds) {
                val drugIndex = (packed shr 7) and 0x1FF
                val doseCode = (packed shr 3) and 0xF
                val freqCode = packed and 0x7
                DecodedMedication(drugIndex, doseCode, freqCode)
            } else null
        }

        val systolic = (buffer.get().toInt() and 0xFF) + 60
        val diastolic = (buffer.get().toInt() and 0xFF) + 30
        val temp = (buffer.get().toInt() and 0xFF) / 10f + 35.0f
        val weight = buffer.get().toInt() and 0xFF
        val pulse = buffer.get().toInt() and 0xFF
        val allergyByte = buffer.get().toInt() and 0xFF
        val followUpValue = buffer.get().toInt() and 0xFF

        val followUpDays = when (followUpType) {
            1 -> followUpValue
            2 -> followUpValue * 7
            3 -> followUpValue * 30
            else -> null
        }

        val encounter = DecodedEncounter(
            date = encounterDate,
            diagnosisIndices = dxIndices,
            medications = medications,
            systolicBP = systolic,
            diastolicBP = diastolic,
            temperature = temp,
            weight = weight,
            pulse = pulse,
            allergyFlags = allergyByte,
            followUpDays = followUpDays,
            urgency = urgencyCode
        )

        // ── Decode health history section (byte 28+) ──
        val histFlags = buffer.get().toInt() and 0xFF
        val numChronicDx = (histFlags shr 5) and 7
        val numAbnormalVitals = (histFlags shr 2) and 7

        val cumulativeAllergyFlags = buffer.get().toInt() and 0xFF
        val totalVisits = buffer.get().toInt() and 0xFF

        // Chronic conditions
        val chronicConditions = (0 until numChronicDx).map {
            val packed = buffer.short.toInt() and 0xFFFF
            val icdIndex = (packed shr 7) and 0x1FF
            val count = packed and 0x7F
            DecodedChronicCondition(icdIndex, count)
        }

        // Abnormal vitals
        val abnormalVitals = (0 until numAbnormalVitals).map {
            val vitalDays = buffer.short.toInt() and 0xFFFF
            val vitalDate = EPOCH.plusDays(vitalDays.toLong())
            val vitalType = buffer.get().toInt() and 0xFF
            val rawValue = buffer.get().toInt() and 0xFF
            DecodedAbnormalVital(vitalDate, vitalType, rawValue)
        }

        return DecodedEncounterV2(
            encounter = encounter,
            totalVisits = totalVisits,
            chronicConditions = chronicConditions,
            abnormalVitals = abnormalVitals,
            cumulativeAllergyFlags = cumulativeAllergyFlags
        )
    }
}

data class DecodedEncounter(
    val date: LocalDate,
    val diagnosisIndices: List<Int>,
    val medications: List<DecodedMedication>,
    val systolicBP: Int,
    val diastolicBP: Int,
    val temperature: Float,
    val weight: Int,
    val pulse: Int,
    val allergyFlags: Int,
    val followUpDays: Int?,
    val urgency: Int
)

data class DecodedMedication(
    val drugIndex: Int,
    val doseCode: Int,
    val freqCode: Int
)

/**
 * V2 decoded payload — includes current encounter + patient health history.
 * The patient can store only the latest SMS and have all significant details.
 */
data class DecodedEncounterV2(
    val encounter: DecodedEncounter,
    val totalVisits: Int,
    val chronicConditions: List<DecodedChronicCondition>,
    val abnormalVitals: List<DecodedAbnormalVital>,
    val cumulativeAllergyFlags: Int
)

data class DecodedChronicCondition(
    val icdHashIndex: Int,
    val occurrenceCount: Int
)

data class DecodedAbnormalVital(
    val date: LocalDate,
    val vitalType: Int,  // 0=systolicBP, 1=diastolicBP, 2=temp, 3=pulse, 4=weight
    val rawValue: Int
) {
    val vitalLabel: String get() = when (vitalType) {
        0 -> "Systolic BP"
        1 -> "Diastolic BP"
        2 -> "Temperature"
        3 -> "Pulse"
        4 -> "Weight"
        else -> "Unknown"
    }

    /** Human-readable formatted value. */
    val displayValue: String get() = when (vitalType) {
        0 -> "${rawValue + 60} mmHg"       // systolic: stored as value-60
        1 -> "${rawValue + 30} mmHg"       // diastolic: stored as value-30
        2 -> "${"%.1f".format(rawValue / 10f + 35.0f)}°C" // temp: stored as (value-35)*10
        3 -> "$rawValue bpm"
        4 -> "$rawValue kg"
        else -> "$rawValue"
    }
}

/**
 * V3 decoded payload — includes raw patient ID + encounter + health history.
 * The patient ID enables cross-facility linkage without needing P2P sync.
 */
data class DecodedEncounterV3(
    val encounter: DecodedEncounter,
    val patientId: String,
    val totalVisits: Int,
    val chronicConditions: List<DecodedChronicCondition>,
    val abnormalVitals: List<DecodedAbnormalVital>,
    val cumulativeAllergyFlags: Int
)

/**
 * V4 decoded payload — expanded vitals, immunization history, growth, clinical flags.
 * Full "portable health record" in a single SMS.
 */
data class DecodedEncounterV4(
    val encounter: DecodedEncounter,
    val patientId: String,
    val height: Int,                      // cm
    val spo2: Int,                        // % (70-101)
    val respiratoryRateCode: Int,         // 0-7 coded
    val respiratoryRateLabel: String,     // human-readable RR range
    val totalVisits: Int,
    val chronicConditions: List<DecodedChronicCondition>,
    val abnormalVitals: List<DecodedAbnormalVital>,
    val cumulativeAllergyFlags: Int,
    val growth: DecodedGrowth?,
    val immunizations: List<DecodedImmunization>,
    val clinicalStatusFlags1: Int,        // infectious/reproductive
    val clinicalStatusFlags2: Int,        // lab/risk
    val freeText: String
) {
    /** Decode clinical status flags1 into human-readable labels. */
    val clinicalStatus1Labels: List<String> get() = buildList {
        if (clinicalStatusFlags1 and (1 shl 7) != 0) add("HIV+")
        if (clinicalStatusFlags1 and (1 shl 6) != 0) add("HIV on ART")
        if (clinicalStatusFlags1 and (1 shl 5) != 0) add("TB active")
        if (clinicalStatusFlags1 and (1 shl 4) != 0) add("TB completed Rx")
        if (clinicalStatusFlags1 and (1 shl 3) != 0) add("Pregnant")
        if (clinicalStatusFlags1 and (1 shl 2) != 0) add("Syphilis+")
        if (clinicalStatusFlags1 and (1 shl 1) != 0) add("HepB+")
        if (clinicalStatusFlags1 and (1 shl 0) != 0) add("Malaria+")
    }

    /** Decode clinical status flags2 into human-readable labels. */
    val clinicalStatus2Labels: List<String> get() = buildList {
        if (clinicalStatusFlags2 and (1 shl 7) != 0) add("Anemia (Hb<10)")
        if (clinicalStatusFlags2 and (1 shl 6) != 0) add("Severe anemia (Hb<7)")
        if (clinicalStatusFlags2 and (1 shl 5) != 0) add("Blood group known")
        if (clinicalStatusFlags2 and (1 shl 4) != 0) add("Rh negative")
        if (clinicalStatusFlags2 and (1 shl 3) != 0) add("High glucose")
        if (clinicalStatusFlags2 and (1 shl 2) != 0) add("Proteinuria")
        if (clinicalStatusFlags2 and (1 shl 1) != 0) add("Sickle cell")
        if (clinicalStatusFlags2 and (1 shl 0) != 0) add("Malnutrition")
    }
}

data class DecodedGrowth(
    val weightKg: Int,
    val heightCm: Int,
    val weightZScore: Float,
    val heightZScore: Float
)

data class DecodedImmunization(
    val vaccineCode: String,
    val doseNumber: Int
)

/** Reverse lookup tables for decoded binary indices → human-readable names. */
object BinaryDecodeLookup {
    /** Reverse dose code → mg value. */
    private val DOSE_REVERSE = mapOf(
        0x1 to "50mg", 0x2 to "100mg", 0x3 to "125mg", 0x4 to "250mg",
        0x5 to "500mg", 0x6 to "1g", 0x7 to "5mg", 0x8 to "10mg",
        0x9 to "20mg", 0xA to "25mg", 0xB to "40mg", 0xC to "2.5mg"
    )

    /** Reverse frequency code → label. */
    private val FREQ_REVERSE = mapOf(
        1 to "OD", 2 to "BD", 3 to "TDS", 4 to "QDS",
        5 to "PRN", 6 to "STAT", 7 to "WEEKLY"
    )

    /** Reverse allergy bit → name. */
    private val ALLERGY_BIT_NAMES = mapOf(
        7 to "Penicillin", 6 to "Sulfa", 5 to "NSAID", 4 to "Latex",
        3 to "Contrast", 2 to "Opioid", 1 to "ACE inhibitor", 0 to "Other"
    )

    fun doseLabel(code: Int): String = DOSE_REVERSE[code] ?: "–"
    fun freqLabel(code: Int): String = FREQ_REVERSE[code] ?: "–"

    /** Decode allergy flags bitmask into list of allergy names. */
    fun allergyLabels(flags: Int): List<String> = buildList {
        for ((bit, name) in ALLERGY_BIT_NAMES) {
            if (flags and (1 shl bit) != 0) add(name)
        }
    }
}

/** Sealed result for SMS decryption — caller inspects which version was decoded. */
sealed class DecryptResult {
    data class V1(val encounter: DecodedEncounter) : DecryptResult()
    data class V2(val data: DecodedEncounterV2) : DecryptResult()
    data class V3(val data: DecodedEncounterV3) : DecryptResult()
    data class V4(val data: DecodedEncounterV4) : DecryptResult()
}
