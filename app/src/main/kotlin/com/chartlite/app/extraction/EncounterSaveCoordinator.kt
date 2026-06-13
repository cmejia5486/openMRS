package com.chartlite.app.extraction

import android.util.Log
import com.chartlite.app.App
import com.chartlite.app.model.CDSSAlert
import com.chartlite.app.model.ClinicStation
import com.chartlite.app.model.Diagnosis
import com.chartlite.app.model.FollowUp
import com.chartlite.app.model.Medication
import com.chartlite.app.model.StructuredEncounter
import com.chartlite.app.model.VitalSigns
import com.chartlite.app.model.destinationLabel
import com.chartlite.app.model.normalizedOrNull
import com.chartlite.app.model.normalizeReferralValue
import com.chartlite.app.sms.BinaryDecodeLookup
import com.chartlite.app.sms.DecodedEncounterV4
import com.google.gson.Gson
import com.google.gson.reflect.TypeToken
import kotlinx.coroutines.Dispatchers
import kotlinx.coroutines.launch
import java.time.Instant
import java.time.ZoneOffset
import java.util.UUID

object EncounterSaveCoordinator {
    private val gson = Gson() // Reuse across calls — avoids ~2ms TypeAdapter rebuild each time

    suspend fun saveEncounter(
        app: App,
        encounter: StructuredEncounter,
        patientId: String,
        visitId: String? = null,
        station: ClinicStation? = null,
        referralInstructions: String? = null,  // Doctor-edited patient instructions
        referralSmsOverride: String? = null     // Doctor-edited SMS text
    ): String {
        val patient = app.patientRepository.getById(patientId)
        val patientAllergies = patient?.let {
            try {
                gson.fromJson<List<String>>(
                    it.allergies,
                    object : TypeToken<List<String>>() {}.type
                )
            } catch (_: Exception) {
                emptyList()
            }
        } ?: emptyList()

        val allAllergies = (patientAllergies + encounter.allergies).distinct()
        val alerts: List<CDSSAlert> = app.cdss.evaluate(encounter, allAllergies)
        val savedId = app.encounterRepository.save(encounter, alerts, stationType = station?.name)

        encounter.referral.normalizedOrNull()?.let { referral ->
            try {
                val urgencyUpper = referral.urgency.uppercase()
                val timeframe = when (urgencyUpper) {
                    "EMERGENCY" -> 0
                    "URGENT" -> 3
                    else -> 14
                }
                val instructions = referralInstructions?.ifBlank { null } ?: when (urgencyUpper) {
                    "EMERGENCY" -> "Go immediately. Bring ID and clinic card."
                    "URGENT" -> "Bring ID, clinic card, and current medications."
                    else -> "Bring ID, clinic card, test results, and medications list."
                }

                // Build plain-text referral SMS ≤160 chars for patient
                val reason = referral.reason ?: "Clinical referral"
                val smsText = referralSmsOverride?.ifBlank { null }?.take(160) ?: run {
                    val patientName = patient?.let {
                        listOfNotNull(it.firstName, it.lastName).joinToString(" ")
                    }?.ifBlank { null }
                    val destination = listOfNotNull(
                        normalizeReferralValue(referral.destinationLabel()),
                        normalizeReferralValue(referral.specialty)
                    ).joinToString("/").ifEmpty { "Referred facility" }
                    buildReferralSms(
                        patientName = patientName,
                        destination = destination,
                        urgency = urgencyUpper,
                        timeframeDays = timeframe,
                        reason = reason
                    )
                }

                val entity = app.referralRepository.createReferral(
                    visitId = visitId ?: encounter.id,
                    patientId = patientId,
                    fromProviderId = app.sessionManager.currentSession?.userId ?: app.appConfig.providerId,
                    fromFacilityId = app.appConfig.facilityId,
                    toFacility = referral.destinationLabel(),
                    urgency = referral.urgency,
                    reason = reason,
                    toDepartment = referral.specialty,
                    clinicalNotes = encounter.freeTextNote.take(500),
                    patientInstructions = instructions,
                    timeframeDays = timeframe,
                    smsText = smsText
                )

                // Send plain-text referral SMS to patient (non-blocking)
                val phone = patient?.phoneNumber
                if (!phone.isNullOrBlank()) {
                    app.appScope.launch(Dispatchers.IO) {
                        try {
                            val refResult = app.smsSender.sendPlainSMS(phone, smsText)
                            Log.d("EncounterSave", "Referral SMS sent to ${phone.takeLast(4)}")
                            try {
                                app.smsLogRepository.log(
                                    patientId = patientId,
                                    encounterId = savedId,
                                    recipientPhone = phone,
                                    messageType = "REFERRAL",
                                    contentSummary = smsText.take(200),
                                    status = refResult.status.name,
                                    error = refResult.error,
                                    provider = if (app.appConfig.twilioAccountSid.isNotBlank()) "TWILIO" else "NATIVE"
                                )
                            } catch (_: Exception) { /* logging failure is non-critical */ }
                        } catch (e: Exception) {
                            Log.e("EncounterSave", "Failed to send referral SMS", e)
                        }
                    }
                }
            } catch (e: Exception) {
                Log.e("EncounterSave", "Failed to create referral record", e)
            }
        }

        if (visitId != null && station != null) {
            val hasMeds = encounter.medications.isNotEmpty()
            app.visitRepository.linkEncounter(visitId, encounter.id, station)
            app.visitRepository.advanceToNextStation(
                visitId,
                app.sessionManager.currentSession?.userId ?: app.appConfig.providerId,
                station,
                hasMeds
            )
            if (station == ClinicStation.TRIAGE) {
                val complaint = encounter.freeTextNote.take(200)
                app.visitRepository.setChiefComplaint(visitId, complaint)
            }
        }

        // ── Auto-populate growth measurements from encounter vitals ──
        val vitals = encounter.vitals
        if (vitals != null && (vitals.weight != null || vitals.height != null)) {
            try {
                val p = patient
                val ageMonths = p?.let { computeAgeMonths(it) }
                val isMale = p?.gender?.lowercase() != "female"
                app.growthRepository.recordMeasurement(
                    patientId = patientId,
                    measuredBy = app.sessionManager.currentSession?.userId ?: app.appConfig.providerId,
                    weight = vitals.weight,
                    height = vitals.height,
                    visitId = visitId,
                    ageInMonths = ageMonths,
                    isMale = isMale
                )
                Log.d("EncounterSave", "Auto-recorded growth measurement from encounter vitals")
            } catch (e: Exception) {
                Log.w("EncounterSave", "Failed to auto-record growth measurement", e)
            }
        }

        // ── Auto-save immunizations from encounter extraction ──
        if (encounter.immunizations.isNotEmpty()) {
            val providerId = app.sessionManager.currentSession?.userId ?: app.appConfig.providerId
            for (immunization in encounter.immunizations) {
                try {
                    app.immunizationRepository.recordImmunization(
                        patientId = patientId,
                        vaccineCode = immunization.vaccineCode,
                        vaccineName = immunization.vaccineName,
                        doseNumber = immunization.doseNumber,
                        administeredBy = providerId,
                        facilityId = app.appConfig.facilityId
                    )
                } catch (e: Exception) {
                    Log.w("EncounterSave", "Failed to auto-record immunization: ${immunization.vaccineCode}", e)
                }
            }
            Log.d("EncounterSave", "Auto-recorded ${encounter.immunizations.size} immunization(s)")
        }

        patient?.let { p ->
            val phone = p.phoneNumber
            val dxList = encounter.diagnoses.ifEmpty { encounter.suggestedDiagnoses }
            val dxSummary = dxList.take(3).joinToString(", ") { it.description }
            val medsSummary = encounter.medications.take(3).joinToString(", ") { it.name }
            val contentSummary = buildString {
                if (dxSummary.isNotEmpty()) append("Dx: ${dxSummary.take(100)}")
                if (medsSummary.isNotEmpty()) {
                    if (isNotEmpty()) append(" | ")
                    append("Rx: ${medsSummary.take(80)}")
                }
                if (isEmpty()) append("Clinical encounter")
            }

            if (!phone.isNullOrBlank()) {
                app.appScope.launch(Dispatchers.IO) {
                    try {
                        val allEntities = app.encounterRepository.getByPatientId(encounter.patientId)
                        val allEncounters = allEntities.map { app.encounterRepository.toStructuredEncounter(it) }
                        val allergiesForSms: List<String> = try {
                            gson.fromJson(
                                p.allergies,
                                object : TypeToken<List<String>>() {}.type
                            ) ?: emptyList()
                        } catch (_: Exception) {
                            emptyList()
                        }

                        // Fetch growth + immunization data so the V4 SMS includes full patient history
                        val latestGrowth = try {
                            app.growthRepository.getByPatient(encounter.patientId)
                                .maxByOrNull { it.measuredAt }
                                ?.let { g ->
                                    com.chartlite.app.sms.PatientHealthSummaryBuilder.GrowthData(
                                        weightKg = g.weight?.toInt() ?: 0,
                                        heightCm = g.height?.toInt() ?: 0,
                                        weightZScore = g.weightForAgeZ ?: 0f,
                                        heightZScore = g.heightForAgeZ ?: 0f
                                    )
                                }
                        } catch (_: Exception) { null }

                        val immunizationRecords = try {
                            app.immunizationRepository.getByPatient(encounter.patientId)
                                .groupBy { it.vaccineCode.uppercase() }
                                .map { (code, records) ->
                                    com.chartlite.app.sms.ImmunizationRecord(
                                        vaccineCode = code,
                                        doseNumber = records.maxOf { it.doseNumber }
                                    )
                                }
                        } catch (_: Exception) { emptyList() }

                        // Merge patient-level allergies into encounter so the current-encounter
                        // allergy byte (V4 byte 32) reflects all known allergies, not just
                        // what the LLM extracted from this session's transcript.
                        val encounterForSms = encounter.copy(
                            allergies = (encounter.allergies + allergiesForSms).distinct()
                        )

                        val result = app.smsSender.sendEncryptedSMS(
                            encounter = encounterForSms,
                            patient = p,
                            allEncounters = allEncounters,
                            patientAllergies = allergiesForSms,
                            growthData = latestGrowth,
                            immunizationRecords = immunizationRecords
                        )
                        app.encounterRepository.updateSmsStatus(savedId, result.status)
                        try {
                            app.smsLogRepository.log(
                                patientId = patientId,
                                encounterId = savedId,
                                recipientPhone = phone,
                                messageType = "ENCOUNTER",
                                contentSummary = contentSummary,
                                status = result.status.name,
                                error = result.error,
                                provider = if (app.appConfig.twilioAccountSid.isNotBlank()) "TWILIO" else "NATIVE"
                            )
                        } catch (_: Exception) { /* logging failure is non-critical */ }
                    } catch (e: Exception) {
                        Log.w("EncounterSave", "SMS sending failed for patient ${patientId.take(4)}***", e)
                        try {
                            app.encounterRepository.updateSmsStatus(savedId, com.chartlite.app.model.SMSStatus.FAILED)
                            app.smsLogRepository.log(
                                patientId = patientId,
                                encounterId = savedId,
                                recipientPhone = phone,
                                messageType = "ENCOUNTER",
                                contentSummary = contentSummary,
                                status = "FAILED",
                                error = e.message,
                                provider = if (app.appConfig.twilioAccountSid.isNotBlank()) "TWILIO" else "NATIVE"
                            )
                        } catch (_: Exception) {}
                    }
                }
            } else {
                // No phone number — log as skipped so it appears in SMS history
                app.appScope.launch(Dispatchers.IO) {
                    try {
                        app.encounterRepository.updateSmsStatus(savedId, com.chartlite.app.model.SMSStatus.FAILED)
                        app.smsLogRepository.log(
                            patientId = patientId,
                            encounterId = savedId,
                            recipientPhone = "none",
                            messageType = "ENCOUNTER",
                            contentSummary = contentSummary,
                            status = "SKIPPED",
                            error = "No phone number on file",
                            provider = "NONE"
                        )
                    } catch (_: Exception) {}
                }
            }
        }

        return savedId
    }

    /**
     * Build a plain-text referral SMS that fits in a single 160-char SMS.
     * Priority: destination → urgency/timeframe → instructions → reason (truncated).
     */
    private fun buildReferralSms(
        patientName: String?,
        destination: String,
        urgency: String,
        timeframeDays: Int,
        reason: String
    ): String {
        val sb = StringBuilder()
        sb.append("REFERRAL: ")
        patientName?.let { sb.append("$it to ") }
        sb.append(destination.take(40))
        sb.append(". ")

        // Urgency + timeframe
        when {
            timeframeDays == 0 -> sb.append("EMERGENCY - go TODAY. ")
            timeframeDays <= 3 -> sb.append("URGENT - within ${timeframeDays}d. ")
            else -> sb.append("Within ${timeframeDays}d. ")
        }

        // Instructions (compact)
        sb.append("Bring ID+clinic card. ")

        // Fill remaining space with reason
        val remaining = 160 - sb.length
        if (remaining > 5) {
            val truncatedReason = if (reason.length <= remaining) reason
                                  else reason.take(remaining - 2) + ".."
            sb.append(truncatedReason)
        }

        return sb.toString().take(160)
    }

    /**
     * Import a full patient health record from a decoded V4 SMS.
     * Creates a synthetic "baseline" encounter so the patient's history
     * (vitals, allergies, medications, diagnoses) is in the local DB and
     * feeds into future SMS encoding and CDSS checks.
     *
     * Also saves immunizations and growth data from the decoded SMS.
     */
    suspend fun importFromDecodedSms(
        app: App,
        patientId: String,
        decoded: DecodedEncounterV4
    ): String {
        val enc = decoded.encounter

        // Reconstruct allergy names from bitmask
        val allergyNames = BinaryDecodeLookup.allergyLabels(enc.allergyFlags)
        val cumulativeAllergies = BinaryDecodeLookup.allergyLabels(decoded.cumulativeAllergyFlags)
        val allAllergies = (allergyNames + cumulativeAllergies).distinct()

        // Reconstruct medications (best-effort: drug index as code, decoded dose/freq)
        val medications = enc.medications.map { med ->
            val doseLabel = BinaryDecodeLookup.doseLabel(med.doseCode)
            Medication(
                formularyCode = med.drugIndex.toString(),
                name = "Drug #${med.drugIndex}",  // best-effort; clinician can update
                dose = doseLabel.replace("mg", "").replace("g", "").toFloatOrNull(),
                unit = if (doseLabel.contains("g") && !doseLabel.contains("mg")) "g" else "mg",
                frequency = BinaryDecodeLookup.freqLabel(med.freqCode)
            )
        }

        // Reconstruct diagnoses from hash indices (store hash — will match on re-encoding)
        val diagnoses = enc.diagnosisIndices.filter { it > 0 }.map { hashIndex ->
            Diagnosis(
                icd10Code = "#$hashIndex",  // hash placeholder; clinician can correct
                description = "Imported diagnosis (hash $hashIndex)",
                confidence = 0f
            )
        }

        // Reconstruct vitals
        val vitals = VitalSigns(
            systolicBP = if (enc.systolicBP != 120) enc.systolicBP else null,
            diastolicBP = if (enc.diastolicBP != 80) enc.diastolicBP else null,
            temperature = if (enc.temperature != 37.0f) enc.temperature else null,
            pulse = if (enc.pulse > 0) enc.pulse else null,
            weight = if (enc.weight > 0) enc.weight.toFloat() else null,
            height = if (decoded.height > 0) decoded.height.toFloat() else null,
            oxygenSaturation = if (decoded.spo2 > 70) decoded.spo2 else null
        )

        // Build synthetic encounter
        val encounterId = UUID.randomUUID().toString()
        val encounter = StructuredEncounter(
            id = encounterId,
            patientId = patientId,
            providerId = "SMS_IMPORT",
            facilityId = "SMS_IMPORT",
            timestamp = enc.date.atStartOfDay().toInstant(ZoneOffset.UTC),
            transcript = "[Imported from encrypted SMS]",
            medications = medications,
            diagnoses = diagnoses,
            vitals = vitals,
            allergies = allAllergies,
            followUp = enc.followUpDays?.let { if (it > 0) FollowUp(days = it) else null },
            referral = null,
            freeTextNote = decoded.freeText.ifBlank { "[Imported from SMS]" },
            extractionConfidence = 0.0f,
            smsSummary = decoded.freeText.ifBlank { null }
        )

        // Save the synthetic encounter
        val savedId = app.encounterRepository.save(encounter, cdssAlerts = emptyList(), stationType = null)
        Log.i("EncounterSave", "Imported SMS baseline encounter $savedId for patient $patientId")

        // Save immunizations from decoded SMS
        val providerId = "SMS_IMPORT"
        for (imm in decoded.immunizations) {
            try {
                app.immunizationRepository.recordImmunization(
                    patientId = patientId,
                    vaccineCode = imm.vaccineCode,
                    vaccineName = imm.vaccineCode,  // code is all we have from binary
                    doseNumber = imm.doseNumber,
                    administeredBy = providerId,
                    facilityId = "SMS_IMPORT"
                )
            } catch (e: Exception) {
                Log.w("EncounterSave", "Failed to import immunization: ${imm.vaccineCode}", e)
            }
        }

        // Save growth data
        decoded.growth?.let { g ->
            try {
                app.growthRepository.recordMeasurement(
                    patientId = patientId,
                    measuredBy = providerId,
                    weight = g.weightKg.toFloat(),
                    height = g.heightCm.toFloat()
                )
            } catch (e: Exception) {
                Log.w("EncounterSave", "Failed to import growth data", e)
            }
        }

        // Update patient-level allergies with decoded cumulative allergies
        try {
            val patient = app.patientRepository.getById(patientId)
            if (patient != null && allAllergies.isNotEmpty()) {
                val existingAllergies: List<String> = try {
                    gson.fromJson(
                        patient.allergies,
                        object : TypeToken<List<String>>() {}.type
                    ) ?: emptyList()
                } catch (_: Exception) { emptyList() }

                val merged = (existingAllergies + allAllergies).distinct()
                app.patientRepository.update(patient.copy(allergies = gson.toJson(merged)))
            }
        } catch (e: Exception) {
            Log.w("EncounterSave", "Failed to update patient allergies from SMS", e)
        }

        return savedId
    }

    /** Compute age in months from PatientEntity's dateOfBirth or ageYears. */
    private fun computeAgeMonths(patient: com.chartlite.app.database.entity.PatientEntity): Int? {
        // Prefer exact DOB
        patient.dateOfBirth?.let { dob ->
            try {
                val birthDate = java.time.LocalDate.parse(dob)
                val now = java.time.LocalDate.now()
                return java.time.Period.between(birthDate, now).toTotalMonths().toInt()
            } catch (_: Exception) { /* fall through */ }
        }
        // Fall back to approximate ageYears
        return patient.ageYears?.let { it * 12 }
    }
}
