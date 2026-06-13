package com.chartlite.app.sms

import com.chartlite.app.config.AppConfig
import com.chartlite.app.database.entity.AppointmentEntity
import com.chartlite.app.database.entity.PatientEntity
import com.chartlite.app.database.repository.AppointmentRepository
import com.chartlite.app.database.PatientRepository
import com.chartlite.app.auth.AuditLogger
import com.chartlite.app.database.repository.SmsLogRepository
import com.chartlite.app.model.AppointmentStatus
import com.google.gson.Gson
import com.google.gson.reflect.TypeToken
import java.text.SimpleDateFormat
import java.time.LocalDate
import java.time.ZoneId
import java.util.Date
import java.util.Locale

/**
 * SMS Appointment Reminder System.
 *
 * Uses the existing SMS infrastructure (native SIM or Twilio) to send
 * appointment reminders to patients. Supports:
 * - Day-before reminders
 * - Same-day reminders
 * - Missed appointment follow-ups
 * - Batch sending for all upcoming appointments
 * - Multi-language message templates (English, Zulu, Xhosa, Afrikaans, Amharic)
 */
class AppointmentReminder(
    private val smsSender: SMSSender,
    private val appointmentRepository: AppointmentRepository,
    private val patientRepository: PatientRepository,
    private val appConfig: AppConfig,
    private val auditLogger: AuditLogger,
    private val smsLogRepository: SmsLogRepository? = null
) {
    private val dateFormat = SimpleDateFormat("dd MMM yyyy", Locale.getDefault())
    private val gson = Gson()

    /**
     * Get all appointments that need reminders sent.
     * Returns appointments scheduled for tomorrow that haven't been reminded yet.
     */
    suspend fun getPendingReminders(): List<ReminderCandidate> {
        val now = System.currentTimeMillis()
        val todayStart = LocalDate.now().atStartOfDay(ZoneId.systemDefault()).toInstant().toEpochMilli()
        val tomorrowStart = todayStart + DAY_MS
        val tomorrowEnd = tomorrowStart + DAY_MS

        val appointments = appointmentRepository.getUpcoming(appConfig.facilityId, now)
        return appointments
            .filter { it.scheduledDate in tomorrowStart until tomorrowEnd }
            .filter { it.status == AppointmentStatus.SCHEDULED.name }
            .filter { !isReminderSent(it, ReminderType.DAY_BEFORE.name.lowercase()) }
            .mapNotNull { appointment ->
                val patient = patientRepository.getById(appointment.patientId)
                if (patient != null && !patient.phoneNumber.isNullOrBlank()) {
                    ReminderCandidate(appointment, patient, ReminderType.DAY_BEFORE)
                } else null
            }
    }

    /**
     * Get same-day reminders (appointments scheduled for today).
     */
    suspend fun getSameDayReminders(): List<ReminderCandidate> {
        val now = System.currentTimeMillis()
        val todayStart = LocalDate.now().atStartOfDay(ZoneId.systemDefault()).toInstant().toEpochMilli()
        val todayEnd = todayStart + DAY_MS

        val appointments = appointmentRepository.getUpcoming(appConfig.facilityId, todayStart)
        return appointments
            .filter { it.scheduledDate in todayStart until todayEnd }
            .filter { it.status == AppointmentStatus.SCHEDULED.name }
            .filter { !isReminderSent(it, ReminderType.SAME_DAY.name.lowercase()) }
            .mapNotNull { appointment ->
                val patient = patientRepository.getById(appointment.patientId)
                if (patient != null && !patient.phoneNumber.isNullOrBlank()) {
                    ReminderCandidate(appointment, patient, ReminderType.SAME_DAY)
                } else null
            }
    }

    /**
     * Get missed appointment follow-ups (past appointments not attended).
     */
    suspend fun getMissedAppointmentFollowUps(): List<ReminderCandidate> {
        val todayStart = LocalDate.now().atStartOfDay(ZoneId.systemDefault()).toInstant().toEpochMilli()
        val yesterdayStart = todayStart - DAY_MS

        val appointments = appointmentRepository.getByDate(appConfig.facilityId, yesterdayStart)
        return appointments
            .filter { it.status == AppointmentStatus.SCHEDULED.name }
            .filter { !isReminderSent(it, "missed") }
            .mapNotNull { appointment ->
                val patient = patientRepository.getById(appointment.patientId)
                if (patient != null && !patient.phoneNumber.isNullOrBlank()) {
                    ReminderCandidate(appointment, patient, ReminderType.MISSED)
                } else null
            }
    }

    /** Check if a reminder was already sent via the metadata JSON field. */
    private fun isReminderSent(appointment: AppointmentEntity, type: String = "reminder"): Boolean {
        val metadata = appointment.metadata ?: return false
        return try {
            val map: Map<String, Any> = gson.fromJson(metadata, object : TypeToken<Map<String, Any>>() {}.type)
            map["${type}_sent"]?.toString() == "true"
        } catch (_: Exception) { false }
    }

    /**
     * Build the SMS message for a reminder.
     */
    fun buildMessage(candidate: ReminderCandidate): String {
        val patientName = candidate.patient.firstName
        val date = dateFormat.format(Date(candidate.appointment.scheduledDate))
        val facilityName = appConfig.facilityId.ifBlank { "the clinic" }
        val appointmentType = candidate.appointment.type.lowercase()
            .replace("_", " ").replaceFirstChar { it.uppercase() }

        return when (candidate.messageType) {
            ReminderType.DAY_BEFORE -> buildDayBeforeMessage(patientName, date, appointmentType, facilityName)
            ReminderType.SAME_DAY -> buildSameDayMessage(patientName, appointmentType, facilityName)
            ReminderType.MISSED -> buildMissedMessage(patientName, date, appointmentType, facilityName)
        }
    }

    private fun buildDayBeforeMessage(name: String, date: String, type: String, facility: String): String =
        when (appConfig.language) {
            "zu" -> "Sawubona $name, siyakukhumbuza ukuthi une-appointment yakho ye-$type ngo-$date e-$facility. Sicela ufike ngesikhathi."
            "xh" -> "Molo $name, siyakukhumbuza ukuba unedinga lakho le-$type ngo-$date e-$facility. Nceda ufike ngexesha."
            "af" -> "Hallo $name, dit is 'n herinnering van jou $type afspraak op $date by $facility. Kom asseblief betyds."
            "am" -> "$name ሰላም፣ በ$date ላይ በ$facility ያለዎትን የ$type ቀጠሮ ለማስታወስ እንፈልጋለን። እባክዎ በሰዓቱ ይምጡ።"
            else -> "Hello $name, this is a reminder of your $type appointment on $date at $facility. Please arrive on time."
        }

    private fun buildSameDayMessage(name: String, type: String, facility: String): String =
        when (appConfig.language) {
            "zu" -> "Sawubona $name, une-appointment ye-$type namuhla e-$facility. Sicela ungalibali."
            "xh" -> "Molo $name, unedinga le-$type namhlanje e-$facility. Nceda ungalibali."
            else -> "Hello $name, you have a $type appointment today at $facility. Please don't forget to attend."
        }

    private fun buildMissedMessage(name: String, date: String, type: String, facility: String): String =
        when (appConfig.language) {
            "zu" -> "Sawubona $name, uphuthelwe yi-appointment yakho ye-$type ngo-$date e-$facility. Sicela ushayele ucingo ukuze sibhukhe futhi."
            "xh" -> "Molo $name, uphoswe lidinga lakho le-$type ngo-$date e-$facility. Nceda utsalele umnxeba ukuze sibhukhe kwakhona."
            else -> "Hello $name, you missed your $type appointment on $date at $facility. Please call to reschedule."
        }

    /**
     * Send a single reminder and log it.
     */
    suspend fun sendReminder(candidate: ReminderCandidate): SendResult {
        val message = buildMessage(candidate)
        val phone = candidate.patient.phoneNumber
            ?: return SendResult(false, candidate.appointment.id, "No phone number")

        return try {
            // Use Twilio if configured, else native SMS (with permission pre-check)
            val smsResult = if (appConfig.twilioAccountSid.isNotBlank()) {
                val provider = TwilioSMSProvider(
                    appConfig.twilioAccountSid, appConfig.twilioAuthToken, appConfig.twilioFromNumber
                )
                provider.sendSMS(phone, message)
            } else {
                // Pre-check SMS permission before attempting native send
                if (!smsSender.hasPermission()) {
                    return SendResult(false, candidate.appointment.id, "SMS permission not granted")
                }
                val nativeResult = smsSender.sendPlainSMS(phone, message)
                TwilioSMSProvider.TwilioResult(nativeResult.status, nativeResult.error)
            }

            val success = smsResult.status == com.chartlite.app.model.SMSStatus.SENT ||
                          smsResult.status == com.chartlite.app.model.SMSStatus.DELIVERED

            if (success) {
                // Persist reminder_sent flag to prevent re-sending
                val typeKey = candidate.messageType.name.lowercase()
                val existing = candidate.appointment.metadata
                val updatedMetadata = try {
                    val map: MutableMap<String, Any> = if (existing != null) {
                        gson.fromJson(existing, object : TypeToken<MutableMap<String, Any>>() {}.type)
                    } else {
                        mutableMapOf()
                    }
                    map["${typeKey}_sent"] = true
                    gson.toJson(map)
                } catch (_: Exception) {
                    """{"${typeKey}_sent":true}"""
                }
                appointmentRepository.updateMetadata(candidate.appointment.id, updatedMetadata)

                auditLogger.log(
                    "SEND_REMINDER", "APPOINTMENT", candidate.appointment.id,
                    AuditLogger.buildDetails(
                        "type" to candidate.messageType.name,
                        "patientId" to candidate.patient.id,
                        "phone" to phone.takeLast(4)
                    )
                )
            }
            // Log to SMS audit trail
            try {
                smsLogRepository?.log(
                    patientId = candidate.patient.id,
                    encounterId = null,
                    recipientPhone = phone,
                    messageType = "REMINDER",
                    contentSummary = "${candidate.messageType.name} reminder: ${candidate.appointment.type}",
                    status = if (success) "SENT" else "FAILED",
                    error = smsResult.error,
                    provider = if (appConfig.twilioAccountSid.isNotBlank()) "TWILIO" else "NATIVE"
                )
            } catch (_: Exception) { /* logging failure is non-critical */ }

            SendResult(success, candidate.appointment.id, smsResult.error)
        } catch (e: Exception) {
            SendResult(false, candidate.appointment.id, e.message ?: "Unknown error")
        }
    }

    /** Send all pending reminders in batch. */
    suspend fun sendAllPending(): BatchResult {
        val candidates = getPendingReminders() + getSameDayReminders()
        val results = candidates.map { sendReminder(it) }
        return BatchResult(results.size, results.count { it.success }, results.count { !it.success }, results)
    }

    companion object {
        private const val DAY_MS = 24 * 60 * 60 * 1000L
    }
}

data class ReminderCandidate(
    val appointment: AppointmentEntity,
    val patient: PatientEntity,
    val messageType: ReminderType
)

enum class ReminderType { DAY_BEFORE, SAME_DAY, MISSED }

data class SendResult(
    val success: Boolean,
    val appointmentId: String,
    val error: String? = null
)

data class BatchResult(
    val total: Int,
    val sent: Int,
    val failed: Int,
    val results: List<SendResult>
)
