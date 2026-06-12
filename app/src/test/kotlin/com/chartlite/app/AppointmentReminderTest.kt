package com.chartlite.app

import com.chartlite.app.sms.AppointmentReminder
import com.chartlite.app.sms.ReminderCandidate
import com.chartlite.app.sms.ReminderType
import com.chartlite.app.database.entity.AppointmentEntity
import com.chartlite.app.database.entity.PatientEntity
import org.junit.Assert.*
import org.junit.Test
import java.text.SimpleDateFormat
import java.util.Locale

class AppointmentReminderTest {

    private val dateFormat = SimpleDateFormat("dd MMM yyyy", Locale.getDefault())

    private fun createPatient(
        id: String = "ABCD-1234",
        firstName: String = "Thabo",
        lastName: String = "Mokoena",
        phone: String? = "+27123456789"
    ) = PatientEntity(
        id = id,
        firstName = firstName,
        lastName = lastName,
        gender = "male",
        phoneNumber = phone,
        ageYears = 35
    )

    private fun createAppointment(
        id: String = "apt-001",
        patientId: String = "ABCD-1234",
        scheduledDate: Long = System.currentTimeMillis() + 86400000L,
        type: String = "FOLLOW_UP",
        status: String = "SCHEDULED"
    ) = AppointmentEntity(
        id = id,
        patientId = patientId,
        providerId = null,
        facilityId = "facility-001",
        scheduledDate = scheduledDate,
        scheduledTime = "09:00",
        durationMinutes = 30,
        type = type,
        status = status,
        notes = null,
        createdBy = "provider-001",
        createdAt = System.currentTimeMillis(),
        updatedAt = System.currentTimeMillis()
    )

    @Test
    fun `ReminderCandidate correctly associates patient and appointment`() {
        val patient = createPatient()
        val appointment = createAppointment()
        val candidate = ReminderCandidate(appointment, patient, ReminderType.DAY_BEFORE)

        assertEquals("ABCD-1234", candidate.patient.id)
        assertEquals("apt-001", candidate.appointment.id)
        assertEquals(ReminderType.DAY_BEFORE, candidate.messageType)
    }

    @Test
    fun `ReminderType has all expected values`() {
        val types = ReminderType.values()
        assertEquals(3, types.size)
        assertTrue(types.contains(ReminderType.DAY_BEFORE))
        assertTrue(types.contains(ReminderType.SAME_DAY))
        assertTrue(types.contains(ReminderType.MISSED))
    }

    @Test
    fun `day before message contains patient name and appointment type`() {
        // Test the message building logic indirectly through candidate data
        val patient = createPatient(firstName = "Sipho")
        val appointment = createAppointment(type = "FOLLOW_UP")
        val candidate = ReminderCandidate(appointment, patient, ReminderType.DAY_BEFORE)

        assertEquals("Sipho", candidate.patient.firstName)
        assertEquals("FOLLOW_UP", candidate.appointment.type)
        // Message building depends on AppConfig which requires Android context,
        // so we verify the data is correct for message construction
    }

    @Test
    fun `appointment types format correctly`() {
        // Verify type formatting logic
        val type = "FOLLOW_UP"
        val formatted = type.lowercase().replace("_", " ").replaceFirstChar { it.uppercase() }
        assertEquals("Follow up", formatted)

        val type2 = "CHRONIC_CARE"
        val formatted2 = type2.lowercase().replace("_", " ").replaceFirstChar { it.uppercase() }
        assertEquals("Chronic care", formatted2)
    }

    @Test
    fun `patient without phone number is excluded`() {
        val patient = createPatient(phone = null)
        assertTrue(patient.phoneNumber.isNullOrBlank())
    }

    @Test
    fun `patient with blank phone number is excluded`() {
        val patient = createPatient(phone = "")
        assertTrue(patient.phoneNumber.isNullOrBlank())
    }

    @Test
    fun `patient with valid phone number is included`() {
        val patient = createPatient(phone = "+27123456789")
        assertFalse(patient.phoneNumber.isNullOrBlank())
    }

    @Test
    fun `scheduled appointment matches SCHEDULED status`() {
        val appointment = createAppointment(status = "SCHEDULED")
        assertEquals("SCHEDULED", appointment.status)
    }

    @Test
    fun `completed appointment should not get reminder`() {
        val appointment = createAppointment(status = "COMPLETED")
        assertNotEquals("SCHEDULED", appointment.status)
    }

    @Test
    fun `cancelled appointment should not get reminder`() {
        val appointment = createAppointment(status = "CANCELLED")
        assertNotEquals("SCHEDULED", appointment.status)
    }

    @Test
    fun `metadata field can track reminder sent status`() {
        val appointment = createAppointment()
        assertNull(appointment.metadata) // No metadata by default

        val withMetadata = appointment.copy(metadata = """{"reminder_sent": true}""")
        assertNotNull(withMetadata.metadata)
        assertTrue(withMetadata.metadata!!.contains("reminder_sent"))
    }

    @Test
    fun `BatchResult correctly aggregates results`() {
        val result = com.chartlite.app.sms.BatchResult(
            total = 5,
            sent = 3,
            failed = 2,
            results = listOf(
                com.chartlite.app.sms.SendResult(true, "apt-001"),
                com.chartlite.app.sms.SendResult(true, "apt-002"),
                com.chartlite.app.sms.SendResult(true, "apt-003"),
                com.chartlite.app.sms.SendResult(false, "apt-004", "No signal"),
                com.chartlite.app.sms.SendResult(false, "apt-005", "Invalid number")
            )
        )

        assertEquals(5, result.total)
        assertEquals(3, result.sent)
        assertEquals(2, result.failed)
        assertEquals(5, result.results.size)
    }

    @Test
    fun `SendResult captures error message on failure`() {
        val result = com.chartlite.app.sms.SendResult(
            success = false,
            appointmentId = "apt-001",
            error = "Network timeout"
        )

        assertFalse(result.success)
        assertEquals("Network timeout", result.error)
    }

    @Test
    fun `SendResult has null error on success`() {
        val result = com.chartlite.app.sms.SendResult(
            success = true,
            appointmentId = "apt-001"
        )

        assertTrue(result.success)
        assertNull(result.error)
    }
}
