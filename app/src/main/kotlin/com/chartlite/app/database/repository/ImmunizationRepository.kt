package com.chartlite.app.database.repository

import com.chartlite.app.database.dao.ImmunizationDao
import com.chartlite.app.database.entity.ImmunizationEntity
import java.util.UUID

/**
 * Business logic for immunization records and EPI schedule tracking.
 */
class ImmunizationRepository(private val immunizationDao: ImmunizationDao) {

    suspend fun recordImmunization(
        patientId: String,
        vaccineCode: String,
        vaccineName: String,
        doseNumber: Int,
        administeredBy: String,
        facilityId: String,
        batchNumber: String? = null,
        site: String? = null,
        nextDoseCode: String? = null,
        nextDoseDueDate: Long? = null
    ): ImmunizationEntity {
        val immunization = ImmunizationEntity(
            id = UUID.randomUUID().toString(),
            patientId = patientId,
            vaccineCode = vaccineCode,
            vaccineName = vaccineName,
            doseNumber = doseNumber,
            administeredAt = System.currentTimeMillis(),
            administeredBy = administeredBy,
            batchNumber = batchNumber,
            site = site,
            nextDoseCode = nextDoseCode,
            nextDoseDueDate = nextDoseDueDate,
            facilityId = facilityId
        )
        immunizationDao.insert(immunization)
        return immunization
    }

    suspend fun getByPatient(patientId: String) = immunizationDao.getByPatient(patientId)
    suspend fun getByPatientAndVaccine(patientId: String, vaccineCode: String) =
        immunizationDao.getByPatientAndVaccine(patientId, vaccineCode)
    suspend fun getOverdue() = immunizationDao.getOverdue(System.currentTimeMillis())
    suspend fun getOverdueCount() = immunizationDao.getOverdueCount(System.currentTimeMillis())
    fun observeByPatient(patientId: String) = immunizationDao.observeByPatient(patientId)
}
