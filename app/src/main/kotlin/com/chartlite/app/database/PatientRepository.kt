package com.chartlite.app.database

import com.chartlite.app.database.dao.PatientDao
import com.chartlite.app.database.entity.PatientEntity
import kotlinx.coroutines.flow.Flow

class PatientRepository(private val dao: PatientDao) {

    suspend fun register(patient: PatientEntity) = dao.insert(patient)

    /**
     * Update a patient record from local edits — stamps a fresh updatedAt
     * so this device's change propagates correctly on the next sync.
     */
    suspend fun update(patient: PatientEntity) = dao.update(
        patient.copy(updatedAt = System.currentTimeMillis())
    )

    /**
     * Merge a remote patient record received via sync — preserves the original
     * updatedAt timestamp so the winning timestamp survives across sync hops.
     * Without this, every merge would rewrite updatedAt to "now", making the
     * local copy appear newest and bouncing edits back to other devices.
     */
    suspend fun mergeFromSync(patient: PatientEntity) = dao.update(patient)

    suspend fun getById(id: String): PatientEntity? = dao.getById(id)

    fun observeById(id: String): Flow<PatientEntity?> = dao.observeById(id)

    suspend fun search(query: String): List<PatientEntity> {
        if (query.isBlank()) return dao.getRecent()
        // If query looks like a patient ID prefix (all caps/digits, short), search by ID prefix
        val cleaned = query.uppercase().replace("-", "")
        return if (cleaned.length <= 8 && cleaned.all { it.isLetterOrDigit() }) {
            val byId = dao.searchByIdPrefix(cleaned)
            if (byId.isNotEmpty()) byId else dao.search(query)
        } else {
            dao.search(query)
        }
    }

    suspend fun getByPhone(phone: String): PatientEntity? = dao.getByPhone(phone)

    suspend fun getRecent(limit: Int = 20): List<PatientEntity> = dao.getRecent(limit)

    fun observeAll(): Flow<List<PatientEntity>> = dao.observeAll()

    suspend fun getCount(): Int = dao.getCount()

    suspend fun getAll(): List<PatientEntity> = dao.getAll()
}
