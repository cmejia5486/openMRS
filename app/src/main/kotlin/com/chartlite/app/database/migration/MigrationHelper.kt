package com.chartlite.app.database.migration

import androidx.room.migration.Migration
import androidx.sqlite.db.SupportSQLiteDatabase

/**
 * Database migrations for ChartLite.
 * Each migration is additive — no destructive changes, existing data always preserved.
 */
object MigrationHelper {

    /**
     * v2 → v3: Add multi-user authentication and audit logging.
     *
     * New tables:
     * - users: Multi-user PIN-based auth with role-based access
     * - audit_logs: Full audit trail for clinical, auth, and admin actions
     */
    val MIGRATION_2_3 = object : Migration(2, 3) {
        override fun migrate(db: SupportSQLiteDatabase) {
            // Create users table
            db.execSQL("""
                CREATE TABLE IF NOT EXISTS users (
                    id TEXT NOT NULL PRIMARY KEY,
                    username TEXT NOT NULL,
                    displayName TEXT NOT NULL,
                    pinHash TEXT NOT NULL,
                    pinSalt TEXT NOT NULL,
                    role TEXT NOT NULL,
                    facilityId TEXT NOT NULL,
                    isActive INTEGER NOT NULL DEFAULT 1,
                    createdBy TEXT NOT NULL,
                    createdAt INTEGER NOT NULL DEFAULT 0,
                    updatedAt INTEGER NOT NULL DEFAULT 0
                )
            """)
            db.execSQL("CREATE UNIQUE INDEX IF NOT EXISTS index_users_username_facilityId ON users(username, facilityId)")
            db.execSQL("CREATE INDEX IF NOT EXISTS index_users_facilityId ON users(facilityId)")
            db.execSQL("CREATE INDEX IF NOT EXISTS index_users_role ON users(role)")

            // Create audit_logs table
            db.execSQL("""
                CREATE TABLE IF NOT EXISTS audit_logs (
                    id TEXT NOT NULL PRIMARY KEY,
                    userId TEXT NOT NULL,
                    action TEXT NOT NULL,
                    targetType TEXT,
                    targetId TEXT,
                    details TEXT,
                    timestamp INTEGER NOT NULL DEFAULT 0
                )
            """)
            db.execSQL("CREATE INDEX IF NOT EXISTS index_audit_logs_userId ON audit_logs(userId)")
            db.execSQL("CREATE INDEX IF NOT EXISTS index_audit_logs_action ON audit_logs(action)")
            db.execSQL("CREATE INDEX IF NOT EXISTS index_audit_logs_timestamp ON audit_logs(timestamp)")
            db.execSQL("CREATE INDEX IF NOT EXISTS index_audit_logs_userId_action_timestamp ON audit_logs(userId, action, timestamp)")
            db.execSQL("CREATE INDEX IF NOT EXISTS index_audit_logs_targetType_targetId ON audit_logs(targetType, targetId)")
        }
    }

    /**
     * v3 → v4: Add lab orders, appointments, referral tracking.
     *
     * All tables include forward-compatible fields:
     * - metadata: JSON blob for future extensibility without schema changes
     * - sourceAgentId: Tracks if created/modified by an AI agent
     * - syncStatus: For future multi-device sync (PENDING/SYNCED/CONFLICT)
     * - fhirResourceId: FHIR R4 resource reference for interoperability
     */
    val MIGRATION_3_4 = object : Migration(3, 4) {
        override fun migrate(db: SupportSQLiteDatabase) {
            // Create lab_orders table
            db.execSQL("""
                CREATE TABLE IF NOT EXISTS lab_orders (
                    id TEXT NOT NULL PRIMARY KEY,
                    visitId TEXT NOT NULL,
                    patientId TEXT NOT NULL,
                    testCode TEXT NOT NULL,
                    testName TEXT NOT NULL,
                    orderedBy TEXT NOT NULL,
                    status TEXT NOT NULL,
                    priority TEXT NOT NULL,
                    resultValue TEXT,
                    resultUnit TEXT,
                    referenceRange TEXT,
                    isAbnormal INTEGER,
                    notes TEXT,
                    orderedAt INTEGER NOT NULL DEFAULT 0,
                    collectedAt INTEGER,
                    resultedAt INTEGER,
                    resultedBy TEXT,
                    metadata TEXT,
                    sourceAgentId TEXT,
                    syncStatus TEXT,
                    fhirResourceId TEXT
                )
            """)
            db.execSQL("CREATE INDEX IF NOT EXISTS index_lab_orders_visitId ON lab_orders(visitId)")
            db.execSQL("CREATE INDEX IF NOT EXISTS index_lab_orders_patientId ON lab_orders(patientId)")
            db.execSQL("CREATE INDEX IF NOT EXISTS index_lab_orders_status ON lab_orders(status)")
            db.execSQL("CREATE INDEX IF NOT EXISTS index_lab_orders_orderedAt ON lab_orders(orderedAt)")
            db.execSQL("CREATE INDEX IF NOT EXISTS index_lab_orders_status_orderedAt ON lab_orders(status, orderedAt)")
            db.execSQL("CREATE INDEX IF NOT EXISTS index_lab_orders_patientId_status ON lab_orders(patientId, status)")

            // Create appointments table
            db.execSQL("""
                CREATE TABLE IF NOT EXISTS appointments (
                    id TEXT NOT NULL PRIMARY KEY,
                    patientId TEXT NOT NULL,
                    providerId TEXT,
                    facilityId TEXT NOT NULL,
                    scheduledDate INTEGER NOT NULL,
                    scheduledTime TEXT,
                    durationMinutes INTEGER NOT NULL,
                    type TEXT NOT NULL,
                    status TEXT NOT NULL,
                    notes TEXT,
                    createdBy TEXT NOT NULL,
                    createdAt INTEGER NOT NULL DEFAULT 0,
                    updatedAt INTEGER NOT NULL DEFAULT 0,
                    metadata TEXT,
                    sourceAgentId TEXT,
                    syncStatus TEXT,
                    fhirResourceId TEXT
                )
            """)
            db.execSQL("CREATE INDEX IF NOT EXISTS index_appointments_patientId ON appointments(patientId)")
            db.execSQL("CREATE INDEX IF NOT EXISTS index_appointments_facilityId ON appointments(facilityId)")
            db.execSQL("CREATE INDEX IF NOT EXISTS index_appointments_scheduledDate ON appointments(scheduledDate)")
            db.execSQL("CREATE INDEX IF NOT EXISTS index_appointments_status ON appointments(status)")
            db.execSQL("CREATE INDEX IF NOT EXISTS index_appointments_facilityId_scheduledDate ON appointments(facilityId, scheduledDate)")
            db.execSQL("CREATE INDEX IF NOT EXISTS index_appointments_facilityId_scheduledDate_status ON appointments(facilityId, scheduledDate, status)")

            // Create referrals table
            db.execSQL("""
                CREATE TABLE IF NOT EXISTS referrals (
                    id TEXT NOT NULL PRIMARY KEY,
                    visitId TEXT NOT NULL,
                    patientId TEXT NOT NULL,
                    fromProviderId TEXT NOT NULL,
                    fromFacilityId TEXT NOT NULL,
                    toFacility TEXT NOT NULL,
                    toDepartment TEXT,
                    urgency TEXT NOT NULL,
                    reason TEXT NOT NULL,
                    clinicalNotes TEXT,
                    status TEXT NOT NULL,
                    referredAt INTEGER NOT NULL DEFAULT 0,
                    updatedAt INTEGER NOT NULL DEFAULT 0,
                    metadata TEXT,
                    sourceAgentId TEXT,
                    syncStatus TEXT,
                    fhirResourceId TEXT
                )
            """)
            db.execSQL("CREATE INDEX IF NOT EXISTS index_referrals_patientId ON referrals(patientId)")
            db.execSQL("CREATE INDEX IF NOT EXISTS index_referrals_visitId ON referrals(visitId)")
            db.execSQL("CREATE INDEX IF NOT EXISTS index_referrals_status ON referrals(status)")
            db.execSQL("CREATE INDEX IF NOT EXISTS index_referrals_fromFacilityId ON referrals(fromFacilityId)")
            db.execSQL("CREATE INDEX IF NOT EXISTS index_referrals_fromFacilityId_status ON referrals(fromFacilityId, status)")
        }
    }

    /**
     * v4 → v5: Add pharmacy stock management.
     */
    val MIGRATION_4_5 = object : Migration(4, 5) {
        override fun migrate(db: SupportSQLiteDatabase) {
            db.execSQL("""
                CREATE TABLE IF NOT EXISTS stock_items (
                    id TEXT NOT NULL PRIMARY KEY,
                    facilityId TEXT NOT NULL,
                    drugCode TEXT NOT NULL,
                    drugName TEXT NOT NULL,
                    quantityOnHand INTEGER NOT NULL,
                    reorderLevel INTEGER NOT NULL,
                    unit TEXT NOT NULL,
                    batchNumber TEXT,
                    expiryDate INTEGER,
                    lastUpdatedBy TEXT NOT NULL,
                    lastUpdatedAt INTEGER NOT NULL,
                    metadata TEXT,
                    sourceAgentId TEXT,
                    syncStatus TEXT,
                    fhirResourceId TEXT
                )
            """)
            db.execSQL("CREATE INDEX IF NOT EXISTS index_stock_items_facilityId ON stock_items(facilityId)")
            db.execSQL("CREATE INDEX IF NOT EXISTS index_stock_items_drugCode ON stock_items(drugCode)")
            db.execSQL("CREATE INDEX IF NOT EXISTS index_stock_items_expiryDate ON stock_items(expiryDate)")
            db.execSQL("CREATE INDEX IF NOT EXISTS index_stock_items_facilityId_drugCode ON stock_items(facilityId, drugCode)")
            db.execSQL("CREATE INDEX IF NOT EXISTS index_stock_items_facilityId_quantityOnHand ON stock_items(facilityId, quantityOnHand)")

            db.execSQL("""
                CREATE TABLE IF NOT EXISTS stock_transactions (
                    id TEXT NOT NULL PRIMARY KEY,
                    stockItemId TEXT NOT NULL,
                    transactionType TEXT NOT NULL,
                    quantity INTEGER NOT NULL,
                    referenceId TEXT,
                    performedBy TEXT NOT NULL,
                    notes TEXT,
                    timestamp INTEGER NOT NULL,
                    metadata TEXT,
                    sourceAgentId TEXT
                )
            """)
            db.execSQL("CREATE INDEX IF NOT EXISTS index_stock_transactions_stockItemId ON stock_transactions(stockItemId)")
            db.execSQL("CREATE INDEX IF NOT EXISTS index_stock_transactions_transactionType ON stock_transactions(transactionType)")
            db.execSQL("CREATE INDEX IF NOT EXISTS index_stock_transactions_timestamp ON stock_transactions(timestamp)")
        }
    }

    /**
     * v5 → v6: Add maternal & child health — immunizations, family planning, growth charts.
     */
    val MIGRATION_5_6 = object : Migration(5, 6) {
        override fun migrate(db: SupportSQLiteDatabase) {
            // Immunizations table
            db.execSQL("""
                CREATE TABLE IF NOT EXISTS immunizations (
                    id TEXT NOT NULL PRIMARY KEY,
                    patientId TEXT NOT NULL,
                    vaccineCode TEXT NOT NULL,
                    vaccineName TEXT NOT NULL,
                    doseNumber INTEGER NOT NULL,
                    administeredAt INTEGER NOT NULL,
                    administeredBy TEXT NOT NULL,
                    batchNumber TEXT,
                    site TEXT,
                    nextDoseCode TEXT,
                    nextDoseDueDate INTEGER,
                    facilityId TEXT NOT NULL,
                    metadata TEXT,
                    sourceAgentId TEXT,
                    syncStatus TEXT,
                    fhirResourceId TEXT
                )
            """)
            db.execSQL("CREATE INDEX IF NOT EXISTS index_immunizations_patientId ON immunizations(patientId)")
            db.execSQL("CREATE INDEX IF NOT EXISTS index_immunizations_vaccineCode ON immunizations(vaccineCode)")
            db.execSQL("CREATE INDEX IF NOT EXISTS index_immunizations_administeredAt ON immunizations(administeredAt)")
            db.execSQL("CREATE INDEX IF NOT EXISTS index_immunizations_patientId_vaccineCode ON immunizations(patientId, vaccineCode)")

            // Family planning visits table
            db.execSQL("""
                CREATE TABLE IF NOT EXISTS fp_visits (
                    id TEXT NOT NULL PRIMARY KEY,
                    patientId TEXT NOT NULL,
                    visitId TEXT,
                    method TEXT NOT NULL,
                    methodStartDate INTEGER,
                    nextFollowUpDate INTEGER,
                    sideEffects TEXT,
                    counselingNotes TEXT,
                    commodityDispensed TEXT,
                    quantity INTEGER,
                    providerId TEXT NOT NULL,
                    facilityId TEXT NOT NULL,
                    createdAt INTEGER NOT NULL,
                    metadata TEXT,
                    sourceAgentId TEXT,
                    syncStatus TEXT,
                    fhirResourceId TEXT
                )
            """)
            db.execSQL("CREATE INDEX IF NOT EXISTS index_fp_visits_patientId ON fp_visits(patientId)")
            db.execSQL("CREATE INDEX IF NOT EXISTS index_fp_visits_method ON fp_visits(method)")
            db.execSQL("CREATE INDEX IF NOT EXISTS index_fp_visits_nextFollowUpDate ON fp_visits(nextFollowUpDate)")

            // Growth measurements table
            db.execSQL("""
                CREATE TABLE IF NOT EXISTS growth_measurements (
                    id TEXT NOT NULL PRIMARY KEY,
                    patientId TEXT NOT NULL,
                    visitId TEXT,
                    weight REAL,
                    height REAL,
                    headCircumference REAL,
                    muac REAL,
                    measuredAt INTEGER NOT NULL,
                    measuredBy TEXT NOT NULL,
                    weightForAgeZ REAL,
                    heightForAgeZ REAL,
                    bmiForAgeZ REAL,
                    metadata TEXT,
                    sourceAgentId TEXT,
                    syncStatus TEXT,
                    fhirResourceId TEXT
                )
            """)
            db.execSQL("CREATE INDEX IF NOT EXISTS index_growth_measurements_patientId ON growth_measurements(patientId)")
            db.execSQL("CREATE INDEX IF NOT EXISTS index_growth_measurements_measuredAt ON growth_measurements(measuredAt)")
        }
    }

    /**
     * v6 → v7: Add performance indexes to patients table.
     *
     * PatientEntity was created in v1 without indexes. Adding them now
     * to improve search, sort, and lookup performance.
     */
    val MIGRATION_6_7 = object : Migration(6, 7) {
        override fun migrate(db: SupportSQLiteDatabase) {
            db.execSQL("CREATE INDEX IF NOT EXISTS index_patients_lastName ON patients(lastName)")
            db.execSQL("CREATE INDEX IF NOT EXISTS index_patients_phoneNumber ON patients(phoneNumber)")
            db.execSQL("CREATE INDEX IF NOT EXISTS index_patients_updatedAt ON patients(updatedAt)")
        }
    }

    /**
     * v7 → v8: Add benchmark-driven clinical categories to encounters.
     *
     * Architecture update (2026-03): Clinical extraction now uses category-specific
     * strategies based on benchmark results:
     * - examFindings: LLM's best category (88% precision) — physical exam observations
     * - investigations: Tests ordered/resulted (80% precision)
     * - plan: Clinical plan items (72% precision)
     * - socialHistory: Social determinants of health
     * - suggestedDiagnoses: AI-suggested diagnoses that need clinician confirmation
     *   (LLMs hallucinate diagnoses 28-63%, so clinician must confirm)
     *
     * All columns default to "[]" (empty JSON array) for backward compatibility.
     */
    val MIGRATION_7_8 = object : Migration(7, 8) {
        override fun migrate(db: SupportSQLiteDatabase) {
            db.execSQL("ALTER TABLE encounters ADD COLUMN examFindings TEXT NOT NULL DEFAULT '[]'")
            db.execSQL("ALTER TABLE encounters ADD COLUMN investigations TEXT NOT NULL DEFAULT '[]'")
            db.execSQL("ALTER TABLE encounters ADD COLUMN plan TEXT NOT NULL DEFAULT '[]'")
            db.execSQL("ALTER TABLE encounters ADD COLUMN socialHistory TEXT NOT NULL DEFAULT '[]'")
            db.execSQL("ALTER TABLE encounters ADD COLUMN suggestedDiagnoses TEXT NOT NULL DEFAULT '[]'")
        }
    }

    /**
     * v8 → v9: Persist extraction queue items so batched note processing survives
     * navigation, app restarts, and Android low-memory kills.
     */
    val MIGRATION_8_9 = object : Migration(8, 9) {
        override fun migrate(db: SupportSQLiteDatabase) {
            db.execSQL(
                """
                CREATE TABLE IF NOT EXISTS extraction_queue_items (
                    id TEXT NOT NULL PRIMARY KEY,
                    transcript TEXT NOT NULL,
                    patientId TEXT NOT NULL,
                    providerId TEXT NOT NULL,
                    facilityId TEXT NOT NULL,
                    visitId TEXT,
                    stationType TEXT,
                    status TEXT NOT NULL,
                    isUrgent INTEGER NOT NULL DEFAULT 0,
                    deferredReview INTEGER NOT NULL DEFAULT 0,
                    strategyUsed TEXT,
                    fallbacksAttempted TEXT NOT NULL DEFAULT '[]',
                    structuredEncounter TEXT,
                    errorMessage TEXT,
                    savedEncounterId TEXT,
                    createdAt INTEGER NOT NULL DEFAULT 0,
                    updatedAt INTEGER NOT NULL DEFAULT 0
                )
                """.trimIndent()
            )
            db.execSQL("CREATE INDEX IF NOT EXISTS index_extraction_queue_items_status ON extraction_queue_items(status)")
            db.execSQL("CREATE INDEX IF NOT EXISTS index_extraction_queue_items_patientId ON extraction_queue_items(patientId)")
            db.execSQL("CREATE INDEX IF NOT EXISTS index_extraction_queue_items_visitId ON extraction_queue_items(visitId)")
            db.execSQL("CREATE INDEX IF NOT EXISTS index_extraction_queue_items_createdAt ON extraction_queue_items(createdAt)")
        }
    }

    /**
     * v9 -> v10: Repair legacy encounter time fields.
     *
     * Some older or partially migrated rows can carry `0` in either `timestamp`
     * or `createdAt`. That renders as 31 Dec 1969 in the UI and can also break
     * "most recent encounter" ordering. Backfill the missing field from the
     * other one when a valid value exists.
     */
    /**
     * v10 → v11: Add patient-facing referral fields for SMS referral letters.
     *
     * New nullable columns on referrals table:
     * - patientInstructions: What to bring / preparation (e.g. "Bring ID, clinic card")
     * - timeframeDays: Days within which patient should attend (0 = today for emergencies)
     * - smsText: The actual plain-text SMS sent to the patient (≤160 chars, stored for display)
     */
    /**
     * v13 → v14: Add SMS log table for communication audit trail.
     */
    /**
     * v14 → v15: Add immunizations + smsSummary columns to encounters table.
     * These were previously in-memory only (StructuredEncounter) and lost on save.
     */
    /**
     * v15 → v16: Add clinical photos table for image capture and OCR extraction.
     */
    val MIGRATION_15_16 = object : Migration(15, 16) {
        override fun migrate(db: SupportSQLiteDatabase) {
            db.execSQL("""
                CREATE TABLE IF NOT EXISTS clinical_photos (
                    id TEXT NOT NULL PRIMARY KEY,
                    encounterId TEXT NOT NULL,
                    patientId TEXT NOT NULL,
                    contentType TEXT NOT NULL,
                    filePath TEXT NOT NULL,
                    extractedJson TEXT,
                    capturedAt INTEGER NOT NULL DEFAULT 0
                )
            """)
            db.execSQL("CREATE INDEX IF NOT EXISTS index_clinical_photos_encounterId ON clinical_photos(encounterId)")
            db.execSQL("CREATE INDEX IF NOT EXISTS index_clinical_photos_patientId ON clinical_photos(patientId)")
            db.execSQL("CREATE INDEX IF NOT EXISTS index_clinical_photos_patientId_contentType ON clinical_photos(patientId, contentType)")
        }
    }

    val MIGRATION_14_15 = object : Migration(14, 15) {
        override fun migrate(db: SupportSQLiteDatabase) {
            db.execSQL("ALTER TABLE encounters ADD COLUMN immunizations TEXT NOT NULL DEFAULT '[]'")
            db.execSQL("ALTER TABLE encounters ADD COLUMN smsSummary TEXT")
        }
    }

    val MIGRATION_13_14 = object : Migration(13, 14) {
        override fun migrate(db: SupportSQLiteDatabase) {
            db.execSQL("""
                CREATE TABLE IF NOT EXISTS sms_logs (
                    id TEXT NOT NULL PRIMARY KEY,
                    patientId TEXT NOT NULL,
                    encounterId TEXT,
                    recipientPhone TEXT NOT NULL,
                    messageType TEXT NOT NULL,
                    contentSummary TEXT NOT NULL,
                    status TEXT NOT NULL,
                    error TEXT,
                    provider TEXT NOT NULL,
                    timestamp INTEGER NOT NULL DEFAULT 0
                )
            """)
            db.execSQL("CREATE INDEX IF NOT EXISTS index_sms_logs_patientId ON sms_logs(patientId)")
            db.execSQL("CREATE INDEX IF NOT EXISTS index_sms_logs_encounterId ON sms_logs(encounterId)")
            db.execSQL("CREATE INDEX IF NOT EXISTS index_sms_logs_timestamp ON sms_logs(timestamp)")
            db.execSQL("CREATE INDEX IF NOT EXISTS index_sms_logs_messageType ON sms_logs(messageType)")
        }
    }

    val MIGRATION_12_13 = object : Migration(12, 13) {
        override fun migrate(db: SupportSQLiteDatabase) {
            // Add draftNote and noteStrategyUsed columns for note-first batch processing
            db.execSQL("ALTER TABLE extraction_queue_items ADD COLUMN draftNote TEXT")
            db.execSQL("ALTER TABLE extraction_queue_items ADD COLUMN noteStrategyUsed TEXT")
        }
    }

    val MIGRATION_11_12 = object : Migration(11, 12) {
        override fun migrate(db: SupportSQLiteDatabase) {
            // Add index on encounters.providerId for query performance
            db.execSQL("CREATE INDEX IF NOT EXISTS index_encounters_providerId ON encounters (providerId)")
        }
    }

    val MIGRATION_10_11 = object : Migration(10, 11) {
        override fun migrate(db: SupportSQLiteDatabase) {
            db.execSQL("ALTER TABLE referrals ADD COLUMN patientInstructions TEXT")
            db.execSQL("ALTER TABLE referrals ADD COLUMN timeframeDays INTEGER")
            db.execSQL("ALTER TABLE referrals ADD COLUMN smsText TEXT")
        }
    }

    val MIGRATION_9_10 = object : Migration(9, 10) {
        override fun migrate(db: SupportSQLiteDatabase) {
            db.execSQL(
                """
                UPDATE encounters
                SET createdAt = timestamp
                WHERE createdAt <= 0 AND timestamp > 0
                """.trimIndent()
            )
            db.execSQL(
                """
                UPDATE encounters
                SET timestamp = createdAt
                WHERE timestamp <= 0 AND createdAt > 0
                """.trimIndent()
            )
        }
    }
}
