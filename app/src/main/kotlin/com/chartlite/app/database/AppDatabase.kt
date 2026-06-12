package com.chartlite.app.database

import android.content.Context
import android.util.Log
import androidx.room.Database
import androidx.room.Room
import androidx.room.RoomDatabase
import androidx.room.TypeConverters
import androidx.room.migration.Migration
import androidx.sqlite.db.SupportSQLiteDatabase
import com.chartlite.app.database.converter.Converters
import com.chartlite.app.database.dao.AppointmentDao
import com.chartlite.app.database.dao.AuditLogDao
import com.chartlite.app.database.dao.EncounterDao
import com.chartlite.app.database.dao.ExtractionQueueDao
import com.chartlite.app.database.dao.FPVisitDao
import com.chartlite.app.database.dao.SmsLogDao
import com.chartlite.app.database.dao.GrowthDao
import com.chartlite.app.database.dao.ImmunizationDao
import com.chartlite.app.database.dao.LabOrderDao
import com.chartlite.app.database.dao.PatientDao
import com.chartlite.app.database.dao.ProviderDao
import com.chartlite.app.database.dao.ReferralDao
import com.chartlite.app.database.dao.StockDao
import com.chartlite.app.database.dao.ClinicalPhotoDao
import com.chartlite.app.database.dao.UserDao
import com.chartlite.app.database.dao.VisitDao
import com.chartlite.app.database.entity.AppointmentEntity
import com.chartlite.app.database.entity.ClinicalPhotoEntity
import com.chartlite.app.database.entity.AuditLogEntity
import com.chartlite.app.database.entity.EncounterEntity
import com.chartlite.app.database.entity.ExtractionQueueEntity
import com.chartlite.app.database.entity.FPVisitEntity
import com.chartlite.app.database.entity.FacilityEntity
import com.chartlite.app.database.entity.GrowthMeasurementEntity
import com.chartlite.app.database.entity.ImmunizationEntity
import com.chartlite.app.database.entity.LabOrderEntity
import com.chartlite.app.database.entity.PatientEntity
import com.chartlite.app.database.entity.ProviderEntity
import com.chartlite.app.database.entity.ReferralEntity
import com.chartlite.app.database.entity.SmsLogEntity
import com.chartlite.app.database.entity.StockItemEntity
import com.chartlite.app.database.entity.StockTransactionEntity
import com.chartlite.app.database.entity.UserEntity
import com.chartlite.app.database.entity.VisitEntity
import com.chartlite.app.database.migration.MigrationHelper
import net.zetetic.database.sqlcipher.SupportOpenHelperFactory

@Database(
    entities = [
        PatientEntity::class,
        EncounterEntity::class,
        ProviderEntity::class,
        FacilityEntity::class,
        VisitEntity::class,
        UserEntity::class,
        AuditLogEntity::class,
        LabOrderEntity::class,
        AppointmentEntity::class,
        ReferralEntity::class,
        StockItemEntity::class,
        StockTransactionEntity::class,
        ImmunizationEntity::class,
        FPVisitEntity::class,
        GrowthMeasurementEntity::class
        ,
        ExtractionQueueEntity::class,
        SmsLogEntity::class,
        ClinicalPhotoEntity::class
    ],
    version = 16,
    exportSchema = true
)
@TypeConverters(Converters::class)
abstract class AppDatabase : RoomDatabase() {
    abstract fun patientDao(): PatientDao
    abstract fun encounterDao(): EncounterDao
    abstract fun extractionQueueDao(): ExtractionQueueDao
    abstract fun providerDao(): ProviderDao
    abstract fun visitDao(): VisitDao
    abstract fun userDao(): UserDao
    abstract fun auditLogDao(): AuditLogDao
    abstract fun labOrderDao(): LabOrderDao
    abstract fun appointmentDao(): AppointmentDao
    abstract fun referralDao(): ReferralDao
    abstract fun stockDao(): StockDao
    abstract fun immunizationDao(): ImmunizationDao
    abstract fun fpVisitDao(): FPVisitDao
    abstract fun growthDao(): GrowthDao
    abstract fun smsLogDao(): SmsLogDao
    abstract fun clinicalPhotoDao(): ClinicalPhotoDao

    companion object {
        private const val TAG = "AppDatabase"

        @Volatile
        private var INSTANCE: AppDatabase? = null

        fun getInstance(context: Context, passphrase: ByteArray): AppDatabase {
            return INSTANCE ?: synchronized(this) {
                INSTANCE ?: buildDatabase(context, passphrase).also { INSTANCE = it }
            }
        }

        private fun buildDatabase(context: Context, passphrase: ByteArray): AppDatabase {
            val factory = SupportOpenHelperFactory(passphrase)
            return Room.databaseBuilder(
                context.applicationContext,
                AppDatabase::class.java,
                "afrimed_clinical.db"
            )
                .openHelperFactory(factory)
                .addMigrations(
                    MIGRATION_1_2,
                    MigrationHelper.MIGRATION_2_3,
                    MigrationHelper.MIGRATION_3_4,
                    MigrationHelper.MIGRATION_4_5,
                    MigrationHelper.MIGRATION_5_6,
                    MigrationHelper.MIGRATION_6_7,
                    MigrationHelper.MIGRATION_7_8,
                    MigrationHelper.MIGRATION_8_9,
                    MigrationHelper.MIGRATION_9_10,
                    MigrationHelper.MIGRATION_10_11,
                    MigrationHelper.MIGRATION_11_12,
                    MigrationHelper.MIGRATION_12_13,
                    MigrationHelper.MIGRATION_13_14,
                    MigrationHelper.MIGRATION_14_15,
                    MigrationHelper.MIGRATION_15_16
                )
                .fallbackToDestructiveMigrationOnDowngrade()
                .addCallback(object : Callback() {
                    override fun onDestructiveMigration(db: SupportSQLiteDatabase) {
                        super.onDestructiveMigration(db)
                        Log.e(TAG, "DESTRUCTIVE MIGRATION occurred — patient data was lost!")
                    }
                })
                .build()
        }

        val MIGRATION_1_2 = object : Migration(1, 2) {
            override fun migrate(db: SupportSQLiteDatabase) {
                // Add stationType to encounters (nullable, backward-compatible)
                db.execSQL("ALTER TABLE encounters ADD COLUMN stationType TEXT")

                // Create visits table for multi-station clinic workflow
                db.execSQL("""
                    CREATE TABLE IF NOT EXISTS visits (
                        id TEXT NOT NULL PRIMARY KEY,
                        patientId TEXT NOT NULL,
                        facilityId TEXT NOT NULL,
                        visitDate TEXT NOT NULL,
                        status TEXT NOT NULL,
                        currentStation TEXT,
                        registeredBy TEXT,
                        triagedBy TEXT,
                        consultedBy TEXT,
                        dispensedBy TEXT,
                        triageEncounterId TEXT,
                        consultEncounterId TEXT,
                        pharmacyNotes TEXT,
                        priorityLevel INTEGER NOT NULL DEFAULT 0,
                        chiefComplaint TEXT,
                        createdAt INTEGER NOT NULL DEFAULT 0,
                        updatedAt INTEGER NOT NULL DEFAULT 0,
                        FOREIGN KEY (patientId) REFERENCES patients(id) ON DELETE CASCADE
                    )
                """)
                db.execSQL("CREATE INDEX IF NOT EXISTS index_visits_patientId ON visits(patientId)")
                db.execSQL("CREATE INDEX IF NOT EXISTS index_visits_status ON visits(status)")
                db.execSQL("CREATE INDEX IF NOT EXISTS index_visits_visitDate ON visits(visitDate)")
            }
        }
    }
}
