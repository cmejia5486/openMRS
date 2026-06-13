package com.chartlite.app

import com.chartlite.app.database.migration.MigrationHelper
import org.junit.Assert.*
import org.junit.Test

/**
 * Tests for database migration definitions.
 * Verifies migration version numbers and existence.
 */
class MigrationHelperTest {

    @Test
    fun `MIGRATION_2_3 has correct start version`() {
        assertEquals(2, MigrationHelper.MIGRATION_2_3.startVersion)
    }

    @Test
    fun `MIGRATION_2_3 has correct end version`() {
        assertEquals(3, MigrationHelper.MIGRATION_2_3.endVersion)
    }

    @Test
    fun `MIGRATION_2_3 is not null`() {
        assertNotNull(MigrationHelper.MIGRATION_2_3)
    }

    @Test
    fun `MIGRATION_3_4 has correct versions`() {
        assertEquals(3, MigrationHelper.MIGRATION_3_4.startVersion)
        assertEquals(4, MigrationHelper.MIGRATION_3_4.endVersion)
    }

    @Test
    fun `MIGRATION_4_5 has correct versions`() {
        assertEquals(4, MigrationHelper.MIGRATION_4_5.startVersion)
        assertEquals(5, MigrationHelper.MIGRATION_4_5.endVersion)
    }

    @Test
    fun `MIGRATION_5_6 has correct versions`() {
        assertEquals(5, MigrationHelper.MIGRATION_5_6.startVersion)
        assertEquals(6, MigrationHelper.MIGRATION_5_6.endVersion)
    }

    @Test
    fun `MIGRATION_6_7 has correct versions`() {
        assertEquals(6, MigrationHelper.MIGRATION_6_7.startVersion)
        assertEquals(7, MigrationHelper.MIGRATION_6_7.endVersion)
    }

    @Test
    fun `MIGRATION_7_8 has correct versions`() {
        assertEquals(7, MigrationHelper.MIGRATION_7_8.startVersion)
        assertEquals(8, MigrationHelper.MIGRATION_7_8.endVersion)
    }

    @Test
    fun `MIGRATION_8_9 has correct versions`() {
        assertEquals(8, MigrationHelper.MIGRATION_8_9.startVersion)
        assertEquals(9, MigrationHelper.MIGRATION_8_9.endVersion)
    }

    @Test
    fun `MIGRATION_9_10 has correct versions`() {
        assertEquals(9, MigrationHelper.MIGRATION_9_10.startVersion)
        assertEquals(10, MigrationHelper.MIGRATION_9_10.endVersion)
    }

    @Test
    fun `all migrations form a contiguous chain from v2 to v10`() {
        val migrations = listOf(
            MigrationHelper.MIGRATION_2_3,
            MigrationHelper.MIGRATION_3_4,
            MigrationHelper.MIGRATION_4_5,
            MigrationHelper.MIGRATION_5_6,
            MigrationHelper.MIGRATION_6_7,
            MigrationHelper.MIGRATION_7_8,
            MigrationHelper.MIGRATION_8_9,
            MigrationHelper.MIGRATION_9_10
        )
        for (i in 0 until migrations.size - 1) {
            assertEquals(
                "Migration chain broken between ${migrations[i].endVersion} and ${migrations[i + 1].startVersion}",
                migrations[i].endVersion,
                migrations[i + 1].startVersion
            )
        }
    }
}
