package com.chartlite.app.database.entity

import androidx.room.Entity
import androidx.room.Index
import androidx.room.PrimaryKey

@Entity(
    tableName = "users",
    indices = [
        Index(value = ["username", "facilityId"], unique = true),
        Index("facilityId"),
        Index("role")
    ]
)
data class UserEntity(
    @PrimaryKey val id: String,
    val username: String,
    val displayName: String,
    val pinHash: String,
    val pinSalt: String,
    val role: String,           // UserRole.name
    val facilityId: String,
    val isActive: Boolean = true,
    val createdBy: String,      // userId of admin who created this user
    val createdAt: Long = System.currentTimeMillis(),
    val updatedAt: Long = System.currentTimeMillis()
)
