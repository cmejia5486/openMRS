package com.chartlite.app.model

enum class AppointmentType {
    FOLLOW_UP, NEW_VISIT, LAB_REVIEW, CHRONIC_CARE, ANTENATAL, IMMUNIZATION
}

enum class AppointmentStatus {
    SCHEDULED, CHECKED_IN, IN_PROGRESS, COMPLETED, NO_SHOW, CANCELLED
}
