package com.chartlite.app.cdss

import com.chartlite.app.model.AlertSeverity
import com.chartlite.app.model.CDSSAlert
import com.chartlite.app.model.VitalSigns

class VitalAlerts {

    fun check(vitals: VitalSigns): List<CDSSAlert> {
        val alerts = mutableListOf<CDSSAlert>()

        vitals.systolicBP?.let { sbp ->
            when {
                sbp < 70 || sbp > 200 -> alerts.add(critical("Systolic BP $sbp mmHg is critically abnormal"))
                sbp < 90 || sbp > 160 -> alerts.add(warning("Systolic BP $sbp mmHg is outside normal range"))
            }
        }

        vitals.diastolicBP?.let { dbp ->
            when {
                dbp < 40 || dbp > 120 -> alerts.add(critical("Diastolic BP $dbp mmHg is critically abnormal"))
                dbp < 50 || dbp > 100 -> alerts.add(warning("Diastolic BP $dbp mmHg is outside normal range"))
            }
        }

        vitals.temperature?.let { temp ->
            when {
                temp < 35.0f || temp > 40.0f -> alerts.add(critical("Temperature ${temp}°C is critically abnormal"))
                temp < 35.5f || temp > 38.5f -> alerts.add(warning("Temperature ${temp}°C is outside normal range"))
            }
        }

        vitals.pulse?.let { hr ->
            when {
                hr < 40 || hr > 150 -> alerts.add(critical("Pulse $hr bpm is critically abnormal"))
                hr < 50 || hr > 120 -> alerts.add(warning("Pulse $hr bpm is outside normal range"))
            }
        }

        vitals.oxygenSaturation?.let { spo2 ->
            when {
                spo2 < 90 -> alerts.add(critical("SpO2 $spo2% is critically low"))
                spo2 < 94 -> alerts.add(warning("SpO2 $spo2% is below normal"))
            }
        }

        vitals.respiratoryRate?.let { rr ->
            when {
                rr < 8 || rr > 30 -> alerts.add(critical("Respiratory rate $rr is critically abnormal"))
                rr < 12 || rr > 20 -> alerts.add(warning("Respiratory rate $rr is outside normal range"))
            }
        }

        return alerts
    }

    private fun critical(message: String) = CDSSAlert(
        severity = AlertSeverity.CRITICAL,
        category = "Vitals",
        message = message,
        relatedField = "vitals"
    )

    private fun warning(message: String) = CDSSAlert(
        severity = AlertSeverity.WARNING,
        category = "Vitals",
        message = message,
        relatedField = "vitals"
    )
}
