package com.chartlite.app.integration

/**
 * DHIS2 connection configuration.
 * Credentials are stored encrypted via AppConfig (EncryptedSharedPreferences).
 */
data class DHIS2Config(
    val serverUrl: String,
    val username: String,
    val password: String,
    val orgUnitId: String,
    val dataSetId: String = "PHC_MONTHLY_REPORT",
    val attributeOptionCombo: String = ""
) {
    val isConfigured: Boolean
        get() = serverUrl.isNotBlank() && username.isNotBlank()
                && password.isNotBlank() && orgUnitId.isNotBlank()

    /** Base API URL with trailing slash */
    val apiUrl: String
        get() = serverUrl.trimEnd('/') + "/api/"

    /** Override toString to prevent password leaking to logs */
    override fun toString(): String =
        "DHIS2Config(serverUrl=$serverUrl, username=$username, password=***, orgUnitId=$orgUnitId)"

    companion object {
        val EMPTY = DHIS2Config("", "", "", "")
    }
}
