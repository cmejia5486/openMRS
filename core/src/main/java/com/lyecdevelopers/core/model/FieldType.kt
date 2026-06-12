package com.lyecdevelopers.core.model

import com.squareup.moshi.Json

enum class FieldType {
    @Json(name = "text")
    TEXT,

    @Json(name = "number")
    NUMBER,

    @Json(name = "date")
    DATE,

    @Json(name = "datetime")
    DATETIME,

    @Json(name = "select")
    SELECT,

    @Json(name = "dropdown")
    DROPDOWN,

    @Json(name = "textarea")
    TEXTAREA,

    @Json(name = "toggle")
    TOGGLE,

    @Json(name = "content_switcher")
    CONTENT_SWITCHER,

    @Json(name = "fixed_value")
    FIXED_VALUE,

    @Json(name = "group")
    GROUP,

    @Json(name = "repeating")
    REPEATING,

    @Json(name = "file")
    FILE,

    @Json(name = "ui-select-extended")
    UI_SELECT_EXTENDED,

    @Json(name = "problem")
    PROBLEM,

    @Json(name = "drug")
    DRUG,

    @Json(name = "checkbox")
    CHECKBOX,

    @Json(name = "radio")
    RADIO,

    @Json(name = "multiCheckbox")
    MULTI_CHECKBOX,

    @Json(name = "markdown")
    MARKDOWN,
}