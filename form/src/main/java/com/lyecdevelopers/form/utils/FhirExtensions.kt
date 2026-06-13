package com.lyecdevelopers.form.utils

import com.lyecdevelopers.core.model.FieldType
import org.hl7.fhir.r4.model.CodeType
import org.hl7.fhir.r4.model.CodeableConcept
import org.hl7.fhir.r4.model.Coding
import org.hl7.fhir.r4.model.Extension
import org.hl7.fhir.r4.model.Questionnaire

object FhirExtensions {

    const val ITEM_CONTROL_URL = "http://hl7.org/fhir/StructureDefinition/questionnaire-itemControl"
    const val CHOICE_ORIENTATION_URL =
        "http://hl7.org/fhir/StructureDefinition/questionnaire-choiceOrientation"

    fun pageItemControlExtension(): Extension {
        return Extension().apply {
            url = ITEM_CONTROL_URL
            setValue(
                CodeableConcept().apply {
                    addCoding(
                        Coding().apply {
                            system = "http://hl7.org/fhir/questionnaire-item-control"
                            code = "page"
                            display = "Page"
                        }
                    )
                    text = "Page"
                }
            )
        }
    }

    fun addItemControlExtension(
        item: Questionnaire.QuestionnaireItemComponent,
        fieldType: FieldType?,
    ) {
        val (code, display) = when (fieldType) {
            FieldType.CHECKBOX -> "check-box" to "Checkbox"
            FieldType.MULTI_CHECKBOX -> "auto-complete" to "Auto-complete"
            FieldType.RADIO -> "radio-button" to "Radio Button"
            FieldType.DROPDOWN, FieldType.SELECT -> "drop-down" to "Drop down"
            FieldType.NUMBER -> "slider" to "Slider"
            else -> null to null
        }

        if (code != null && display != null) {
            item.extension.add(
                Extension().apply {
                    url = ITEM_CONTROL_URL
                    setValue(
                        CodeableConcept().apply {
                            addCoding(
                                Coding().apply {
                                    system = "http://hl7.org/fhir/questionnaire-item-control"
                                    this.code = code
                                    this.display = display
                                }
                            )
                            text = display
                        }
                    )
                }
            )
        }

        if (fieldType == FieldType.RADIO) {
            item.extension.add(choiceOrientationHorizontal())
        }
    }

    fun choiceOrientationHorizontal(): Extension {
        return Extension().apply {
            url = CHOICE_ORIENTATION_URL
            setValue(CodeType("horizontal"))
        }
    }

    fun mapFieldType(fieldType: FieldType?): Questionnaire.QuestionnaireItemType {
        return when (fieldType) {
            FieldType.NUMBER -> Questionnaire.QuestionnaireItemType.INTEGER
            FieldType.DATE -> Questionnaire.QuestionnaireItemType.DATE
            FieldType.DATETIME -> Questionnaire.QuestionnaireItemType.DATETIME
            FieldType.TEXT, FieldType.TEXTAREA -> Questionnaire.QuestionnaireItemType.STRING
            FieldType.DROPDOWN, FieldType.SELECT, FieldType.RADIO,
            FieldType.CHECKBOX, FieldType.MULTI_CHECKBOX,
                -> Questionnaire.QuestionnaireItemType.CHOICE

            FieldType.FILE -> Questionnaire.QuestionnaireItemType.ATTACHMENT
            FieldType.REPEATING -> Questionnaire.QuestionnaireItemType.GROUP
            FieldType.UI_SELECT_EXTENDED -> Questionnaire.QuestionnaireItemType.STRING
            FieldType.GROUP -> Questionnaire.QuestionnaireItemType.GROUP
            else -> error("Unsupported field type: $fieldType")
        }
    }

}
