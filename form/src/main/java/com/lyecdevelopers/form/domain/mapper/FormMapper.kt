package com.lyecdevelopers.form.domain.mapper

import com.lyecdevelopers.core.BuildConfig
import com.lyecdevelopers.core.data.local.entity.FormEntity
import com.lyecdevelopers.core.model.FieldType
import com.lyecdevelopers.core.model.OpenmrsObs
import com.lyecdevelopers.core.model.o3.Questions
import com.lyecdevelopers.core.utils.AppLogger
import com.lyecdevelopers.form.utils.FhirExtensions
import org.hl7.fhir.r4.model.Coding
import org.hl7.fhir.r4.model.Extension
import org.hl7.fhir.r4.model.Questionnaire
import org.hl7.fhir.r4.model.QuestionnaireResponse
import org.hl7.fhir.r4.model.UriType
import java.time.Instant

object FormMapper {

    fun toQuestionnaire(form: FormEntity): Questionnaire {
        val questionnaire = Questionnaire().apply {
            id = form.uuid
            title = form.name
            description = form.description
            version = form.version
        }

        form.pages?.forEachIndexed { pageIndex, page ->
            val pageGroup = Questionnaire.QuestionnaireItemComponent().apply {
                linkId = "page-${pageIndex + 1}"
                type = Questionnaire.QuestionnaireItemType.GROUP
                text = page.label
                extension.add(FhirExtensions.pageItemControlExtension())
            }

            page.sections.forEachIndexed { sectionIndex, section ->
                section.questions.forEachIndexed { questionIndex, question ->
                    val isRepeating = question.questionoptions.rendering == FieldType.REPEATING
                    if (isRepeating) {

                        val repeatingGroupLinkId =
                            "page-${pageIndex + 1}.section-${sectionIndex + 1}.q-${questionIndex + 1}"

                        val repeatingGroup = Questionnaire.QuestionnaireItemComponent().apply {
                            linkId = repeatingGroupLinkId
                            type = Questionnaire.QuestionnaireItemType.GROUP
                            text = question.label
                            repeats =
                                true // This makes the *group* repeatable, allowing multiple instances of the set of questions
                            AppLogger.d("Checking child questions for repeating group '${this.linkId}'.")
                            if (question.questions.isNullOrEmpty()) {
                                AppLogger.w("Repeating group '${question.label}' (linkId: '${this.linkId}') has no child questions defined in its 'questions' property.")
                            } else {
                                AppLogger.d("Repeating group '${question.label}' (linkId: '${this.linkId}') found ${question.questions?.size} child questions.")
                                question.questions?.takeIf { it.isNotEmpty() }
                                    ?.forEachIndexed { childIndex, childQuestion ->
                                        // IMPORTANT: Call the extension function on 'this' (which refers to the 'repeatingGroup' instance)
                                        AppLogger.d("Attempting to add child question: '${childQuestion.label}' (index: $childIndex) to repeating group '${this.linkId}'.")
                                        this.addChildQuestionItem( // 'this' is the repeatingGroup object here
                                            question = childQuestion, childIndex = childIndex
                                        )
                                    }
                                AppLogger.d("Finished iterating and attempting to add children to repeating group '${this.linkId}'. Total children now stored in repeatingGroup.item: ${this.item.size}")
                            }
                        }
                        // Add the fully constructed repeatingGroup to its parent (e.g., pageGroup)
                        AppLogger.d("--- Finalizing Repeating Group Addition ---")
                        AppLogger.d("Adding repeating group '${repeatingGroup.linkId}' to its parent page group (linkId: '${pageGroup.linkId}')")
                        pageGroup.addItem(repeatingGroup)
                        AppLogger.d("Page group '${pageGroup.linkId}' now has ${pageGroup.item.size} direct items after adding repeating group.")
                    } else {
                        val questionItem = Questionnaire.QuestionnaireItemComponent().apply {
                            linkId =
                                "page-${pageIndex + 1}.section-${sectionIndex + 1}.q-${questionIndex + 1}"
                            type = FhirExtensions.mapFieldType(question.questionoptions.rendering)
                            text = question.label
                            required = question.required?.toBooleanStrictOrNull() ?: false
                            repeats = when (question.questionoptions.rendering) {
                                FieldType.MULTI_CHECKBOX -> true
                                else -> false
                            }

                            FhirExtensions.addItemControlExtension(
                                this, question.questionoptions.rendering
                            )

                            val conceptUuid =
                                question.questionoptions.concept?.takeIf { it.isNotBlank() }
                            if (conceptUuid != null) {
                                definition = "${BuildConfig.API_BASE_URL}concept#$conceptUuid"
                                addCode(
                                    Coding().apply {
                                        system = "${BuildConfig.API_BASE_URL}concept"
                                        code = conceptUuid
                                        display = question.label
                                    })
                                extension.add(
                                    Extension().apply {
                                        url = "${BuildConfig.API_BASE_URL}concept"
                                        setValue(UriType("${BuildConfig.API_BASE_URL}concept#$conceptUuid"))
                                    })
                                AppLogger.d("Mapped question '${question.label}' with concept: $conceptUuid")
                            } else {
                                AppLogger.w("Question '${question.id}' has no concept UUID. Skipping concept metadata.")
                            }

                            question.questionoptions.answers?.forEach { ans ->
                                ans.concept?.takeIf { it.isNotBlank() }?.let { ansConcept ->
                                    addAnswerOption(
                                        Questionnaire.QuestionnaireItemAnswerOptionComponent()
                                            .apply {
                                                value = Coding().apply {
                                                    system = "${BuildConfig.API_BASE_URL}concept"
                                                    code = ansConcept
                                                    display = ans.label
                                                }
                                            })
                                }
                                    ?: AppLogger.w("Answer '${ans.label}' for question '${question.id}' has no concept.")
                            }
                        }

                        pageGroup.addItem(questionItem)
                    }
                }
            }

            questionnaire.addItem(pageGroup)
        }

        return questionnaire
    }


    fun extractObsFromResponse(
        response: QuestionnaireResponse,
        questionnaireItems: List<Questionnaire.QuestionnaireItemComponent>,
        patientUuid: String,
        encounterDateTime: String = Instant.now().toString(),
    ): List<OpenmrsObs> {

        val obsList = mutableListOf<OpenmrsObs>()

        fun processItems(items: List<QuestionnaireResponse.QuestionnaireResponseItemComponent>) {
            for (item in items) {

                val matchingQuestionItem =
                    findQuestionnaireItemByLinkId(item.linkId, questionnaireItems)

                if (matchingQuestionItem == null) {
                    println("Warning: No matching Questionnaire item for linkId '${item.linkId}'. Skipping.")
                    if (item.hasItem()) processItems(item.item)
                    continue
                }

                // ✅ Resolve concept from Questionnaire definition, code or extension:
                val questionConceptIdentifier = matchingQuestionItem.code.firstOrNull()?.code
                    ?: matchingQuestionItem.extension.find {
                        it.url == "${BuildConfig.API_BASE_URL}concept"
                    }?.value?.primitiveValue()
                    ?: matchingQuestionItem.definition?.substringAfterLast("#")

                if (questionConceptIdentifier.isNullOrBlank()) {
                    println("Warning: Questionnaire item for linkId '${item.linkId}' has no concept. Skipping.")
                    if (item.hasItem()) processItems(item.item)
                    continue
                }

                if (item.hasAnswer()) {
                    item.answer.forEach { answer ->
                        val obsConcept: String
                        val obsValue: Any

                        when {
                            answer.hasValueCoding() -> {
                                val codedValueCode = answer.valueCoding.code
                                if (codedValueCode == null) {
                                    println("Warning: Coded answer for linkId '${item.linkId}' has null code. Skipping.")
                                    return@forEach
                                }
                                obsConcept = codedValueCode
                                obsValue = answer.valueCoding.display ?: codedValueCode
                            }
                            answer.hasValueStringType() -> {
                                obsConcept = questionConceptIdentifier
                                obsValue = answer.valueStringType.value
                            }
                            answer.hasValueDateType() -> {
                                obsConcept = questionConceptIdentifier
                                obsValue = answer.valueDateType.valueAsString
                            }
                            answer.hasValueIntegerType() -> {
                                obsConcept = questionConceptIdentifier
                                obsValue = answer.valueIntegerType.value
                            }
                            answer.hasValueDecimalType() -> {
                                obsConcept = questionConceptIdentifier
                                obsValue = answer.valueDecimalType.value
                            }
                            answer.hasValueBooleanType() -> {
                                obsConcept = questionConceptIdentifier
                                obsValue = answer.valueBooleanType.value
                            }
                            answer.hasValueDateTimeType() -> {
                                obsConcept = questionConceptIdentifier
                                obsValue = answer.valueDateTimeType.valueAsString
                            }
                            else -> {
                                println("Warning: Unsupported answer type for linkId '${item.linkId}'. Skipping.")
                                return@forEach
                            }
                        }

                        obsList.add(
                            OpenmrsObs(
                                person = patientUuid,
                                concept = obsConcept,
                                obsDatetime = encounterDateTime,
                                value = obsValue,
                            )
                        )
                    }
                }

                if (item.hasItem()) {
                    processItems(item.item)
                }
            }
        }

        processItems(response.item)

        return obsList
    }

    /**
     * Finds a Questionnaire item by linkId (recursive).
     */
    fun findQuestionnaireItemByLinkId(
        linkId: String,
        items: List<Questionnaire.QuestionnaireItemComponent>,
    ): Questionnaire.QuestionnaireItemComponent? {
        for (item in items) {
            if (item.linkId == linkId) {
                return item
            }
            val found = findQuestionnaireItemByLinkId(linkId, item.item)
            if (found != null) return found
        }
        return null
    }

    // Assuming this is your refactored extension function for adding children to a group
    fun Questionnaire.QuestionnaireItemComponent.addChildQuestionItem(
        question: Questions, // The data model for the child question
        childIndex: Int? = null,
    ) {
        // 'this' refers to the parent QuestionnaireItemComponent (e.g., the repeatingGroup)
        val parentLinkId = this.linkId
        AppLogger.d("addChildQuestionItem: Called on parent '${parentLinkId}' to add child '${question.label}' (index: $childIndex)")

        val childLinkId = buildString {
            append(parentLinkId) // Crucial: Start with the parent group's linkId
            if (childIndex != null) {
                append(".q-${childIndex + 1}") // Append a unique identifier for the child within this group
            } else {
                // Fallback for uniqueness if childIndex is not provided (should ideally be for children in a loop)
                AppLogger.w("addChildQuestionItem: childIndex is null for question '${question.id}'. Using question ID for linkId.")
                append(".${question.id}") // Use question ID for uniqueness
            }
        }

        val childItem = Questionnaire.QuestionnaireItemComponent().apply {
            this.linkId = childLinkId
            this.type = FhirExtensions.mapFieldType(question.questionoptions.rendering)
            this.text = question.label
            this.required = question.required?.toBooleanStrictOrNull() ?: false

            this.repeats = when (question.questionoptions.rendering) {
                FieldType.MULTI_CHECKBOX -> true // This applies to the child item itself
                else -> false
            }

            FhirExtensions.addItemControlExtension(
                this, question.questionoptions.rendering
            )

            val conceptUuid = question.questionoptions.concept?.takeIf { it.isNotBlank() }
            if (conceptUuid != null) {
                this.definition = "${BuildConfig.API_BASE_URL}concept#$conceptUuid"
                this.addCode(
                    Coding().apply {
                        system = "${BuildConfig.API_BASE_URL}concept"
                        code = conceptUuid
                        display = question.label
                    })
                this.extension.add(
                    Extension().apply {
                        url = "${BuildConfig.API_BASE_URL}concept"
                        setValue(UriType("${BuildConfig.API_BASE_URL}concept#$conceptUuid"))
                    })
                AppLogger.d("Mapped question '${question.label}' with concept: $conceptUuid to child linkId: $childLinkId")
            } else {
                AppLogger.w("Question '${question.id}' has no concept UUID. Skipping concept metadata for child linkId: $childLinkId.")
            }

            question.questionoptions.answers?.forEach { ans ->
                ans.concept?.takeIf { it.isNotBlank() }?.let { ansConcept ->
                    this.addAnswerOption(
                        Questionnaire.QuestionnaireItemAnswerOptionComponent().apply {
                            value = Coding().apply {
                                system = "${BuildConfig.API_BASE_URL}concept"
                                code = ansConcept
                                display = ans.label
                            }
                        })
                }
                    ?: AppLogger.w("Answer '${ans.label}' for question '${question.id}' has no concept for child linkId: $childLinkId.")
            }
        }

        // Crucial: Add the newly created childItem to the current receiver ('this'),
        // which is the parent group (e.g., repeatingGroup)
        this.addItem(childItem)
        AppLogger.d("-> Added child item '${childItem.linkId}' to parent '${this.linkId}'. Parent now has ${this.item.size} children.")
    }



}



