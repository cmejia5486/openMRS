package com.lyecdevelopers.form.utils

import org.hl7.fhir.r4.model.BooleanType
import org.hl7.fhir.r4.model.DateType
import org.hl7.fhir.r4.model.IntegerType
import org.hl7.fhir.r4.model.QuestionnaireResponse
import org.hl7.fhir.r4.model.StringType
import java.util.Date

object QuestionnaireUtils {
    fun updateResponseItem(
        response: QuestionnaireResponse,
        linkId: String,
        answer: Any?,
    ) {
        val item = response.item.find { it.linkId == linkId }
            ?: QuestionnaireResponse.QuestionnaireResponseItemComponent().apply {
                this.linkId = linkId
                response.addItem(this)
            }

        item.answer.clear()
        val newAnswer = QuestionnaireResponse.QuestionnaireResponseItemAnswerComponent()

        when (answer) {
            is String -> newAnswer.value = StringType(answer)
            is Boolean -> newAnswer.value = BooleanType(answer)
            is Int -> newAnswer.value = IntegerType(answer)
            is Date -> newAnswer.value = DateType(answer)
        }

        item.addAnswer(newAnswer)
    }
}
