package com.lyecdevelopers.core.data.remote

import com.lyecdevelopers.core.model.FormsListResponse
import com.lyecdevelopers.core.model.IdentifierListResponse
import com.lyecdevelopers.core.model.PersonAttributeTypeListResponse
import com.lyecdevelopers.core.model.cohort.CohortListResponse
import com.lyecdevelopers.core.model.cohort.DataDefinition
import com.lyecdevelopers.core.model.encounter.EncounterTypeListResponse
import com.lyecdevelopers.core.model.o3.o3Form
import com.lyecdevelopers.core.model.order.OrderTypeListResponse
import okhttp3.RequestBody
import okhttp3.ResponseBody
import retrofit2.Response
import retrofit2.http.Body
import retrofit2.http.GET
import retrofit2.http.POST
import retrofit2.http.PUT
import retrofit2.http.Path
import retrofit2.http.Query


interface FormApi {
    // form
    @GET("rest/v1/form")
    suspend fun getForms(
        @Query("v") view: String = "full",
    ): Response<FormsListResponse>

    @GET("rest/v1/o3/forms/{formId}")
    suspend fun loadFormByUuid(
        @Path("formId") formId: String,
        @Query("v") view: String = "full",
    ): Response<o3Form>

    @GET("rest/v1/form")
    suspend fun filterForms(
        @Query("q") query: String,
        @Query("v") view: String = "full",
    ): Response<FormsListResponse>

    @GET("rest/v1/o3/forms/{formId}")
    suspend fun getFormByUuid(@Path("formId") formId: String): Response<o3Form>

    // cohort
    @GET("rest/v1/cohort")
    suspend fun getCohorts(@Query("v") view: String = "full"): Response<CohortListResponse>

    // orders
    @GET("rest/v1/ordertype")
    suspend fun getOrderTypes(): Response<OrderTypeListResponse>

    // encounters
    @GET("rest/v1/encountertype")
    suspend fun getEncounterTypes(): Response<EncounterTypeListResponse>

    // patientIdentifiers
    @GET("rest/v1/patientidentifiertype")
    suspend fun getPatientIdentifiers(): Response<IdentifierListResponse>

    // personattributetype
    @GET("rest/v1/personattributetype")
    suspend fun getPersonAttributeTypes(): Response<PersonAttributeTypeListResponse>

    // conditions
    @GET("rest/v1/ugandaemrreports/concepts/conditions")
    suspend fun getConditions(): Response<Any>

    // data definition
    @POST("rest/v1/ugandaemrreports/dataDefinition")
    suspend fun generateDataDefinition(
        @Body payload: DataDefinition,
    ): Response<ResponseBody>


    // save encounter
    @POST("rest/v1/encounter")
    suspend fun saveEncounter(@Body payload: Any): Response<Any>

    @PUT("fhir2/R4/Patient/{uuid}")
    suspend fun savePatient(
        @Path("uuid") patientId: String,
        @Body patient: RequestBody,
    ): Response<Unit>

}
