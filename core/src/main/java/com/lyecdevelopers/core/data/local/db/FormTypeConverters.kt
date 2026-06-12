package com.lyecdevelopers.core.data.local.db

import androidx.room.TypeConverter
import com.lyecdevelopers.core.model.OpenmrsObs
import com.lyecdevelopers.core.model.encounter.Order
import com.lyecdevelopers.core.model.o3.Meta
import com.lyecdevelopers.core.model.o3.Pages
import com.lyecdevelopers.core.model.o3.Programs
import com.squareup.moshi.Moshi
import com.squareup.moshi.Types
import com.squareup.moshi.kotlin.reflect.KotlinJsonAdapterFactory

class FormTypeConverters {

    private val moshi: Moshi = Moshi.Builder().add(KotlinJsonAdapterFactory()).build()

    // ----- Meta -----
    @TypeConverter
    fun fromMeta(meta: Meta?): String? {
        return meta?.let { moshi.adapter(Meta::class.java).toJson(it) }
    }

    @TypeConverter
    fun toMeta(metaJson: String?): Meta? {
        return metaJson?.let { moshi.adapter(Meta::class.java).fromJson(it) }
    }

    // ----- List<Page> -----
    @TypeConverter
    fun fromPages(pages: List<Pages>?): String? {
        return pages?.let {
            val type = Types.newParameterizedType(List::class.java, Pages::class.java)
            moshi.adapter<List<Pages>>(type).toJson(it)
        }
    }

    @TypeConverter
    fun toPages(pagesJson: String?): List<Pages>? {
        return pagesJson?.let {
            val type = Types.newParameterizedType(List::class.java, Pages::class.java)
            moshi.adapter<List<Pages>>(type).fromJson(it)
        }
    }

    // ----- Programs -----
    @TypeConverter
    fun fromPrograms(programs: Programs?): String? {
        return programs?.let { moshi.adapter(Programs::class.java).toJson(it) }
    }

    @TypeConverter
    fun toPrograms(json: String?): Programs? {
        return json?.let { moshi.adapter(Programs::class.java).fromJson(it) }
    }

    // ----- List<OpenmrsObs> -----
    @TypeConverter
    fun fromObsList(obs: List<OpenmrsObs>?): String? {
        return obs?.let {
            val type = Types.newParameterizedType(List::class.java, OpenmrsObs::class.java)
            moshi.adapter<List<OpenmrsObs>>(type).toJson(it)
        }
    }

    @TypeConverter
    fun toObsList(obsJson: String?): List<OpenmrsObs>? {
        return obsJson?.let {
            val type = Types.newParameterizedType(List::class.java, OpenmrsObs::class.java)
            moshi.adapter<List<OpenmrsObs>>(type).fromJson(it)
        }
    }


    @TypeConverter
    fun fromOrder(order: Order?): String? {
        return order?.let { moshi.adapter(Order::class.java).toJson(it) }
    }

    @TypeConverter
    fun toOrder(json: String?): Order? {
        return json?.let { moshi.adapter(Order::class.java).fromJson(it) }
    }

    @TypeConverter
    fun fromOrderList(list: List<Order>?): String? {
        return list?.let {
            val type = Types.newParameterizedType(List::class.java, Order::class.java)
            moshi.adapter<List<Order>>(type).toJson(it)
        }
    }

    @TypeConverter
    fun toOrderList(json: String?): List<Order>? {
        return json?.let {
            val type = Types.newParameterizedType(List::class.java, Order::class.java)
            moshi.adapter<List<Order>>(type).fromJson(it)
        }
    }
}

