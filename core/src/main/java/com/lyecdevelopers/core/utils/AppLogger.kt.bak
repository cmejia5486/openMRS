package com.lyecdevelopers.core.utils

import android.util.Log
import com.google.firebase.crashlytics.FirebaseCrashlytics
import com.lyecdevelopers.core.BuildConfig
import timber.log.Timber

object AppLogger {

    fun init() {
        if (BuildConfig.DEBUG) {
            Timber.plant(Timber.DebugTree())
        } else {
            Timber.plant(CrashReportingTree())
        }
    }

    fun d(message: String, vararg args: Any?) {
        Timber.d(message, *args)
    }

    fun d(throwable: Throwable, message: String, vararg args: Any?) {
        Timber.d(throwable, message, *args)
    }

    fun i(message: String, vararg args: Any?) {
        Timber.i(message, *args)
    }

    fun i(throwable: Throwable, message: String, vararg args: Any?) {
        Timber.i(throwable, message, *args)
    }

    fun w(message: String, vararg args: Any?) {
        Timber.w(message, *args)
    }

    fun w(throwable: Throwable, message: String, vararg args: Any?) {
        Timber.w(throwable, message, *args)
    }

    fun e(message: String, vararg args: Any?) {
        Timber.e(message, *args)
    }

    fun e(throwable: Throwable, message: String, vararg args: Any?) {
        Timber.e(throwable, message, *args)
    }

    private class CrashReportingTree : Timber.Tree() {
        override fun log(priority: Int, tag: String?, message: String, t: Throwable?) {
            if (priority == Log.VERBOSE || priority == Log.DEBUG || priority == Log.INFO) return

            val crashlytics = FirebaseCrashlytics.getInstance()
            crashlytics.log(message)

            if (t != null && priority == Log.ERROR) {
                crashlytics.recordException(t)
            }
        }
    }
}
