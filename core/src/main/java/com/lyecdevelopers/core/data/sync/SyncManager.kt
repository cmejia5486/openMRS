package com.lyecdevelopers.core.data.sync

import android.content.Context
import androidx.work.Constraints
import androidx.work.ExistingPeriodicWorkPolicy
import androidx.work.ListenableWorker
import androidx.work.NetworkType
import androidx.work.OneTimeWorkRequest
import androidx.work.PeriodicWorkRequest
import androidx.work.WorkManager
import dagger.hilt.android.qualifiers.ApplicationContext
import java.util.concurrent.TimeUnit
import javax.inject.Inject
import kotlin.reflect.KClass


class SyncManager @Inject constructor(
    @ApplicationContext private val context: Context,
) {

    fun syncNow(workers: List<KClass<out ListenableWorker>>) {
        val constraints =
            Constraints.Builder().setRequiredNetworkType(NetworkType.CONNECTED).build()

        if (workers.isEmpty()) return

        val first =
            OneTimeWorkRequest.Builder(workers.first().java).setConstraints(constraints).build()

        var chain = WorkManager.getInstance(context).beginWith(first)

        workers.drop(1).forEach { workerClass ->
            val next =
                OneTimeWorkRequest.Builder(workerClass.java).setConstraints(constraints).build()
            chain = chain.then(next)
        }

        chain.enqueue()
    }

    fun schedulePeriodicSync(
        workers: List<KClass<out ListenableWorker>>,
        intervalHours: Long,
    ) {
        val constraints = Constraints.Builder().setRequiredNetworkType(NetworkType.UNMETERED)
            .setRequiresCharging(true).build()

        workers.forEach { workerClass ->
            val request =
                PeriodicWorkRequest.Builder(workerClass.java, intervalHours, TimeUnit.HOURS)
                    .setConstraints(constraints).build()

            WorkManager.getInstance(context).enqueueUniquePeriodicWork(
                "${workerClass.simpleName}_PeriodicSync", ExistingPeriodicWorkPolicy.UPDATE, request
            )
        }
    }

    fun cancelPeriodicSync(workers: List<KClass<out ListenableWorker>>) {
        workers.forEach { workerClass ->
            WorkManager.getInstance(context)
                .cancelUniqueWork("${workerClass.simpleName}_PeriodicSync")
        }
    }
}



