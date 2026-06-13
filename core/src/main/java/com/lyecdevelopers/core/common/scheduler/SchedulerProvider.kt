package com.lyecdevelopers.core.common.scheduler

import kotlinx.coroutines.CoroutineDispatcher

interface SchedulerProvider {
    val io: CoroutineDispatcher
    val computation: CoroutineDispatcher
    val main: CoroutineDispatcher
}
