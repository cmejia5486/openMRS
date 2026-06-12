package com.lyecdevelopers.core.common.scheduler

import kotlinx.coroutines.Dispatchers

class DefaultSchedulerProvider : SchedulerProvider {
    override val io = Dispatchers.IO
    override val computation = Dispatchers.Default
    override val main = Dispatchers.Main
}
