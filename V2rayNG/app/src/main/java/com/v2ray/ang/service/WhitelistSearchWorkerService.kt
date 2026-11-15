package com.v2ray.ang.service

import android.content.Context
import com.v2ray.ang.core.SidecarEngineManager
import com.v2ray.ang.core.WhitelistSpeedTester
import com.v2ray.ang.dto.RealPingEvent
import com.v2ray.ang.enums.EConfigType
import com.v2ray.ang.handler.MmkvManager
import com.v2ray.ang.handler.SettingsManager
import kotlinx.coroutines.CancellationException
import kotlinx.coroutines.CoroutineName
import kotlinx.coroutines.CoroutineScope
import kotlinx.coroutines.SupervisorJob
import kotlinx.coroutines.asCoroutineDispatcher
import kotlinx.coroutines.joinAll
import kotlinx.coroutines.launch
import java.util.concurrent.Executors

/**
 * Two-phase "whitelist" profile search.
 *
 * Phase 1: real ping every profile in parallel (full HTTP delay through a
 * temporary core, same as the regular delay test) to drop dead ones fast.
 * Phase 2: speed-probe the best candidates sequentially (one temp core at a
 * time), best ping first, until the target number of stable profiles is found.
 *
 * Profiles behind "type 2" whitelists answer pings but cannot sustain a
 * download, so only the download phase separates them from usable profiles.
 */
class WhitelistSearchWorkerService(
    private val context: Context,
    private val guids: List<String>,
    private val onEvent: (RealPingEvent) -> Unit = {}
) {
    private val job = SupervisorJob()
    private val concurrency = SettingsManager.getRealPingConcurrency()
    private val dispatcher = Executors.newFixedThreadPool(concurrency)
        .asCoroutineDispatcher()
    private val scope = CoroutineScope(job + dispatcher + CoroutineName("WhitelistSearchWorker"))

    fun start() {
        scope.launch {
            try {
                runSearch()
                if (job.isActive) onEvent(RealPingEvent.Finish("0"))
            } catch (_: CancellationException) {
                // cancelled, no finish event
            } catch (e: Exception) {
                if (job.isActive) onEvent(RealPingEvent.Finish(e.message ?: "error"))
            } finally {
                close()
            }
        }
    }

    fun cancel() {
        job.cancel()
    }

    private fun close() {
        try {
            dispatcher.close()
        } catch (_: Throwable) {
        }
    }

    private suspend fun runSearch() {
        val probeSettings = WhitelistSpeedTester.Settings(
            downloadSizeMb = SettingsManager.getWlDownloadSizeMb(),
            downloadTimeoutSeconds = SettingsManager.getWlDownloadTimeoutSeconds(),
            downloadAttempts = SettingsManager.getWlDownloadAttempts(),
        )

        // Фаза 1: реальный пинг. Профили, у которых уже есть измеренная задержка
        // (например, от предыдущего обычного теста), берутся как есть; меряются
        // только неизмеренные.
        //
        // Профили FPTN ИСКЛЮЧАЮТСЯ из обеих фаз, а не получают фиктивное значение.
        // Причина: для FPTN Xray-конфиг не строится вовсе (fptn-client владеет
        // собственным TUN), поэтому временного ядра для пробы не существует.
        // Прежний код писал в этом случае -1 в testDelayMillis, а «Удалить
        // недействительные» удаляет профили с задержкой < 0 - то есть пользователь
        // терял рабочий профиль форка.
        //
        // Сайдкар-профили (AmneziaWG, NaiveProxy, OpenConnect, Mimic) здесь НЕ
        // пропускаются: они измеряются честно, потому что RealPingMeasure и
        // WhitelistSpeedTester теперь поднимают нужный движок локально в процессе
        // пробы (SidecarEngineManager.acquireForProbe).
        val pingResults = HashMap<String, Long>()
        val toPing = ArrayList<String>()
        val skippedSidecar = ArrayList<String>()
        for (guid in guids) {
            val cfgType = MmkvManager.decodeServerConfig(guid)?.configType
            if (cfgType != null && SidecarEngineManager.cannotMeasureInTempCore(cfgType)) {
                // Не трогаем ни задержку, ни скорость профиля: измерение невозможно,
                // а записывать фиктивное значение опасно (см. выше).
                skippedSidecar.add("${cfgType.name}")
                continue
            }
            val existing = MmkvManager.decodeServerAffiliationInfo(guid)?.testDelayMillis ?: 0L
            if (existing == 0L) toPing.add(guid) else pingResults[guid] = existing
        }
        if (skippedSidecar.isNotEmpty()) {
            onEvent(
                RealPingEvent.Progress(
                    "Пропущено профилей на сайдкар-движках: ${skippedSidecar.size} " +
                        "(${skippedSidecar.distinct().joinToString()}) - " +
                        "их нельзя измерить временным ядром, значения не менялись"
                )
            )
        }

        if (toPing.isNotEmpty()) {
            onEvent(RealPingEvent.Progress("ping 0/${toPing.size}"))
            val done = java.util.concurrent.atomic.AtomicInteger(0)
            val jobs = toPing.map { guid ->
                scope.launch {
                    val ping = RealPingMeasure.measure(guid)
                    if (ping == RealPingMeasure.NOT_MEASURABLE) {
                        // Профиль нельзя измерить временным ядром (FPTN). НЕ
                        // записываем значение и НЕ добавляем профиль в кандидаты:
                        // иначе «Удалить недействительные» стёр бы рабочий профиль.
                        if (job.isActive) {
                            val n = done.incrementAndGet()
                            onEvent(RealPingEvent.Progress("ping $n/${toPing.size}"))
                        }
                        return@launch
                    }
                    synchronized(pingResults) {
                        pingResults[guid] = ping
                    }
                    MmkvManager.encodeServerTestDelayMillis(guid, ping)
                    if (job.isActive) {
                        onEvent(RealPingEvent.Result(guid, ping))
                        val n = done.incrementAndGet()
                        onEvent(RealPingEvent.Progress("ping $n/${toPing.size}"))
                    }
                }
            }
            joinAll(*jobs.toTypedArray())
        }
        if (!job.isActive) return

        // Phase 2: speed-probe every responsive profile, best ping first, in
        // parallel using the same concurrency setting as the ping phase.
        // No early exit: leaving profiles unlabeled made it impossible to tell
        // whether they were ever speed-checked.
        val candidates = pingResults.filterValues { it >= 0L }
            .entries.sortedBy { it.value }
            .map { it.key }

        if (candidates.isNotEmpty()) {
            onEvent(RealPingEvent.Progress("speed 0/${candidates.size}"))
            val next = java.util.concurrent.atomic.AtomicInteger(0)
            val done = java.util.concurrent.atomic.AtomicInteger(0)
            // Every probe spins up a full Xray core; too many live cores at once
            // pressure-kill the VPN daemon process, so cap this phase hard.
            val workers = minOf(candidates.size, concurrency, SPEED_PROBE_MAX_PARALLEL).coerceAtLeast(1)
            val probeJobs = (0 until workers).map {
                scope.launch {
                    while (job.isActive) {
                        val index = next.getAndIncrement()
                        if (index >= candidates.size) break
                        val guid = candidates[index]
                        // The measured ping stays untouched: a shaped profile keeps its green
                        // delay numbers and is flagged only through its speed result.
                        val cfgType = MmkvManager.decodeServerConfig(guid)?.configType

                        // Профили FPTN нельзя мерить временным ядром (Xray для них
                        // не используется). Прежний код записывал в этом случае 0 в
                        // скорость, а «Удалить нулевые» затем УДАЛЯЛ такой профиль -
                        // то есть рабочая функция теряла данные пользователя.
                        // Честно пропускаем: измерения не трогаем, сообщаем причину.
                        // Сайдкар-профили (AmneziaWG/Naive/OpenConnect/Mimic)
                        // измеряются: движок поднимается локально в WhitelistSpeedTester.
                        if (cfgType != null && SidecarEngineManager.cannotMeasureInTempCore(cfgType)) {
                            if (job.isActive) {
                                onEvent(
                                    RealPingEvent.Progress(
                                        "speed: ${cfgType.name} не измеряется временным ядром, " +
                                            "профиль пропущен без изменения значений"
                                    )
                                )
                                onEvent(RealPingEvent.Progress("speed ${done.incrementAndGet()}/${candidates.size}"))
                            }
                            continue
                        }

                        val outcome = if (cfgType == EConfigType.CUSTOM) {
                            RealPingExecutionLimiter.run(EConfigType.CUSTOM) {
                                WhitelistSpeedTester.measureProfileSpeed(guid, probeSettings)
                            }
                        } else {
                            WhitelistSpeedTester.measureProfileSpeed(guid, probeSettings)
                        }
                        MmkvManager.encodeServerTestSpeedBytesPerSec(guid, outcome.first, outcome.second)
                        if (job.isActive) {
                            onEvent(RealPingEvent.SpeedResult(guid, outcome.first, outcome.second))
                            onEvent(RealPingEvent.Progress("speed ${done.incrementAndGet()}/${candidates.size}"))
                        }
                    }
                }
            }
            joinAll(*probeJobs.toTypedArray())
        }
    }

    companion object {
        /** Live-core ceiling for the download stage regardless of user concurrency. */
        private const val SPEED_PROBE_MAX_PARALLEL = 8
    }
}
