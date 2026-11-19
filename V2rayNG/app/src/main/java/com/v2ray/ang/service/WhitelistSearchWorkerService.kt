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
import java.util.concurrent.atomic.AtomicInteger

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

        // Профили делятся на две РАЗНЫЕ дорожки, потому что измеряются они
        // принципиально разными механизмами:
        //
        //   обычные (VLESS/VMess/SS/Trojan/WG/Hysteria2/MASQUE/CUSTOM и сайдкар-типы
        //   AmneziaWG/Naive/OpenConnect/Mimic) - временное ядро Xray в этом же
        //   процессе; их можно мерить параллельно, ограничение берётся из настроек
        //   клиента;
        //
        //   FPTN - изолированный network namespace с собственным fptn-client
        //   (FptnProbeRunner). Такая проба настраивает ОБЩИЕ для устройства ресурсы
        //   (ip rule с фиксированными приоритетами, правила в общих цепочках
        //   iptables, флаг ip_forward), поэтому двух одновременно работающих проб
        //   быть не может. Для FPTN параллельность принудительно равна ОДНОЙ и НЕ
        //   зависит от настройки пользователя: несколько FPTN-профилей в одной
        //   подписке измеряются строго по очереди.
        val normalGuids = ArrayList<String>()
        val fptnGuids = ArrayList<String>()
        for (guid in guids) {
            val cfgType = MmkvManager.decodeServerConfig(guid)?.configType
            if (cfgType != null && SidecarEngineManager.cannotMeasureInTempCore(cfgType)) {
                fptnGuids.add(guid)
            } else {
                normalGuids.add(guid)
            }
        }
        val fptnSet = fptnGuids.toHashSet()
        if (fptnGuids.isNotEmpty()) {
            onEvent(
                RealPingEvent.Progress(
                    "FPTN-профилей: ${fptnGuids.size} - измеряются строго по одному " +
                        "(изолированный netns), настройка параллельности к ним не применяется"
                )
            )
        }

        // Фаза 1: реальный пинг. Профили, у которых уже есть измеренная задержка
        // (например, от предыдущего обычного теста), берутся как есть; меряются
        // только неизмеренные.
        val pingResults = HashMap<String, Long>()
        runPingPhase(normalGuids, pingResults, "ping", parallel = true)
        if (!job.isActive) return
        runPingPhase(fptnGuids, pingResults, "ping FPTN", parallel = false)
        if (!job.isActive) return

        // Фаза 2: проба скорости по всем отозвавшимся профилям, лучшие по пингу
        // первыми. Раннего выхода нет намеренно: непроверенный профиль неотличим от
        // непроверяемого, и пользователь не мог понять, мерился ли он вообще.
        val candidates = pingResults.filterValues { it >= 0L }
            .entries.sortedBy { it.value }
            .map { it.key }
        // partition возвращает (удовлетворившие предикату, остальные):
        // first — FPTN (it in fptnSet), second — обычные. Прежняя
        // деструктуризация (normalCandidates, fptnCandidates) ПЕРЕПУТАЛА
        // дорожки: все обычные профили уходили в фазу «speed FPTN»
        // (надпись при сканировании любого протокола — жалоба владельца
        // 19.11 06:33), а FPTN — в параллельную «speed», что ещё и нарушало
        // инвариант «FPTN строго по одному» (общие ip rule/iptables).
        val (fptnCandidates, normalCandidates) = splitProbeLanes(candidates, fptnSet)

        runSpeedPhase(normalCandidates, "speed", parallel = true, probeSettings = probeSettings)
        if (!job.isActive) return
        runSpeedPhase(fptnCandidates, "speed FPTN", parallel = false, probeSettings = probeSettings)
    }

    /**
     * Фаза пинга для одной дорожки профилей.
     *
     * @param parallel true - несколько воркеров согласно настройке клиента;
     *   false - ровно один воркер (дорожка FPTN).
     *
     * Значение [RealPingMeasure.NOT_MEASURABLE] никогда не записывается в профиль:
     * иначе «Удалить недействительные» стёр бы рабочий профиль, который просто не
     * удалось измерить. Такой профиль и в кандидаты фазы 2 не попадает.
     */
    private suspend fun runPingPhase(
        targets: List<String>,
        pingResults: MutableMap<String, Long>,
        label: String,
        parallel: Boolean,
    ) {
        if (targets.isEmpty()) return

        val toPing = ArrayList<String>()
        for (guid in targets) {
            val existing = MmkvManager.decodeServerAffiliationInfo(guid)?.testDelayMillis ?: 0L
            if (existing == 0L) {
                toPing.add(guid)
            } else {
                synchronized(pingResults) { pingResults[guid] = existing }
            }
        }
        if (toPing.isEmpty()) return

        val workers = if (parallel) {
            minOf(toPing.size, concurrency).coerceAtLeast(1)
        } else {
            1
        }
        val next = AtomicInteger(0)
        val done = AtomicInteger(0)
        onEvent(RealPingEvent.Progress("$label 0/${toPing.size}"))

        val jobs = (0 until workers).map {
            scope.launch {
                while (job.isActive) {
                    val index = next.getAndIncrement()
                    if (index >= toPing.size) break
                    val guid = toPing[index]
                    val ping = RealPingMeasure.measure(guid)
                    if (ping == RealPingMeasure.NOT_MEASURABLE) {
                        if (job.isActive) {
                            onEvent(RealPingEvent.Progress("$label ${done.incrementAndGet()}/${toPing.size}"))
                        }
                        continue
                    }
                    synchronized(pingResults) { pingResults[guid] = ping }
                    MmkvManager.encodeServerTestDelayMillis(guid, ping)
                    if (job.isActive) {
                        onEvent(RealPingEvent.Result(guid, ping))
                        onEvent(RealPingEvent.Progress("$label ${done.incrementAndGet()}/${toPing.size}"))
                    }
                }
            }
        }
        joinAll(*jobs.toTypedArray())
    }

    /**
     * Фаза пробы скорости для одной дорожки профилей.
     *
     * @param parallel true - пул воркеров с жёстким потолком
     *   [SPEED_PROBE_MAX_PARALLEL]: каждая проба поднимает полноценное ядро Xray, и
     *   слишком много живых ядер одновременно убивают процесс демона по памяти.
     *   false - ровно один воркер (дорожка FPTN).
     */
    private suspend fun runSpeedPhase(
        candidates: List<String>,
        label: String,
        parallel: Boolean,
        probeSettings: WhitelistSpeedTester.Settings,
    ) {
        if (candidates.isEmpty()) return

        val workers = if (parallel) {
            minOf(candidates.size, concurrency, SPEED_PROBE_MAX_PARALLEL).coerceAtLeast(1)
        } else {
            1
        }
        val next = AtomicInteger(0)
        val done = AtomicInteger(0)
        onEvent(RealPingEvent.Progress("$label 0/${candidates.size}"))

        val jobs = (0 until workers).map {
            scope.launch {
                while (job.isActive) {
                    val index = next.getAndIncrement()
                    if (index >= candidates.size) break
                    val guid = candidates[index]
                    // Измеренный пинг не затирается: профиль за шейпингом сохраняет
                    // зелёные цифры задержки и помечается только результатом скорости.
                    val cfgType = MmkvManager.decodeServerConfig(guid)?.configType
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
                        onEvent(RealPingEvent.Progress("$label ${done.incrementAndGet()}/${candidates.size}"))
                    }
                }
            }
        }
        joinAll(*jobs.toTypedArray())
    }

    companion object {
        /** Live-core ceiling for the download stage regardless of user concurrency. */
        private const val SPEED_PROBE_MAX_PARALLEL = 8

        /**
         * Разделение кандидатов фазы скорости на дорожки: (FPTN, обычные).
         *
         * Чистая функция — доказывается JVM-тестом. Дефект 19.11 06:33:
         * деструктуризация partition была перевёрнута, и ВСЕ обычные профили
         * попадали в фазу «speed FPTN» (надпись при любом протоколе), а FPTN —
         * в параллельную «speed» (нарушение инварианта «строго по одному»).
         * Порядок пары зафиксирован здесь один раз, чтобы вызов не мог его
         * перепутать молча.
         */
        internal fun splitProbeLanes(
            candidates: List<String>,
            fptnGuids: Set<String>,
        ): Pair<List<String>, List<String>> {
            val fptn = ArrayList<String>()
            val normal = ArrayList<String>()
            for (guid in candidates) {
                if (guid in fptnGuids) fptn.add(guid) else normal.add(guid)
            }
            return fptn to normal
        }
    }
}
