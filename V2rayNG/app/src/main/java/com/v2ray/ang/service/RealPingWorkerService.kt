package com.v2ray.ang.service

import android.content.Context
import com.v2ray.ang.AngApplication
import com.v2ray.ang.core.CoreConfigManager
import com.v2ray.ang.core.CoreNativeManager
import com.v2ray.ang.core.FptnProbeRunner
import com.v2ray.ang.core.SidecarEngineManager
import com.v2ray.ang.AppConfig
import com.v2ray.ang.dto.RealPingEvent
import com.v2ray.ang.dto.entities.ProfileItem
import com.v2ray.ang.enums.EConfigType
import com.v2ray.ang.extension.isComplexType
import com.v2ray.ang.extension.isNotNullEmpty
import com.v2ray.ang.handler.MmkvManager
import com.v2ray.ang.handler.SettingsManager
import com.v2ray.ang.handler.SpeedtestManager
import com.v2ray.ang.util.LogUtil
import kotlinx.coroutines.CancellationException
import kotlinx.coroutines.Job
import kotlinx.coroutines.CoroutineName
import kotlinx.coroutines.CoroutineScope
import kotlinx.coroutines.SupervisorJob
import kotlinx.coroutines.asCoroutineDispatcher
import kotlinx.coroutines.isActive
import kotlinx.coroutines.joinAll
import kotlinx.coroutines.launch
import kotlinx.coroutines.sync.Mutex
import kotlinx.coroutines.sync.withLock
import java.util.concurrent.Executors
import java.util.concurrent.atomic.AtomicInteger

internal object RealPingExecutionLimiter {
    private val customConfigMutex = Mutex()

    suspend fun <T> run(configType: EConfigType, block: () -> T): T {
        // Custom profiles bypass speed-test trimming and start complete Xray configs.
        // Parallel teardown can abort the native probe process, so serialize their
        // JNI measurements globally across batches.
        //
        // Сайдкар-профили сериализуются отдельно - общей блокировкой
        // SidecarEngineManager.probeLock, потому что им нужна монопольность
        // не только относительно других пингов, но и относительно пробы скорости.
        return if (configType == EConfigType.CUSTOM) {
            customConfigMutex.withLock { block() }
        } else {
            block()
        }
    }
}

/**
 * Shared real-ping implementation: TCP pre-check when applicable, then a full
 * HTTP delay measurement through a temporary Xray instance for the profile.
 * Used by the regular batch tester and by the whitelist search.
 */
internal object RealPingMeasure {
    /**
     * Значение-признак «измерить этот профиль технически невозможно».
     *
     * Отличается от [FAIL] принципиально: FAIL означает «профиль не отвечает» и
     * legitimately используется функциями «Удалить недействительные», а
     * [NOT_MEASURABLE] означает «мы не смогли измерить», и записывать его нельзя -
     * иначе рабочий профиль был бы удалён как недействительный.
     */
    const val NOT_MEASURABLE = Long.MIN_VALUE

    /** Профиль не ответил: честный отрицательный результат измерения. */
    const val FAIL = -1L

    suspend fun measure(guid: String): Long {
        val retFailure = FAIL

        val config = MmkvManager.decodeServerConfig(guid) ?: return retFailure

        // Профили, для которых временное ядро Xray построить невозможно (сейчас это
        // FPTN: fptn-client владеет собственным TUN, Xray-конфига для него нет),
        // измеряются в ИЗОЛИРОВАННОМ network namespace через FptnProbeRunner.
        // Иначе пришлось бы либо вернуть фиктивное значение (тогда «Удалить
        // недействительные» стёр бы рабочий профиль), либо оставить профиль
        // неизмеренным. Здесь используется тот же тестовый URL из настроек клиента,
        // что и для остальных профилей.
        if (SidecarEngineManager.cannotMeasureInTempCore(config.configType)) {
            val probeDelay = FptnProbeRunner.measureDelayMs(
                AngApplication.application,
                config,
                SettingsManager.getDelayTestUrl(),
            )
            if (probeDelay >= 0L) {
                return probeDelay
            }
            // Измерить не удалось (нет root, нет токена, туннель не поднялся).
            // Возвращаем NOT_MEASURABLE, а не FAIL: значение не запишется, и профиль
            // не будет удалён как недействительный.
            LogUtil.w(
                AppConfig.TAG,
                "RealPing: профиль ${config.configType} не удалось измерить, значение не изменяется"
            )
            return NOT_MEASURABLE
        }

        if (!config.configType.isComplexType()
            && tcpProbeApplicable(config)
        ) {
            val url = config.server.orEmpty()
            val port = config.serverPort.orEmpty().toInt()
            val tcpTime = SpeedtestManager.socketConnectTime(url, port, 1000)
            if (tcpTime <= -1L) {
                return retFailure
            }
        }

        // Профили на сайдкар-движках требуют, чтобы движок был поднят В ЭТОМ ЖЕ
        // процессе: SidecarEngineManager - объект, у процесса :tasks свой экземпляр
        // с currentPort == 0, и построение конфига падало бы с
        // «Sidecar engine is not running». Без этого профиль получал фиктивную
        // задержку -1, а «Удалить недействительные» затем стирал рабочий профиль.
        //
        // Всё, что касается движка (подъём -> построение конфига -> замер ->
        // остановка), сериализовано через RealPingExecutionLimiter: currentPort
        // в процессе один, параллельные пробы перезаписали бы его друг у друга.
        val context = AngApplication.application
        val needsEngine = SidecarEngineManager.needsProbeEngine(config.configType)
        // Блокировка ОБЯЗАНА быть той же, что у пробы скорости
        // (SidecarEngineManager.probeLock): обычный тест задержки и «поиск
        // стабильных профилей» могут идти одновременно, а currentPort на процесс
        // один. Отдельный Mutex здесь не дал бы взаимного исключения с
        // synchronized-блокировкой пробы скорости.
        return RealPingExecutionLimiter.run(config.configType) {
            SidecarEngineManager.runExclusiveProbe {
                if (needsEngine && !SidecarEngineManager.acquireForProbe(context, config, guid)) {
                    LogUtil.e(AppConfig.TAG, "RealPing: sidecar engine unavailable for profile $guid")
                    return@runExclusiveProbe retFailure
                }
                try {
                    val configResult = CoreConfigManager.getV2rayConfig4Speedtest(context, guid)
                    if (!configResult.status) {
                        return@runExclusiveProbe retFailure
                    }
                    CoreNativeManager.measureOutboundDelay(
                        configResult.content,
                        SettingsManager.getDelayTestUrl(),
                    )
                } finally {
                    if (needsEngine) {
                        try {
                            SidecarEngineManager.releaseAfterProbe()
                        } catch (e: Exception) {
                            LogUtil.w(AppConfig.TAG, "RealPing: failed to stop probe engine: ${e.message}")
                        }
                    }
                }
            }
        }
    }
}

/**
 * Worker that runs a batch of real-ping tests independently.
 * Each batch owns its own CoroutineScope/dispatcher and can be cancelled separately.
 */
class RealPingWorkerService(
    private val context: Context,
    private val guids: List<String>,
    private val onlyTcp: Boolean = false,
    private val onlyIcmp: Boolean = false,
    private val onEvent: (RealPingEvent) -> Unit = {}
) {
    private val job = SupervisorJob()
    private val concurrency = SettingsManager.getRealPingConcurrency()
    private val dispatcher = Executors.newFixedThreadPool(if (onlyTcp || onlyIcmp) concurrency * 2 else concurrency).asCoroutineDispatcher()
    private val scope = CoroutineScope(job + dispatcher + CoroutineName("RealPingBatchWorker"))

    /**
     * Отдельный ОДНОПОТОЧНЫЙ исполнитель для профилей FPTN.
     *
     * Проба FPTN выполняется в изолированном netns и физически не может идти
     * параллельно с другой пробой FPTN (FptnProbeRunner.probeLock). Если запускать
     * её в общем пуле, то при нескольких FPTN-профилях в подписке они заняли бы все
     * потоки пула и заблокировали измерение остальных профилей: каждый поток стоял
     * бы в очереди за блокировкой. Отдельный поток с последовательной обработкой
     * решает обе проблемы - FPTN мерится по одному, а общий пул остаётся свободным.
     */
    private val fptnDispatcher = Executors.newSingleThreadExecutor().asCoroutineDispatcher()
    private val fptnScope = CoroutineScope(job + fptnDispatcher + CoroutineName("RealPingFptnWorker"))

    private val runningCount = AtomicInteger(0)
    private val totalCount = AtomicInteger(0)

    fun start() {
        // Профили FPTN уходят в отдельную последовательную дорожку (см. fptnScope).
        val fptnGuids = ArrayList<String>()
        val normalGuids = ArrayList<String>()
        if (onlyTcp || onlyIcmp) {
            // tcping/icmping измеряют только доступность сервера и не поднимают
            // туннель, поэтому разделение не требуется.
            normalGuids.addAll(guids)
        } else {
            for (guid in guids) {
                val type = MmkvManager.decodeServerConfig(guid)?.configType
                if (type != null && SidecarEngineManager.cannotMeasureInTempCore(type)) {
                    fptnGuids.add(guid)
                } else {
                    normalGuids.add(guid)
                }
            }
        }

        val jobs = ArrayList<Job>(guids.size + 1)
        jobs += normalGuids.map { guid ->
            totalCount.incrementAndGet()
            scope.launch {
                runningCount.incrementAndGet()
                try {
                    val result = if (onlyTcp) startTcping(guid) else if (onlyIcmp) startIcmping(guid) else startRealPing(guid)
                    if (scope.isActive) {
                        // NOT_MEASURABLE не отправляем как результат: обработчик
                        // записал бы его в testDelayMillis, а «Удалить
                        // недействительные» удаляет профили с задержкой < 0 -
                        // то есть рабочий профиль был бы стёрт.
                        if (result == RealPingMeasure.NOT_MEASURABLE) {
                            onEvent(
                                RealPingEvent.Progress(
                                    "профиль не измеряется временным ядром, значение сохранено без изменений"
                                )
                            )
                        } else {
                            onEvent(RealPingEvent.Result(guid, result))
                        }
                    }
                } catch (_: Throwable) {
                    // ignore
                } finally {
                    val count = totalCount.decrementAndGet()
                    val left = runningCount.decrementAndGet()
                    if (scope.isActive) {
                        onEvent(RealPingEvent.Progress("$left / $count"))
                    }
                }
            }
        }

        if (fptnGuids.isNotEmpty()) {
            totalCount.addAndGet(fptnGuids.size)
            // Одна корутина на все FPTN-профили: они измеряются строго по очереди.
            jobs += fptnScope.launch {
                for (guid in fptnGuids) {
                    if (!isActive) break
                    runningCount.incrementAndGet()
                    try {
                        val result = RealPingMeasure.measure(guid)
                        if (isActive) {
                            if (result == RealPingMeasure.NOT_MEASURABLE) {
                                onEvent(
                                    RealPingEvent.Progress(
                                        "профиль FPTN не удалось измерить, значение сохранено без изменений"
                                    )
                                )
                            } else {
                                onEvent(RealPingEvent.Result(guid, result))
                            }
                        }
                    } catch (_: Throwable) {
                        // ignore
                    } finally {
                        val count = totalCount.decrementAndGet()
                        val left = runningCount.decrementAndGet()
                        if (isActive) {
                            onEvent(RealPingEvent.Progress("$left / $count"))
                        }
                    }
                }
            }
        }

        scope.launch {
            try {
                joinAll(*jobs.toTypedArray())
                if (isActive) {
                    onEvent(RealPingEvent.Finish("0"))
                }
            } catch (_: CancellationException) {
                // If cancelled, don't send finish event to avoid confusion
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
            // ignore
        }
        try {
            fptnDispatcher.close()
        } catch (_: Throwable) {
            // ignore
        }
    }

    private suspend fun startRealPing(guid: String): Long {
        return RealPingMeasure.measure(guid)
    }

    companion object {
        /**
         * Применима ли TCP-проба (TCPing) к профилю. QUIC-протоколы
         * (Hysteria2, Hysteria v1) и WireGuard слушают UDP: TCP-рукопожатие
         * к их порту дало бы ложный -1/таймаут вместо честного «не применимо»,
         * а профили с alpn h3 идут QUIC даже поверх TCP-подобных схем.
         */
        internal fun tcpProbeApplicable(config: ProfileItem): Boolean =
            config.configType != EConfigType.HYSTERIA2 &&
                config.configType != EConfigType.HYSTERIA &&
                config.configType != EConfigType.WIREGUARD &&
                config.alpn?.split(',')?.all { it.trim().startsWith("h3") } != true &&
                config.server.isNotNullEmpty() &&
                config.serverPort?.toIntOrNull() != null
    }

    private fun startTcping(guid: String): Long {
        val retFailure = -1L

        val config = MmkvManager.decodeServerConfig(guid) ?: return retFailure
        if (!config.configType.isComplexType()
            && tcpProbeApplicable(config)
        ) {
            val url = config.server.orEmpty()
            val port = config.serverPort.orEmpty().toInt()
            val tcpTime = SpeedtestManager.socketConnectTime(url, port, 1000)

            return tcpTime
        }

        return retFailure
    }

    private fun startIcmping(guid: String): Long {
        val retFailure = -1L
        val config = MmkvManager.decodeServerConfig(guid) ?: return retFailure
        val url = config.server ?: config.getServerAddressAndPort().substringBefore(":")
        if (url.isNotEmpty() && url != AppConfig.LOOPBACK) {
            return SpeedtestManager.icmpConnectTime(url, 1000)
        }
        return retFailure
    }
}
