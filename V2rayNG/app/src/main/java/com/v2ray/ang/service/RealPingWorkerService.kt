package com.v2ray.ang.service

import android.content.Context
import com.v2ray.ang.AngApplication
import com.v2ray.ang.core.CoreConfigManager
import com.v2ray.ang.core.CoreNativeManager
import com.v2ray.ang.core.SidecarEngineManager
import com.v2ray.ang.AppConfig
import com.v2ray.ang.dto.RealPingEvent
import com.v2ray.ang.enums.EConfigType
import com.v2ray.ang.extension.isComplexType
import com.v2ray.ang.extension.isNotNullEmpty
import com.v2ray.ang.handler.MmkvManager
import com.v2ray.ang.handler.SettingsManager
import com.v2ray.ang.handler.SpeedtestManager
import com.v2ray.ang.util.LogUtil
import kotlinx.coroutines.CancellationException
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
        if (!config.configType.isComplexType()
            && config.configType != EConfigType.HYSTERIA2
            && config.configType != EConfigType.WIREGUARD
            && config.alpn?.startsWith("h3") != true
            && config.server.isNotNullEmpty()
            && config.serverPort?.toIntOrNull() != null
        ) {
            val url = config.server.orEmpty()
            val port = config.serverPort.orEmpty().toInt()
            val tcpTime = SpeedtestManager.socketConnectTime(url, port, 1000)
            if (tcpTime <= -1L) {
                return retFailure
            }
            // Профили, для которых временное ядро Xray построить невозможно (FPTN:
            // fptn-client владеет собственным TUN, Xray-конфига нет), дальше не идут.
            // Для них уже полученный TCP-пинг до сервера и есть честная задержка.
            // Если же и TCP-пинг неприменим (у FPTN адрес сервера живёт внутри JWT и
            // поле server может быть пустым), возвращаем NOT_MEASURABLE, чтобы
            // значение НЕ записалось и профиль не был удалён как недействительный.
            if (SidecarEngineManager.cannotMeasureInTempCore(config.configType)) {
                return tcpTime
            }
        }

        if (SidecarEngineManager.cannotMeasureInTempCore(config.configType)) {
            LogUtil.i(
                AppConfig.TAG,
                "RealPing: профиль ${config.configType} нельзя измерить временным ядром, " +
                    "значение задержки не изменяется"
            )
            return NOT_MEASURABLE
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

    private val runningCount = AtomicInteger(0)
    private val totalCount = AtomicInteger(0)

    fun start() {
        val jobs = guids.map { guid ->
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
    }

    private suspend fun startRealPing(guid: String): Long {
        return RealPingMeasure.measure(guid)
    }

    private fun startTcping(guid: String): Long {
        val retFailure = -1L

        val config = MmkvManager.decodeServerConfig(guid) ?: return retFailure
        if (!config.configType.isComplexType()
            && config.configType != EConfigType.HYSTERIA2
            && config.configType != EConfigType.WIREGUARD
            && config.alpn?.split(',')?.all { it.trim().startsWith("h3") } != true
            && config.server.isNotNullEmpty()
            && config.serverPort?.toIntOrNull() != null
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
