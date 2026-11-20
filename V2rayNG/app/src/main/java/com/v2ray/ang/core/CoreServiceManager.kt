package com.v2ray.ang.core

import android.app.Activity
import android.app.Service
import android.content.BroadcastReceiver
import android.content.Context
import android.content.Intent
import android.content.IntentFilter
import android.net.ConnectivityManager
import android.os.Build
import android.os.Handler
import android.os.Looper
import android.os.ParcelFileDescriptor
import android.os.Process
import android.system.OsConstants
import androidx.core.content.ContextCompat
import com.v2ray.ang.AppConfig
import com.v2ray.ang.contracts.IDialerService
import com.v2ray.ang.contracts.ServiceControl
import com.v2ray.ang.dto.ConnectionTestResult
import com.v2ray.ang.dto.RunningProxyEndpoint
import com.v2ray.ang.util.JsonUtil
import com.v2ray.ang.dto.OutboundTrafficStat
import com.v2ray.ang.dto.entities.ProfileItem
import com.v2ray.ang.enums.EConfigType
import com.v2ray.ang.enums.BrowserDialerMode
import com.v2ray.ang.extension.delay
import com.v2ray.ang.extension.isNotNullEmpty
import com.v2ray.ang.handler.MmkvManager
import com.v2ray.ang.handler.NotificationManager
import com.v2ray.ang.handler.SettingsManager
import com.v2ray.ang.handler.SpeedtestManager
import com.v2ray.ang.helper.MessageHelper
import com.v2ray.ang.service.DialerNativeService
import com.v2ray.ang.service.DialerWebviewService
import com.v2ray.ang.service.NetworkMonitor
import com.v2ray.ang.util.LogUtil
import com.v2ray.ang.util.Utils
import kotlinx.coroutines.CoroutineScope
import kotlinx.coroutines.CancellationException
import kotlinx.coroutines.Dispatchers
import kotlinx.coroutines.SupervisorJob
import kotlinx.coroutines.cancelChildren
import kotlinx.coroutines.ensureActive
import kotlinx.coroutines.launch
import kotlinx.coroutines.withContext
import libv2ray.CoreCallbackHandler
import libv2ray.CoreController
import libv2ray.ProcessFinder
import java.lang.ref.SoftReference
import java.net.InetSocketAddress
import java.util.concurrent.atomic.AtomicBoolean
import java.util.concurrent.atomic.AtomicInteger

object CoreServiceManager {

    private val coreController: CoreController = CoreNativeManager.newCoreController(CoreCallback())
    private val mMsgReceive = ReceiveMessageHandler()
    private var currentConfig: ProfileItem? = null
    private var processFinder: XrayProcessFinder? = null
    private var browserDialer: IDialerService? = null
    private var networkMonitor: NetworkMonitor? = null
    private val connectionTestScope = CoroutineScope(SupervisorJob() + Dispatchers.IO)

    @Volatile
    private var isReloading = false

    /** Tun descriptor the core was started with, null in the proxy only and root run modes. */
    private var currentVpnInterface: ParcelFileDescriptor? = null

    var serviceControl: SoftReference<ServiceControl>? = null
        set(value) {
            field = value
            val service = value?.get()?.getService()
            CoreNativeManager.initCoreEnv(service)
            if (service != null && processFinder == null && Build.VERSION.SDK_INT >= Build.VERSION_CODES.Q) {
                processFinder = XrayProcessFinder(service)
                coreController.registerProcessFinder(processFinder)
            }
        }

    /**
     * Checks if the V2Ray service is running.
     * @return True if the service is running, false otherwise.
     */
    fun isRunning() = coreController.isRunning || FptnRootRunner.active

    /**
     * Gets the name of the currently running server.
     * @return The name of the running server.
     */
    fun getRunningServerName() = currentConfig?.remarks.orEmpty()

    /**
     * Scope асинхронного запуска ядра. Отдельный от [connectionTestScope]:
     * тесты задержки отменяются через cancelChildren, а незавершённый запуск
     * ядра отменять нельзя — иначе профиль остался бы незапущенным без причины.
     */
    private val startScope = CoroutineScope(SupervisorJob() + Dispatchers.IO)

    /**
     * Доставка результата запуска на главный поток. Один экземпляр на объект,
     * а не на каждый запуск: колбэки сервисов меняют состояние, которое
     * читается из main (setupJob, isRunning, mInterface).
     */
    private val mainHandler = Handler(Looper.getMainLooper())

    /**
     * Идёт ли запуск ядра прямо сейчас. Защита от двойного старта: между
     * [startCoreLoopAsync] и фактическим подъёмом ядра [isRunning] ещё false,
     * поэтому повторный onStartCommand (или быстрый старт/рестарт) запустил бы
     * второе ядро на тех же портах.
     */
    private val isStarting = AtomicBoolean(false)

    /**
     * Поколение операции запуска. Защита от гонки «stop во время старта»:
     * [stopCoreLoop] увеличивает его, и отложенный запуск, увидев чужое
     * поколение, не поднимает ядро (иначе stop отработал бы раньше launchCore
     * и оставил работающий core при очищенном состоянии — трафик в чёрную дыру).
     * Приём тот же, что downloadGeneration в загрузчике обновлений.
     */
    private val startGeneration = AtomicInteger(0)

    /**
     * Асинхронный запуск ядра: тяжёлая часть ([startCoreLoop]) выполняется на
     * IO-диспетчере, результат приходит в [onFinished] НА ГЛАВНОМ ПОТОКЕ (чтобы
     * сервис мог безопасно менять своё состояние — см. комментарий у post).
     * Если старт не запланирован (ядро уже работает или старт уже идёт),
     * [onFinished] НЕ вызывается вовсе — см. возвращаемое значение.
     *
     * Зачем (вещдок 20.11.2026, жалоба «NetworkOnMainThreadException»):
     * сборка конфига ядра выполнялась СИНХРОННО в onStartCommand трёх сервисов,
     * то есть на ГЛАВНОМ потоке, а внутри неё блокирующие сетевые и процессные
     * операции:
     *  - DNS-резолв домена сервера ([CoreOutboundBuilder.getServerAddress] и
     *    dns.hosts в [CoreConfigManager]) при
     *    `pref_outbound_domain_resolve_method=2`;
     *  - поднятие сайдкар-движка: ProcessBuilder + ожидание открытия порта
     *    ([SidecarEngineManager.ensureRunning]);
     *  - поиск свободного порта ([Utils.findRandomFreePort], ServerSocket);
     *  - сериализация JSON всего конфига и нативный старт ядра.
     * StrictMode запрещает сеть на главном потоке, поэтому резолв падал с
     * NetworkOnMainThreadException, [com.v2ray.ang.util.HttpUtil.resolveHostToIP] глотал её и
     * возвращал null — настройка «резолвить домен» НЕ РАБОТАЛА вовсе
     * (в outbound уходил домен, dns.hosts не заполнялся), а в лог валился стек.
     * В VPN-режиме исключения не было только потому, что
     * CoreVpnService.onCreate вызывает StrictMode.permitAll(): main там
     * блокировался молча.
     *
     * Решение — вынести с главного потока ВСЮ цепочку запуска, а не один
     * резолв: тогда ни одна из перечисленных операций не может попасть на main,
     * и новые сетевые вызовы в сборке конфига не вернут дефект. Кэширование
     * адресов НЕ используется намеренно: адрес, отрезолвленный на умершей сети,
     * непригоден на новой (см. KDoc [reloadCore]).
     *
     * Контракт FGS не нарушается: вызывающий сервис поднимает foreground ДО
     * этого вызова (NotificationManager.ensureForeground первым в
     * onStartCommand), поэтому ожидание запуска не грозит FGS-таймаутом.
     *
     * @return true, если запуск ЗАПЛАНИРОВАН (колбэк будет вызван); false, если
     *   ядро уже работает или запуск уже идёт — колбэк в этом случае НЕ
     *   вызывается.
     */
    fun startCoreLoopAsync(
        vpnInterface: ParcelFileDescriptor?,
        onFinished: (Boolean) -> Unit,
    ): Boolean {
        // Правило — чистая функция [CoreStartPolicy.canStart] (JVM-тест):
        // старт невозможен, если ядро уже работает ИЛИ старт уже идёт.
        if (!CoreStartPolicy.canStart(coreRunning = isRunning(), startInFlight = isStarting.get())) {
            LogUtil.w(
                AppConfig.TAG,
                "StartCore-Manager: старт пропущен (running=${isRunning()}, inFlight=${isStarting.get()})"
            )
            return false
        }
        // CAS обязателен: между проверкой и установкой флага два onStartCommand
        // успели бы пройти оба (проверка isStarting.get() не атомарна с set).
        if (!isStarting.compareAndSet(false, true)) {
            LogUtil.w(AppConfig.TAG, "StartCore-Manager: старт ядра уже идёт, повторный запрос проигнорирован")
            return false
        }
        val generation = startGeneration.incrementAndGet()
        startScope.launch {
            val started = try {
                startCoreLoop(vpnInterface)
            } catch (e: Exception) {
                // startCoreLoop сам ловит и логирует свои ошибки; эта ветка —
                // страховка от исключений вне его try (например, в getService()).
                LogUtil.e(AppConfig.TAG, "StartCore-Manager: async start failed", e)
                false
            }
            isStarting.set(false)
            // Устарел ли результат — решает та же чистая функция, что и
            // поведение сервиса (CoreStartPolicy.decide): STALE = stop/рестарт
            // пришёл во время старта, колбэк вызывать нельзя.
            when (
                CoreStartPolicy.decide(
                    started = started,
                    generation = generation,
                    currentGeneration = startGeneration.get(),
                )
            ) {
                CoreStartPolicy.StartOutcome.STALE -> {
                    LogUtil.w(
                        AppConfig.TAG,
                        "StartCore-Manager: запуск ядра устарел (поколение $generation), результат проигнорирован"
                    )
                    // КОМПЕНСАЦИЯ (гонка, появившаяся вместе с асинхронным
                    // стартом): stopCoreLoop мог отработать, когда ядро ещё НЕ
                    // было поднято (isRunning()==false), и поэтому не вызвал
                    // stopLoop. Если launchCore поднял ядро ПОСЛЕ этого, сервис
                    // уже уничтожён, а core остался работать: isRunning() true
                    // заблокировал бы следующий старт, а трафик никуда не шёл
                    // (правила маршрутизации сняты).
                    if (isRunning()) {
                        LogUtil.w(
                            AppConfig.TAG,
                            "StartCore-Manager: ядро поднялось после stop — останавливаю (компенсация гонки)"
                        )
                        abortStaleStart()
                    }
                }

                // Колбэк — НА ГЛАВНОМ ПОТОКЕ (намеренно). Сервисы в нём меняют
                // СВОЁ состояние, которое читается из main: CoreRootService
                // пишет setupJob (onDestroy делает cancelAndJoin на main),
                // CoreVpnService трогает isRunning/mInterface. Вызов из IO
                // открыл бы гонку видимости, поэтому результат доставляется
                // через Handler главного Looper'а.
                else -> mainHandler.post {
                    // ПОВТОРНАЯ проверка поколения — уже на main, в момент
                    // выполнения колбэка. Проверка выше сделана ДО post, а
                    // onDestroy (stopCoreLoop / cancelPendingStart) может пройти
                    // в окне между ними. Без этой проверки колбэк выполнился бы
                    // ПОСЛЕ уничтожения сервиса: CoreRootService поставил бы
                    // iptables+tun на уже остановленное ядро (чёрная дыра
                    // трафика до следующего start/stop), CoreVpnService —
                    // RootLanSharing/stopAllService на закрытом mInterface.
                    when (
                        CoreStartPolicy.decide(
                            started = started,
                            generation = generation,
                            currentGeneration = startGeneration.get(),
                        )
                    ) {
                        CoreStartPolicy.StartOutcome.STALE -> {
                            LogUtil.w(
                                AppConfig.TAG,
                                "StartCore-Manager: сервис остановлен, пока шёл запуск — колбэк отброшен (поколение $generation)"
                            )
                            startScope.launch {
                                if (isRunning()) abortStaleStart()
                            }
                        }

                        else -> onFinished(started)
                    }
                }
            }
        }
        return true
    }

    /**
     * Refer to the official documentation for [registerReceiver](https://developer.android.com/reference/androidx/core/content/ContextCompat#registerReceiver(android.content.Context,android.content.BroadcastReceiver,android.content.IntentFilter,int):
     * `registerReceiver(Context, BroadcastReceiver, IntentFilter, int)`.
     * Starts the V2Ray core service.
     *
     * СИНХРОННЫЙ и БЛОКИРУЮЩИЙ (DNS, запуск сайдкара, нативный старт ядра):
     * вызывается ТОЛЬКО не на главном потоке — из [startCoreLoopAsync] или
     * [reloadCore] (последний уже идёт на IO через NetworkMonitor).
     */
    fun startCoreLoop(vpnInterface: ParcelFileDescriptor?): Boolean {
        if (isRunning()) {
            LogUtil.w(AppConfig.TAG, "StartCore-Manager: Core already running")
            return false
        }

        val service = getService()
        if (service == null) {
            LogUtil.e(AppConfig.TAG, "StartCore-Manager: Service is null")
            return false
        }

        try {
            doStartCoreLoop(service, vpnInterface)
            return true
        } catch (e: Exception) {
            val message = e.message?.takeUnless { it.isBlank() } ?: e.javaClass.simpleName
            LogUtil.e(AppConfig.TAG, "StartCore-Manager: $message", e)
            MessageHelper.sendMsg2UI(service, AppConfig.MSG_STATE_START_FAILURE, message)
            NotificationManager.cancelNotification()
            return false
        }
    }

    @Throws(Exception::class)
    private fun doStartCoreLoop(service: Service, vpnInterface: ParcelFileDescriptor?) {
        val mFilter = IntentFilter(AppConfig.BROADCAST_ACTION_SERVICE)
        mFilter.addAction(Intent.ACTION_SCREEN_ON)
        mFilter.addAction(Intent.ACTION_SCREEN_OFF)
        mFilter.addAction(Intent.ACTION_USER_PRESENT)
        ContextCompat.registerReceiver(service, mMsgReceive, mFilter, Utils.receiverFlags())

        currentVpnInterface = vpnInterface
        launchCore(service, vpnInterface)
        startNetworkMonitor(service)
    }

    @Throws(Exception::class)
    private fun launchCore(service: Service, vpnInterface: ParcelFileDescriptor?, isReload: Boolean = false) {
        val guid = MmkvManager.getSelectServer() ?: error("No server selected")
        val config = MmkvManager.decodeServerConfig(guid) ?: error("Failed to decode server config")

        LogUtil.i(AppConfig.TAG, "StartCore-Manager: Starting core loop for ${config.remarks}")

        // ===== Порядок здесь КРИТИЧЕН =====
        //
        // (1) FPTN обрабатывается ПЕРВЫМ и вообще не требует конфига Xray.
        //     Раньше ветка FPTN стояла ПОСЛЕ getV2rayConfig(), а построение конфига
        //     для EConfigType.FPTN шло в CoreOutboundBuilder.toOutboundSidecar(),
        //     где SidecarEngineManager.currentPort == 0 (FPTN запускается не через
        //     SidecarEngineManager, а через FptnRootRunner) -> error("Sidecar engine
        //     is not running") -> getV2rayConfig возвращал status=false -> launchCore
        //     падал на строке проверки status, НЕ ДОХОДЯ до ветки FPTN. Профиль FPTN
        //     не запускался никогда.
        if (config.configType == EConfigType.FPTN) {
            if (!SettingsManager.isRootMode()) {
                error("FPTN profiles require root mode: Android grants a single VPN slot")
            }
            currentConfig = config
            if (!FptnRootRunner.start(service, config)) {
                error("fptn-client failed to start; see engines/fptn-client.log")
            }
            MmkvManager.encodeSettings(AppConfig.PREF_CORE_DAEMON_PID, Process.myPid())
            // Xray и его loopback HTTP inbound для FPTN не поднимаются: fptn-client
            // владеет собственным TUN и маршрутизирует трафик всего устройства,
            // включая наше приложение (оно НЕ исключено из fptn0). Поэтому снимок
            // прокси помечается как «туннельный режим без HTTP-прокси», и вызывающий
            // код знает, что прямой запрос здесь как раз и идёт через профиль.
            MmkvManager.encodeSettings(
                AppConfig.PREF_CORE_PROXY_ENDPOINT,
                JsonUtil.toJson(
                    RunningProxyEndpoint(
                        host = "",
                        port = 0,
                        udpEnabled = true,
                        routeOnly = false,
                        configType = EConfigType.FPTN.name,
                        tunnelOnly = true,
                    )
                )
            )
            NotificationManager.showNotification(currentConfig)
            if (!isReload) {
                MessageHelper.sendMsg2UI(service, AppConfig.MSG_STATE_START_SUCCESS, "")
            }
            NotificationManager.startSpeedNotification()
            LogUtil.i(AppConfig.TAG, "StartCore-Manager: FPTN client started successfully")
            return
        }

        // (2) Сайдкар-движок (mihomo / sing-box / mimic-client) поднимается ДО
        //     построения конфига. Конфиг читает SidecarEngineManager.currentPort,
        //     чтобы подключить движок как SOCKS-upstream; если строить конфиг раньше,
        //     порт ещё равен 0 и построение падает. Раньше syncForProfile() стоял
        //     ПОСЛЕ getV2rayConfig() - из-за этого AmneziaWG, NaiveProxy,
        //     OpenConnect и Mimic не запускались вообще.
        SidecarEngineManager.syncForProfile(service, config, guid)

        // (3) Только теперь строим конфиг Xray - движок уже слушает свой порт.
        val result = CoreConfigManager.getV2rayConfig(service, guid)
        LogUtil.d(AppConfig.TAG, result.content)
        if (!result.status) {
            // Конфиг не собрался - движок оставлять нельзя: он продолжит висеть
            // в памяти и держать порт, а профиль не запущен.
            SidecarEngineManager.stopAll()
            error(result.errorMessage.ifBlank { "Failed to get V2Ray config" })
        }

        currentConfig = config
        var tunFd = vpnInterface?.fd ?: 0
        val dialerMode = BrowserDialerMode.from(config.browserDialerMode)
        val dialerAddr = if (dialerMode != null) {
            "127.0.0.1:${Utils.findRandomFreePort()}"
        } else {
            ""
        }
        if (SettingsManager.isUsingHevTun()) {
            tunFd = 0
        }

        NotificationManager.showNotification(currentConfig)
        if (dialerAddr.isNotNullEmpty()) {
            CoreNativeManager.reconcileBrowserDialer(dialerAddr)
        }
        coreController.startLoop(result.content, tunFd)

        if (!isRunning()) {
            error("Core failed to start")
        }

        // Публикуем PID демона и снимок РЕАЛЬНО запущенного прокси, чтобы другие
        // процессы (UI :main, :tasks) могли и понять, что профиль работает, и
        // достучаться до его прокси. Снимок строится разбором того самого конфига,
        // который ушёл в ядро, а не текущими настройками: настройки пользователь
        // может поменять в любой момент, а запущенное ядро слушает старые значения.
        MmkvManager.encodeSettings(AppConfig.PREF_CORE_DAEMON_PID, Process.myPid())
        publishRunningProxyEndpoint(result.content, config.configType)

        if (browserDialer != null) {
            browserDialer!!.stop()
            browserDialer = null
        }
        when (dialerMode) {
            BrowserDialerMode.OKHTTP -> {
                browserDialer = DialerNativeService()
                browserDialer!!.start(service, dialerAddr)
            }

            BrowserDialerMode.WEBVIEW -> {
                browserDialer = DialerWebviewService()
                browserDialer!!.start(service, dialerAddr)
            }

            else -> {}
        }

        if (!isReload) {
            MessageHelper.sendMsg2UI(service, AppConfig.MSG_STATE_START_SUCCESS, "")
        }
        NotificationManager.startSpeedNotification()
        LogUtil.i(AppConfig.TAG, "StartCore-Manager: Core started successfully")
    }

    /**
     * Гарантированно останавливает ядро, поднятое устаревшим запуском.
     *
     * НЕ использует [stopCoreLoop]: тот выходит рано на `getService() ?: return
     * false`, а в момент компенсации сервис уже уничтожен (SoftReference
     * очищена), поэтому stopLoop до ядра не дошёл бы. Здесь остановка идёт
     * напрямую, в том же IO-контексте, плюс снимается опубликованное состояние
     * (PID демона и снимок прокси), иначе другие процессы считали бы профиль
     * работающим.
     */
    private fun abortStaleStart() {
        MmkvManager.encodeSettings(AppConfig.PREF_CORE_DAEMON_PID, 0)
        MmkvManager.encodeSettings(AppConfig.PREF_CORE_PROXY_ENDPOINT, "")
        try {
            SidecarEngineManager.stopAll()
        } catch (e: Exception) {
            LogUtil.e(AppConfig.TAG, "StartCore-Manager: не удалось остановить сайдкар после устаревшего старта", e)
        }
        try {
            coreController.stopLoop()
        } catch (e: Exception) {
            LogUtil.e(AppConfig.TAG, "StartCore-Manager: не удалось остановить ядро после устаревшего старта", e)
        }
        NotificationManager.cancelNotification()
        LogUtil.w(AppConfig.TAG, "StartCore-Manager: устаревший запуск остановлен, состояние очищено")
    }

    /**
     * Инвалидирует незавершённый асинхронный старт БЕЗ остановки уже
     * работающего ядра.
     *
     * Зачем отдельно от [stopCoreLoop]: у CoreVpnService.onDestroy исторически
     * НЕ вызывает stopCoreLoop (он идёт через stopAllService), поэтому при
     * неожиданном уничтожении сервиса поколение старта не менялось. Асинхронный
     * запуск в этом окне продолжался и поднимал ядро ПОСЛЕ уничтожения сервиса:
     * isRunning()==true заблокировал бы следующий старт, а трафик не шёл бы
     * (туннель закрыт). После этого вызова отложенный старт получит STALE и сам
     * остановит поднятое ядро (компенсация в startCoreLoopAsync).
     *
     * Безопасно вызывать всегда: если старта в полёте нет, метод ничего не
     * делает.
     */
    fun cancelPendingStart() {
        startGeneration.incrementAndGet()
        isStarting.set(false)
    }

    /**
     * Stops the V2Ray core service.
     * Unregisters broadcast receivers, stops notifications, and shuts down plugins.
     * @return True if the core was stopped successfully, false otherwise.
     */
    fun stopCoreLoop(): Boolean {
        // Инвалидируем незавершённый асинхронный запуск: stop, пришедший во
        // время старта, обязан победить (см. startGeneration). isStarting
        // сбрасываем здесь же, иначе следующая попытка старта была бы
        // заблокирована навсегда (колбэк устаревшего поколения не выполнится).
        startGeneration.incrementAndGet()
        isStarting.set(false)
        MmkvManager.encodeSettings(AppConfig.PREF_CORE_DAEMON_PID, 0)
        MmkvManager.encodeSettings(AppConfig.PREF_CORE_PROXY_ENDPOINT, "")
        SidecarEngineManager.stopAll()
        getService()?.let { FptnRootRunner.stop(it) }
        connectionTestScope.coroutineContext.cancelChildren()
        val service = getService() ?: return false

        networkMonitor?.unregister()
        networkMonitor = null
        currentVpnInterface = null

        if (isRunning()) {
            CoroutineScope(Dispatchers.IO).launch {
                try {
                    coreController.stopLoop()
                } catch (e: Exception) {
                    LogUtil.e(AppConfig.TAG, "StartCore-Manager: Failed to stop V2Ray loop", e)
                }
            }
        }

        // Close existing browser dialer
        CoreNativeManager.reconcileBrowserDialer("")
        if (browserDialer != null) {
            browserDialer!!.stop()
            browserDialer = null
        }

        MessageHelper.sendMsg2UI(service, AppConfig.MSG_STATE_STOP_SUCCESS, "")
        NotificationManager.cancelNotification()

        try {
            service.unregisterReceiver(mMsgReceive)
        } catch (e: Exception) {
            LogUtil.e(AppConfig.TAG, "StartCore-Manager: Failed to unregister receiver", e)
        }

        return true
    }

    /**
     * Subscribes to upstream network changes for whichever run mode is active.
     * All three services share this manager, so the tunnel recovers from a handover in proxy only
     * and root mode as well, not just behind the VPN interface.
     */
    private fun startNetworkMonitor(service: Service) {
        if (Build.VERSION.SDK_INT < Build.VERSION_CODES.P) return
        if (networkMonitor != null) return

        val connectivity = service.getSystemService(Context.CONNECTIVITY_SERVICE) as? ConnectivityManager ?: return
        networkMonitor = NetworkMonitor(
            connectivity = connectivity,
            onUnderlyingNetworksChanged = { networks -> serviceControl?.get()?.setUnderlyingNetworks(networks) },
            onHandover = { reloadCore() },
        ).also { it.register() }
    }

    /**
     * Restarts the core in place after the upstream network changed: the service, the notification
     * and the VPN interface all stay up, so nothing of this is visible.
     *
     * The config is rebuilt on purpose, outbound server domains are resolved while building it and
     * an address resolved on a network that is gone can be unusable on the new one.
     *
     * @return True if the core is running again.
     */
    private fun reloadCore(): Boolean {
        val service = getService() ?: return false
        // Правило — чистая функция [CoreStartPolicy.canReload] (JVM-тест):
        // ядро поднято, reload ещё не идёт и ПЕРВИЧНЫЙ старт завершён.
        // Третье условие закрывает окно, в котором startLoop уже поднял ядро,
        // но isStarting ещё не сброшен — иначе два launchCore пошли бы
        // параллельно и сделали два startLoop на одном coreController.
        if (!CoreStartPolicy.canReload(
                coreRunning = isRunning(),
                alreadyReloading = isReloading,
                startInFlight = isStarting.get(),
            )
        ) {
            if (isStarting.get()) {
                LogUtil.w(AppConfig.TAG, "StartCore-Manager: reload пропущен — запуск ядра ещё идёт")
            }
            return false
        }

        return try {
            val tunFd = currentVpnInterface

            isReloading = true
            connectionTestScope.coroutineContext.cancelChildren()
            LogUtil.i(AppConfig.TAG, "StartCore-Manager: Core reload start...")

            // Для профиля FPTN ядро Xray не запускалось вовсе (fptn-client владеет
            // собственным TUN), поэтому coreController.stopLoop() здесь обращался бы
            // к неинициализированному нативному состоянию. Пропускаем остановку и
            // даём launchCore заново поднять fptn-client (он сам делает stop первым шагом).
            if (!FptnRootRunner.active) {
                coreController.stopLoop()
            } else {
                LogUtil.i(AppConfig.TAG, "StartCore-Manager: reload for FPTN profile, skipping Xray stopLoop")
            }
            launchCore(service, tunFd, isReload = true)

            LogUtil.i(AppConfig.TAG, "StartCore-Manager: Core reload finished")
            true
        } catch (e: Exception) {
            val message = e.message?.takeUnless { it.isBlank() } ?: e.javaClass.simpleName
            LogUtil.e(AppConfig.TAG, "StartCore-Manager: Failed to reload core: $message", e)
            MessageHelper.sendMsg2UI(service, AppConfig.MSG_STATE_START_FAILURE, message)
            false
        } finally {
            isReloading = false
        }
    }

    /**
     * Queries and resets all outbound traffic counters in one core call.
     * Go side format: tag,direction,value;tag,direction,value;
     */
    fun queryAllOutboundTrafficStats(): List<OutboundTrafficStat> {
        // The stats manager is gone once the core stops, querying it then reaches into freed state.
        if (!isRunning()) return emptyList()

        val payload = coreController.queryAllOutboundTrafficStats()

        val result = ArrayList<OutboundTrafficStat>()

        payload.split(';').forEach { entry ->
            if (entry.isBlank()) return@forEach

            val parts = entry.split(',', limit = 3)
            if (parts.size != 3) return@forEach

            val value = parts[2].toLongOrNull() ?: return@forEach

            result.add(
                OutboundTrafficStat(
                    tag = parts[0],
                    direction = parts[1],
                    value = value,
                )
            )
        }
//        LogUtil.d(AppConfig.TAG, "Queried outbound traffic stats: $result")
        return result
    }

    /**
     * Measures the connection delay for the current V2Ray configuration.
     * Tests with primary URL first, then falls back to alternative URL if needed.
     * Also fetches remote IP information if the delay test was successful.
     */
    private fun measureV2rayDelay(requestId: String) {
        val service = getService() ?: return
        if (!isRunning() || isReloading) {
            MessageHelper.sendMsg2UI(service, AppConfig.MSG_MEASURE_DELAY_CANCEL, "", requestId)
            return
        }

        connectionTestScope.coroutineContext.cancelChildren()
        connectionTestScope.launch {
            var time = -1L
            var errorStr = ""

            try {
                time = coreController.measureDelay(SettingsManager.getDelayTestUrl())
            } catch (e: Exception) {
                LogUtil.e(AppConfig.TAG, "StartCore-Manager: Failed to measure delay", e)
                errorStr = e.message?.substringAfter("\":").orEmpty()
            }
            if (time == -1L) {
                ensureActive()
                try {
                    time = coreController.measureDelay(SettingsManager.getDelayTestUrl(true))
                } catch (e: Exception) {
                    LogUtil.e(AppConfig.TAG, "StartCore-Manager: Failed to measure delay", e)
                    errorStr = e.message?.substringAfter("\":").orEmpty()
                }
            }

            ensureActive()
            val initialResult = ConnectionTestResult(
                delayMillis = time,
                errorMessage = errorStr,
                country = null,
                ipAddress = null,
            )
            withContext(Dispatchers.Main.immediate) {
                if (isRunning()) {
                    MessageHelper.sendMsg2UI(service, AppConfig.MSG_MEASURE_DELAY_RESULT, initialResult, requestId)
                } else {
                    MessageHelper.sendMsg2UI(service, AppConfig.MSG_MEASURE_DELAY_CANCEL, "", requestId)
                    return@withContext
                }
            }

            if (time >= 0) {
                val endpoint = SpeedtestManager.getRemoteIPInfo()
                if (endpoint != null && (endpoint.country != null || endpoint.ipAddress != null)) {
                    ensureActive()
                    val fullResult = ConnectionTestResult(
                        delayMillis = time,
                        errorMessage = errorStr,
                        country = endpoint.country,
                        ipAddress = endpoint.ipAddress,
                    )
                    withContext(Dispatchers.Main.immediate) {
                        if (isRunning()) {
                            MessageHelper.sendMsg2UI(service, AppConfig.MSG_MEASURE_DELAY_RESULT, fullResult, requestId)
                        }
                    }
                }
            }
        }.invokeOnCompletion { cause ->
            if (cause is CancellationException) {
                MessageHelper.sendMsg2UI(service, AppConfig.MSG_MEASURE_DELAY_CANCEL, "", requestId)
            }
        }
    }

    /**
     * Публикует снимок loopback-прокси, который ядро РЕАЛЬНО подняло.
     *
     * Источник - JSON конфига, переданный в coreController.startLoop(), поэтому
     * значения верны для любого сочетания режимов (hev-tun, root, root+LAN,
     * proxy-only, VPN-tun, per-app, routeOnly) и любых пользовательских настроек,
     * включая динамический порт и смену адреса/порта/учётных данных после старта.
     *
     * Если HTTP inbound в конфиге нет (профиль поднят без локального прокси),
     * снимок очищается: функция «через активный профиль» в этом случае честно
     * отказывает, а не уходит напрямую в обход профиля.
     */
    private fun publishRunningProxyEndpoint(configJson: String, configType: EConfigType?) {
        val endpoint = RunningProxyEndpoint.fromCoreConfig(configJson, configType?.name)
        if (endpoint == null) {
            MmkvManager.encodeSettings(AppConfig.PREF_CORE_PROXY_ENDPOINT, "")
            LogUtil.i(
                AppConfig.TAG,
                "StartCore-Manager: профиль поднят без локального HTTP-прокси, снимок очищен"
            )
            return
        }
        // Учётные данные не логируются: только адрес и порт.
        LogUtil.i(
            AppConfig.TAG,
            "StartCore-Manager: опубликован снимок прокси ${endpoint.host}:${endpoint.port} " +
                "(udp=${endpoint.udpEnabled}, routeOnly=${endpoint.routeOnly}, " +
                "auth=${endpoint.username != null}, type=${endpoint.configType})"
        )
        MmkvManager.encodeSettings(
            AppConfig.PREF_CORE_PROXY_ENDPOINT,
            JsonUtil.toJson(endpoint)
        )
    }

    /**
     * Gets the current service instance.
     * @return The current service instance, or null if not available.
     */
    private fun getService(): Service? {
        return serviceControl?.get()?.getService()
    }

    /**
     * Core callback handler implementation for handling V2Ray core events.
     * Handles startup, shutdown, socket protection, and status emission.
     */
    private class CoreCallback : CoreCallbackHandler {
        /**
         * Called when V2Ray core starts up.
         * @return 0 for success, any other value for failure.
         */
        override fun startup(): Long {
            LogUtil.i(AppConfig.TAG, "StartCore-Manager: CoreCallback startup")
            return 0
        }

        /**
         * Called when V2Ray core shuts down.
         * @return 0 for success, any other value for failure.
         */
        override fun shutdown(): Long {
            LogUtil.i(AppConfig.TAG, "StartCore-Manager: CoreCallback shutdown")
            return 0
        }

        /**
         * Called when V2Ray core emits status information.
         * @param l Status code.
         * @param s Status message.
         * @return Always returns 0.
         */
        override fun onEmitStatus(l: Long, s: String?): Long {
            LogUtil.i(AppConfig.TAG, "StartCore-Manager: CoreCallback onEmitStatus $s")
            return 0
        }
    }

    /**
     * Process finder implementation for Xray core.
     * Uses ConnectivityManager to find the owning UID of a connection based on network parameters.
     */
    private class XrayProcessFinder(context: Context) : ProcessFinder {
        private val cm: ConnectivityManager? = context.getSystemService(ConnectivityManager::class.java)

        override fun findProcessByConnection(network: String, srcIP: String, srcPort: Long, destIP: String, destPort: Long): Long {
            if (Build.VERSION.SDK_INT < Build.VERSION_CODES.Q) return -1L
            if (cm == null) return -1L
            val proto = when (network) {
                "tcp" -> OsConstants.IPPROTO_TCP
                "udp" -> OsConstants.IPPROTO_UDP
                else -> return -1L
            }

            if (destIP.isBlank() || destPort == 0L) {
                LogUtil.d(AppConfig.TAG, "ProcessFinder: Find $network connection from $srcIP:$srcPort to :$destPort, (no dest)")
                return -1L
            }

            return try {
                val uid = cm.getConnectionOwnerUid(
                    proto,
                    InetSocketAddress(srcIP, srcPort.toInt()),
                    InetSocketAddress(destIP, destPort.toInt())
                ).toLong()
                LogUtil.d(AppConfig.TAG, "ProcessFinder: Find $network connection from $srcIP:$srcPort to $destIP:$destPort, uid=$uid")
                //LogUtil.d(AppConfig.TAG, "ProcessFinder: Find $network connection from $srcIP:$srcPort to $destIP:$destPort, uid=$uid,${PackageUidResolver.uidToPackageName(uid.toString())}")

                uid
            } catch (_: Exception) {
                -1L
            }
        }
    }

    /**
     * Broadcast receiver for handling messages sent to the service.
     * Handles registration, service control, and screen events.
     */
    private class ReceiveMessageHandler : BroadcastReceiver() {
        /**
         * Handles received broadcast messages.
         * Processes service control messages and screen state changes.
         * @param ctx The context in which the receiver is running.
         * @param intent The intent being received.
         */
        override fun onReceive(ctx: Context?, intent: Intent?) {
            val serviceControl = serviceControl?.get() ?: return
            when (intent?.getIntExtra("key", 0)) {
                AppConfig.MSG_REGISTER_CLIENT -> {
                    if (isRunning()) {
                        MessageHelper.sendMsg2UI(serviceControl.getService(), AppConfig.MSG_STATE_RUNNING, "")
                    } else {
                        MessageHelper.sendMsg2UI(serviceControl.getService(), AppConfig.MSG_STATE_NOT_RUNNING, "")
                    }
                }

                AppConfig.MSG_UNREGISTER_CLIENT -> {
                    // nothing to do
                }

                AppConfig.MSG_STATE_START -> {
                    // nothing to do
                }

                AppConfig.MSG_STATE_STOP -> {
                    LogUtil.i(AppConfig.TAG, "StartCore-Manager: Stop service")
                    serviceControl.stopService()
                }

                AppConfig.MSG_STATE_RESTART -> {
                    LogUtil.i(AppConfig.TAG, "StartCore-Manager: Restart service")
                    // The UI and daemon run in separate processes, so acknowledge the active
                    // daemon before stopping it instead of relying on possibly stale UI state.
                    if (isOrderedBroadcast) resultCode = Activity.RESULT_OK

                    val pendingResult = goAsync()
                    CoroutineScope(Dispatchers.Default).launch {
                        try {
                            serviceControl.stopService()
                            delay(500L)
                            LauncherManager.startService(serviceControl.getService())
                        } finally {
                            pendingResult.finish()
                        }
                    }
                }

                AppConfig.MSG_MEASURE_DELAY -> {
                    if (isOrderedBroadcast) resultCode = Activity.RESULT_OK
                    measureV2rayDelay(intent.getStringExtra("content").orEmpty())
                }
            }

            when (intent?.action) {
                Intent.ACTION_SCREEN_OFF -> {
                    LogUtil.i(AppConfig.TAG, "StartCore-Manager: Screen off")
                    NotificationManager.stopSpeedNotification()
                }

                Intent.ACTION_SCREEN_ON -> {
                    LogUtil.i(AppConfig.TAG, "StartCore-Manager: Screen on")
                    NotificationManager.startSpeedNotification()
                }
            }
        }
    }
}
