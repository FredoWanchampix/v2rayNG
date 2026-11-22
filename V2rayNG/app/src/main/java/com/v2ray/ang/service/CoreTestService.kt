package com.v2ray.ang.service

import android.app.PendingIntent
import android.app.Service
import android.content.Context
import android.content.Intent
import android.os.IBinder
import androidx.core.app.NotificationCompat
import com.v2ray.ang.AppConfig
import com.v2ray.ang.R
import com.v2ray.ang.core.CoreNativeManager
import com.v2ray.ang.dto.RealPingEvent
import com.v2ray.ang.dto.TestServiceMessage
import com.v2ray.ang.enums.NotificationChannelType
import com.v2ray.ang.extension.serializable
import com.v2ray.ang.handler.AngConfigManager
import com.v2ray.ang.handler.AppLocaleManager
import com.v2ray.ang.handler.MmkvManager
import com.v2ray.ang.helper.MessageHelper
import com.v2ray.ang.helper.NotificationHelper
import com.v2ray.ang.util.LogUtil
import java.util.Collections

class CoreTestService : Service() {

    override fun attachBaseContext(newBase: Context?) {
        super.attachBaseContext(newBase?.let(AppLocaleManager::localizedContext))
    }

    // manage active batch workers so each batch is independent and cancellable
    private val activeWorkers = Collections.synchronizedList(mutableListOf<RealPingWorkerService>())
    private val activeWhitelistWorkers = Collections.synchronizedList(mutableListOf<WhitelistSearchWorkerService>())
    private val cancelAction by lazy {
        val intent = Intent(this, CoreTestService::class.java).putExtra(
            "content",
            TestServiceMessage(AppConfig.MSG_MEASURE_CONFIG_CANCEL)
        )
        val pendingIntent = PendingIntent.getService(
            this,
            NotificationChannelType.CORE_TEST.notificationId,
            intent,
            PendingIntent.FLAG_UPDATE_CURRENT or PendingIntent.FLAG_IMMUTABLE
        )
        NotificationCompat.Action.Builder(
            R.drawable.ic_stop_24dp,
            getString(R.string.action_cancel),
            pendingIntent
        ).build()
    }

    /**
     * Initializes the V2Ray environment.
     */
    override fun onCreate() {
        super.onCreate()
        CoreNativeManager.initCoreEnv(this)
    }

    /**
     * Binds the service.
     * @param intent The intent.
     * @return The binder.
     */
    override fun onBind(intent: Intent?): IBinder? {
        return null
    }

    /**
     * Cleans up resources when the service is destroyed.
     */
    override fun onDestroy() {
        LogUtil.i(AppConfig.TAG, "CoreTestService is being destroyed, cancelling ${activeWorkers.size} active workers")
        // cancel any active workers
        val snapshot = ArrayList(activeWorkers)
        snapshot.forEach { it.cancel() }
        activeWorkers.clear()
        val wlSnapshot = ArrayList(activeWhitelistWorkers)
        wlSnapshot.forEach { it.cancel() }
        activeWhitelistWorkers.clear()
        NotificationHelper.stopForeground(this)
        super.onDestroy()
    }

    /**
     * Handles the start command for the service.
     * @param intent The intent.
     * @param flags The flags.
     * @param startId The start ID.
     * @return The start mode.
     */
    override fun onStartCommand(intent: Intent?, flags: Int, startId: Int): Int {
        NotificationHelper.startForeground(
            this,
            NotificationChannelType.CORE_TEST,
            getString(R.string.app_name),
            getString(R.string.title_real_ping_all_server),
            cancelAction
        )
        val message = intent?.serializable<TestServiceMessage>("content")
        if (message == null) {
            stopSelf(startId)
            return START_NOT_STICKY
        }

        when (message.key) {
            AppConfig.MSG_MEASURE_CONFIG_START -> handleMeasureStart(message, startId)
            AppConfig.MSG_WL_SEARCH_START -> handleWhitelistSearchStart(message, startId)
            AppConfig.MSG_MEASURE_CONFIG_CANCEL -> handleMeasureCancel()
            else -> {
                NotificationHelper.stopForeground(this); stopSelf(startId)
            }
        }
        return START_NOT_STICKY
    }

    private fun handleWhitelistSearchStart(message: TestServiceMessage, startId: Int) {
        LogUtil.i(AppConfig.TAG, "CoreTestService starting whitelist search   subscription ${message.subscriptionId}")

        val guidsList = when {
            message.serverGuids.isNotEmpty() -> message.serverGuids
            message.subscriptionId.isNotEmpty() -> MmkvManager.decodeServerList(message.subscriptionId)
            else -> MmkvManager.decodeAllServerList()
        }

        if (guidsList.isNotEmpty()) {
            lateinit var worker: WhitelistSearchWorkerService
            worker = WhitelistSearchWorkerService(
                context = this,
                guids = guidsList,
                onEvent = { event ->
                    handleWorkerEvent(event, message, isWhitelistSearch = true) {
                        activeWhitelistWorkers.remove(worker)
                    }
                }
            )
            activeWhitelistWorkers.add(worker)
            worker.start()
        } else {
            NotificationHelper.stopForeground(this)
            stopSelf(startId)
        }
    }

    private fun handleMeasureStart(message: TestServiceMessage, startId: Int) {
        LogUtil.i(AppConfig.TAG, "CoreTestService starting worker   subscription ${message.subscriptionId}")

        val guidsList = when {
            message.serverGuids.isNotEmpty() -> message.serverGuids
            message.subscriptionId.isNotEmpty() -> MmkvManager.decodeServerList(message.subscriptionId)
            else -> MmkvManager.decodeAllServerList()
        }

        if (guidsList.isNotEmpty()) {
            lateinit var worker: RealPingWorkerService
            worker = RealPingWorkerService(
                context = this,
                guids = guidsList,
                onlyTcp = message.onlyTcp,
                onlyIcmp = message.onlyIcmp,
                onEvent = { event ->
                    handleWorkerEvent(event, message, isWhitelistSearch = false) {
                        activeWorkers.remove(worker)
                    }
                }
            )
            activeWorkers.add(worker)
            worker.start()
        } else {
            NotificationHelper.stopForeground(this)
            stopSelf(startId)
        }
    }

    /**
     * Общий обработчик событий воркеров.
     *
     * @param isWhitelistSearch true — событие пришло от «Поиска стабильных
     *   профилей» ([WhitelistSearchWorkerService]), false — от обычного теста
     *   задержки ([RealPingWorkerService]). Нужен, потому что обработчик ОДИН на
     *   два вида воркеров, а итоговая сортировка у них РАЗНАЯ:
     *   обычный тест меряет только задержку → сортировка по пингу, как и раньше,
     *   под свитчом [AppConfig.PREF_AUTO_SORT_AFTER_TEST];
     *   поиск стабильных профилей меряет ещё и скорость → сортировка по скорости
     *   БЕЗУСЛОВНО.
     *
     *   Требование владельца (22.11.2026): «когда именно функция поиск стабильных
     *   профилей закончит работать, чтобы она сортировала не по пингу, а по
     *   скорости». Требование БЕЗУСЛОВНОЕ, поэтому сортировка по скорости на
     *   финише поиска НЕ зависит от свитча «авто-сортировка после теста»: тот
     *   свитч управляет прежним поведением обычного теста задержки и не должен
     *   гасить эту сортировку. Сам поиск (две фазы, разделение дорожек FPTN,
     *   намеренное отсутствие раннего выхода) НЕ меняется ни на строку — меняется
     *   только выбор готовой функции сортировки на его финише.
     *
     *   СКОУП действий на финише (авто-удаление недействительных и сортировка)
     *   берётся из [TestFinishScopePolicy] и обязан совпадать со скоупом
     *   ИЗМЕРЕНИЯ воркера: вкладка «Все», одна подписка или только отфильтрованные
     *   по слову профили. Прежняя привязка к `subscriptionId.isNotEmpty()` давала
     *   три дефекта — см. KDoc политики.
     */
    private fun handleWorkerEvent(
        event: RealPingEvent,
        message: TestServiceMessage,
        isWhitelistSearch: Boolean,
        onWorkerDone: () -> Unit,
    ) {
        when (event) {
            is RealPingEvent.Progress -> {
                NotificationHelper.updateNotification(
                    channelType = NotificationChannelType.CORE_TEST,
                    context = this,
                    title = getString(R.string.app_name),
                    content = getString(R.string.connection_running_task_left, event.text)
                )
                MessageHelper.sendMsg2UI(this, AppConfig.MSG_MEASURE_CONFIG_NOTIFY, event.text)
            }

            is RealPingEvent.Result -> {
                MmkvManager.encodeServerTestDelayMillis(event.guid, event.delayMillis)
                MessageHelper.sendMsg2UI(this, AppConfig.MSG_MEASURE_CONFIG_SUCCESS, event.guid)
            }

            is RealPingEvent.SpeedResult -> {
                MmkvManager.encodeServerTestSpeedBytesPerSec(event.guid, event.speedBytesPerSec, event.stable)
                MessageHelper.sendMsg2UI(this, AppConfig.MSG_MEASURE_CONFIG_SUCCESS, event.guid)
            }

            is RealPingEvent.Finish -> {
                applyFinishActions(message, isWhitelistSearch)

                MessageHelper.sendMsg2UI(this, AppConfig.MSG_MEASURE_CONFIG_FINISH, event.status)
                onWorkerDone()
                // Останавливаемся, только когда не осталось НИ ОДНОГО воркера
                // обоих видов. Прежняя проверка учитывала лишь activeWorkers,
                // поэтому финиш обычного теста задержки мог остановить сервис,
                // пока «Поиск стабильных профилей» ещё работал (и наоборот).
                if (activeWorkers.isEmpty() && activeWhitelistWorkers.isEmpty()) {
                    NotificationHelper.stopForeground(this)
                    stopSelf()
                }
            }
        }
    }

    /**
     * Действия на финише теста: авто-удаление недействительных профилей и
     * итоговая сортировка. СКОУП обоих берётся из [TestFinishScopePolicy] и
     * совпадает со скоупом измерения воркера — иначе на вкладке «Все» действия
     * не выполнялись вовсе, а при активном фильтре удалялись ещё и НЕ измеренные
     * в этом прогоне профили (потеря данных).
     *
     * Все три ветки авто-удаления используют ГОТОВЫЕ функции — ничего нового не
     * изобретается:
     *  - [TestFinishScopePolicy.InvalidCleanup.GUIDS] →
     *    `MmkvManager.removeInvalidServer(guid)` по каждому измеренному guid
     *    (функция сама удаляет только при `testDelayMillis < 0`);
     *  - [TestFinishScopePolicy.InvalidCleanup.SUBSCRIPTION] →
     *    [AngConfigManager.removeInvalidServer] (прежнее поведение);
     *  - [TestFinishScopePolicy.InvalidCleanup.ALL] →
     *    `MmkvManager.removeInvalidServer("")` — перебор всех записей, ровно как
     *    пункт меню «Удалить недействительные» на вкладке «Все».
     *
     * Сортировка: обычный тест задержки — по пингу и только под свитчом
     * [AppConfig.PREF_AUTO_SORT_AFTER_TEST] (прежнее поведение); «Поиск
     * стабильных профилей» — по СКОРОСТИ и БЕЗУСЛОВНО (требование владельца
     * 22.11.2026), потому что поиск заканчивается фазой скорости. Обе выполняются
     * ДО отправки FINISH: UI перезагружает список по FINISH, значит новый порядок
     * виден сразу, гонки нет.
     *
     * @param message сообщение запуска теста: из него берутся скоуп и подписка.
     * @param isWhitelistSearch true — финиш «Поиска стабильных профилей».
     */
    private fun applyFinishActions(message: TestServiceMessage, isWhitelistSearch: Boolean) {
        // Шаг 1: авто-удаление недействительных — только по свитчу (как и раньше).
        if (MmkvManager.decodeSettingsBool(AppConfig.PREF_AUTO_REMOVE_INVALID_AFTER_TEST, false)) {
            val removed = when (
                TestFinishScopePolicy.invalidCleanup(message.serverGuids, message.subscriptionId)
            ) {
                TestFinishScopePolicy.InvalidCleanup.GUIDS ->
                    message.serverGuids.sumOf { MmkvManager.removeInvalidServer(it) }

                TestFinishScopePolicy.InvalidCleanup.SUBSCRIPTION ->
                    AngConfigManager.removeInvalidServer(message.subscriptionId)

                TestFinishScopePolicy.InvalidCleanup.ALL ->
                    MmkvManager.removeInvalidServer("")
            }
            LogUtil.i(
                AppConfig.TAG,
                "Auto-remove invalid after test: $removed profile(s) removed " +
                    "(sub=${message.subscriptionId.ifEmpty { "all" }}, " +
                    "guids=${message.serverGuids.size})"
            )
        }

        // Шаг 2: итоговая сортировка. Скоуп списков общий для обоих видов теста.
        val sortTargets = TestFinishScopePolicy.sortTargets(
            subscriptionId = message.subscriptionId,
            subsList = MmkvManager.decodeSubsList(),
            defaultSubId = AppConfig.DEFAULT_SUBSCRIPTION_ID,
        )
        if (isWhitelistSearch) {
            sortTargets.forEach { AngConfigManager.sortBySpeedResultsForSub(it) }
            LogUtil.i(
                AppConfig.TAG,
                "Whitelist search finished: sorted by SPEED, ${sortTargets.size} list(s)"
            )
        } else if (MmkvManager.decodeSettingsBool(AppConfig.PREF_AUTO_SORT_AFTER_TEST, false)) {
            sortTargets.forEach { AngConfigManager.sortByTestResultsForSub(it) }
            LogUtil.i(
                AppConfig.TAG,
                "Delay test finished: sorted by PING, ${sortTargets.size} list(s)"
            )
        }
    }

    private fun handleMeasureCancel() {
        MessageHelper.sendMsg2UI(this, AppConfig.MSG_MEASURE_CONFIG_FINISH, "0")
        LogUtil.i(AppConfig.TAG, "CoreTestService received cancel message, cancelling ${activeWorkers.size} active workers")
        val snapshot = ArrayList(activeWorkers)
        snapshot.forEach { it.cancel() }
        activeWorkers.clear()
        val wlSnapshot = ArrayList(activeWhitelistWorkers)
        wlSnapshot.forEach { it.cancel() }
        activeWhitelistWorkers.clear()
        NotificationHelper.stopForeground(this)
        stopSelf()
    }
}
