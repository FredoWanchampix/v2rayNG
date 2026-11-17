package com.v2ray.ang.core

import android.content.Context
import android.os.Build
import com.v2ray.ang.AppConfig
import com.v2ray.ang.dto.entities.ProfileItem
import com.v2ray.ang.enums.EConfigType
import com.v2ray.ang.util.LogUtil
import com.v2ray.ang.util.Utils
import java.io.File
import java.net.InetSocketAddress
import java.net.Socket

/**
 * Manages sidecar proxy engines (sing-box, mihomo, Mimic, FPTN client).
 *
 * A sidecar runs as a standalone executable process (the same pattern the fork
 * already uses for libhevsockstun in root mode) and exposes a local mixed
 * (SOCKS/HTTP) port. The Xray core then treats that port as an upstream socks
 * proxy, so hev-tun, proxy mode and the service lifecycle stay untouched.
 *
 * РАСПОЛОЖЕНИЕ БИНАРНИКОВ (критично). Движок упакован в APK как lib*.so в
 * libs/<abi>/ и исполняется из nativeLibraryDir. Копирование из assets в
 * filesDir и запуск оттуда на Android 10+ НЕВОЗМОЖНЫ: SELinux-политика W^X
 * запрещает домену untrusted_app исполнять файлы с контекстом app_data_file
 * (filesDir) и shell_data_file (/data/local/tmp) - execve вернёт EACCES.
 * nativeLibraryDir имеет контекст apk_data_file: исполнение оттуда разрешено
 * и приложению, и root (проверено на устройстве, Android 16/API 36).
 *
 * Loop safety: in VPN mode the app package is excluded from the tunnel
 * (VpnService.Builder.addDisallowedApplication), in root mode the app uid is
 * returned from the mark chain, so sidecar sockets never re-enter the tunnel.
 */
object SidecarEngineManager {

    /** Local mixed port of the running sidecar, 0 when none is running. */
    @Volatile
    var currentPort: Int = 0
        private set

    @Volatile
    private var currentGuid: String? = null

    @Volatile
    private var process: Process? = null

    private const val PORT_WAIT_MS = 10_000L

    /**
     * ЕДИНСТВЕННАЯ блокировка всех проб, поднимающих движок, для всего процесса.
     *
     * [currentPort] один на процесс, поэтому две параллельные пробы сайдкар-профилей
     * перезаписали бы порт друг друга. Проверяющая код выполняется из разных мест
     * (обычный тест задержки, «поиск стабильных профилей», проба скорости), и эти
     * места могут работать одновременно - поэтому блокировка обязана быть общей,
     * а не своей у каждого вызывающего. Иначе две разные блокировки не дали бы
     * никакой защиты: каждая считала бы, что владеет движком единолично.
     */
    private val probeLock = Any()

    /** Выполняет [block] монопольно относительно всех остальных проб движка. */
    fun <T> runExclusiveProbe(block: () -> T): T = synchronized(probeLock) { block() }

    // Логические имена движков. Они же используются в именах конфигов и логов
    // внутри filesDir/engines (данные писать туда разрешено - запрещено только
    // ИСПОЛНЯТЬ оттуда).
    const val ENGINE_MIHOMO = "mihomo"
    const val ENGINE_SINGBOX = "sing-box"
    const val ENGINE_MIMIC = "mimic-client"
    const val ENGINE_FPTN = "fptn-client"
    const val ENGINE_DNSPROXY = "dnsproxy"
    const val ENGINE_SPEEDPROBE = "speedprobe"

    /** Все движки, которые форк упаковывает как lib*.so в libs/<abi>/. */
    val ALL_ENGINES: List<String> = listOf(
        ENGINE_MIHOMO,
        ENGINE_SINGBOX,
        ENGINE_MIMIC,
        ENGINE_FPTN,
        ENGINE_DNSPROXY,
        ENGINE_SPEEDPROBE,
    )

    /** Asset/executable name per engine, null when the profile needs no sidecar. */
    fun engineFor(type: EConfigType): String? = when (type) {
        EConfigType.AMNEZIAWG -> ENGINE_MIHOMO
        // Hysteria v1: Xray форка не имеет v1-outbound, sing-box собран без
        // QUIC ("QUIC is not included in this build", эксперимент check),
        // а mihomo v1.19.33 принимает hysteria-outbound (`mihomo -t` green).
        EConfigType.HYSTERIA -> ENGINE_MIHOMO
        EConfigType.NAIVE, EConfigType.OPENCONNECT -> ENGINE_SINGBOX
        EConfigType.MIMIC -> ENGINE_MIMIC
        else -> null
    }

    /**
     * Карта «логическое имя движка -> имя lib*.so в nativeLibraryDir».
     *
     * Имя обязано начинаться с "lib" и заканчиваться на ".so": PackageManager
     * извлекает в nativeLibraryDir только такие записи из lib/<abi>/ APK.
     * Константы лежат в [AppConfig] рядом с ROOT_TUN2SOCKS_BIN (тот же паттерн).
     *
     * @return null для неизвестного имени, чтобы опечатка не превратилась
     *   в молчаливый запуск несуществующего файла.
     */
    fun libNameFor(engine: String): String? = when (engine) {
        ENGINE_MIHOMO -> AppConfig.ENGINE_MIHOMO_BIN
        ENGINE_SINGBOX -> AppConfig.ENGINE_SINGBOX_BIN
        ENGINE_MIMIC -> AppConfig.ENGINE_MIMIC_BIN
        ENGINE_FPTN -> AppConfig.ENGINE_FPTN_BIN
        ENGINE_DNSPROXY -> AppConfig.ENGINE_DNSPROXY_BIN
        ENGINE_SPEEDPROBE -> AppConfig.ENGINE_SPEEDPROBE_BIN
        else -> null
    }

    /**
     * Исполняемый файл движка в nativeLibraryDir или null, если он недоступен.
     *
     * Ничего не копирует и не создаёт: установщик уже извлёк lib*.so из APK.
     * Отдельно различает две причины отказа - файла нет вовсе (движок не
     * собран для ABI этого APK) и файл есть, но не исполняем (сломан
     * extractNativeLibs) - потому что лечатся они по-разному, а пользователю
     * нужен честный диагноз, а не общее «движок не запустился».
     */
    fun engineBinary(context: Context, engine: String): File? {
        val libName = libNameFor(engine)
        if (libName == null) {
            LogUtil.w(AppConfig.TAG, "SidecarEngineManager: неизвестный движок '$engine'")
            return null
        }
        val dir = context.applicationInfo.nativeLibraryDir
        val file = File(dir, libName)
        if (!file.isFile) {
            LogUtil.w(
                AppConfig.TAG,
                "SidecarEngineManager: $libName отсутствует в $dir (ABI=${primaryAbi()})",
            )
            return null
        }
        if (!file.canExecute()) {
            LogUtil.e(
                AppConfig.TAG,
                "SidecarEngineManager: $libName в $dir не исполняем " +
                    "(проверьте packaging.jniLibs.useLegacyPackaging/extractNativeLibs)",
            )
            return null
        }
        return file
    }

    /**
     * Человекочитаемое объяснение, почему движок не может быть запущен.
     * Попадает в текст исключения при старте профиля, поэтому обязан называть
     * и ABI, и ожидаемый файл - иначе «не запускается» невозможно диагностировать.
     */
    fun missingEngineMessage(context: Context, engine: String): String {
        val libName = libNameFor(engine)
            ?: return "Sidecar engine '$engine' is not known to this build"
        val dir = context.applicationInfo.nativeLibraryDir
        return "Sidecar engine '$engine' ($libName) is unavailable for ABI '${primaryAbi()}' " +
            "in this build: $dir/$libName is missing or not executable"
    }

    private fun primaryAbi(): String = Build.SUPPORTED_ABIS.firstOrNull() ?: "unknown"

    /** True when the profile type is served by a sidecar engine. */
    fun needsSidecar(profile: ProfileItem?): Boolean =
        profile != null && engineFor(profile.configType) != null

    /**
     * True, когда профиль ВООБЩЕ нельзя измерить временным ядром.
     *
     * Сейчас это только FPTN: для него Xray-конфиг не строится вовсе, fptn-client
     * владеет собственным TUN, поэтому временного ядра для пробы не существует.
     *
     * Сайдкар-типы (AmneziaWG, NaiveProxy, OpenConnect, Mimic) сюда НЕ входят: их
     * можно измерить, если поднять движок в том же процессе, где выполняется проба
     * (см. [acquireForProbe]). Раньше они ошибочно попадали в эту категорию и
     * получали фиктивные -1/0, из-за чего «Удалить недействительные» и «Удалить
     * нулевые» стирали рабочие профили пользователя.
     */
    fun cannotMeasureInTempCore(type: EConfigType): Boolean = type == EConfigType.FPTN

    /** True, если для измерения профиля нужен локально поднятый сайдкар-движок. */
    fun needsProbeEngine(type: EConfigType): Boolean = engineFor(type) != null

    /**
     * Makes sure the sidecar required by [profile] is running, stopping any
     * sidecar that belongs to a different profile. No-op for Xray-native types.
     */
    @Synchronized
    fun syncForProfile(context: Context, profile: ProfileItem?, guid: String?) {
        val engine = profile?.let { engineFor(it.configType) }
        if (engine == null) {
            stopAll()
            return
        }
        if (guid != null && currentGuid == guid && isAlive() && isPortOpen(currentPort)) return
        stopAll()
        ensureRunning(context, profile, engine)
        currentGuid = guid
    }

    @Synchronized
    fun stopAll() {
        process?.let {
            runCatching { it.destroy() }
            runCatching { it.waitFor() }
        }
        process = null
        currentPort = 0
        currentGuid = null
    }

    private fun ensureRunning(context: Context, profile: ProfileItem, engine: String) {
        val binary = engineBinary(context, engine)
            ?: error(missingEngineMessage(context, engine))
        val port = Utils.findRandomFreePort()
        val configText = SidecarConfigBuilder.build(profile, engine, port)
            ?: error("Cannot build a sidecar config for ${profile.configType}")
        val ext = if (engine == ENGINE_MIHOMO || engine == ENGINE_MIMIC) "yaml" else "json"
        // Каталоги данных: конфиг и лог. binary.parentFile использовать НЕЛЬЗЯ -
        // это nativeLibraryDir, он только для чтения (владелец system:system),
        // а mihomo пишет в -d свою рабочую директорию.
        val dataDir = File(context.filesDir, "engines").apply { mkdirs() }
        val config = File(dataDir, "$engine-$port.$ext").apply { writeText(configText) }
        val command = when (engine) {
            ENGINE_MIHOMO -> listOf(binary.absolutePath, "-d", dataDir.absolutePath, "-f", config.absolutePath)
            ENGINE_MIMIC -> listOf(binary.absolutePath, "-config", config.absolutePath)
            else -> listOf(binary.absolutePath, "run", "-c", config.absolutePath, "--disable-color")
        }
        val log = File(dataDir, "$engine.log")
        val started = ProcessBuilder(command)
            .redirectErrorStream(true)
            .redirectOutput(log)
            .start()
        if (!waitPort(port)) {
            runCatching { started.destroy() }
            // Полный путь к логу обязателен: движок теперь живёт в read-only
            // nativeLibraryDir, а логи - в filesDir, и «see $engine.log» без пути
            // не позволяет найти файл ни пользователю, ни при отладке.
            error("Sidecar engine '$engine' did not open port $port; see ${log.absolutePath}")
        }
        process = started
        currentPort = port
        LogUtil.i(AppConfig.TAG, "SidecarEngineManager: $engine up on 127.0.0.1:$port for ${profile.remarks}")
    }

    /**
     * Поднимает движок профиля в ТЕКУЩЕМ процессе на время пробы и гарантирует,
     * что по её завершении он остановлен.
     *
     * Зачем это нужно. [currentPort] - это состояние объекта, а объект в Android
     * свой для каждого процесса. Основной профиль поднимает движок в :daemon,
     * а проверка скорости и «поиск стабильных профилей» выполняют временное ядро
     * в :tasks, где currentPort равен 0. Поэтому [CoreOutboundBuilder.toOutboundSidecar]
     * падал с «Sidecar engine is not running», конфиг пробы не собирался, профиль
     * получал фиктивную задержку -1 и скорость 0 - и затем «Удалить нулевые» /
     * «Удалить недействительные» стирали РАБОЧИЙ профиль пользователя.
     *
     * Здесь движок поднимается локально в процессе пробы (на случайном свободном
     * порту, независимом от порта основного профиля), временное ядро подключается
     * к нему как к SOCKS-upstream, и измерение становится честным.
     *
     * Вызов ОБЯЗАН быть сериализован: [currentPort] общий для процесса, поэтому
     * две параллельные пробы сайдкар-профилей перезаписали бы порт друг друга.
     * Сериализацию обеспечивает RealPingExecutionLimiter.
     *
     * @return true, если движок поднят (или профиль его не требует), false при сбое.
     */
    fun acquireForProbe(context: Context, profile: ProfileItem?, guid: String?): Boolean {
        if (profile == null || engineFor(profile.configType) == null) return true
        return try {
            syncForProfile(context, profile, guid)
            currentPort > 0
        } catch (e: Exception) {
            LogUtil.e(
                AppConfig.TAG,
                "SidecarEngineManager: не удалось поднять ${profile.configType} для пробы: ${e.message}",
                e,
            )
            false
        }
    }

    /** Останавливает движок, поднятый [acquireForProbe]. Безопасно звать всегда. */
    fun releaseAfterProbe() {
        stopAll()
    }

    private fun isAlive(): Boolean = process?.isAlive == true

    private fun isPortOpen(port: Int): Boolean =
        port > 0 && runCatching { Socket().use { it.connect(InetSocketAddress("127.0.0.1", port), 400); true } }
            .getOrDefault(false)

    private fun waitPort(port: Int): Boolean {
        val deadline = System.currentTimeMillis() + PORT_WAIT_MS
        while (System.currentTimeMillis() < deadline) {
            if (isPortOpen(port)) return true
            if (process?.isAlive != true) return false
            Thread.sleep(200)
        }
        return isPortOpen(port)
    }
}
