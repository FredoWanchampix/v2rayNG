package com.v2ray.ang.util

import android.os.Process
import com.v2ray.ang.AppConfig
import com.v2ray.ang.core.CoreServiceManager
import com.v2ray.ang.handler.MmkvManager
import com.v2ray.ang.handler.SettingsManager
import java.io.File

/**
 * Resolves how an in-app HTTP fetch (subscription update, update check) must be
 * routed when the user asked for it to travel through the active profile.
 *
 * Why a port probe alone is not enough
 * ------------------------------------
 * Both callers used to decide with a single TCP connect to the loopback HTTP
 * port. That answers "is something listening", not "is a profile active", and
 * the two disagree in real configurations:
 *
 *  - The loopback HTTP inbound only exists when the core was configured with
 *    `enableLocalProxy` (see CoreConfigManager.configureInbounds). It is forced on
 *    for hev-tun and root modes, but in plain VPN-tun mode it follows the user's
 *    "local proxy" switch. With that switch off, a profile can be fully active
 *    while nothing listens on the port - the probe said "no active profile" and
 *    the caller silently gave up.
 *  - An FPTN profile runs fptn-client instead of the Xray core
 *    (CoreServiceManager.isRunning() = coreController.isRunning ||
 *    FptnRootRunner.active), so again there is no HTTP inbound while a profile is
 *    active.
 *  - Conversely a listener left over from a previous run can still accept a TCP
 *    connect after the core stopped, so the probe can also report a profile that
 *    is gone.
 *
 * Why "just connect directly" is WRONG in tun/root mode
 * -----------------------------------------------------
 * The app deliberately exempts itself from its own tunnel: VpnService calls
 * `addDisallowedApplication(selfPackageName)` (CoreVpnService.configurePerAppProxy)
 * and root mode installs `-m owner --uid-owner <appUid> -j RETURN`
 * (RootProxyManager.buildMangleMarking). A direct socket therefore bypasses the
 * profile entirely and would leak the request outside the tunnel - precisely the
 * opposite of "update only via the active profile". The only correct in-app route
 * is the loopback HTTP proxy, which forwards into the core.
 *
 * Run-mode matrix (what CoreConfigManager.configureInbounds actually builds)
 * -----------------------------------------------------------------------
 *  - VPN + hev-tun ............ HTTP inbound FORCED on  -> proxy reachable
 *  - VPN + hev-tun + per-app ... HTTP inbound FORCED on  -> proxy reachable
 *      (bypass OR allow-only: in BOTH the app exempts itself from its own
 *       tunnel, so a direct socket would bypass the profile either way)
 *  - Root mode ................ HTTP inbound FORCED on  -> proxy reachable
 *  - Root + LAN sharing ....... HTTP inbound FORCED on  -> proxy reachable
 *  - Proxy-only ............... HTTP inbound on by default (PREF_ENABLE_LOCAL_PROXY)
 *  - Plain VPN-tun, proxy ON .. HTTP inbound on         -> proxy reachable
 *  - Plain VPN-tun, proxy OFF . NO HTTP inbound, profile alive -> must REFUSE
 *  - FPTN (root) .............. NO Xray inbound at all, fptn owns the TUN -> REFUSE
 *  - Nothing running .......... NO inbound, daemon dead -> "no active profile"
 *
 * So the decision reduces to two cross-process signals:
 *  1. is the loopback HTTP inbound listening right now?  (a TCP probe: works
 *     from the UI :main and :tasks processes, unlike the native core flag)
 *  2. is the core/FPTN daemon process alive?             (PID published to MMKV)
 * and the pure mapping [decideMode] turns them into the Mode. The listener, when
 * up, is ground truth that a usable in-app proxy exists, so it wins; otherwise a
 * live daemon without a listener means "profile on but cannot be honoured" and a
 * dead daemon means "nothing running".
 *
 * Both signals must be read CROSS-PROCESS. The port comes from [resolveHttpPort]
 * (value published by the daemon, or the tunnel runtime config), NOT from
 * SettingsManager.getHttpPort(): with a dynamic SOCKS port that getter derives the
 * port from a per-process variable, so the UI process would probe a port nobody
 * listens on and wrongly conclude "no active profile".
 */
object ActiveProfileRoute {

    enum class Mode {
        /** No profile is running at all. */
        NONE,

        /** The loopback HTTP inbound is listening; route the request through it. */
        LOCAL_HTTP_PROXY,

        /**
         * A profile is running but no loopback HTTP inbound exists, so the request
         * cannot be forced through the profile. Callers that require the active
         * profile must refuse here rather than fetch directly, because the app
         * exempts itself from its own tunnel and a direct fetch would bypass it.
         */
        PROFILE_WITHOUT_LOCAL_PROXY,
    }

    data class Route(
        val mode: Mode,
        /** Loopback HTTP port to use, or 0 when the request must go direct. */
        val httpPort: Int = 0,
        val proxyUsername: String? = null,
        val proxyPassword: String? = null,
        /** True when a profile is running in any mode (core or FPTN). */
        val profileRunning: Boolean = false,
        /** True when the resolved route really carries traffic through the profile. */
        val routedViaProfile: Boolean = false,
    )

    /**
     * Pure mapping from the two cross-process signals to a [Mode]. Extracted so the
     * whole run-mode matrix can be unit-tested without Android, sockets or MMKV.
     *
     * @param portListening the loopback HTTP inbound accepted a TCP connect now.
     * @param coreAlive the core/FPTN daemon process is alive (native flag inside
     *   :daemon, published PID elsewhere).
     */
    internal fun decideMode(portListening: Boolean, coreAlive: Boolean): Mode = when {
        // A live loopback listener is the one in-app path that carries the request
        // through the profile in EVERY mode that builds an HTTP inbound (hev-tun,
        // root, root+LAN, proxy-only, VPN-tun with the local proxy on). It is ground
        // truth, so it wins over the daemon-liveness signal.
        portListening -> Mode.LOCAL_HTTP_PROXY
        // Profile is up but there is no HTTP inbound to force the request through
        // (plain VPN-tun with the local proxy off, or FPTN which owns its own TUN).
        // Callers must REFUSE here: the app exempts itself from its own tunnel, so a
        // direct fetch would bypass the profile - the opposite of what was asked.
        coreAlive -> Mode.PROFILE_WITHOUT_LOCAL_PROXY
        // Nothing is running; a leftover listener (if any) is not trusted because the
        // daemon that owned it is gone.
        else -> Mode.NONE
    }

    /**
     * Determines the route to use right now.
     *
     * Credentials are read from the runtime tunnel config first
     * (hev-socks5-tunnel.yaml / sys_cache/tun2socks.yml) and only then from the
     * persisted settings: the core writes the values it actually enforces into
     * its runtime config, while the settings may lag behind a change made while
     * the core was already running, or carry no credentials at all. Using the
     * stale pair makes the proxy answer HTTP 407.
     */
    fun resolve(): Route {
        // Two cross-process signals, then one pure decision. See decideMode() and the
        // run-mode matrix in the class doc for why the port probe (not the native core
        // flag) is authoritative from the UI/:tasks processes.
        val httpPort = resolveHttpPort()
        val portListening = httpPort > 0 && HttpUtil.isLocalProxyAvailable(httpPort)
        val coreAlive = isCoreProcessAlive()

        return when (val mode = decideMode(portListening, coreAlive)) {
            Mode.LOCAL_HTTP_PROXY -> {
                // Credentials are read from the runtime tunnel config first
                // (hev-socks5-tunnel.yaml / sys_cache/tun2socks.yml) and only then from
                // the persisted settings: the core writes the values it actually
                // enforces into its runtime config, while the settings may lag behind a
                // change made while the core was already running, or carry none at all.
                // Using the stale pair makes the proxy answer HTTP 407.
                val liveCreds = SettingsManager.readLocalProxyCredentials()
                Route(
                    mode = mode,
                    httpPort = httpPort,
                    proxyUsername = liveCreds?.first ?: SettingsManager.getSocksUsername(),
                    proxyPassword = liveCreds?.second ?: SettingsManager.getSocksPassword(),
                    profileRunning = true,
                    routedViaProfile = true,
                )
            }
            Mode.PROFILE_WITHOUT_LOCAL_PROXY -> Route(mode = mode, profileRunning = true)
            Mode.NONE -> Route(mode = mode)
        }
    }

    /**
     * HTTP-порт loopback inbound, на котором ядро РЕАЛЬНО слушает.
     *
     * Порядок источников правды (все кросс-процессные):
     *  1. значение, опубликованное демоном в MMKV при старте ядра;
     *  2. порт из runtime-конфига туннеля (hev-socks5-tunnel.yaml / tun2socks.yml);
     *  3. SettingsManager.getHttpPort() как последний резерв.
     *
     * Почему нельзя просто звать SettingsManager.getHttpPort(): при включённом
     * «динамическом порте» он опирается на переменную runtimeSocksPort, которая
     * живёт внутри процесса. Демон сгенерировал один случайный порт, а UI-процесс
     * (:main) и :tasks сгенерировали бы ДРУГОЙ - и TCP-проба уходила бы не туда,
     * давая ложное «профиль выключен» ровно при работающем прокси.
     */
    internal fun resolveHttpPort(): Int {
        // Порядок важен и ленив: SettingsManager.getHttpPort() вызывается только
        // как последний резерв, потому что при включённом динамическом порте он
        // ГЕНЕРИРУЕТ случайный порт и кэширует его в переменной этого процесса -
        // бессмысленный побочный эффект, если у нас уже есть достоверный порт.
        val published = MmkvManager.decodeSettingsInt(AppConfig.PREF_CORE_HTTP_PORT, 0)
        if (published > 0) return published

        val runtime = SettingsManager.readRuntimeSocksPort()
        if (runtime != null && runtime > 0) return runtime + 1

        return pickHttpPort(0, null, SettingsManager.getHttpPort())
    }

    /**
     * Чистое правило выбора порта, покрытое unit-тестом.
     *
     * @param publishedHttpPort порт, который демон опубликовал в MMKV при старте
     *   ядра (0 - не опубликован).
     * @param runtimeSocksPort SOCKS-порт из runtime-конфига туннеля, null если
     *   конфиг недоступен. HTTP inbound всегда на socks+1.
     * @param settingsHttpPort значение из настроек - последний резерв. При
     *   включённом динамическом порте оно НЕДОСТОВЕРНО в чужом процессе.
     */
    internal fun pickHttpPort(
        publishedHttpPort: Int,
        runtimeSocksPort: Int?,
        settingsHttpPort: Int,
    ): Int {
        if (publishedHttpPort > 0) return publishedHttpPort
        if (runtimeSocksPort != null && runtimeSocksPort > 0) return runtimeSocksPort + 1
        return settingsHttpPort
    }

    /**
     * True when the core/FPTN daemon process is running, evaluated correctly from
     * ANY process. Inside :daemon the native flag is authoritative; from the UI and
     * :tasks processes we fall back to the PID the daemon published to MMKV and
     * check that the process is still alive.
     */
    private fun isCoreProcessAlive(): Boolean {
        val published = MmkvManager.decodeSettingsInt(AppConfig.PREF_CORE_DAEMON_PID, 0)
        if (published <= 0) return false

        // Same process as the core daemon: the native state is the truth here.
        if (published == Process.myPid()) {
            return runCatching { CoreServiceManager.isRunning() }.getOrDefault(false)
        }

        // Another process. "/proc/<pid> exists" alone is not enough: after a daemon
        // crash the PID can be recycled by an unrelated process, which would make us
        // report a profile that is gone (and then refuse the fetch forever). Verify
        // the process really is ours by comparing its cmdline.
        return isOurProcess(published)
    }

    /**
     * True when the given PID belongs to this application. Reads /proc/<pid>/cmdline,
     * which for Android holds the package/process name (e.g. "com.v2ray.ang:daemon").
     * Falls back to a mere existence check only if cmdline cannot be read, so a
     * hardened/unreadable /proc never turns a running profile into "none".
     */
    private fun isOurProcess(pid: Int): Boolean {
        val dir = File("/proc/$pid")
        if (!dir.exists()) return false
        val cmdline = try {
            // /proc/<pid>/cmdline завершается NUL-байтами; Kotlin trim() их убирает,
            // так как '\u0000' входит в набор пробельных символов.
            File(dir, "cmdline").readText().trim()
        } catch (e: Exception) {
            null
        }
        if (cmdline.isNullOrEmpty()) return true // unreadable: do not lie about "none"
        val pkg = AppConfig.ANG_PACKAGE
        return cmdline == pkg || cmdline.startsWith("$pkg:")
    }

    /** Human-readable description for logs and user-facing errors. */
    fun describe(route: Route): String = when (route.mode) {
        Mode.LOCAL_HTTP_PROXY -> "local http proxy 127.0.0.1:${route.httpPort}"
        Mode.PROFILE_WITHOUT_LOCAL_PROXY ->
            "profile running but the local proxy is not listening"
        Mode.NONE -> "no active profile"
    }

    /**
     * Logs the resolved decision together with the run mode, so a support report
     * shows why a fetch went through the proxy, was refused, or went direct.
     */
    fun log(what: String, route: Route) {
        LogUtil.i(
            AppConfig.TAG,
            "$what via ${describe(route)}; profileRunning=${route.profileRunning}, " +
                "vpnMode=${SettingsManager.isVpnMode()}, hevTun=${SettingsManager.isUsingHevTun()}, " +
                "rootMode=${SettingsManager.isRootMode()}"
        )
    }
}
