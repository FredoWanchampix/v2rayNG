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
 * So the decision is three-way, and the core's own state is checked FIRST:
 *  - nothing running                  -> "no active profile" (a leftover
 *                                        listener must not be trusted);
 *  - listener up                      -> go through it (works in every mode);
 *  - profile running, no listener     -> cannot honour the request; report it
 *                                        instead of silently falling back.
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
        // The loopback HTTP inbound is the ONLY in-app path that can carry a
        // request through the profile: the app exempts itself from its own tunnel
        // (addDisallowedApplication / --uid-owner RETURN), so a direct socket
        // would bypass the profile. Probe it FIRST: it is a cross-process check
        // (a TCP connect), so it works from the UI (:main) and :tasks processes.
        //
        // CRITICAL regression fix: CoreServiceManager.isRunning() reads the NATIVE
        // core state, which exists only inside the :daemon process. Called from the
        // UI process it is ALWAYS false, so making it the primary gate reported
        // "no active profile" even while the proxy was up and serving - exactly the
        // bug that broke subscription updates, update checks and geo downloads "via
        // the active profile". It is used only to DISTINGUISH the two failure modes
        // below, never to veto a working listener.
        val httpPort = SettingsManager.getHttpPort()
        if (httpPort > 0 && HttpUtil.isLocalProxyAvailable(httpPort)) {
            val liveCreds = SettingsManager.readLocalProxyCredentials()
            return Route(
                mode = Mode.LOCAL_HTTP_PROXY,
                httpPort = httpPort,
                proxyUsername = liveCreds?.first ?: SettingsManager.getSocksUsername(),
                proxyPassword = liveCreds?.second ?: SettingsManager.getSocksPassword(),
                profileRunning = true,
                routedViaProfile = true,
            )
        }

        // No listener. A profile can still be active (plain VPN-tun with the local
        // proxy switch off, or an FPTN profile that runs fptn-client with its own
        // TUN and no HTTP inbound). Determine that with a CROSS-PROCESS signal: the
        // :daemon process publishes its PID to MMKV, so any process can tell whether
        // the core/FPTN daemon is alive without touching native state.
        if (isCoreProcessAlive()) {
            return Route(mode = Mode.PROFILE_WITHOUT_LOCAL_PROXY, profileRunning = true)
        }

        return Route(mode = Mode.NONE)
    }

    /**
     * True when the core/FPTN daemon process is running, evaluated correctly from
     * ANY process. Inside :daemon the native flag is authoritative; from the UI and
     * :tasks processes we fall back to the PID the daemon published to MMKV and
     * check that the process is still alive.
     */
    private fun isCoreProcessAlive(): Boolean {
        // Same process as the core daemon: the native state is the truth here.
        val published = MmkvManager.decodeSettingsInt(AppConfig.PREF_CORE_DAEMON_PID, 0)
        if (published > 0 && published == Process.myPid()) {
            return runCatching { CoreServiceManager.isRunning() }.getOrDefault(false)
        }
        // Different process: trust the published PID only while it is alive.
        return published > 0 && File("/proc/$published").exists()
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
