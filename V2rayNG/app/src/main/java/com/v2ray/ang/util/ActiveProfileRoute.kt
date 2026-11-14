package com.v2ray.ang.util

import com.v2ray.ang.AppConfig
import com.v2ray.ang.core.CoreServiceManager
import com.v2ray.ang.handler.SettingsManager

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
        val running = runCatching { CoreServiceManager.isRunning() }.getOrDefault(false)

        // Not running wins over "something answered the TCP probe". A listener
        // left behind by a previous core run (or another app on the same port)
        // still accepts a connect, and routing through it would send the request
        // into a dead proxy. The state of the core is the authoritative signal.
        if (!running) {
            return Route(mode = Mode.NONE)
        }

        val httpPort = SettingsManager.getHttpPort()
        val httpUp = httpPort > 0 && HttpUtil.isLocalProxyAvailable(httpPort)
        if (httpUp) {
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

        return Route(mode = Mode.PROFILE_WITHOUT_LOCAL_PROXY, profileRunning = true)
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
