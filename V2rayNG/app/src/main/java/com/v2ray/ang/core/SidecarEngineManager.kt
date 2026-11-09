package com.v2ray.ang.core

import android.content.Context
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

    /** Asset/executable name per engine, null when the profile needs no sidecar. */
    fun engineFor(type: EConfigType): String? = when (type) {
        EConfigType.AMNEZIAWG -> "mihomo"
        EConfigType.NAIVE, EConfigType.OPENCONNECT -> "sing-box"
        EConfigType.MIMIC -> "mimic-client"
        else -> null
    }

    /** True when the profile type is served by a sidecar engine. */
    fun needsSidecar(profile: ProfileItem?): Boolean =
        profile != null && engineFor(profile.configType) != null

    /**
     * Makes sure the sidecar required by [profile] is running, stopping any
     * sidecar that belongs to a different profile. No-op for Xray-native types.
     */
    @Synchronized
    fun syncForProfile(context: Context, profile: ProfileItem?) {
        val engine = profile?.let { engineFor(it.configType) }
        if (engine == null) {
            stopAll()
            return
        }
        if (currentGuid == profile.guid && isAlive() && isPortOpen(currentPort)) return
        stopAll()
        ensureRunning(context, profile, engine)
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
        val binary = ensureBinary(context, engine)
        if (binary == null) {
            error("Sidecar engine '$engine' is not bundled with this build")
        }
        val port = Utils.findRandomFreePort()
        val configText = SidecarConfigBuilder.build(profile, engine, port)
            ?: error("Cannot build a sidecar config for ${profile.configType}")
        val ext = if (engine == "mihomo" || engine == "mimic-client") "yaml" else "json"
        val config = File(context.filesDir, "engines/$engine-$port.$ext").apply {
            parentFile?.mkdirs()
            writeText(configText)
        }
        val command = when (engine) {
            "mihomo" -> listOf(binary.absolutePath, "-d", binary.parentFile!!.absolutePath, "-f", config.absolutePath)
            "mimic-client" -> listOf(binary.absolutePath, "-config", config.absolutePath)
            else -> listOf(binary.absolutePath, "run", "-c", config.absolutePath, "--disable-color")
        }
        val log = File(context.filesDir, "engines/$engine.log")
        val started = ProcessBuilder(command)
            .redirectErrorStream(true)
            .redirectOutput(log)
            .start()
        if (!waitPort(port)) {
            runCatching { started.destroy() }
            error("Sidecar engine '$engine' did not open port $port; see ${log.name}")
        }
        process = started
        currentPort = port
        currentGuid = profile.guid
        LogUtil.i(AppConfig.TAG, "SidecarEngineManager: $engine up on 127.0.0.1:$port for ${profile.remarks}")
    }

    /** Exposed for [FptnRootRunner], which starts its binary outside this manager. */
    fun ensureBinaryPublic(context: Context, engine: String): File? = ensureBinary(context, engine)

    private fun ensureBinary(context: Context, engine: String): File? {
        val target = File(context.filesDir, "engines/$engine")
        if (target.isFile && target.canExecute()) return target
        return try {
            context.assets.open("engines/$engine").use { input ->
                target.parentFile?.mkdirs()
                target.outputStream().use { output -> input.copyTo(output) }
            }
            target.setExecutable(true, true)
            if (target.canExecute()) target else null
        } catch (e: Exception) {
            LogUtil.w(AppConfig.TAG, "SidecarEngineManager: no bundled engine '$engine': ${e.message}")
            null
        }
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
