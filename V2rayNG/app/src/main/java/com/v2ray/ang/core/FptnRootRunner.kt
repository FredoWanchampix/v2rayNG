package com.v2ray.ang.core

import android.content.Context
import com.v2ray.ang.AppConfig
import com.v2ray.ang.dto.entities.ProfileItem
import com.v2ray.ang.root.RootShell
import com.v2ray.ang.util.LogUtil
import java.io.File

/**
 * Runs the FPTN client as a standalone root-mode VPN provider.
 *
 * Unlike the SOCKS sidecars, fptn-client creates and owns its own TUN
 * interface, so it replaces the whole Xray + hev-tun stack for FPTN profiles.
 * In VpnService mode Android allows only one VPN slot, therefore FPTN profiles
 * are served in root mode only; the UI reports that explicitly.
 */
object FptnRootRunner {

    private const val TUN_NAME = "fptn0"
    private const val PID_FILE = "engines/fptn-client.pid"
    private const val LOG_FILE = "engines/fptn-client.log"

    @Volatile
    var active: Boolean = false
        private set

    fun start(context: Context, profile: ProfileItem): Boolean {
        stop(context)
        val binary = SidecarEngineManager.ensureBinaryPublic(context, "fptn-client")
        if (binary == null) {
            LogUtil.e(AppConfig.TAG, "FptnRootRunner: fptn-client binary is not bundled")
            return false
        }
        val token = profile.fptnToken.orEmpty()
        val args = buildList {
            add("--access-token"); add(token)
            add("--server-ip"); add(profile.server.orEmpty())
            add("--server-port"); add(profile.serverPort.orEmpty())
            add("--username"); add(profile.username.orEmpty())
            add("--tun-interface-name"); add(TUN_NAME)
            profile.sni?.takeIf { it.isNotBlank() }?.let { add("--sni"); add(it) }
        }.joinToString(" ") { "\'" + it.replace("'", "'\\''") + "\'" }
        val pidFile = File(context.filesDir, PID_FILE).absolutePath
        val logFile = File(context.filesDir, LOG_FILE).absolutePath
        val script = buildString {
            appendLine("nohup '${binary.absolutePath}' $args >'$logFile' 2>&1 &")
            appendLine("echo \$! > '$pidFile'")
            appendLine("i=0; while [ \$i -lt 30 ]; do ip link show $TUN_NAME >/dev/null 2>&1 && break; sleep 0.3; i=\$((i+1)); done")
            appendLine("ip link show $TUN_NAME >/dev/null 2>&1 || { echo 'fptn tun did not come up'; cat '$logFile' 2>/dev/null | tail -5; exit 1; }")
        }
        val result = RootShell.runScript(context, "fptn_start.sh", script)
        if (!result.success) {
            LogUtil.e(AppConfig.TAG, "FptnRootRunner: start failed: ${result.output}")
            stop(context)
            return false
        }
        active = true
        LogUtil.i(AppConfig.TAG, "FptnRootRunner: fptn-client up on $TUN_NAME")
        return true
    }

    fun stop(context: Context) {
        val pidFile = File(context.filesDir, PID_FILE).absolutePath
        val script = buildString {
            appendLine("[ -f '$pidFile' ] && kill \$(cat '$pidFile') 2>/dev/null")
            appendLine("rm -f '$pidFile'")
            appendLine("ip link del $TUN_NAME 2>/dev/null || true")
        }
        RootShell.runScript(context, "fptn_stop.sh", script)
        active = false
    }
}
