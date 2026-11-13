package com.v2ray.ang.fmt

import com.v2ray.ang.AppConfig
import com.v2ray.ang.dto.entities.ProfileItem
import com.v2ray.ang.enums.EConfigType
import com.v2ray.ang.extension.idnHost
import com.v2ray.ang.util.Utils
import java.net.URI

/**
 * Parses FPTN access links: fptn://user:pass@host:port?token=...&sni=...#remark
 *
 * The access token travels in the `token` query parameter, matching the
 * fptn-client CLI flag (the JWT in `--access-token` is the primary credential and
 * already carries the server list, so the host/port part of the link is only a
 * display hint).
 *
 * `sni` is carried through as well: the editor exposes it and FptnRootRunner
 * passes it to the client as `--sni` for TLS obfuscation, so a link that sets it
 * must not lose it on import. The same key is written back on export.
 *
 * Query keys are matched case-insensitively (`token`/`Token`, `sni`/`SNI`) for
 * the same reason as in [AmneziaFmt]: panels capitalise parameter names and a
 * case-sensitive lookup silently drops them.
 */
object FptnFmt : FmtBase() {

    private fun Map<String, String>.ci(key: String): String? =
        this[key] ?: entries.firstOrNull { it.key.equals(key, ignoreCase = true) }?.value

    fun parse(str: String): ProfileItem? {
        val config = ProfileItem.create(EConfigType.FPTN)
        val normalized = str.replace(AppConfig.FPTN, "https://")
        val uri = URI(Utils.fixIllegalUrl(normalized))
        config.remarks = Utils.decodeURIComponent(uri.fragment.orEmpty()).let { it.ifEmpty { "none" } }
        config.server = uri.idnHost
        config.serverPort = uri.port.toString()
        val userInfo = uri.userInfo
        if (!userInfo.isNullOrEmpty()) {
            val idx = userInfo.indexOf(':')
            if (idx > 0) {
                config.username = Utils.decodeURIComponent(userInfo.substring(0, idx))
                config.password = Utils.decodeURIComponent(userInfo.substring(idx + 1))
            } else {
                config.username = Utils.decodeURIComponent(userInfo)
            }
        }
        if (uri.rawQuery.isNullOrEmpty()) return config
        val query = getQueryParam(uri)
        config.fptnToken = query.ci("token") ?: query.ci("access_token")
        config.sni = query.ci("sni")?.takeIf { it.isNotBlank() }
        return config
    }

    fun toUri(config: ProfileItem): String {
        val userInfo = Utils.encodeURIComponent(config.username.orEmpty()) + ":" +
                Utils.encodeURIComponent(config.password.orEmpty())
        val params = buildList {
            config.fptnToken?.takeIf { it.isNotBlank() }
                ?.let { add("token=${Utils.encodeURIComponent(it)}") }
            config.sni?.takeIf { it.isNotBlank() }
                ?.let { add("sni=${Utils.encodeURIComponent(it)}") }
        }
        val query = if (params.isEmpty()) "" else "?" + params.joinToString("&")
        // Returns the body only: AngConfigManager.shareConfig prepends
        // `protocolScheme` itself, so emitting AppConfig.FPTN here would produce
        // a doubled `fptn://fptn://` prefix. Matches the WireguardFmt contract.
        return "$userInfo@${config.server}:${config.serverPort}$query#${Utils.encodeURIComponent(config.remarks)}"
    }
}
