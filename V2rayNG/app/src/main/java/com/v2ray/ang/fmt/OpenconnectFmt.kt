package com.v2ray.ang.fmt

import com.v2ray.ang.AppConfig
import com.v2ray.ang.dto.entities.ProfileItem
import com.v2ray.ang.enums.EConfigType
import com.v2ray.ang.extension.idnHost
import com.v2ray.ang.util.Utils
import java.net.URI

/**
 * Parses OpenConnect / Cisco AnyConnect links:
 * anyconnect://user:pass@host:port?group=...&flavor=anyconnect
 * Also accepts the `openconnect://` spelling.
 */
object OpenconnectFmt : FmtBase() {

    fun parse(str: String): ProfileItem? {
        val config = ProfileItem.create(EConfigType.OPENCONNECT)
        val normalized = str
            .replace(AppConfig.OPENCONNECT, "https://")
            .replace(AppConfig.ANYCONNECT, "https://")
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
        config.ocservAuthGroup = query["group"] ?: query["authgroup"]
        config.ocservFlavor = query["flavor"] ?: "anyconnect"
        return config
    }

    fun toUri(config: ProfileItem): String {
        val params = buildList {
            config.ocservAuthGroup?.takeIf { it.isNotBlank() }?.let { add("group=${Utils.encodeURIComponent(it)}") }
            config.ocservFlavor?.takeIf { it.isNotBlank() && it != "anyconnect" }?.let { add("flavor=$it") }
        }
        val userInfo = Utils.encodeURIComponent(config.username.orEmpty()) + ":" +
                Utils.encodeURIComponent(config.password.orEmpty())
        val query = if (params.isEmpty()) "" else "?" + params.joinToString("&")
        return "${AppConfig.ANYCONNECT}$userInfo@${config.server}:${config.serverPort}$query#${Utils.encodeURIComponent(config.remarks)}"
    }
}
