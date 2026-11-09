package com.v2ray.ang.fmt

import com.v2ray.ang.AppConfig
import com.v2ray.ang.dto.entities.ProfileItem
import com.v2ray.ang.enums.EConfigType
import com.v2ray.ang.extension.idnHost
import com.v2ray.ang.util.Utils
import org.json.JSONArray
import java.net.URI

/**
 * Parses Mimic links: mimic://uuid@host:port?domains=[...]#remark
 *
 * Mimic is a Hysteria2-family transport (TLS mimicry plus the MTP transport),
 * so the profile is stored as [EConfigType.MIMIC] and served by the Mimic Go
 * client running as a sidecar with a local SOCKS5 port.
 */
object MimicFmt : FmtBase() {

    fun parse(str: String): ProfileItem? {
        val config = ProfileItem.create(EConfigType.MIMIC)
        val normalized = str.replace(AppConfig.MIMIC, "https://")
        val uri = URI(Utils.fixIllegalUrl(normalized))
        config.remarks = Utils.decodeURIComponent(uri.fragment.orEmpty()).let { it.ifEmpty { "none" } }
        config.server = uri.idnHost
        config.serverPort = uri.port.toString()
        config.password = Utils.decodeURIComponent(uri.userInfo ?: return null)
        if (!uri.rawQuery.isNullOrEmpty()) {
            val query = getQueryParam(uri)
            query["domains"]?.takeIf { it.isNotBlank() }?.let { raw ->
                config.mimicDomains = runCatching { JSONArray(raw).toString() }.getOrNull()
            }
        }
        return config
    }

    fun toUri(config: ProfileItem): String {
        val domains = config.mimicDomains?.takeIf { it.isNotBlank() }
            ?.let { "?domains=${Utils.encodeURIComponent(it)}" } ?: ""
        return "${AppConfig.MIMIC}${Utils.encodeURIComponent(config.password.orEmpty())}" +
                "@${config.server}:${config.serverPort}$domains#${Utils.encodeURIComponent(config.remarks)}"
    }
}
