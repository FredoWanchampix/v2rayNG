package com.v2ray.ang.fmt

import com.v2ray.ang.AppConfig
import com.v2ray.ang.dto.entities.ProfileItem
import com.v2ray.ang.enums.EConfigType
import com.v2ray.ang.extension.idnHost
import com.v2ray.ang.util.Utils
import java.net.URI

/**
 * Parses FPTN access links: fptn://user:pass@host:port?token=...#remark
 * The access token travels in the `token` query parameter, matching the
 * fptn-client CLI flags (access token is the primary credential).
 */
object FptnFmt : FmtBase() {

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
        config.fptnToken = query["token"] ?: query["access_token"]
        return config
    }

    fun toUri(config: ProfileItem): String {
        val userInfo = Utils.encodeURIComponent(config.username.orEmpty()) + ":" +
                Utils.encodeURIComponent(config.password.orEmpty())
        val token = config.fptnToken?.takeIf { it.isNotBlank() }
            ?.let { "?token=${Utils.encodeURIComponent(it)}" } ?: ""
        return "${AppConfig.FPTN}$userInfo@${config.server}:${config.serverPort}$token#${Utils.encodeURIComponent(config.remarks)}"
    }
}
