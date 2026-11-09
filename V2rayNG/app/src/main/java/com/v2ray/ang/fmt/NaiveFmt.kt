package com.v2ray.ang.fmt

import com.v2ray.ang.AppConfig
import com.v2ray.ang.dto.entities.ProfileItem
import com.v2ray.ang.enums.EConfigType
import com.v2ray.ang.extension.idnHost
import com.v2ray.ang.util.Utils
import java.net.URI

/**
 * Parses NaiveProxy share links: naive+https://user:pass@host:port?params#remark
 * and the bare naive:// spelling. TLS fields reuse the common query keys.
 */
object NaiveFmt : FmtBase() {

    fun parse(str: String): ProfileItem? {
        val config = ProfileItem.create(EConfigType.NAIVE)
        val normalized = str
            .replace(AppConfig.NAIVE, "https://")
            .replace("naive+https://", "https://")
        val uri = URI(Utils.fixIllegalUrl(normalized))
        config.remarks = Utils.decodeURIComponent(uri.fragment.orEmpty()).let { it.ifEmpty { "none" } }
        config.server = uri.idnHost
        config.serverPort = uri.port.toString()
        val userInfo = uri.userInfo ?: return null
        val idx = userInfo.indexOf(':')
        if (idx <= 0) return null
        config.username = Utils.decodeURIComponent(userInfo.substring(0, idx))
        config.password = Utils.decodeURIComponent(userInfo.substring(idx + 1))
        if (uri.rawQuery.isNullOrEmpty()) return config
        getItemFormQuery(config, getQueryParam(uri))
        return config
    }

    fun toUri(config: ProfileItem): String {
        val dicQuery = getQueryDic(config)
        val userInfo = Utils.encodeURIComponent(config.username.orEmpty()) + ":" +
                Utils.encodeURIComponent(config.password.orEmpty())
        val query = dicQuery.toList().joinToString("&") { "${it.first}=${Utils.encodeURIComponent(it.second)}" }
        return "${AppConfig.NAIVE}$userInfo@${config.server}:${config.serverPort}?$query#${Utils.encodeURIComponent(config.remarks)}"
    }
}
