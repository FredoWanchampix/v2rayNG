package com.v2ray.ang.fmt

import com.v2ray.ang.AppConfig
import com.v2ray.ang.dto.entities.ProfileItem
import com.v2ray.ang.enums.EConfigType
import com.v2ray.ang.extension.idnHost
import com.v2ray.ang.util.Utils
import java.net.URI

/**
 * Parses AmneziaWG share links.
 *
 * Accepts the common `awg://` and `amnezia://` shapes produced by AmneziaWG
 * server panels: a WireGuard-style URI whose query carries the Amnezia
 * obfuscation parameters (jc, jmin, jmax, s1, s2 and, for protocol 3.x,
 * h1-h4 / header-protection fields). The parameters are kept as a JSON blob in
 * [ProfileItem.amneziaOptions] and handed to the mihomo sidecar verbatim.
 */
object AmneziaFmt : FmtBase() {

    private val INT_KEYS = listOf("jc", "jmin", "jmax", "s1", "s2", "s3", "s4", "itime", "version")
    private val STR_KEYS = listOf(
        "h1", "h2", "h3", "h4", "i1", "i2", "i3", "i4", "i5", "j1", "j2", "j3",
        "header-protection-key", "content-padding-addition", "rekey-after-time",
        "rekey-timeout", "reject-after-time", "keepalive-timeout", "max-handshake-attempts"
    )
    private val BOOL_KEYS = listOf("random-trailers", "disable-cookies")

    fun parse(str: String): ProfileItem? {
        val config = ProfileItem.create(EConfigType.AMNEZIAWG)
        val uri = URI(Utils.fixIllegalUrl(str.replace(AppConfig.AMNEZIAWG, AppConfig.WIREGUARD)))
        if (uri.rawQuery.isNullOrEmpty()) return null
        val query = getQueryParam(uri)

        config.remarks = Utils.decodeURIComponent(uri.fragment.orEmpty()).let { it.ifEmpty { "none" } }
        config.server = uri.idnHost
        config.serverPort = uri.port.toString()
        config.secretKey = uri.userInfo
        config.publicKey = query["publickey"] ?: query["publicKey"] ?: return null
        config.preSharedKey = query["presharedkey"] ?: query["preSharedKey"]
        config.localAddress = query["address"] ?: query["allowedips"]?.let { null }
            ?: AppConfig.WIREGUARD_LOCAL_ADDRESS_V4 + "," + AppConfig.WIREGUARD_LOCAL_ADDRESS_V6
        query["mtu"]?.toIntOrNull()?.let { config.mtu = it }
        query["reserved"]?.let { config.reserved = it }

        val opts = org.json.JSONObject()
        opts.put("version", query["version"]?.toIntOrNull() ?: 3)
        INT_KEYS.forEach { k -> query[k]?.toIntOrNull()?.let { opts.put(k, it) } }
        STR_KEYS.forEach { k -> query[k]?.takeIf { it.isNotBlank() }?.let { opts.put(k, it) } }
        BOOL_KEYS.forEach { k -> query[k]?.toBooleanStrictOrNull()?.let { opts.put(k, it) } }
        config.amneziaOptions = opts.toString()
        return config
    }

    fun toUri(config: ProfileItem): String {
        val dicQuery = HashMap<String, String>()
        config.publicKey?.let { dicQuery["publickey"] = it }
        config.preSharedKey?.takeIf { it.isNotBlank() }?.let { dicQuery["presharedkey"] = it }
        config.localAddress?.takeIf { it.isNotBlank() }?.let { dicQuery["address"] = it }
        config.mtu?.let { dicQuery["mtu"] = it.toString() }
        config.reserved?.takeIf { it.isNotBlank() }?.let { dicQuery["reserved"] = it }
        runCatching { org.json.JSONObject(config.amneziaOptions.orEmpty()) }.getOrNull()?.let { opts ->
            opts.keys().forEach { k -> opts.opt(k)?.toString()?.takeIf { it.isNotBlank() }?.let { dicQuery[k] = it } }
        }
        return toUri(config, config.secretKey, dicQuery)
    }
}
