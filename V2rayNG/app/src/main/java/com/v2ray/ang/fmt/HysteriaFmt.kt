package com.v2ray.ang.fmt

import com.v2ray.ang.AppConfig
import com.v2ray.ang.dto.entities.ProfileItem
import com.v2ray.ang.enums.EConfigType
import com.v2ray.ang.extension.idnHost
import com.v2ray.ang.extension.nullIfBlank
import com.v2ray.ang.util.Utils
import java.net.URI

/**
 * Hysteria v1 share links: hysteria://host:port?auth=...&protocol=...&upmbps=...
 * &downmbps=...&peer=...&insecure=...&alpn=...&obfs=...&mport=...#remark
 *
 * Поддержка v1 в форке опирается на сайдкар mihomo (MetaCubeX v1.19.33):
 * эксперимент на устройстве владельца (`libmihomo.so -t` с hysteria-outbound)
 * дал "test is successful", тогда как sing-box форка собран без QUIC
 * ("QUIC is not included in this build"). Поэтому профиль HYSTERIA
 * обслуживается движком mihomo, как AmneziaWG.
 *
 * Маппинг на ProfileItem (без новых полей, переиспользуются существующие):
 *   auth (строка)      -> password
 *   protocol           -> method (udp / wechat-video / faketcp)
 *   upmbps/downmbps    -> bandwidthUp/bandwidthDown ("100Mbps")
 *   peer (SNI)         -> sni
 *   insecure           -> insecure
 *   alpn               -> alpn
 *   obfs               -> obfsPassword
 *   mport (hop)        -> portHopping
 * Base64-форма auth= (auth=base64str) декодируется в строку.
 */
object HysteriaFmt : FmtBase() {

    fun parse(str: String): ProfileItem? {
        val config = ProfileItem.create(EConfigType.HYSTERIA)
        val normalized = str.replace(AppConfig.HYSTERIA, "https://")
        val uri = URI(Utils.fixIllegalUrl(normalized))
        config.remarks = Utils.decodeURIComponent(uri.fragment.orEmpty()).let { it.ifEmpty { "none" } }
        config.server = uri.idnHost
        config.serverPort = (if (uri.port == -1) AppConfig.DEFAULT_PORT else uri.port).toString()
        // дефолт протокола v1 — udp (схема hysteria:// без protocol=)
        config.method = "udp"
        if (uri.rawQuery.isNullOrEmpty()) return config
        val queryParam = getQueryParam(uri)

        // auth: строка или base64 (upstream допускает оба написания)
        val auth = queryParam["auth"]?.nullIfBlank()
        config.password = auth?.let { raw ->
            runCatching {
                val decoded = android.util.Base64.decode(raw, android.util.Base64.NO_WRAP)
                    .toString(Charsets.UTF_8)
                // base64-форма: декодированное не содержит управляющих символов
                if (decoded.isNotEmpty() && decoded.none { c -> c.code < 0x20 && c != '\t' }) decoded else raw
            }.getOrDefault(raw)
        }
        config.method = queryParam["protocol"]?.nullIfBlank() ?: "udp"
        // mihomo ОТКАЗЫВАЕТ hysteria-outbound без up/down (эксперимент:
        // "unset fields: down, up"), поэтому отсутствие mbps в ссылке
        // дополняется дефолтом, а не оставляет мёртвый профиль.
        config.bandwidthUp = queryParam["upmbps"]?.toIntOrNull()?.let { "${it}Mbps" } ?: "100Mbps"
        config.bandwidthDown = queryParam["downmbps"]?.toIntOrNull()?.let { "${it}Mbps" } ?: "100Mbps"
        config.sni = queryParam["peer"]?.nullIfBlank()
        config.insecure = when (queryParam["insecure"]) {
            "1", "true" -> true
            "0", "false" -> false
            else -> false
        }
        config.alpn = queryParam["alpn"]?.nullIfBlank()
        config.obfsPassword = queryParam["obfs"]?.nullIfBlank()
        config.portHopping = queryParam["mport"]?.nullIfBlank()
        return config
    }

    fun toUri(config: ProfileItem): String {
        val params = buildList {
            config.password?.nullIfBlank()?.let { add("auth=${Utils.encodeURIComponent(it)}") }
            config.method?.nullIfBlank()?.takeIf { it != "udp" }?.let { add("protocol=$it") }
            config.bandwidthUp?.nullIfBlank()?.let { add("upmbps=${it.removeSuffix("Mbps")}") }
            config.bandwidthDown?.nullIfBlank()?.let { add("downmbps=${it.removeSuffix("Mbps")}") }
            config.sni?.nullIfBlank()?.let { add("peer=${Utils.encodeURIComponent(it)}") }
            if (config.insecure == true) add("insecure=1")
            config.alpn?.nullIfBlank()?.let { add("alpn=${Utils.encodeURIComponent(it)}") }
            config.obfsPassword?.nullIfBlank()?.let { add("obfs=${Utils.encodeURIComponent(it)}") }
            config.portHopping?.nullIfBlank()?.let { add("mport=${Utils.encodeURIComponent(it)}") }
        }
        val query = if (params.isEmpty()) "" else "?" + params.joinToString("&")
        // Body only: shareConfig сам добавляет схему hysteria://.
        return "${config.server.orEmpty()}:${config.serverPort.orEmpty()}$query#${Utils.encodeURIComponent(config.remarks)}"
    }
}