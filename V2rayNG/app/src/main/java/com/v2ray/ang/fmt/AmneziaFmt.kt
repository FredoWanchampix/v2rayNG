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
 *
 * Query keys are matched case-insensitively: Amnezia's own clients emit
 * CamelCase/uppercase names (`Jc`, `Jmin`, `S1`, `H1`, `HeaderProtectionKey`),
 * while hand-written links and this fork's own `toUri` use lowercase. A
 * case-sensitive lookup silently dropped every obfuscation parameter of an
 * imported official link, leaving a plain WireGuard tunnel that the server
 * rejects.
 *
 * The stored keys are normalised to lowercase so that
 * [com.v2ray.ang.core.SidecarConfigBuilder] and the editor, which both use the
 * lowercase spelling, always find them.
 */
object AmneziaFmt : FmtBase() {

    private val INT_KEYS = listOf("jc", "jmin", "jmax", "s1", "s2", "s3", "s4", "itime", "version")
    private val STR_KEYS = listOf(
        "h1", "h2", "h3", "h4", "i1", "i2", "i3", "i4", "i5", "j1", "j2", "j3",
        "header-protection-key", "content-padding-addition", "rekey-after-time",
        "rekey-timeout", "reject-after-time", "keepalive-timeout", "max-handshake-attempts"
    )
    private val BOOL_KEYS = listOf("random-trailers", "disable-cookies")

    /** Query map with case-insensitive lookup, keeping the first spelling seen. */
    private class CiMap(private val map: Map<String, String>) {
        // Later duplicates do not overwrite the first spelling seen.
        private val lower: Map<String, String> = run {
            val out = LinkedHashMap<String, String>()
            map.forEach { (k, v) -> if (!out.containsKey(k.lowercase())) out[k.lowercase()] = v }
            out
        }

        operator fun get(key: String): String? = map[key] ?: lower[key.lowercase()]

        /** Matches `header-protection-key` and `HeaderProtectionKey` alike. */
        fun getLoose(key: String): String? {
            get(key)?.let { return it }
            val bare = key.replace("-", "").lowercase()
            return lower.entries.firstOrNull { it.key.replace("-", "") == bare }?.value
        }
    }

    fun parse(str: String): ProfileItem? {
        val config = ProfileItem.create(EConfigType.AMNEZIAWG)
        val uri = URI(Utils.fixIllegalUrl(str.replace(AppConfig.AMNEZIAWG, AppConfig.WIREGUARD)))
        if (uri.rawQuery.isNullOrEmpty()) return null
        val query = CiMap(getQueryParam(uri))

        config.remarks = Utils.decodeURIComponent(uri.fragment.orEmpty()).let { it.ifEmpty { "none" } }
        config.server = uri.idnHost
        config.serverPort = uri.port.toString()
        config.secretKey = uri.userInfo
        config.publicKey = query.getLoose("publickey") ?: return null
        config.preSharedKey = query.getLoose("presharedkey")
        // `address` is the canonical key; Amnezia panels also emit `AllowedIPs`.
        // The previous expression had a dead branch
        // (`query["allowedips"]?.let { null }` always yields null), so links
        // carrying only AllowedIPs silently fell back to the hardcoded default.
        config.localAddress = query.getLoose("address")?.takeIf { it.isNotBlank() }
            ?: query.getLoose("allowedips")?.takeIf { it.isNotBlank() }
            ?: AppConfig.WIREGUARD_LOCAL_ADDRESS_V4 + "," + AppConfig.WIREGUARD_LOCAL_ADDRESS_V6
        query.getLoose("mtu")?.toIntOrNull()?.let { config.mtu = it }
        query.getLoose("reserved")?.takeIf { it.isNotBlank() }?.let { config.reserved = it }

        val opts = org.json.JSONObject()
        // No hardcoded default: mihomo treats an explicit `version: 3` as "use the
        // v3 implementation", which rejects the v1.5-only knobs (j1-j3, itime).
        // Forcing 3 on a legacy link therefore made mihomo refuse to start it.
        // When the link states no version, omit the key and let mihomo pick the
        // legacy implementation.
        query.getLoose("version")?.toIntOrNull()?.let { opts.put("version", it) }
        INT_KEYS.filter { it != "version" }.forEach { k ->
            query.getLoose(k)?.toIntOrNull()?.let { opts.put(k, it) }
        }
        STR_KEYS.forEach { k -> query.getLoose(k)?.takeIf { it.isNotBlank() }?.let { opts.put(k, it) } }
        BOOL_KEYS.forEach { k ->
            query.getLoose(k)?.let { raw ->
                when (raw.trim().lowercase()) {
                    "true", "1", "yes" -> opts.put(k, true)
                    "false", "0", "no" -> opts.put(k, false)
                }
            }
        }
        config.amneziaOptions = if (opts.length() == 0) null else opts.toString()
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
