package com.v2ray.ang.core

import com.v2ray.ang.dto.entities.ProfileItem
import com.v2ray.ang.enums.EConfigType
import org.json.JSONArray
import org.json.JSONObject

/**
 * Builds configuration documents for the sidecar engines.
 *
 * sing-box configs use a local mixed inbound plus either an outbound (naive,
 * hysteria2) or an endpoint routed via a rule (openconnect); both shapes were
 * validated against sing-box 1.14.4 with `sing-box check`.
 * mihomo configs carry the AmneziaWG options through `amnezia-wg-option`,
 * validated against mihomo 1.19.33 with `mihomo -t`.
 * Mimic configs follow the upstream client.yaml schema (server, uuid,
 * transport mtp, local SOCKS5 port, optional mimicry domains).
 */
object SidecarConfigBuilder {

    fun build(profile: ProfileItem, engine: String, port: Int): String? = when (engine) {
        "sing-box" -> singBox(profile, port)
        "mihomo" -> mihomo(profile, port)
        "mimic-client" -> mimic(profile, port)
        else -> null
    }

    // ---------------- sing-box ----------------

    private fun singBox(profile: ProfileItem, port: Int): String? {
        val root = JSONObject()
        root.put("log", JSONObject().put("level", "warn"))
        root.put(
            "inbounds",
            JSONArray().put(
                JSONObject()
                    .put("type", "mixed")
                    .put("tag", "mixed-in")
                    .put("listen", "127.0.0.1")
                    .put("listen_port", port)
            )
        )

        val tag = "engine-out"
        when (profile.configType) {
            EConfigType.NAIVE -> {
                root.put(
                    "outbounds",
                    JSONArray().put(
                        JSONObject()
                            .put("type", "naive")
                            .put("tag", tag)
                            .put("server", profile.server.orEmpty())
                            .put("server_port", profile.serverPort.orEmpty().toIntOrNull() ?: 443)
                            .put("username", profile.username.orEmpty())
                            .put("password", profile.password.orEmpty())
                            .put("tls", tlsBlock(profile))
                    )
                )
            }

            EConfigType.OPENCONNECT -> {
                // Endpoints are addressed by route rules; verified with
                // `sing-box check`: action=route accepts an endpoint tag.
                val server = profile.server.orEmpty() +
                        ":" + (profile.serverPort.orEmpty().toIntOrNull() ?: 443)
                root.put(
                    "endpoints",
                    JSONArray().put(
                        JSONObject()
                            .put("type", "openconnect")
                            .put("tag", tag)
                            .put("server", server)
                            .put("flavor", profile.ocservFlavor ?: "anyconnect")
                            .put("username", profile.username.orEmpty())
                            .put("password", profile.password.orEmpty())
                            .putOpt("auth_group", profile.ocservAuthGroup?.takeIf { it.isNotBlank() })
                    )
                )
            }

            else -> return null
        }

        root.put(
            "route",
            JSONObject()
                .put(
                    "rules",
                    JSONArray().put(
                        JSONObject()
                            .put("inbound", JSONArray().put("mixed-in"))
                            .put("action", "route")
                            .put("outbound", tag)
                    )
                )
                .put("final", tag)
        )
        return root.toString(2)
    }

    private fun tlsBlock(profile: ProfileItem): JSONObject = JSONObject()
        .put("enabled", true)
        .putOpt("server_name", profile.sni?.takeIf { it.isNotBlank() })
        .put("insecure", profile.insecure == true)
        .putOpt("alpn", profile.alpn?.takeIf { it.isNotBlank() }?.split(",")?.let { JSONArray(it) })

    // ---------------- mihomo (AmneziaWG) ----------------

    private fun mihomo(profile: ProfileItem, port: Int): String {
        val opts = profile.amneziaOptions
            ?.takeIf { it.isNotBlank() }
            ?.let { runCatching { JSONObject(it) }.getOrNull() } ?: JSONObject()
        val sb = StringBuilder()
        sb.append("mixed-port: ").append(port).append('\n')
        sb.append("mode: global\n")
        sb.append("log-level: silent\n")
        sb.append("proxies:\n")
        sb.append("  - name: awg\n")
        sb.append("    type: wireguard\n")
        sb.append("    server: ").append(yq(profile.server)).append('\n')
        sb.append("    port: ").append(profile.serverPort.orEmpty().toIntOrNull() ?: 51820).append('\n')
        profile.localAddress?.takeIf { it.isNotBlank() }?.let { addr ->
            val parts = addr.split(",").map { it.trim() }.filter { it.isNotEmpty() }
            parts.getOrNull(0)?.let { sb.append("    ip: ").append(yq(it.removeSuffix("/32").removeSuffix("/128"))).append('\n') }
            parts.getOrNull(1)?.let { sb.append("    ipv6: ").append(yq(it.removeSuffix("/128"))).append('\n') }
        }
        sb.append("    private-key: ").append(yq(profile.secretKey)).append('\n')
        sb.append("    public-key: ").append(yq(profile.publicKey)).append('\n')
        profile.preSharedKey?.takeIf { it.isNotBlank() }?.let { sb.append("    pre-shared-key: ").append(yq(it)).append('\n') }
        profile.reserved?.takeIf { it.isNotBlank() }?.let { r ->
            sb.append("    reserved: [").append(r.split(",").joinToString(", ") { it.trim() }).append("]\n")
        }
        sb.append("    udp: true\n")
        sb.append("    mtu: ").append(profile.mtu ?: 1420).append('\n')
        sb.append("    amnezia-wg-option:\n")
        sb.append("      version: ").append(opts.optInt("version", 3)).append('\n')
        listOf("jc", "jmin", "jmax", "s1", "s2", "s3", "s4").forEach { k ->
            if (opts.has(k)) sb.append("      ").append(k).append(": ").append(opts.optInt(k)).append('\n')
        }
        listOf("h1", "h2", "h3", "h4", "i1", "i2", "i3", "i4", "i5", "j1", "j2", "j3",
            "header-protection-key", "content-padding-addition", "rekey-after-time",
            "rekey-timeout", "reject-after-time", "keepalive-timeout", "max-handshake-attempts"
        ).forEach { k ->
            val key = if (k.length <= 3) k.uppercase() else k
            if (opts.has(key)) sb.append("      ").append(k).append(": ").append(yq(opts.optString(key))).append('\n')
        }
        if (opts.optBoolean("randomTrailers", false)) sb.append("      random-trailers: true\n")
        if (opts.optBoolean("disableCookies", false)) sb.append("      disable-cookies: true\n")
        sb.append("proxy-groups:\n")
        sb.append("  - name: GLOBAL\n")
        sb.append("    type: select\n")
        sb.append("    proxies: [awg]\n")
        return sb.toString()
    }

    // ---------------- Mimic (Hysteria2 transport) ----------------

    private fun mimic(profile: ProfileItem, port: Int): String {
        val sb = StringBuilder()
        sb.append("server: ").append(yq(profile.server.orEmpty() + ":" + (profile.serverPort.orEmpty().toIntOrNull() ?: 443))).append('\n')
        sb.append("uuid: ").append(yq(profile.password)).append('\n')
        sb.append("transport: mtp\n")
        sb.append("local_port: ").append(port).append('\n')
        profile.mimicDomains?.takeIf { it.isNotBlank() }?.let { raw ->
            val arr = runCatching { JSONArray(raw) }.getOrNull()
            if (arr != null && arr.length() > 0) {
                sb.append("domains:\n")
                for (i in 0 until arr.length()) {
                    val o = arr.optJSONObject(i)
                    if (o != null) {
                        sb.append("  - domain: ").append(yq(o.optString("domain"))).append('\n')
                        o.optString("preset").takeIf { it.isNotBlank() }?.let { sb.append("    preset: ").append(yq(it)).append('\n') }
                    } else {
                        sb.append("  - domain: ").append(yq(arr.optString(i))).append('\n')
                    }
                }
            }
        }
        sb.append("routing:\n  default_policy: proxy\n")
        return sb.toString()
    }

    private fun yq(value: String?): String = "\"" + (value.orEmpty()).replace("\\", "\\\\").replace("\"", "\\\"") + "\""
}
