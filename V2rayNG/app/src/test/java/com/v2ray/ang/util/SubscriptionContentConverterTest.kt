package com.v2ray.ang.util

import org.json.JSONObject
import org.junit.jupiter.api.Assertions.assertEquals
import org.junit.jupiter.api.Assertions.assertFalse
import org.junit.jupiter.api.Assertions.assertNotNull
import org.junit.jupiter.api.Assertions.assertNull
import org.junit.jupiter.api.Assertions.assertTrue
import org.junit.jupiter.api.Test

/**
 * Покрывает конвертацию кастомных JSON-конфигов в ссылки при обновлении
 * подписки («Кастомные в ссылки») и защиту от молчаливой потери данных.
 *
 * Почему это важно: раньше конвертер знал только vless/vmess/shadowsocks/
 * trojan/hysteria/tuic/socks/http, поэтому wireguard-конфиг при включённом
 * переключателе оставался кастомным без какой-либо причины в логе. Владелец
 * требует, чтобы конвертер покрывал ВСЕ протоколы форка, а конфиги, которые
 * нельзя выразить ссылкой БЕЗ потери данных (цепочки dialerProxy/detour),
 * оставались кастомными с явной причиной.
 */
class SubscriptionContentConverterTest {

    // --- Реальный конфиг владельца: WARP с шумовой цепочкой ---
    // wireguard -> freedom(noises) через streamSettings.sockopt.dialerProxy.
    // Формат ссылки wireguard:// не выражает следующий хоп, поэтому конвертация
    // обязана оставить конфиг кастомным, а не молча выбросить noise-outbound.
    private val warpWithNoise = """
        {
          "remarks": "WARP",
          "routing": { "rules": [ { "type": "field", "network": "tcp,udp", "outboundTag": "warp" } ] },
          "outbounds": [
            {
              "tag": "warp",
              "protocol": "wireguard",
              "settings": {
                "mtu": 1280,
                "peers": [ { "endpoint": "162.159.195.1:500", "publicKey": "PUBKEY=", "allowedIPs": ["0.0.0.0/0", "::/0"] } ],
                "address": ["172.16.0.2/32"],
                "secretKey": "SECRETKEY="
              },
              "streamSettings": { "sockopt": { "dialerProxy": "noise-out" } }
            },
            { "tag": "noise-out", "protocol": "freedom", "settings": { "noises": [ { "type": "rand", "delay": "1-3", "packet": "23-911" } ] } }
          ]
        }
    """.trimIndent()

    // Тот же wireguard, но БЕЗ цепочки: обязан конвертироваться в ссылку.
    private val plainWireguard = """
        {
          "remarks": "WG plain",
          "outbounds": [
            {
              "tag": "wg",
              "protocol": "wireguard",
              "settings": {
                "mtu": 1280,
                "peers": [ { "endpoint": "162.159.195.1:500", "publicKey": "PUBKEY=", "allowedIPs": ["0.0.0.0/0", "::/0"] } ],
                "address": ["172.16.0.2/32", "2606:4700:110::1/128"],
                "secretKey": "SECRETKEY="
              }
            }
          ]
        }
    """.trimIndent()

    @Test
    fun `chain reason is detected for xray dialerProxy`() {
        val reason = SubscriptionContentConverter.chainReason(JSONObject(warpWithNoise))
        assertNotNull(reason, "цепочка dialerProxy обязана быть распознана")
        assertTrue(reason!!.contains("dialerProxy"), "причина обязана называть dialerProxy: $reason")
    }

    @Test
    fun `no chain reason without dialerProxy or detour`() {
        assertNull(SubscriptionContentConverter.chainReason(JSONObject(plainWireguard)))
        assertNull(SubscriptionContentConverter.chainReason(JSONObject("""{"outbounds":[]}""")))
    }

    @Test
    fun `chain reason is detected for singbox detour`() {
        val sb = JSONObject("""{"type":"wireguard","server":"1.2.3.4","server_port":500,"detour":"prev"}""")
        assertNotNull(SubscriptionContentConverter.chainReason(sb))
    }

    @Test
    fun `warp noise chain converts to wireguard link preserving the noise`() {
        // Цепочка wireguard -> freedom(noises) поглощается: ядро применяет шум
        // на самом wireguard через streamSettings.finalmask (Xray-core v26.11.9,
        // wireguard/client.go: FinalMask.DialUDP), а ссылка несёт finalmask в
        // ключе fm (WireguardFmt.parse -> ProfileItem.finalMask). Поэтому
        // «прелесть» (шум до handshake) НЕ теряется и профиль становится ссылкой.
        val out = SubscriptionContentConverter.convert(warpWithNoise, decodeBase64 = false, customToLinks = true)
        assertTrue(out.startsWith("wireguard://"), "ожидалась wireguard-ссылка: $out")
        assertTrue(out.contains("SECRETKEY"), "secretKey обязан попасть в userinfo: $out")
        assertTrue(out.contains("162.159.195.1:500"), "endpoint обязан попасть: $out")
        assertTrue(out.contains("fm="), "finalmask обязан попасть в ссылку ключом fm: $out")
        // шум пережил конвертацию: rand 23-911 из freedom-noises стал rand в finalmask
        assertTrue(out.contains("23-911"), "диапазон шума обязан сохраниться: $out")
        // noise-outbound больше не нужен отдельным хопом: он поглощён finalmask
        assertFalse(out.contains("noise-out"), "freedom-хоп обязан быть поглощён: $out")
    }

    @Test
    fun `real multi-hop chain to a non-freedom outbound stays custom`() {
        // dialerProxy на outbound, который НЕ является freedom с шумами, — это
        // настоящая multi-hop цепочка: формат ссылки её не выражает, поэтому
        // конфиг остаётся кастомным с причиной в логе.
        val chain = """
            {
              "remarks": "chain",
              "outbounds": [
                { "tag": "wg", "protocol": "wireguard",
                  "settings": { "secretKey": "S=", "address": ["172.16.0.2/32"], "mtu": 1280,
                    "peers": [ { "endpoint": "1.2.3.4:500", "publicKey": "P=", "allowedIPs": ["0.0.0.0/0", "::/0"] } ] },
                  "streamSettings": { "sockopt": { "dialerProxy": "prev" } } },
                { "tag": "prev", "protocol": "vless",
                  "settings": { "vnext": [ { "address": "9.9.9.9", "port": 443,
                    "users": [ { "id": "u", "encryption": "none" } ] } ] } }
              ]
            }
        """.trimIndent()
        val out = SubscriptionContentConverter.convert(chain, decodeBase64 = false, customToLinks = true)
        assertFalse(out.startsWith("wireguard://"), "цепочка через vless не выражается ссылкой: $out")
        assertTrue(out.contains("\"wireguard\""), "конфиг обязан остаться кастомным: $out")
    }

    @Test
    fun `plain wireguard converts to wireguard link`() {
        val out = SubscriptionContentConverter.convert(plainWireguard, decodeBase64 = false, customToLinks = true)
        assertTrue(out.startsWith("wireguard://"), "ожидалась wireguard-ссылка, получено: $out")
        assertTrue(out.contains("publickey=PUBKEY%3D") || out.contains("publickey="), "publicKey обязан попасть в ссылку: $out")
        assertTrue(out.contains("162.159.195.1:500"), "endpoint обязан попасть в ссылку: $out")
        assertTrue(out.contains("address="), "address обязан попасть в ссылку: $out")
        assertTrue(out.contains("mtu=1280"), "mtu обязан попасть в ссылку: $out")
    }

    @Test
    fun `wireguard with two peers stays custom`() {
        val two = JSONObject(plainWireguard)
        val ob = two.getJSONArray("outbounds").getJSONObject(0)
        val peers = ob.getJSONObject("settings").getJSONArray("peers")
        peers.put(peers.getJSONObject(0))
        val out = SubscriptionContentConverter.convert(two.toString(), decodeBase64 = false, customToLinks = true)
        assertFalse(out.startsWith("wireguard://"), "multi-peer не выражается одной ссылкой: $out")
        assertTrue(out.contains("\"wireguard\""), "конфиг обязан остаться кастомным: $out")
    }

    @Test
    fun `singbox wireguard converts to wireguard link`() {
        val sb = """
            {
              "type": "wireguard",
              "tag": "wg-out",
              "server": "engage.cloudflareclient.com",
              "server_port": 2408,
              "local_address": ["172.16.0.2/32"],
              "private_key": "PRIV=",
              "peer_public_key": "PUB=",
              "mtu": 1280,
              "reserved": [1, 2, 3]
            }
        """.trimIndent()
        val out = SubscriptionContentConverter.convert(sb, decodeBase64 = false, customToLinks = true)
        assertTrue(out.startsWith("wireguard://"), "ожидалась wireguard-ссылка: $out")
        assertTrue(out.contains("reserved=1%2C2%2C3") || out.contains("reserved=1,2,3"), "reserved обязан попасть: $out")
    }

    @Test
    fun `singbox naive converts to naive link`() {
        val sb = """
            { "type": "naive", "tag": "n", "server": "example.com", "server_port": 443,
              "username": "u", "password": "p", "tls": { "server_name": "example.com", "insecure": true } }
        """.trimIndent()
        val out = SubscriptionContentConverter.convert(sb, decodeBase64 = false, customToLinks = true)
        assertTrue(out.startsWith("naive://"), "ожидалась naive-ссылка: $out")
        assertTrue(out.contains("u:p@example.com:443"), "userinfo и адрес обязаны попасть: $out")
        assertTrue(out.contains("sni=example.com"), "sni обязан попасть: $out")
    }

    @Test
    fun `singbox openconnect converts to openconnect link`() {
        val sb = """
            { "type": "openconnect", "tag": "oc", "server": "vpn.example.com:443",
              "username": "u", "password": "p", "flavor": "gp", "auth_group": "g1" }
        """.trimIndent()
        val out = SubscriptionContentConverter.convert(sb, decodeBase64 = false, customToLinks = true)
        assertTrue(out.startsWith("openconnect://"), "ожидалась openconnect-ссылка: $out")
        assertTrue(out.contains("group=g1"), "auth_group обязан попасть как group: $out")
        assertTrue(out.contains("flavor=gp"), "flavor обязан попасть: $out")
    }

    @Test
    fun `xray masque converts to masque link`() {
        val cfg = """
            {
              "remarks": "MQ",
              "outbounds": [
                {
                  "tag": "m",
                  "protocol": "masque",
                  "settings": { "address": "mq.example.com", "port": 443, "remoteDNS": ["1.1.1.1"] },
                  "streamSettings": {
                    "masqueSettings": {
                      "host": "mq.example.com",
                      "path": "/masque",
                      "warp": { "privateKey": "PRIV=", "publicKey": "PUB=", "address": ["172.16.0.2/32"] }
                    }
                  }
                }
              ]
            }
        """.trimIndent()
        val out = SubscriptionContentConverter.convert(cfg, decodeBase64 = false, customToLinks = true)
        assertTrue(out.startsWith("masque://"), "ожидалась masque-ссылка: $out")
        assertTrue(out.contains("publickey=PUB%3D") || out.contains("publickey="), "publicKey обязан попасть: $out")
        assertTrue(out.contains("dns=1.1.1.1"), "remoteDNS обязан попасть как dns: $out")
    }

    @Test
    fun `vless still converts as before`() {
        // Регрессия: существующее поведение для vless не должно измениться.
        val cfg = """
            {
              "remarks": "V",
              "outbounds": [
                {
                  "tag": "p", "protocol": "vless",
                  "settings": { "vnext": [ { "address": "1.2.3.4", "port": 443,
                    "users": [ { "id": "uuid-1", "encryption": "none" } ] } ] },
                  "streamSettings": { "network": "tcp", "security": "none" }
                }
              ]
            }
        """.trimIndent()
        val out = SubscriptionContentConverter.convert(cfg, decodeBase64 = false, customToLinks = true)
        assertTrue(out.startsWith("vless://"), "ожидалась vless-ссылка: $out")
        assertTrue(out.contains("uuid-1@1.2.3.4:443"), "адрес и id обязаны попасть: $out")
    }

    @Test
    fun `warp noise link carries explicit noises key`() {
        // «Весь контекст»: ссылка несёт и полный fm, и явный список шумов,
        // чтобы поле шума в редакторе заполнилось сразу после импорта.
        val out = SubscriptionContentConverter.convert(warpWithNoise, decodeBase64 = false, customToLinks = true)
        assertTrue(out.startsWith("wireguard://"), out)
        assertTrue(out.contains("noises="), "явный ключ noises обязан быть в ссылке: $out")
        assertTrue(out.contains("fm="), "fm обязан остаться: $out")
        // явный список — валидный finalmask-массив c rand 23-911
        val q = out.substringAfter("?").substringBefore("#")
            .split("&").associate { val (k, v) = it.split("=", limit = 2); k to java.net.URLDecoder.decode(v, "UTF-8") }
        val noises = org.json.JSONArray(q["noises"]!!)
        assertTrue(noises.length() >= 1)
        assertEquals("23-911", noises.getJSONObject(0).getString("rand"))
    }

    @Test
    fun `wireguard with own finalmask keeps it without chain`() {
        // Конфиг, ранее собранный форком: шум уже в streamSettings.finalmask
        // самого wireguard (без freedom-цепочки). Конвертер обязан перенести
        // его в ссылку, а не потерять.
        val cfg = """
            {
              "remarks": "WG own fm",
              "outbounds": [
                {
                  "tag": "wg", "protocol": "wireguard",
                  "settings": { "secretKey": "S=", "address": ["172.16.0.2/32"], "mtu": 1280,
                    "peers": [ { "endpoint": "1.2.3.4:500", "publicKey": "P=", "allowedIPs": ["0.0.0.0/0", "::/0"] } ] },
                  "streamSettings": { "finalmask": { "udp": [ { "type": "noise",
                    "settings": { "noise": [ { "rand": "40-70", "delay": "10-20" } ] } } ] } }
                }
              ]
            }
        """.trimIndent()
        val out = SubscriptionContentConverter.convert(cfg, decodeBase64 = false, customToLinks = true)
        assertTrue(out.startsWith("wireguard://"), out)
        assertTrue(out.contains("fm="), "собственный finalmask обязан попасть в fm: $out")
        assertTrue(out.contains("noises="), "явный список обязан попасть в noises: $out")
        assertTrue(out.contains("40-70"), "диапазон шума обязан сохраниться: $out")
    }

    @Test
    fun `keepBalancers keeps balancer config custom`() {
        val bal = """
            {
              "remarks": "B",
              "routing": { "balancers": [ { "tag": "b1", "selector": ["p"] } ] },
              "outbounds": [
                { "tag": "p", "protocol": "vless",
                  "settings": { "vnext": [ { "address": "1.2.3.4", "port": 443,
                    "users": [ { "id": "u", "encryption": "none" } ] } ] } }
              ]
            }
        """.trimIndent()
        val kept = SubscriptionContentConverter.convert(bal, decodeBase64 = false, customToLinks = true, keepBalancers = true)
        assertTrue(kept.contains("\"balancers\""), "балансер обязан остаться кастомным: $kept")
        val converted = SubscriptionContentConverter.convert(bal, decodeBase64 = false, customToLinks = true, keepBalancers = false)
        assertTrue(converted.startsWith("vless://"), "без keepBalancers балансер конвертируется: $converted")
    }
}
