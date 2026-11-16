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
    fun `warp with noise chain stays custom and is not silently converted`() {
        // convert() с включённым customToLinks: конфиг с цепочкой обязан пройти
        // насквозь как JSON (кастомный профиль), а не превратиться в ссылку и не
        // исчезнуть. Проверяем, что результат содержит исходный wireguard-тег.
        val out = SubscriptionContentConverter.convert(warpWithNoise, decodeBase64 = false, customToLinks = true)
        assertTrue(out.contains("\"wireguard\""), "wireguard-часть обязана сохраниться: $out")
        assertTrue(out.contains("noise-out"), "noise-outbound обязан сохраниться: $out")
        assertFalse(out.startsWith("wireguard://"), "конфиг с цепочкой НЕ должен стать ссылкой")
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
