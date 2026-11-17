package com.v2ray.ang.util

import com.v2ray.ang.AppConfig
import org.json.JSONArray
import org.json.JSONObject
import org.json.JSONTokener
import java.net.URLEncoder

/**
 * Per-subscription content transformer used right after the subscription body
 * is fetched and before it is parsed into profiles.
 *
 * Two independent switches driven by the subscription settings:
 *  - [decodeBase64ToText]: whole-body or per-line base64 blobs are decoded to
 *    plain link lists / JSON text.
 *  - [customToLinks]: custom JSON configs (xray outbound objects/arrays,
 *    sing-box style entries) are converted into regular share links so they
 *    can be edited with the normal profile UI.
 */
object SubscriptionContentConverter {

    fun convert(content: String, decodeBase64: Boolean, customToLinks: Boolean, keepBalancers: Boolean = false): String {
        // We don't early return here anymore so we can always compact JSONs.
        LogUtil.i("SubConverter", "v2 convert: b64=$decodeBase64 links=$customToLinks balancers=$keepBalancers")
        return walk(content, decodeBase64, customToLinks, keepBalancers)
    }

    /**
     * Splits text that contains multiple top-level JSON objects separated by
     * newlines into individual JSON strings. Uses a brace-depth counter so
     * nested objects inside arrays don't cause premature splits.
     */
    private fun splitConcatenatedJson(text: String): List<String> {
        val trimmed = text.trim()
        // A single whole JSON value doesn't need splitting.
        if (isWholeJsonValue(trimmed)) return listOf(trimmed)

        val chunks = mutableListOf<String>()
        var depth = 0
        var start = -1
        var inString = false
        var escaped = false

        for (i in trimmed.indices) {
            val c = trimmed[i]
            if (escaped) { escaped = false; continue }
            if (c == '\\') { escaped = true; continue }
            if (c == '"') { inString = !inString; continue }
            if (inString) continue

            when {
                c == '{' || c == '[' -> {
                    if (depth == 0) start = i
                    depth++
                }
                c == '}' || c == ']' -> {
                    depth--
                    if (depth == 0 && start >= 0) {
                        chunks.add(trimmed.substring(start, i + 1))
                        start = -1
                    }
                }
            }
        }
        return chunks.ifEmpty { listOf(trimmed) }
    }

    private fun walk(input: String, b64: Boolean, j2l: Boolean, kb: Boolean = false): String {
        val trimmed = input.trim()
        if (trimmed.isEmpty()) return input

        // If the input contains multiple top-level JSON objects concatenated,
        // process each object independently to avoid destroying pretty-printed JSON.
        if (trimmed.startsWith("{")) {
            val split = splitConcatenatedJson(trimmed)
            if (split.size > 1) {
                val out = StringBuilder()
                for (chunk in split) {
                    val p = walk(chunk, b64, j2l, kb)
                    if (p.isNotBlank()) out.append(p).append("\n")
                }
                return out.toString().trim()
            }
        }

        // Whole body is one base64 blob -> decode first and recurse.
        if (b64) {
            tryDecodeBase64(trimmed)?.let { decoded ->
                return walk(decoded, b64, j2l, kb)
            }
        }

        // Whole body is a single JSON value (compact or pretty) -> handle it.
        if ((trimmed.startsWith("{") || trimmed.startsWith("[")) && isWholeJsonValue(trimmed)) {
            if (j2l) {
                convertJsonText(trimmed, kb)?.let { return it }
            } else {
                return try {
                    if (trimmed.startsWith("[")) {
                        val arr = JSONArray(trimmed)
                        val sb = StringBuilder()
                        for (i in 0 until arr.length()) {
                            sb.append(arr.getJSONObject(i).toString()).append("\n")
                        }
                        sb.toString().trim()
                    } else {
                        JSONObject(trimmed).toString()
                    }
                } catch (e: Exception) {
                    trimmed
                }
            }
        }

        val res = StringBuilder()
        input.lines().forEach { line ->
            val t = line.trim()
            if (t.isEmpty()) return@forEach

            if (b64) {
                tryDecodeBase64(t)?.let { decoded ->
                    res.append(walk(decoded, b64, j2l, kb)).append("\n")
                    return@forEach
                }
            }

            if (j2l && (t.startsWith("{") || t.startsWith("["))) {
                // When keepBalancers is on, balancer configs pass through as raw JSON.
                if (kb && t.startsWith("{")) {
                    try {
                        val probe = JSONObject(t)
                        if (isBalancerConfig(probe)) {
                            logCustomKept(probe, "балансер/multi-server: включён «Оставить балансеры кастомными»")
                            res.append(probe.toString()).append("\n")
                            return@forEach
                        }
                    } catch (_: Throwable) { }
                }
                convertJsonText(t, kb)?.let {
                    res.append(it).append("\n")
                    return@forEach
                }
            }

            res.append(t).append("\n")
        }
        return res.toString().trim()
    }

    /** true if the whole string is one valid JSON value (no trailing junk). */
    private fun isWholeJsonValue(s: String): Boolean = try {
        val tokener = JSONTokener(s)
        tokener.nextValue()
        tokener.nextClean().code == 0
    } catch (_: Throwable) {
        false
    }

    /** True when a config is a balancer/multi-server that must stay as custom JSON. */
    private fun isBalancerConfig(root: org.json.JSONObject): Boolean {
        // Has routing.balancers array
        if (root.optJSONObject("routing")?.optJSONArray("balancers")?.length() ?: 0 > 0) return true
        // Multiple proxy outbounds
        val obs = root.optJSONArray("outbounds") ?: return false
        var proxyCount = 0
        for (i in 0 until obs.length()) {
            val o = obs.optJSONObject(i) ?: continue
            val p = o.optString("protocol", o.optString("type"))
            if (p in PROXY_PROTOCOLS || isShadowsocks(o)) proxyCount++
        }
        return proxyCount > 1
    }

    private fun convertJsonText(t: String, keepBalancers: Boolean = false): String? = try {
        if (t.startsWith("[")) {
            val arr = JSONArray(t)
            val out = StringBuilder()
            for (i in 0 until arr.length()) {
                val obj = arr.optJSONObject(i)
                if (obj == null) {
                    arr.opt(i)?.toString()?.takeIf { it != "null" && it.isNotEmpty() }
                        ?.let { out.append(it).append("\n") }
                    continue
                }
                // Full configs carry many proxy outbounds; emit one link each.
                val links = processJsonAll(obj, keepBalancers)
                if (links.isNotEmpty()) {
                    links.forEach { out.append(it).append("\n") }
                } else {
                    out.append(obj.toString()).append("\n")
                }
            }
            out.toString().trim().takeIf { it.isNotEmpty() }
        } else {
            processJsonAll(JSONObject(t), keepBalancers).joinToString("\n").takeIf { it.isNotEmpty() }
        }
    } catch (_: Throwable) {
        null
    }

    private val PROXY_SCHEMES = arrayOf(
        "vless://", "vmess://", "trojan://", "ss://", "ssr://",
        "hysteria://", "hysteria2://", "hy2://", "tuic://", "socks://",
        "http://", "https://",
        // Схемы остальных протоколов форка: без них base64-тело подписки,
        // начинающееся с такой ссылки, не распознавалось бы как список прокси
        // и проходило бы мимо декодирования.
        "wireguard://", "masque://", "awg://", "naive://", "openconnect://",
        "anyconnect://", "fptn://", "mimic://"
    )

    /**
     * Decodes a base64 blob only when the result looks like a config list:
     * strict UTF-8, no control characters, first line starts with a proxy
     * scheme or JSON. Anything else returns null and the text passes through.
     */
    private fun tryDecodeBase64(input: String): String? {
        if (input.length < 10) return null
        val cleaned = input.trim()

        var hasStd = false
        var hasUrl = false
        for (c in cleaned) {
            when {
                c in 'A'..'Z' || c in 'a'..'z' || c in '0'..'9' || c == ' ' || c == '\t' ||
                    c == '=' || c == '\r' || c == '\n' -> {}
                c == '+' || c == '/' -> hasStd = true
                c == '-' || c == '_' -> hasUrl = true
                else -> return null
            }
        }
        if (hasStd && hasUrl) return null
        val flag = if (hasUrl) android.util.Base64.URL_SAFE else android.util.Base64.DEFAULT

        return try {
            val data = android.util.Base64.decode(cleaned, flag)
            if (data.isEmpty()) return null
            val decodedRaw = Charsets.UTF_8.newDecoder()
                .onMalformedInput(java.nio.charset.CodingErrorAction.REPORT)
                .onUnmappableCharacter(java.nio.charset.CodingErrorAction.REPORT)
                .decode(java.nio.ByteBuffer.wrap(data))
                .toString()
            for (ch in decodedRaw) {
                val cc = ch.code
                if (cc == 0x7f || (cc < 0x20 && cc != 0x09 && cc != 0x0a && cc != 0x0d)) return null
            }
            val decoded = decodedRaw.trimStart()
            val firstLine = decoded.lineSequence().firstOrNull { it.isNotBlank() }?.trimStart() ?: return null
            val looksLikeJson = firstLine.startsWith("{") || firstLine.startsWith("[")
            val looksLikeProxyList = PROXY_SCHEMES.any { firstLine.startsWith(it, ignoreCase = true) }
            if (looksLikeJson || looksLikeProxyList) decoded.trim() else null
        } catch (_: IllegalArgumentException) {
            null
        }
    }

    //region JSON outbound -> share link

    /**
     * Processes one JSON config object. Balancer/multi-server configs return
     * empty list so the caller preserves them as compact JSON custom profiles.
     * Single-outbound configs are converted to their share link normally.
     */
    private fun processJsonAll(root: JSONObject, keepBalancers: Boolean = false): List<String> {
        // Balancer configs stay as custom only when keepBalancers is explicitly on.
        if (keepBalancers && isBalancerConfig(root)) {
            logCustomKept(root, "балансер/multi-server: включён «Оставить балансеры кастомными»")
            return emptyList()
        }

        // Цепочка outbounds (multi-hop) выражается в Xray через
        // streamSettings.sockopt.dialerProxy, а в sing-box через detour. Формат
        // share-ссылки не имеет поля для следующего хопа, поэтому конвертация
        // такого конфига МОЛЧА потеряла бы обфускацию/цепочку (например WARP с
        // noise-outbound). Конфиг остаётся кастомным, а причина фиксируется в
        // логе: молчаливая потеря настроек хуже честного «осталось как есть».
        // Цепочка wireguard -> freedom(noises) НЕ является потерей: ядро умеет
        // шум на самом wireguard-outbound через streamSettings.finalmask.udp
        // (в Xray-core v26.11.9 wireguard/client.go вызывает
        // streamSettings.FinalMask.DialUDP), а формат ссылки форка уже несёт
        // finalmask в ключе fm/finalmask (WireguardFmt.parse/toUri, поле
        // ProfileItem.finalMask). Конвертируем такую цепочку в wireguard-ссылку
        // с fm, сохраняя защиту от DPI. Прочие цепочки (dialerProxy на не-freedom)
        // по-прежнему остаются кастомными с причиной в логе.
        val noiseFm = noiseChainFinalMask(root)
        if (noiseFm == null) {
            chainReason(root)?.let { reason ->
            // Лог обёрнут в runCatching намеренно: LogUtil читает уровень из
            // MMKV, а в unit-тестах MMKV не инициализирован, поэтому прямой
            // вызов ронял бы конвертацию подписки в тестах. На устройстве
            // исключение невозможно, но защита делает функцию безопасной в
            // любом контексте. Диагностика не должна ломать обновление.
                runCatching {
                    LogUtil.w(
                        "SubConverter",
                        "конфиг '${root.optString("remarks", root.optString("tag", "?"))}' оставлен кастомным: $reason",
                    )
                }
                return emptyList()
            }
        }
        // Bare sing-box / direct outbound object (single server by definition)
        val sbType = root.optString("type")
        if (sbType.isNotEmpty() && (root.has("server") || root.has("server_port"))) {
            val rem = root.optString("tag", "")
            val built = when (sbType) {
                "vless" -> buildSbVless(root, rem)
                "vmess" -> buildSbVmess(root, rem)
                "trojan" -> buildSbTrojan(root, rem)
                "shadowsocks" -> buildSbShadowsocks(root, rem)
                "hysteria2" -> buildSbHysteria2(root, rem)
                // TUIC: парсер форка отключён, ссылка была бы мёртвой.
                "tuic" -> null
                "socks" -> buildUserPassLink("socks", root, rem)
                // http:// не импортируется форком — мёртвая ссылка запрещена
                "http" -> null
                "wireguard" -> buildSbWireguard(root, rem)
                "naive" -> buildSbNaive(root, rem)
                "openconnect", "anyconnect" -> buildSbOpenconnect(root, rem)
                "mimic" -> buildSbMimic(root, rem)
                else -> null
            }
            if (built != null) return listOf(built)
            // Причина точная: сначала таблица неподдерживаемых протоколов,
            // затем диагностика по содержимому (например, vmess+xhttp).
            logCustomKept(root, unsupportedProtocolReason(sbType)
                ?: conversionFailureReason(root, sbType))
            return emptyList()
        }

        // Bare vmess outbound
        val proto0 = root.optString("protocol", root.optString("type"))
        if (proto0 == "vmess") {
            val built = buildVmess(root, root.optString("tag", root.optString("remarks", "")))
            if (built != null) return listOf(built)
            logCustomKept(root, conversionFailureReason(root, proto0))
            return emptyList()
        }
        if (proto0 == "tuic") {
            logCustomKept(root, unsupportedProtocolReason("tuic")!!)
            return emptyList()
        }
        // Явный protocol без outbounds и без server/server_port: называем причину.
        if (proto0.isNotEmpty() && !root.has("outbounds")) {
            unsupportedProtocolReason(proto0)?.let {
                logCustomKept(root, it)
                return emptyList()
            }
            if (proto0 in PROXY_PROTOCOLS || isShadowsocks(root)) {
                val built = buildXrayProxy(root, proto0, root.optString("tag", root.optString("remarks", "")), noiseFm)
                if (built != null) return listOf(built)
                logCustomKept(root, conversionFailureReason(root, proto0))
                return emptyList()
            }
        }

        // Full xray config: count convertible proxy outbounds
        val obs = root.optJSONArray("outbounds") ?: run {
            if (isShadowsocks(root)) {
                buildShadowsocks(root, root.optString("remarks", ""))?.let { return listOf(it) }
                logCustomKept(root, "shadowsocks: обязательные поля отсутствуют")
            } else {
                logCustomKept(root, "JSON не распознан как конфиг: нет outbounds/server/распознаваемого протокола")
            }
            return emptyList()
        }

        val rem = root.optString("remarks", "")
        val proxies = mutableListOf<Pair<org.json.JSONObject, String>>() // ob to protocol
        for (i in 0 until obs.length()) {
            val ob = obs.optJSONObject(i) ?: continue
            val p = ob.optString("protocol", ob.optString("type"))
            if (p in PROXY_PROTOCOLS || isShadowsocks(ob)) {
                proxies.add(Pair(ob, p))
            }
        }

        // Exactly one proxy outbound -> convert to a link.
        if (proxies.size == 1) {
            val (ob, p) = proxies[0]
            val built = buildXrayProxy(ob, p, rem, noiseFm)
            if (built != null) return listOf(built)
            logCustomKept(root, conversionFailureReason(ob, p))
            return emptyList()
        }

        // Multiple proxy outbounds (balancer / multi-server) -> emit one link per
        // proxy ТОЛЬКО если собраны ВСЕ: возврат подмножества молча потерял бы
        // несконвертированные outbounds. Иначе конфиг целиком остаётся
        // кастомным (исходный JSON сохраняется без потерь), а причина каждого
        // отказа зафиксирована в логе.
        if (proxies.size > 1) {
            val links = mutableListOf<String>()
            var failed = false
            for ((ob, p) in proxies) {
                val built = buildXrayProxy(ob, p, rem, noiseFm)
                if (built != null) links.add(built)
                else {
                    failed = true
                    logCustomKept(root, "outbound '${ob.optString("tag", "?")}': ${conversionFailureReason(ob, p)}")
                }
            }
            if (!failed && links.isNotEmpty()) return links
            if (failed) {
                logCustomKept(root, "multi-server: не все outbounds конвертируются, конфиг сохранён целиком без потерь")
                return emptyList()
            }
        }

        // Ни одного прокси-outbound: явная причина вместо молчаливого пустого списка.
        val firstProto = (0 until obs.length())
            .mapNotNull { obs.optJSONObject(it)?.optString("protocol")?.takeIf { s -> s.isNotEmpty() } }
            .firstOrNull()
        logCustomKept(root, when {
            firstProto != null && unsupportedProtocolReason(firstProto) != null ->
                unsupportedProtocolReason(firstProto)!!
            isShadowsocks(root) -> "shadowsocks: обязательные поля отсутствуют"
            else -> "в конфиге нет распознаваемых прокси-outbound (протоколы: " +
                (0 until obs.length()).mapNotNull { obs.optJSONObject(it)?.optString("protocol") }
                    .joinToString(",").ifEmpty { "нет outbounds" } + ")"
        })
        return emptyList()
    }

    /**
     * Единый диспетчер «xray-outbound -> ссылка» для полного конфига.
     * Возвращает ссылку, либо null — и тогда вызывающий ОБЯЗАН зафиксировать
     * причину отказа (conversionFailureReason), молчаливых пустых списков нет.
     */
    private fun buildXrayProxy(ob: JSONObject, p: String, rem: String, noiseFm: String?): String? = when (p) {
        "vless" -> buildVless(ob, rem)
        "vmess" -> buildVmess(ob, rem)
        "shadowsocks" -> buildShadowsocks(ob, rem)
        "trojan" -> buildTrojan(ob, rem)
        "hysteria", "hysteria2" -> buildHysteriaX(ob, rem)
        // TUIC: парсер в форке отключён (EConfigType.TUIC закомментирован,
        // в configFmtParsers нет) — tuic:// ссылка не импортировалась бы.
        // Честный отказ вместо мёртвой ссылки.
        "tuic" -> null
        "wireguard" -> buildWireguard(ob, rem, noiseFm)
        "masque" -> buildMasque(ob, rem)
        // http:// ссылки форк НЕ импортирует (схемы нет в configFmtParsers),
        // а для приватного IP строка ещё и ушла бы в подписку (isValidSubUrl).
        // Честный отказ; socks:// парсер есть — собираем.
        "socks" -> buildXrayUserPass(p, ob, rem)
        "http" -> null
        "amneziawg", "awg" -> buildAmnezia(ob, rem)
        "mimic" -> buildXrayMimic(ob, rem)
        else -> if (isShadowsocks(ob)) buildShadowsocks(ob, rem) else null
    }

    /**
     * Явная причина, по которой протокол/конфиг не конвертируется в ссылку.
     * null — для протоколов, которые диспетчер умеет собирать (там отказ
     * объясняет conversionFailureReason по содержимому outbound).
     */
    private fun unsupportedProtocolReason(p: String): String? = when (p) {
        "fptn" -> "FPTN поднимает собственный TUN в root-режиме; outbound-конфига Xray для него не существует, а токен доступа передаётся только ссылкой fptn://, не JSON-конфигом"
        "policygroup", "policy-group" -> "POLICYGROUP — внутренняя группа форка (балансер/фильтр подписки), формат share-ссылки её не выражает"
        "proxychain", "proxy-chain" -> "PROXYCHAIN — внутренняя цепочка профилей форка, формат share-ссылки её не выражает"
        "custom", "custom_outbound", "custom-outbound" -> "кастомный профиль уже хранит исходный JSON без потерь; конвертация в ссылку не требуется"
        "tuic" -> "TUIC: парсер ссылок в форке отключён (EConfigType.TUIC закомментирован), tuic:// ссылка не импортировалась бы — профиль остаётся кастомным"
        "hysteria" -> "hysteria: версия 1 не поддерживается парсером форка (профиль остаётся кастомным без потерь)"
        "freedom", "blackhole", "dns", "dokodemo-door", "loopback",
        "direct", "block" -> "служебный outbound '$p' не является прокси-сервером"
        else -> null
    }

    /**
     * Причина отказа конвертации конкретного outbound, когда сборщик вернул
     * null. Диагностическая: называет протокол и самое вероятное ограничение,
     * чтобы в логе было видно, ПОЧЕМУ запись осталась кастомной.
     */
    private fun conversionFailureReason(ob: JSONObject, p: String): String {
        unsupportedProtocolReason(p)?.let { return it }
        val st = ob.optJSONObject("settings")
        val multi = when (p) {
            "vless", "vmess" -> st?.optJSONArray("vnext")?.let { it.length() != 1 } == true
            "shadowsocks", "trojan", "hysteria", "hysteria2", "socks", "http" ->
                st?.optJSONArray("servers")?.let { it.length() != 1 } == true
            else -> false
        }
        if (multi) return "$p: multi-server outbound (несколько адресов/пользователей) — ссылка выражает один сервер; профиль остаётся кастомным без потерь"
        return when (p) {
            "wireguard" -> when {
                (ob.optJSONObject("amnezia-wg-option") ?: ob.optJSONObject("amnezia")
                    ?: st?.optJSONObject("amnezia-wg-option"))?.length() ?: 0 > 0 ->
                    "wireguard с AmneziaWG-опциями: awg-сборка не удалась (нет ключей/endpoint), plain-ссылка потеряла бы обфускацию"
                ob.has("private_key") && ob.optString("private_key").isEmpty() ->
                    "wireguard (sing-box): пустой private_key"
                st?.optJSONArray("peers")?.length() ?: 0 > 1 ->
                    "wireguard: peers > 1 (multi-peer не выражается одной ссылкой)"
                st?.optJSONArray("peers")?.optJSONObject(0)?.optJSONArray("allowedIPs")?.let { a ->
                    (0 until a.length()).map { a.optString(it) }.toSet()
                }?.let { it.isNotEmpty() && it != setOf("0.0.0.0/0", "::/0") } == true ->
                    "wireguard: allowedIPs отличается от полного маршрута (ссылка его не выражает)"
                else -> "wireguard: нет secretKey/endpoint или иной обязательный параметр отсутствует"
            }
            "vmess" -> {
                val net = ob.optJSONObject("streamSettings")?.optString("network")
                    ?: ob.optJSONObject("transport")?.optString("type")
                if (net == "xhttp" || net == "splithttp" || net == "splitHttp")
                    "vmess: транспорт xhttp не выражается форматом vmess:// v2 (нет полей mode/extra) — профиль остаётся кастомным без потерь"
                else "vmess: обязательные поля отсутствуют (xray: vnext/users/id; sing-box: server/server_port/uuid) или транспорт xhttp не выражается vmess:// v2"
            }
            "amneziawg", "awg" -> when {
                (ob.optJSONObject("amnezia-wg-option") ?: ob.optJSONObject("amneziaOptions")
                    ?: ob.optJSONObject("settings")?.optJSONObject("amnezia-wg-option"))
                    ?.length() ?: 0 == 0 ->
                    "amneziawg: нет amnezia-wg-option — обфускации нет, awg-ссылка бессмысленна (для plain используйте protocol=wireguard)"
                else -> "amneziawg: нет обязательных полей (secretKey/publicKey/endpoint) или version не число"
            }
            "mimic" -> "mimic: нет uuid/адреса/порта"
            "trojan" -> "trojan: транспорт xhttp не выражается trojan:// (нет полей mode/extra) или обязательные поля отсутствуют — профиль остаётся кастомным без потерь"
            "shadowsocks" -> "shadowsocks: plugin не поддерживается профилем форка (только obfs=http), профиль остаётся кастомным без потерь"
            "socks" -> "socks: settings.servers[] пуст или содержит более одного сервера"
            "http" -> "http: форк не импортирует http:// ссылки (схемы нет в карте парсеров); для приватного IP строка ушла бы в подписку — профиль остаётся кастомным"
            "hysteria", "hysteria2" -> {
                val ver = ob.optJSONObject("streamSettings")?.optJSONObject("hysteriaSettings")?.optInt("version", 0)
                    ?: ob.optJSONObject("settings")?.optInt("version", 0)
                    ?: ob.optInt("version", 0)
                if (ver == 1 || (ver == 0 && p == "hysteria"))
                    "hysteria: версия 1 не поддерживается парсером форка (профиль остаётся кастомным без потерь)"
                else "hysteria2: нет адреса/порта или обязательных полей"
            }
            else -> "$p: обязательные поля outbound отсутствуют или формат не распознан"
        }
    }

    /** Лог причины с защитой от неинициализированного MMKV в unit-тестах. */
    private fun logCustomKept(root: JSONObject, reason: String) {
        runCatching {
            LogUtil.w(
                "SubConverter",
                "конфиг '${root.optString("remarks", root.optString("tag", "?"))}' оставлен кастомным: $reason",
            )
        }
    }

    /**
     * Xray socks/http outbound полного конфига -> socks://|http:// ссылка.
     * В отличие от bare sing-box объекта, здесь креды лежат в
     * settings.servers[0].{address,port,users[0].{user,pass}}.
     * Более одного сервера — отказ (одна ссылка = один сервер).
     */
    private fun buildXrayUserPass(scheme: String, ob: JSONObject, rem: String): String? = try {
        val servers = ob.optJSONObject("settings")?.optJSONArray("servers") ?: return null
        if (servers.length() != 1) return null
        val s = servers.getJSONObject(0)
        val address = s.optString("address", "")
        val port = s.optInt("port", 0)
        if (address.isEmpty() || port <= 0) return null
        val u = s.optJSONArray("users")?.optJSONObject(0)
        val user = u?.optString("user", "").orEmpty()
        val pass = u?.optString("pass", "").orEmpty()
        // SocksFmt.parse читает userInfo с ':' напрямую, без URL-декодирования,
        // но спецсимволы (@/:/пробел) обязаны быть percent-encoded для URI.
        val userinfo = if (user.isEmpty() && pass.isEmpty()) "" else
            "${URLEncoder.encode(user, "UTF-8").replace("+", "%20")}:${URLEncoder.encode(pass, "UTF-8").replace("+", "%20")}@"
        val hp = if (address.contains(':')) "[$address]" else address
        val encRem = URLEncoder.encode(ob.optString("remarks", rem), "UTF-8").replace("+", "%20")
        "$scheme://$userinfo$hp:$port#$encRem"
    } catch (_: Throwable) {
        null
    }

    /**
     * AmneziaWG outbound (mihomo-стиль type=wireguard + amnezia-wg-option, либо
     * явный protocol=amneziawg) -> awg:// ссылка, которую читает AmneziaFmt.
     *
     * ВАЖНО: конвертация в plain wireguard:// ПОТЕРЯЛА бы обфускацию
     * (jc/jmin/jmax/s1-s4/h1-h4/i1-i5/version...) — сервер отверг бы такой
     * туннель. Поэтому опции переносятся в query один-в-один теми же ключами,
     * которые AmneziaFmt.parse читает регистронезависимо и нормализует.
     * Ключи mihomo snake_case (header_protection_key) переводятся в
     * kebab-case (header-protection-key), boolean-ключи random-trailers/
     * disable-cookies — в spelling AmneziaFmt.
     */
    private fun buildAmnezia(ob: JSONObject, rem: String): String? = try {
        // mihomo-поля верхнего уровня либо xray settings
        val st = ob.optJSONObject("settings")
        // xray-форма с peers: ровно один peer (multi-peer ссылка не выражает)
        st?.optJSONArray("peers")?.takeIf { it.length() != 1 }?.let { return null }
        val secret = ob.optString("private-key",
            ob.optString("private_key", st?.optString("secretKey", "").orEmpty()))
        if (secret.isEmpty()) return null
        val peer0 = st?.optJSONArray("peers")?.optJSONObject(0)
        val pub = ob.optString("public-key",
            ob.optString("public_key", ob.optString("peer_public_key",
                peer0?.optString("publicKey", "").orEmpty())))
        if (pub.isEmpty()) return null
        var host = ob.optString("server", "")
        var port = ob.optInt("port", ob.optInt("server_port", 0))
        if (host.isEmpty() || port <= 0) {
            val sp = splitEndpoint(peer0?.optString("endpoint", "").orEmpty()) ?: return null
            host = sp.first; port = sp.second.toIntOrNull() ?: 0
        }
        if (host.isEmpty() || port <= 0) return null

        val opts = ob.optJSONObject("amnezia-wg-option")
            ?: ob.optJSONObject("amneziaOptions")
            ?: st?.optJSONObject("amnezia-wg-option")
        // Без опций это обычный wireguard: конвертируем как wireguard,
        // не выдумывая awg-профиль с пустой обфускацией.
        if (opts == null || opts.length() == 0) return null

        val params = linkedMapOf<String, String>()
        params["publickey"] = pub
        ob.optString("pre-shared-key",
            ob.optString("pre_shared_key", peer0?.optString("preSharedKey", "").orEmpty()))
            .takeIf { it.isNotEmpty() }?.let { params["presharedkey"] = it }
        // mihomo хранит ip/ipv6 БЕЗ маски, AmneziaWG-профиль ждёт CIDR:
        // дополняем /32 и /128, иначе туннель поднимется с неверным адресом.
        val ip = ob.optString("ip", "").let { if (it.isNotEmpty() && !it.contains("/")) "$it/32" else it }
        val ip6 = ob.optString("ipv6", "").let { if (it.isNotEmpty() && !it.contains("/")) "$it/128" else it }
        val addr = listOf(ip, ip6).filter { it.isNotEmpty() }.joinToString(",")
        if (addr.isNotEmpty()) params["address"] = addr
        else (st?.optJSONArray("address") ?: ob.optJSONArray("local_address"))?.let { a ->
            if (a.length() > 0) params["address"] = (0 until a.length())
                .mapNotNull { a.optString(it).takeIf { s -> s.isNotEmpty() } }.joinToString(",")
        }
        (ob.optInt("mtu", 0).takeIf { it > 0 } ?: st?.optInt("mtu", 0)?.takeIf { it > 0 })
            ?.let { params["mtu"] = it.toString() }
        when (val r = ob.opt("reserved") ?: st?.opt("reserved")) {
            is JSONArray -> if (r.length() > 0) params["reserved"] =
                (0 until r.length()).map { r.opt(it).toString() }.joinToString(",")
            is String -> r.takeIf { it.isNotEmpty() }?.let { params["reserved"] = it }
            else -> {}
        }

        // version обязан быть числом: AmneziaFmt читает его toIntOrNull,
        // нечисловой молча потерялся бы — отказываемся честно.
        opts.opt("version")?.toString()?.takeIf { it.isNotEmpty() && it != "null" }?.let {
            if (it.toIntOrNull() == null) return null
        }
        // Опции: ключи нормализуем к чтимому AmneziaFmt виду.
        val boolKeys = mapOf(
            "random-trailers" to "random-trailers", "randomtrailers" to "random-trailers",
            "random_trailers" to "random-trailers",
            "disable-cookies" to "disable-cookies", "disablecookies" to "disable-cookies",
            "disable_cookies" to "disable-cookies",
        )
        opts.keys().forEach { k ->
            val v = opts.opt(k)?.toString().orEmpty()
            if (v.isEmpty() || v == "null") return@forEach
            val lk = k.lowercase()
            val boolKey = boolKeys[lk]
            if (boolKey != null) {
                params[boolKey] = if (v == "true" || v == "1") "true" else "false"
            } else {
                // header_protection_key -> header-protection-key; h1/jc как есть
                params[lk.replace('_', '-')] = v
            }
        }
        // %20 вместо '+': Utils.decodeURIComponent (им читает AmneziaFmt)
        // трактует '+' как литеральный плюс, а j1/i1 содержат пробелы.
        val q = params.toList().joinToString("&") {
            "${it.first}=${URLEncoder.encode(it.second, "UTF-8").replace("+", "%20")}"
        }
        val hp = if (host.contains(':')) "[$host]" else host
        val encRem = URLEncoder.encode(rem, "UTF-8").replace("+", "%20")
        "awg://${URLEncoder.encode(secret, "UTF-8").replace("+", "%20")}@$hp:$port?$q#$encRem"
    } catch (_: Throwable) {
        null
    }

    /**
     * Mimic outbound (xray-стиль settings{address,port,uuid/password} либо
     * sing-box-стиль server/server_port/uuid) -> mimic:// ссылка (MimicFmt).
     * Домены мимикрии — JSON-массив в ключе domains, как их хранит профиль.
     */
    private fun buildMimicCommon(
        host: String, port: Int, uuid: String, domains: JSONArray?, rem: String
    ): String? {
        if (host.isEmpty() || port <= 0 || uuid.isEmpty()) return null
        val hp = if (host.contains(':')) "[$host]" else host
        val q = domains?.takeIf { it.length() > 0 }
            ?.let { "?domains=${URLEncoder.encode(it.toString(), "UTF-8").replace("+", "%20")}" } ?: ""
        val encRem = URLEncoder.encode(rem, "UTF-8").replace("+", "%20")
        return "mimic://${URLEncoder.encode(uuid, "UTF-8").replace("+", "%20")}@$hp:$port$q#$encRem"
    }

    private fun buildXrayMimic(ob: JSONObject, rem: String): String? = try {
        val st = ob.optJSONObject("settings") ?: return null
        val host = st.optString("address", "")
        val port = st.optInt("port", 0)
        val uuid = st.optString("uuid", st.optString("password", ""))
        val domains = st.optJSONArray("domains") ?: ob.optJSONArray("domains")
        buildMimicCommon(host, port, uuid, domains, ob.optString("remarks", rem))
    } catch (_: Throwable) {
        null
    }

    private fun buildSbMimic(root: JSONObject, rem: String): String? = try {
        val host = root.optString("server", "")
        val port = root.optInt("server_port", 0)
        val uuid = root.optString("uuid", root.optString("password", ""))
        val domains = root.optJSONArray("domains")
        buildMimicCommon(host, port, uuid, domains, rem)
    } catch (_: Throwable) {
        null
    }

    /** Accepted spellings of the certificate pin inside a custom JSON profile. */
    private val PIN_SHA256_KEYS = arrayOf("pinnedPeerCertSha256", "pinSHA256")

    private val PROXY_PROTOCOLS = setOf(
        "vless", "vmess", "shadowsocks", "trojan",
        "hysteria", "hysteria2", "tuic", "socks", "http",
        // wireguard и masque добавлены, чтобы конвертер покрывал ВСЕ протоколы,
        // которые форк умеет разбирать из ссылок (см. configFmtParsers в
        // AngConfigManager). Раньше wireguard-конфиг при включённом
        // «Кастомные в ссылки» молча оставался кастомным: протокол не
        // распознавался, processJsonAll возвращал пустой список.
        "wireguard", "masque",
        // amneziawg/mimic собираются в awg:// и mimic:// (см. buildAmnezia/
        // buildXrayMimic). fptn включён, чтобы отказ был ЯВНЫМ в логе
        // («FPTN не выражается outbound-конфигом»), а не молчаливым пропуском.
        "amneziawg", "awg", "mimic", "fptn"
    )

    /**
     * Поглощает цепочку «wireguard -> freedom с noises» и возвращает JSON
     * finalmask для ключа fm, либо null, если цепочки такого вида нет.
     *
     * Почему это безопасно и не потеря данных:
     *   - Xray-core (v26.11.9, wireguard/client.go) применяет
     *     streamSettings.FinalMask к UDP-сокету wireguard, то есть шум идёт
     *     ПЕРЕД handshake ровно так же, как через freedom-цепочку;
     *   - сам core помечает noises в freedom устаревшими и рекомендует
     *     finalmask.udp (infra/conf/freedom.go: PrintDeprecatedFeatureWarning);
     *   - формат элемента шума совпадает: type/packet/delay, а freedom-«rand»
     *     (диапазон в packet) переходит в поле rand finalmask.
     *
     * Условия поглощения (иначе null, и цепочка остаётся кастомной):
     *   - ровно один outbound с sockopt.dialerProxy и он wireguard;
     *   - цель dialerProxy — freedom с непустым settings.noises;
     *   - ни у одного другого outbound нет dialerProxy (иначе это настоящая
     *     multi-hop цепочка, её формат ссылки не выражает);
     *   - каждый noise-элемент конвертируем (type rand/hex/str/base64/exp).
     */
    internal fun noiseChainFinalMask(root: JSONObject): String? {
        val obs = root.optJSONArray("outbounds") ?: return null
        var wgWithDialer: JSONObject? = null
        var dialerTag: String? = null
        var otherDialers = 0
        val byTag = mutableMapOf<String, JSONObject>()
        for (i in 0 until obs.length()) {
            val ob = obs.optJSONObject(i) ?: continue
            ob.optString("tag").takeIf { it.isNotEmpty() }?.let { byTag[it] = ob }
            val dialer = ob.optJSONObject("streamSettings")
                ?.optJSONObject("sockopt")
                ?.optString("dialerProxy")?.takeIf { it.isNotEmpty() }
            if (dialer != null) {
                otherDialers++
                if (ob.optString("protocol") == "wireguard" && wgWithDialer == null) {
                    wgWithDialer = ob; dialerTag = dialer; otherDialers--
                }
            }
        }
        if (wgWithDialer == null || otherDialers > 0) return null
        val target = byTag[dialerTag] ?: return null
        if (target.optString("protocol") != "freedom") return null
        val noises = target.optJSONObject("settings")?.optJSONArray("noises")
        if (noises == null || noises.length() == 0) return null

        val items = org.json.JSONArray()
        for (i in 0 until noises.length()) {
            val n = noises.optJSONObject(i) ?: return null
            val type = n.optString("type", "")
            val packet = n.optString("packet", "")
            val delay = n.optString("delay", "")
            val item = JSONObject()
            when (type) {
                // freedom: диапазон длины лежит в packet; finalmask: поле rand
                "rand" -> {
                    if (packet.isEmpty()) return null
                    item.put("rand", packet)
                }
                "hex", "str", "base64", "exp" -> {
                    item.put("type", type)
                    item.put("packet", packet)
                }
                "" -> {
                    // freedom без type = сырые байты массивом; finalmask type array
                    item.put("type", "array")
                    item.put("packet", n.opt("packet") ?: return null)
                }
                else -> return null
            }
            if (delay.isNotEmpty()) item.put("delay", delay)
            items.put(item)
        }
        val fm = JSONObject()
            .put("udp", org.json.JSONArray().put(
                JSONObject().put("type", "noise").put("settings", JSONObject().put("noise", items))
            ))
        return fm.toString()
    }

    /**
     * Причина, по которой конфиг НЕ может быть конвертирован в ссылку без
     * потери данных, или null, если цепочки нет.
     *
     * Цепочка outbounds (multi-hop) выражается в Xray через
     * streamSettings.sockopt.dialerProxy, а в sing-box через detour. Формат
     * share-ссылки не имеет поля для следующего хопа, поэтому конвертация
     * такого конфига МОЛЧА потеряла бы обфускацию или промежуточный прокси
     * (пример: WARP, у которого wireguard ходит через freedom с noises).
     * Конфиг остаётся кастомным, а причина фиксируется в логе: молчаливая
     * потеря настроек хуже честного «осталось как есть».
     *
     * Функция чистая (без логов и состояния), чтобы её можно было покрыть
     * unit-тестом: LogUtil в тестах недоступен (тянет MMKV).
     */
    internal fun chainReason(root: JSONObject): String? {
        // sing-box: detour у самого outbound-объекта
        if (root.optString("detour").isNotEmpty()) {
            return "outbound использует detour (цепочку), которую формат ссылки не выражает"
        }
        val dialer = fun(ob: JSONObject): String? =
            ob.optJSONObject("streamSettings")
                ?.optJSONObject("sockopt")
                ?.optString("dialerProxy")
                ?.takeIf { it.isNotEmpty() }
                ?.let { "outbound использует sockopt.dialerProxy=$it (цепочку), которую формат ссылки не выражает" }
        // Xray: полный конфиг — проверяем каждый outbound
        val obs = root.optJSONArray("outbounds")
        if (obs != null) {
            for (i in 0 until obs.length()) {
                val ob = obs.optJSONObject(i) ?: continue
                dialer(ob)?.let { return it }
            }
            return null
        }
        // Xray: одиночный outbound-объект
        return dialer(root)
    }

    /**
     * Xray wireguard outbound -> wireguard:// ссылка.
     *
     * Формат outbound (см. CoreOutboundBuilder.toOutboundWireguard):
     * settings.secretKey, settings.address[], settings.mtu, settings.peers[]
     * с endpoint/publicKey/preSharedKey. Ссылка читается WireguardFmt.parse:
     * userInfo=secretKey, query publickey/address/mtu/reserved/dns/presharedkey.
     *
     * Ограничения, при которых конвертация НЕ выполняется (конфиг остаётся
     * кастомным), чтобы не потерять данные молча:
     *   - peers больше одного (multi-peer не выражается одной ссылкой);
     *   - allowedIPs отличны от полного маршрута (0.0.0.0/0 и ::/0);
     *   - цепочка dialerProxy (проверяется выше).
     */
    private fun buildWireguard(ob: JSONObject, rem: String, finalMaskJson: String? = null): String? = try {
        // AmneziaWG-опции (mihomo-формат верхнего уровня ИЛИ xray settings):
        // конвертация в plain wireguard:// ПОТЕРЯЛА бы обфускацию. Проверяем
        // ДО требования settings: mihomo-объект (type=wireguard + server/port/
        // private-key + amnezia-wg-option) не имеет settings вовсе, и ранний
        // return null делал awg-сборку недостижимой.
        val stEarly = ob.optJSONObject("settings")
        val awgOpts = ob.optJSONObject("amnezia-wg-option")
            ?: stEarly?.optJSONObject("amnezia-wg-option")
            ?: ob.optJSONObject("amneziaOptions")
        if (awgOpts != null && awgOpts.length() > 0) {
            return buildAmnezia(ob, rem)
        }
        val st = stEarly ?: return null
        val secret = st.optString("secretKey", "")
        if (secret.isEmpty()) return null
        val peers = st.optJSONArray("peers")
        if (peers == null || peers.length() != 1) {
            LogUtil.w("SubConverter", "wireguard: peers != 1, оставлен кастомным")
            return null
        }
        val peer = peers.getJSONObject(0)
        val endpoint = peer.optString("endpoint", "")
        if (endpoint.isEmpty()) return null
        val (host, port) = splitEndpoint(endpoint) ?: return null
        val allowed = peer.optJSONArray("allowedIPs")
        if (allowed != null) {
            val set = (0 until allowed.length()).map { allowed.optString(it) }.toSet()
            if (set != setOf("0.0.0.0/0", "::/0")) {
                LogUtil.w("SubConverter", "wireguard: нестандартный allowedIPs, оставлен кастомным")
                return null
            }
        }
        val params = linkedMapOf<String, String>()
        params["publickey"] = peer.optString("publicKey", "")
        val addr = st.optJSONArray("address")
        if (addr != null && addr.length() > 0) {
            params["address"] = (0 until addr.length()).mapNotNull { addr.optString(it).takeIf { s -> s.isNotEmpty() } }.joinToString(",")
        }
        st.optInt("mtu").takeIf { it > 0 }?.let { params["mtu"] = it.toString() }
        peer.optString("preSharedKey", "").takeIf { it.isNotEmpty() }?.let { params["presharedkey"] = it }
        st.optString("remoteDNS", "").takeIf { it.isNotEmpty() }?.let { params["dns"] = it }
        // Шумовая защита от DPI: finalmask целиком (JSON), ключ fm читает
        // WireguardFmt.parse в ProfileItem.finalMask, а CoreOutboundBuilder
        // кладёт его в streamSettings.finalmask. Приоритет у поглощённой
        // цепочки freedom-noises; если её нет, но у самого wireguard уже есть
        // свой finalmask (например, конфиг, ранее собранный этим форком),
        // переносим его без потери.
        val ownFm = ob.optJSONObject("streamSettings")?.optJSONObject("finalmask")
            ?.takeIf { it.length() > 0 }?.toString()
        val fm = finalMaskJson?.takeIf { it.isNotEmpty() } ?: ownFm
        fm?.let { params["fm"] = it }
        // Шум целиком несёт fm; поле шума при импорте восстанавливается из fm
        // (WireguardFmt.parse). Отдельный ключ noises не пишем: удвоение
        // payload с большим hex-пакетом превышает ёмкость QR-кода.
        val q = params.toList().joinToString("&") { "${it.first}=${URLEncoder.encode(it.second, "UTF-8")}" }
        val enc = URLEncoder.encode(rem, "UTF-8").replace("+", "%20")
        "wireguard://${URLEncoder.encode(secret, "UTF-8")}@$host:$port?$q#$enc"
    } catch (_: Throwable) {
        null
    }

    /**
     * Xray masque outbound -> masque:// ссылка (обратно читается MasqueFmt.parse).
     * settings.address/settings.port, settings.remoteDNS[],
     * streamSettings.masqueSettings.{host,path,warp{privateKey,publicKey,address}}.
     */
    private fun buildMasque(ob: JSONObject, rem: String): String? = try {
        val st = ob.optJSONObject("settings") ?: return null
        val address = st.optString("address", "")
        val port = st.optInt("port", 0)
        if (address.isEmpty() || port <= 0) return null
        val (host, portStr) = splitEndpoint("$address:$port") ?: return null
        val ms = ob.optJSONObject("streamSettings")?.optJSONObject("masqueSettings")
        val warp = ms?.optJSONObject("warp")
        val params = linkedMapOf<String, String>()
        warp?.optString("publicKey", "")?.takeIf { it.isNotEmpty() }?.let { params["publickey"] = it }
        warp?.optJSONArray("address")?.let { a ->
            if (a.length() > 0) params["address"] = (0 until a.length()).mapNotNull { a.optString(it).takeIf { s -> s.isNotEmpty() } }.joinToString(",")
        }
        st.optJSONArray("remoteDNS")?.let { d ->
            if (d.length() > 0) params["dns"] = (0 until d.length()).mapNotNull { d.optString(it).takeIf { s -> s.isNotEmpty() } }.joinToString(",")
        }
        ms?.optString("host", "")?.takeIf { it.isNotEmpty() }?.let { params["host"] = it }
        ms?.optString("path", "")?.takeIf { it.isNotEmpty() }?.let { params["path"] = it }
        ms?.optJSONObject("headers")?.let { h ->
            if (h.length() > 0) params["headers"] = h.toString()
        }
        val q = params.toList().joinToString("&") { "${it.first}=${URLEncoder.encode(it.second, "UTF-8")}" }
        val secret = warp?.optString("privateKey", "").orEmpty()
        val enc = URLEncoder.encode(rem, "UTF-8").replace("+", "%20")
        "masque://${URLEncoder.encode(secret, "UTF-8")}@$host:$portStr?$q#$enc"
    } catch (_: Throwable) {
        null
    }

    /**
     * sing-box wireguard outbound -> wireguard:// ссылка.
     * Поля: server, server_port, local_address[], private_key, peer_public_key,
     * pre_shared_key, mtu, reserved (массив или base64-строка).
     */
    private fun buildSbWireguard(root: JSONObject, rem: String): String? = try {
        // AmneziaWG в sing-box-обёртке: обфускацию терять нельзя, plain-ссылка
        // её не выражает. awg-сборщик понимает mihomo-имена; sing-box
        // awg-поля (junk_packet_count и т.п.) не нормализованы — честный отказ.
        val awgOpts = root.optJSONObject("amnezia-wg-option") ?: root.optJSONObject("amnezia")
        if (awgOpts != null && awgOpts.length() > 0) {
            return buildAmnezia(root, root.optString("tag", ""))
        }
        val secret = root.optString("private_key", "")
        if (secret.isEmpty()) return null
        val host = root.optString("server", "")
        val port = root.optInt("server_port", 0)
        if (host.isEmpty() || port <= 0) return null
        val params = linkedMapOf<String, String>()
        root.optString("peer_public_key", "").takeIf { it.isNotEmpty() }?.let { params["publickey"] = it }
        root.optString("pre_shared_key", "").takeIf { it.isNotEmpty() }?.let { params["presharedkey"] = it }
        val la = root.optJSONArray("local_address")
        if (la != null && la.length() > 0) {
            params["address"] = (0 until la.length()).mapNotNull { la.optString(it).takeIf { s -> s.isNotEmpty() } }.joinToString(",")
        }
        root.optInt("mtu").takeIf { it > 0 }?.let { params["mtu"] = it.toString() }
        when (val r = root.opt("reserved")) {
            is org.json.JSONArray ->
                if (r.length() > 0) params["reserved"] = (0 until r.length()).map { r.opt(it).toString() }.joinToString(",")
            is String -> r.takeIf { it.isNotEmpty() }?.let { params["reserved"] = it }
            else -> {}
        }
        val q = params.toList().joinToString("&") { "${it.first}=${URLEncoder.encode(it.second, "UTF-8")}" }
        val enc = URLEncoder.encode(rem, "UTF-8").replace("+", "%20")
        val hp = if (host.contains(':')) "[$host]" else host
        "wireguard://${URLEncoder.encode(secret, "UTF-8")}@$hp:$port?$q#$enc"
    } catch (_: Throwable) {
        null
    }

    /**
     * sing-box naive outbound -> naive:// ссылка (обратно читает NaiveFmt.parse).
     * JSON: type=naive, server, server_port, username, password, tls{server_name,
     * insecure}. TLS-поля кладём в query теми же ключами, что читает
     * getItemFormQuery (sni, insecure).
     */
    private fun buildSbNaive(root: JSONObject, rem: String): String? = try {
        val host = root.optString("server", "")
        val port = root.optInt("server_port", 0)
        if (host.isEmpty() || port <= 0) return null
        val user = root.optString("username", "")
        val pass = root.optString("password", "")
        val tls = root.optJSONObject("tls")
        val params = linkedMapOf<String, String>()
        tls?.optString("server_name", "")?.takeIf { it.isNotEmpty() }?.let { params["sni"] = it }
        if (tls?.optBoolean("insecure", false) == true) params["insecure"] = "1"
        val q = if (params.isEmpty()) "" else "?" + params.toList()
            .joinToString("&") { "${it.first}=${URLEncoder.encode(it.second, "UTF-8")}" }
        val hp = if (host.contains(':')) "[$host]" else host
        val enc = URLEncoder.encode(rem, "UTF-8").replace("+", "%20")
        "naive://${URLEncoder.encode(user, "UTF-8")}:${URLEncoder.encode(pass, "UTF-8")}@$hp:$port$q#$enc"
    } catch (_: Throwable) {
        null
    }

    /**
     * sing-box openconnect endpoint -> openconnect:// ссылка (обратно читает
     * OpenconnectFmt.parse). JSON: type=openconnect, server ("host:port" или
     * host + server_port), username, password, flavor, auth_group, tls{...}.
     */
    private fun buildSbOpenconnect(root: JSONObject, rem: String): String? = try {
        var host = root.optString("server", "")
        var port = root.optInt("server_port", 0)
        if (port <= 0 && host.contains(':')) {
            val sp = splitEndpoint(host) ?: return null
            host = sp.first; port = sp.second.toIntOrNull() ?: 0
        }
        if (host.isEmpty() || port <= 0) return null
        val user = root.optString("username", "")
        val pass = root.optString("password", "")
        val params = linkedMapOf<String, String>()
        root.optString("auth_group", "").takeIf { it.isNotEmpty() }?.let { params["group"] = it }
        root.optString("flavor", "").takeIf { it.isNotEmpty() && it != "anyconnect" }
            ?.let { params["flavor"] = it }
        val tls = root.optJSONObject("tls")
        tls?.optString("server_name", "")?.takeIf { it.isNotEmpty() }?.let { params["sni"] = it }
        if (tls?.optBoolean("insecure", false) == true) params["insecure"] = "1"
        val q = if (params.isEmpty()) "" else "?" + params.toList()
            .joinToString("&") { "${it.first}=${URLEncoder.encode(it.second, "UTF-8")}" }
        val hp = if (host.contains(':')) "[$host]" else host
        val enc = URLEncoder.encode(rem, "UTF-8").replace("+", "%20")
        "openconnect://${URLEncoder.encode(user, "UTF-8")}:${URLEncoder.encode(pass, "UTF-8")}@$hp:$port$q#$enc"
    } catch (_: Throwable) {
        null
    }

    /** "host:port" или "[ipv6]:port" -> пара строк; null если разобрать нельзя. */
    private fun splitEndpoint(endpoint: String): Pair<String, String>? {
        val e = endpoint.trim()
        return when {
            e.startsWith("[") -> {
                val close = e.indexOf(']')
                if (close <= 0) null
                else e.substring(1, close) to e.substring(close + 1).removePrefix(":")
            }
            e.count { it == ':' } == 1 -> e.substringBefore(':') to e.substringAfter(':')
            else -> null
        }
    }

    private fun isShadowsocks(obj: JSONObject): Boolean {
        if (obj.has("server") && obj.has("server_port") && obj.has("password") && obj.has("method")) return true
        val servers = obj.optJSONObject("settings")?.optJSONArray("servers")
        if (servers != null && servers.length() > 0) {
            val s = servers.getJSONObject(0)
            if (s.has("address") && s.has("port") && s.has("password") && s.has("method")) return true
        }
        return false
    }

    /**
     * Extracts the pinned peer certificate SHA-256 from a TLS settings block.
     *
     * Custom (JSON) profiles carry the pin under Xray's `pinnedPeerCertSha256`
     * key, while Hysteria-family configs and v2rayN share links use `pinSHA256`.
     * Both spellings are accepted so the pin survives conversion into a share
     * link; losing it silently disables certificate pinning and leaves the
     * `autoSetInsecureWhenSha256Present` subscription switch with nothing to
     * detect.
     *
     * @param sources TLS-like JSON blocks to inspect, first match wins.
     * @return the pin, or null when none of the sources provides one.
     */
    private fun pinSha256(vararg sources: JSONObject?): String? {
        for (source in sources) {
            for (key in PIN_SHA256_KEYS) {
                source?.optString(key)?.takeIf { it.isNotEmpty() }?.let { return it }
            }
        }
        return null
    }

    private fun buildVless(ob: JSONObject, rem: String): String? = try {
        val s = ob.optJSONObject("settings") ?: return null
        // Две формы settings: классическая vnext[] и прямая
        // address/port/id/encryption/flow — именно её пишут собственные
        // конфиги форка (CoreOutboundBuilder.toOutboundVless). Конвертер
        // обязан понимать обе, иначе конфиг владельца не конвертируется.
        val vnext = s.optJSONArray("vnext")
        val address: String
        val port: Int
        val u: JSONObject
        if (vnext != null && vnext.length() > 0) {
            // multi-server outbound: ссылка выражает один сервер; молча
            // потерять остальные нельзя — честный отказ.
            if (vnext.length() != 1) return null
            val vn = vnext.getJSONObject(0)
            address = vn.optString("address", "")
            port = vn.optInt("port", 0)
            val users = vn.optJSONArray("users")
            if (users == null || users.length() != 1) return null
            u = users.getJSONObject(0)
        } else {
            address = s.optString("address", "")
            port = s.optInt("port", 0)
            if (address.isEmpty() || port <= 0 || s.optString("id", "").isEmpty()) return null
            u = JSONObject()
                .put("id", s.optString("id"))
                .put("encryption", s.optString("encryption", "none"))
            s.optString("flow", "").takeIf { it.isNotEmpty() }?.let { u.put("flow", it) }
        }
        if (address.isEmpty() || port <= 0) return null
        val ss = ob.optJSONObject("streamSettings")
        val rs = ss?.optJSONObject("realitySettings")
        val enc = URLEncoder.encode(rem, "UTF-8").replace("+", "%20")
        val tlsSettings = ss?.optJSONObject("tlsSettings")
        val tlsAlpnArr = tlsSettings?.optJSONArray("alpn")
        val tlsAlpn = tlsAlpnArr?.let { a -> (0 until a.length()).mapNotNull { a.optString(it) }
            .filter { it.isNotEmpty() }.joinToString(",") } ?: ""
        val tlsInsecure = tlsSettings?.optBoolean("allowInsecure", false) == true
        val tlsFp = tlsSettings?.optString("fingerprint", "") ?: ""
        val fp = rs?.optString("fingerprint", "")?.takeIf { it.isNotEmpty() }
            ?: tlsFp.takeIf { it.isNotEmpty() } ?: "chrome"
        val pbk = rs?.optString("publicKey", "") ?: ""
        val sid = rs?.optString("shortId", "") ?: ""
        // REALITY carries its own serverName; for plain TLS it lives in
        // tlsSettings. Reading only realitySettings dropped the SNI of every
        // non-REALITY profile, making the core fall back to the bare server
        // address as the TLS server_name.
        val sni = rs?.optString("serverName", "")?.takeIf { it.isNotEmpty() }
            ?: tlsSettings?.optString("serverName", "").orEmpty()
        val security = ss?.optString("security", "none") ?: "none"
        val type = ss?.optString("network", "tcp") ?: "tcp"
        val params = linkedMapOf(
            "encryption" to u.optString("encryption", "none"),
            "flow" to u.optString("flow", ""),
            "fp" to fp,
            "pbk" to pbk,
            "security" to security,
            "sid" to sid,
            "sni" to sni,
            "type" to type,
        )
        if (tlsAlpn.isNotEmpty()) params["alpn"] = tlsAlpn
        if (tlsInsecure) params["allowInsecure"] = "1"
        pinSha256(tlsSettings)?.let { params["pcs"] = it }
        tlsSettings?.optString("verifyPeerCertByName")?.takeIf { it.isNotEmpty() }
            ?.let { params["vcn"] = it }
        // Transports are unusable without their parameters
        val wsSettings = ss?.optJSONObject("wsSettings")
        val httpSettings = ss?.optJSONObject("httpSettings")
        (wsSettings?.optString("path") ?: httpSettings?.optString("path"))
            ?.takeIf { it.isNotEmpty() }?.let { params["path"] = it }
        (wsSettings?.optJSONObject("headers")?.optString("Host")
            ?: httpSettings?.optJSONArray("host")?.optString(0))
            ?.takeIf { it.isNotEmpty() }?.let { params["host"] = it }
        val grpcSettings = ss?.optJSONObject("grpcSettings")
        grpcSettings?.optString("serviceName")?.takeIf { it.isNotEmpty() }?.let { params["serviceName"] = it }
        grpcSettings?.optString("mode")?.takeIf { it.isNotEmpty() }?.let { params["mode"] = it }
        grpcSettings?.optString("authority")?.takeIf { it.isNotEmpty() }?.let { params["authority"] = it }
        // multi-host http outbound: Host is an array
        httpSettings?.optJSONArray("host")?.let { a ->
            val j = (0 until a.length()).mapNotNull { a.optString(it) }.filter { it.isNotEmpty() }
                .joinToString(",")
            if (j.isNotEmpty()) params["host"] = j
        }
        // tcp/kcp/quic header types and kcp tuning
        when (type) {
            "tcp" -> ss?.optJSONObject("tcpSettings")?.optJSONObject("header")
                ?.optString("type")?.takeIf { it != "none" }?.let { params["headerType"] = it }
            "kcp" -> {
                ss?.optJSONObject("kcpSettings")?.optJSONObject("header")
                    ?.optString("type")?.takeIf { it != "none" }?.let { params["headerType"] = it }
                ss?.optJSONObject("kcpSettings")?.optString("seed")
                    ?.takeIf { it.isNotEmpty() }?.let { params["seed"] = it }
                ss?.optJSONObject("kcpSettings")?.optInt("mtu")?.takeIf { it > 0 }
                    ?.let { params["mtu"] = it.toString() }
                ss?.optJSONObject("kcpSettings")?.optInt("tti")?.takeIf { it > 0 }
                    ?.let { params["tti"] = it.toString() }
            }
            "quic" -> {
                val q = ss?.optJSONObject("quicSettings")
                q?.optString("security")?.takeIf { it.isNotEmpty() }?.let { params["quicSecurity"] = it }
                q?.optString("key")?.takeIf { it.isNotEmpty() }?.let { params["key"] = it }
                q?.optJSONObject("header")?.optString("type")?.takeIf { it != "none" }
                    ?.let { params["headerType"] = it }
            }
            "httpupgrade" -> ss?.optJSONObject("httpupgradeSettings")?.let { h ->
                h.optString("path")?.takeIf { it.isNotEmpty() }?.let { params["path"] = it }
                h.optJSONObject("headers")?.optString("Host")
                    ?.takeIf { it.isNotEmpty() }?.let { params["host"] = it }
            }
            "splithttp", "splitHttp", "xhttp" -> ss?.optJSONObject("splitHttpSettings")
                ?.takeIf { it.length() > 0 } ?: ss?.optJSONObject("xhttpSettings")?.let { x ->
                x.optString("path")?.takeIf { it.isNotEmpty() }?.let { params["path"] = it }
                x.optJSONArray("host")?.let { a ->
                    val j = (0 until a.length()).mapNotNull { a.optString(it) }.filter { it.isNotEmpty() }
                        .joinToString(",")
                    if (j.isNotEmpty()) params["host"] = j
                }
                x.optString("mode")?.takeIf { it.isNotEmpty() }?.let { params["mode"] = it }
                x.optJSONObject("extra")?.toString()?.takeIf { it != "null" }?.let { params["extra"] = it }
            }
        }
        // xhttp transport
        ss?.optJSONObject("xhttpSettings")?.let { x ->
            x.optString("path")?.takeIf { it.isNotEmpty() }?.let { params["path"] = it }
            x.optJSONArray("host")?.let { a ->
                val j = (0 until a.length()).mapNotNull { a.optString(it) }.filter { it.isNotEmpty() }
                    .joinToString(",")
                if (j.isNotEmpty()) params["host"] = j
            }
            x.optString("mode")?.takeIf { it.isNotEmpty() }?.let { params["mode"] = it }
            x.optJSONObject("extra")?.toString()?.takeIf { it != "null" }?.let { params["extra"] = it }
        }
        // shop QUIC tuning block (finalmask) rides along as fm
        ss?.optJSONObject("finalmask")?.toString()
            ?.takeIf { it != "null" && it.isNotEmpty() }?.let { params["fm"] = it }
        // reality spiderX
        rs?.optString("spiderX")?.takeIf { it.isNotEmpty() }?.let { params["spx"] = it }
        // TLS ECH
        tlsSettings?.optString("echConfigList")?.takeIf { it.isNotEmpty() }
            ?.let { params["ech"] = it }
        val query = params.filterValues { it.isNotEmpty() }
            .entries.joinToString("&") { "${it.key}=${URLEncoder.encode(it.value, "UTF-8")}" }
        "vless://${u.optString("id")}@$address:$port?$query#$enc"
    } catch (_: Exception) {
        null
    }

    private fun buildVmess(ob: JSONObject, rem: String): String? = try {
        val linkJson = JSONObject()
        linkJson.put("v", "2")

        val settings = ob.optJSONObject("settings")
        settings?.optJSONArray("vnext")?.takeIf { it.length() != 1 }?.let { return null }
        settings?.optJSONArray("vnext")?.optJSONObject(0)?.optJSONArray("users")
            ?.takeIf { it.length() != 1 }?.let { return null }
        val vnext = settings?.optJSONArray("vnext")?.optJSONObject(0)

        // Обе формы: vnext[] и прямая address/port/id (конфиги форка)
        val addr = ob.optString("server",
            vnext?.optString("address", "") ?: settings?.optString("address", "").orEmpty())
        val port = if (ob.has("server_port")) ob.getInt("server_port")
        else vnext?.optInt("port", 0) ?: settings?.optInt("port", 0) ?: 0
        val user0 = vnext?.optJSONArray("users")?.optJSONObject(0)
        val uuid = ob.optString("uuid",
            user0?.optString("id", "") ?: settings?.optString("id", "").orEmpty())
        val alterId = user0?.optInt("alterId", 0) ?: 0
        val security = user0?.optString("security", "")
            ?: settings?.optString("security", "").orEmpty().ifEmpty { "auto" }
        // Мёртвая ссылка (пустой адрес/порт/id) запрещена: честный отказ
        if (addr.isEmpty() || port <= 0 || uuid.isEmpty()) return null

        linkJson.put("add", addr)
        linkJson.put("port", port.toString())
        linkJson.put("id", uuid)
        linkJson.put("aid", alterId.toString())
        linkJson.put("scy", security)

        val transport = ob.optJSONObject("transport")
        val stream = ob.optJSONObject("streamSettings")
        val net = transport?.optString("type") ?: stream?.optString("network") ?: "tcp"
        // vmess:// v2 не имеет полей xhttp (mode/extra): конвертация дала бы
        // ссылку с нерабочим транспортом. Честный отказ (null -> причина в логе).
        if (net == "xhttp" || net == "splithttp" || net == "splitHttp") return null
        linkJson.put("net", net)

        val tlsObj = ob.optJSONObject("tls")
        val isTls = tlsObj?.optBoolean("enabled") ?: (stream?.optString("security") == "tls")
        linkJson.put("tls", if (isTls) "tls" else "")
        val xTls = stream?.optJSONObject("tlsSettings")
        xTls?.optString("serverName")?.takeIf { it.isNotEmpty() }?.let { linkJson.put("sni", it) }
        xTls?.optJSONArray("alpn")?.let { a ->
            val j = (0 until a.length()).mapNotNull { a.optString(it) }.filter { it.isNotEmpty() }
                .joinToString(",")
            if (j.isNotEmpty()) linkJson.put("alpn", j)
        }
        xTls?.optString("fingerprint")?.takeIf { it.isNotEmpty() }?.let { linkJson.put("fp", it) }
        if (xTls?.optBoolean("allowInsecure", false) == true) linkJson.put("allowInsecure", 1)
        pinSha256(xTls)?.let { linkJson.put("pcs", it) }
        xTls?.optString("verifyPeerCertByName")?.takeIf { it.isNotEmpty() }
            ?.let { linkJson.put("vcn", it) }

        // Транспорт vmess обязан переехать целиком: VmessFmt.parse читает
        // grpc/kcp из type/path/host, иначе туннель поднимется не туда.
        when (net) {
            "ws" -> {
                val ws = transport ?: stream?.optJSONObject("wsSettings")
                linkJson.put("path", ws?.optString("path"))
                val host = ws?.optJSONObject("headers")?.optString("Host") ?: ws?.optString("headers")
                if (host != null) linkJson.put("host", host)
            }
            "grpc" -> {
                val grpc = stream?.optJSONObject("grpcSettings")
                linkJson.put("type", grpc?.optString("mode").orEmpty())
                linkJson.put("path", grpc?.optString("serviceName"))
                linkJson.put("host", grpc?.optString("authority"))
            }
            "kcp" -> {
                val kcp = stream?.optJSONObject("kcpSettings")
                linkJson.put("type", kcp?.optJSONObject("header")?.optString("type").orEmpty())
                linkJson.put("path", kcp?.optString("seed"))
            }
            "h2", "http" -> {
                val http = stream?.optJSONObject("httpSettings")
                linkJson.put("path", http?.optString("path"))
                http?.optJSONArray("host")?.optString(0)?.takeIf { it.isNotEmpty() }
                    ?.let { linkJson.put("host", it) }
            }
            "tcp" -> {
                val header = stream?.optJSONObject("tcpSettings")?.optJSONObject("header")
                header?.optString("type")?.takeIf { it != "none" }?.let { linkJson.put("type", it) }
            }
            else -> {}
        }

        val finalRem = if (ob.has("tag")) ob.getString("tag") else ob.optString("remarks", rem)
        linkJson.put("ps", finalRem)

        val base64 = android.util.Base64.encodeToString(linkJson.toString().toByteArray(), android.util.Base64.NO_WRAP)
        "vmess://$base64"
    } catch (_: Exception) {
        null
    }

    private fun buildShadowsocks(ob: JSONObject, rem: String): String? = try {
        val address: String
        val port: Int
        val method: String
        val password: String
        if (ob.has("server")) {
            address = ob.getString("server")
            port = ob.getInt("server_port")
            method = ob.getString("method")
            password = ob.getString("password")
            // sing-box ss plugin: профиль форка не имеет поля plugin, а
            // ShadowsocksFmt понимает только obfs=http. obfs-local переносим
            // через plugin_opts (формат "obfs=http;obfs-host=..."), любой
            // другой plugin (v2ray-plugin, shadow-tls) молча потерялся бы —
            // честный отказ, профиль остаётся кастомным.
            val sbPlugin = ob.optString("plugin", "")
            if (sbPlugin.isNotEmpty() && sbPlugin != "obfs-local") return null
        } else {
            val servers = ob.optJSONObject("settings")?.optJSONArray("servers") ?: return null
            if (servers.length() != 1) return null
            val s = servers.getJSONObject(0)
            address = s.getString("address")
            port = s.getInt("port")
            method = s.getString("method")
            password = s.getString("password")
        }
        val credentials = "$method:$password"
        val ui = android.util.Base64.encodeToString(credentials.toByteArray(), android.util.Base64.NO_WRAP)
        val finalRem = ob.optString("remarks", rem)
        val encRem = URLEncoder.encode(finalRem, "UTF-8").replace("+", "%20")
        // plugin: xray-стиль уже несёт готовую строку; sing-box obfs-local
        // даёт opts в plugin_opts — их и кладём (ShadowsocksFmt ждёт obfs=http;...).
        val plugin = ob.optString("plugin").takeIf { it.isNotEmpty() && it != "obfs-local" }
            ?: ob.optString("plugin_opts", "")
        val pluginQ = if (plugin.isNullOrEmpty()) "" else "/?plugin=" + URLEncoder.encode(plugin, "UTF-8")
        "ss://$ui@$address:$port$pluginQ#$encRem"
    } catch (_: Exception) {
        null
    }

    private fun buildTrojan(ob: JSONObject, rem: String): String? = try {
        val serversArr = ob.optJSONObject("settings")?.optJSONArray("servers") ?: return null
        if (serversArr.length() != 1) return null
        val server = serversArr.getJSONObject(0)
        val address = server.optString("address")
        val port = server.optInt("port")
        val password = server.optString("password")

        val ss = ob.optJSONObject("streamSettings")
        val network = ss?.optString("network")
        // trojan:// не имеет полей xhttp (mode/extra): ссылка была бы
        // нерабочей. Честный отказ вместо молчаливой потери транспорта.
        if (network == "xhttp" || network == "splithttp" || network == "splitHttp") return null
        val security = ss?.optString("security")

        val query = mutableMapOf<String, String>()
        if (!network.isNullOrEmpty()) query["type"] = network

        val tTls = ss?.optJSONObject("tlsSettings") ?: ss?.optJSONObject("realitySettings")
        if (security == "tls" || security == "reality") {
            tTls?.optString("serverName")?.takeIf { it.isNotEmpty() }?.let {
                query["sni"] = it
                query["host"] = it
            }
        }
        tTls?.optJSONArray("alpn")?.let { a ->
            val j = (0 until a.length()).mapNotNull { a.optString(it) }.filter { it.isNotEmpty() }
                .joinToString(",")
            if (j.isNotEmpty()) query["alpn"] = j
        }
        tTls?.optString("fingerprint")?.takeIf { it.isNotEmpty() }?.let { query["fp"] = it }
        if (tTls?.optBoolean("allowInsecure", false) == true) query["allowInsecure"] = "1"
        pinSha256(tTls)?.let { query["pcs"] = it }
        tTls?.optString("verifyPeerCertByName")?.takeIf { it.isNotEmpty() }
            ?.let { query["vcn"] = it }

        // Транспорт trojan обязан переехать целиком (TrojanFmt читает всё из
        // query): ws, kcp (headerType/seed), grpc (mode/serviceName/authority),
        // h2/http (path/host). Раньше не-ws терялись молча.
        when (network) {
            "ws" -> {
                val ws = ss?.optJSONObject("wsSettings")
                ws?.optString("path")?.takeIf { it.isNotEmpty() }?.let { query["path"] = it }
                ws?.optJSONObject("headers")?.optString("Host")?.takeIf { it.isNotEmpty() }?.let { query["host"] = it }
            }
            "kcp" -> {
                val kcp = ss?.optJSONObject("kcpSettings")
                kcp?.optJSONObject("header")?.optString("type")?.takeIf { it.isNotEmpty() && it != "none" }
                    ?.let { query["headerType"] = it }
                kcp?.optString("seed")?.takeIf { it.isNotEmpty() }?.let { query["seed"] = it }
            }
            "grpc" -> {
                val grpc = ss?.optJSONObject("grpcSettings")
                grpc?.optString("mode")?.takeIf { it.isNotEmpty() }?.let { query["mode"] = it }
                grpc?.optString("serviceName")?.takeIf { it.isNotEmpty() }?.let { query["serviceName"] = it }
                grpc?.optString("authority")?.takeIf { it.isNotEmpty() }?.let { query["authority"] = it }
            }
            "h2", "http" -> {
                val http = ss?.optJSONObject("httpSettings")
                http?.optString("path")?.takeIf { it.isNotEmpty() }?.let { query["path"] = it }
                http?.optJSONArray("host")?.optString(0)?.takeIf { it.isNotEmpty() }?.let { query["host"] = it }
            }
            else -> {}
        }

        val queryStr = query.entries.sortedBy { it.key }.joinToString("&") {
            "${it.key}=${URLEncoder.encode(it.value, "UTF-8")}"
        }
        val queryString = if (queryStr.isNotEmpty()) "?$queryStr" else ""
        val encPass = URLEncoder.encode(password, "UTF-8")
        val encRem = URLEncoder.encode(ob.optString("remarks", rem), "UTF-8").replace("+", "%20")

        "trojan://$encPass@$address:$port$queryString#$encRem"
    } catch (_: Exception) {
        null
    }

    private fun buildHysteria2(ob: JSONObject, rem: String): String? = try {
        val server = ob.optJSONObject("settings")?.optJSONArray("servers")?.optJSONObject(0) ?: return null
        val address = server.optString("address")
        val port = server.optInt("port")

        val ss = ob.optJSONObject("streamSettings")
        val hy2 = ss?.optJSONObject("hy2Settings")
        val password = hy2?.optString("password") ?: ""
        val obfs = hy2?.optJSONObject("obfs")
        val obfsType = obfs?.optString("type")
        val obfsPassword = obfs?.optString("password")
        val hy2Tls = ss?.optJSONObject("tlsSettings")
        val sni = hy2Tls?.optString("serverName")

        val query = StringBuilder()
        if (!obfsType.isNullOrEmpty()) query.append("&obfs=").append(URLEncoder.encode(obfsType, "UTF-8"))
        if (!obfsPassword.isNullOrEmpty()) query.append("&obfs-password=").append(URLEncoder.encode(obfsPassword, "UTF-8"))
        if (!sni.isNullOrEmpty()) query.append("&sni=").append(URLEncoder.encode(sni, "UTF-8"))
        pinSha256(hy2Tls, hy2)?.let {
            query.append("&pinSHA256=").append(URLEncoder.encode(it, "UTF-8"))
        }

        val queryString = if (query.isNotEmpty()) "?" + query.substring(1) else ""
        val encRem = URLEncoder.encode(rem, "UTF-8").replace("+", "%20")

        "hysteria2://$password@$address:$port$queryString#$encRem"
    } catch (_: Exception) {
        null
    }

    // Не вызывается: парсер TUIC в форке отключён, конвертация даёт мёртвую
    // ссылку (см. unsupportedProtocolReason). Сохранён для будущего включения.
    @Suppress("unused")
    private fun buildTuic(ob: JSONObject, rem: String): String? = try {
        val address = ob.optString("server")
        val port = ob.optInt("server_port")
        val uuid = ob.optString("uuid")
        val password = ob.optString("password")

        val query = mutableMapOf<String, String>()
        ob.optString("congestion_control").takeIf { it.isNotEmpty() }?.let { query["congestion_control"] = it }
        ob.optString("udp_relay_mode").takeIf { it.isNotEmpty() }?.let { query["udp_relay_mode"] = it }

        val tls = ob.optJSONObject("tls")
        if (tls != null && tls.optBoolean("enabled", false)) {
            tls.optString("server_name").takeIf { it.isNotEmpty() }?.let { query["sni"] = it }
            // alpn — список через запятую (TuicFmt/getItemFormQuery читают строку)
            tls.optJSONArray("alpn")?.let { a ->
                (0 until a.length()).mapNotNull { a.optString(it).takeIf { s -> s.isNotEmpty() } }
                    .joinToString(",").takeIf { it.isNotEmpty() }?.let { query["alpn"] = it }
            }
            if (tls.optBoolean("insecure", false)) query["allow_insecure"] = "1"
        }

        val queryStr = query.entries.sortedBy { it.key }.joinToString("&") {
            "${it.key}=${URLEncoder.encode(it.value, "UTF-8")}"
        }
        val queryString = if (queryStr.isNotEmpty()) "?$queryStr" else ""

        val finalRem = if (ob.has("tag")) ob.getString("tag") else ob.optString("remarks", rem)
        val encRem = URLEncoder.encode(finalRem, "UTF-8").replace("+", "%20")

        "tuic://$uuid:$password@$address:$port$queryString#$encRem"
    } catch (_: Exception) {
        null
    }

    /**
     * Hysteria v1/v2 as served inside full xray configs by proxy shops:
     * address/port live either in settings{address,port} or
     * settings.servers[0], auth in hysteriaSettings{version,auth}.
     */
    private fun buildHysteriaX(ob: JSONObject, rem: String): String? = try {
        val settings = ob.optJSONObject("settings")
        settings?.optJSONArray("servers")?.takeIf { it.length() > 1 }?.let { return null }
        val serverObj = settings?.optJSONArray("servers")?.optJSONObject(0)
        val address = (settings?.optString("address", "") ?: "")
            .ifEmpty { serverObj?.optString("address", "") ?: "" }
        val port = if (settings?.has("port") == true) settings.optInt("port")
        else serverObj?.optInt("port", 0) ?: 0
        if (address.isEmpty() || port <= 0) return null

        val stream = ob.optJSONObject("streamSettings")
        val hy = stream?.optJSONObject("hysteriaSettings")
        val version = hy?.optInt("version")
            ?: settings?.optInt("version")
            ?: if (ob.optString("protocol") == "hysteria2") 2 else 1
        // Our parser has no hysteria v1 - keep the entry as a custom config
        // instead of emitting a dead link.
        if (version < 2) return null
        val auth = hy?.optString("auth")
            ?: serverObj?.optString("password")
            ?: settings?.optString("auth")
            ?: ""

        val tls = ob.optJSONObject("streamSettings")?.optJSONObject("tlsSettings")

        // Обфускация hy2 в xray-конфиге живёт НЕ в hysteriaSettings, а в
        // streamSettings.finalmask.udp[type=salamander] (см.
        // CoreOutboundBuilder.populateTransportSettings): password и
        // packetSize("min-max" для gecko). Раньше она молча терялась —
        // сервер отвергал туннель без obfs-password. Читаем оттуда.
        val fmObjNode = stream?.optJSONObject("finalmask")
        val salamander = fmObjNode?.optJSONArray("udp")?.let { udp ->
            (0 until udp.length()).mapNotNull { udp.optJSONObject(it) }
                .firstOrNull { it.optString("type") == "salamander" }
        }

        val sni = tls?.optString("serverName")
        val alpn = tls?.optJSONArray("alpn")?.optString(0)

        val query = StringBuilder()
        if (version < 2 && auth.isNotEmpty()) query.append("&auth=").append(URLEncoder.encode(auth, "UTF-8"))
        sni?.takeIf { it.isNotEmpty() }?.let { query.append("&sni=").append(URLEncoder.encode(it, "UTF-8")) }
        alpn?.takeIf { it.isNotEmpty() }?.let { query.append("&alpn=").append(URLEncoder.encode(it, "UTF-8")) }
        if (tls?.optBoolean("allowInsecure", false) == true) query.append("&insecure=1")
        val obfsObj = hy?.optJSONObject("obfs") ?: settings?.optJSONObject("obfs")
        val salamanderSettings = salamander?.optJSONObject("settings")
        val obfsPassword = obfsObj?.optString("password")?.takeIf { it.isNotEmpty() }
            ?: salamanderSettings?.optString("password")?.takeIf { it.isNotEmpty() }
        val packetSize = salamanderSettings?.optString("packetSize")?.takeIf { it.isNotEmpty() }
        if (obfsPassword != null) {
            // packetSize "min-max" означает gecko; salamander без размеров — salamander
            query.append("&obfs=").append(if (packetSize != null) "gecko" else "salamander")
            query.append("&obfs-password=").append(URLEncoder.encode(obfsPassword, "UTF-8"))
            packetSize?.split("-")?.takeIf { it.size == 2 }?.let { mm ->
                query.append("&minPacketSize=").append(URLEncoder.encode(mm[0], "UTF-8"))
                query.append("&maxPacketSize=").append(URLEncoder.encode(mm[1], "UTF-8"))
            }
        }
        hy?.optString("pinSHA256")?.takeIf { it.isNotEmpty() }
            ?.let { query.append("&pinSHA256=").append(URLEncoder.encode(it, "UTF-8")) }
        // finalmask целиком в ссылку не кладём (URL-encoded JSON раздувает
        // URI и ломает QR-ёмкость); но ОБФУСКАЦИЯ из него извлечена выше
        // (salamander/gecko -> obfs/obfs-password/min-max), а прочее в
        // finalmask hy2 — tuning-подсказки ядра, не требования подключения.
        val queryString = if (query.isNotEmpty()) "?" + query.substring(1) else ""

        val encRem = URLEncoder.encode(ob.optString("remarks", rem), "UTF-8").replace("+", "%20")
        if (version >= 2) {
            // v2 carries auth in userinfo position
            "hysteria2://$auth@$address:$port$queryString#$encRem"
        } else {
            "hysteria://$address:$port$queryString#$encRem"
        }
    } catch (_: Exception) {
        null
    }

    //region sing-box direct outbounds

    private fun sbTls(root: JSONObject): JSONObject? =
        root.optJSONObject("tls")?.takeIf { it.optBoolean("enabled", true) }

    private fun sbTransportType(root: JSONObject): String =
        root.optJSONObject("transport")?.optString("type")?.takeIf { it.isNotEmpty() } ?: "tcp"

    private fun buildSbVless(root: JSONObject, rem: String): String? = try {
        val uuid = root.optString("uuid")
        val address = root.optString("server")
        val port = root.optInt("server_port")
        if (uuid.isEmpty() || address.isEmpty() || port <= 0) return null

        val tls = sbTls(root)
        val sbAlpnArr = tls?.optJSONArray("alpn")
        val sbAlpn = sbAlpnArr?.let { a -> (0 until a.length()).mapNotNull { a.optString(it) }
            .filter { it.isNotEmpty() }.joinToString(",") } ?: ""
        val sbInsec = tls?.optBoolean("insecure", false) == true
        val reality = tls?.optJSONObject("reality")
        val params = linkedMapOf(
            "encryption" to "none",
            "flow" to root.optString("flow", ""),
            "fp" to (tls?.optJSONObject("utls")?.optString("fingerprint") ?: ""),
            "pbk" to (reality?.optString("public_key") ?: ""),
            "security" to if (tls != null) "tls" else "none",
            "sid" to (reality?.optString("short_id") ?: ""),
            "sni" to (tls?.optString("server_name") ?: ""),
            "type" to sbTransportType(root),
        )
        val transport = root.optJSONObject("transport")
        val query = StringBuilder()
        params.forEach { (k, v) ->
            if (v.isNotEmpty()) query.append("&").append(k).append("=").append(URLEncoder.encode(v, "UTF-8"))
        }
        transport?.optString("path")?.takeIf { it.isNotEmpty() }?.let {
            query.append("&path=").append(URLEncoder.encode(it, "UTF-8"))
        }
        transport?.optJSONObject("headers")?.optString("Host")?.takeIf { it.isNotEmpty() }?.let {
            query.append("&host=").append(URLEncoder.encode(it, "UTF-8"))
        }
        // h2/http: host в sing-box — массив
        if (sbTransportType(root) == "h2" || sbTransportType(root) == "http") {
            transport?.optJSONArray("host")?.optString(0)?.takeIf { it.isNotEmpty() }?.let {
                query.append("&host=").append(URLEncoder.encode(it, "UTF-8"))
            }
        }
        // xhttp: mode и extra обязательны для рабочего туннеля (xray-ветка их
        // переносит; sing-box хранит их в transport)
        if (sbTransportType(root) == "xhttp" || sbTransportType(root) == "splithttp" || sbTransportType(root) == "splitHttp") {
            transport?.optString("mode")?.takeIf { it.isNotEmpty() }?.let {
                query.append("&mode=").append(URLEncoder.encode(it, "UTF-8"))
            }
            transport?.optJSONObject("extra")?.toString()?.takeIf { it != "null" && it.isNotEmpty() }?.let {
                query.append("&extra=").append(URLEncoder.encode(it, "UTF-8"))
            }
            transport?.optJSONArray("host")?.optString(0)?.takeIf { it.isNotEmpty() }?.let {
                query.append("&host=").append(URLEncoder.encode(it, "UTF-8"))
            }
        }
        // grpc: service_name обязателен, иначе поток не совпадёт с сервером
        if (sbTransportType(root) == "grpc") {
            transport?.optString("service_name")?.takeIf { it.isNotEmpty() }?.let {
                query.append("&serviceName=").append(URLEncoder.encode(it, "UTF-8"))
            }
        }
        if (sbAlpn.isNotEmpty()) query.append("&alpn=").append(URLEncoder.encode(sbAlpn, "UTF-8"))
        if (sbInsec) query.append("&allowInsecure=1")
        val encRem = URLEncoder.encode(rem, "UTF-8").replace("+", "%20")
        "vless://$uuid@$address:$port?${query.substring(1)}#$encRem"
    } catch (_: Exception) {
        null
    }

    private fun buildSbVmess(root: JSONObject, rem: String): String? = try {
        val linkJson = JSONObject()
        linkJson.put("v", "2")
        linkJson.put("add", root.optString("server"))
        linkJson.put("port", root.optInt("server_port").toString())
        linkJson.put("id", root.optString("uuid"))
        linkJson.put("aid", root.optInt("alter_id", 0).toString())
        linkJson.put("scy", root.optString("security", "auto"))

        val net = sbTransportType(root)
        // vmess:// v2 не выражает xhttp: честный отказ вместо нерабочей ссылки
        if (net == "xhttp" || net == "splithttp" || net == "splitHttp") return null
        linkJson.put("net", net)
        val tls = sbTls(root)
        linkJson.put("tls", if (tls != null) "tls" else "")
        linkJson.put("sni", tls?.optString("server_name") ?: "")

        // sing-box транспорт: ws (path/Host) и grpc (service_name) — иначе
        // потеря маршрута туннеля.
        when (net) {
            "ws" -> {
                val ws = root.optJSONObject("transport")
                linkJson.put("path", ws?.optString("path"))
                val host = ws?.optJSONObject("headers")?.optString("Host")
                if (host != null) linkJson.put("host", host)
            }
            "grpc" -> {
                // type остаётся пустым: VmessFmt.parse кладёт type в mode,
                // а mode grpc — это ""/gun/multi, не "grpc".
                val grpc = root.optJSONObject("transport")
                linkJson.put("path", grpc?.optString("service_name"))
            }
            "h2", "http" -> {
                val http = root.optJSONObject("transport")
                linkJson.put("path", http?.optString("path"))
                http?.optJSONArray("host")?.optString(0)?.takeIf { it.isNotEmpty() }
                    ?.let { linkJson.put("host", it) }
            }
            else -> {}
        }

        linkJson.put("ps", rem)
        val base64 = android.util.Base64.encodeToString(linkJson.toString().toByteArray(), android.util.Base64.NO_WRAP)
        "vmess://$base64"
    } catch (_: Exception) {
        null
    }

    private fun buildSbTrojan(root: JSONObject, rem: String): String? = try {
        val password = root.optString("password")
        val address = root.optString("server")
        val port = root.optInt("server_port")
        if (password.isEmpty() || address.isEmpty() || port <= 0) return null
        // xhttp не выражается trojan:// — честный отказ
        val sbNet = sbTransportType(root)
        if (sbNet == "xhttp" || sbNet == "splithttp" || sbNet == "splitHttp") return null

        val query = mutableMapOf<String, String>()
        query["type"] = sbTransportType(root)
        val sbTlsObj = sbTls(root)
        sbTlsObj?.optString("server_name")?.takeIf { it.isNotEmpty() }?.let {
            query["sni"] = it
            query["host"] = it
        }
        sbTlsObj?.optJSONArray("alpn")?.let { a ->
            val j = (0 until a.length()).mapNotNull { a.optString(it) }.filter { it.isNotEmpty() }
                .joinToString(",")
            if (j.isNotEmpty()) query["alpn"] = j
        }
        if (sbTlsObj?.optBoolean("insecure", false) == true) query["allowInsecure"] = "1"
        // ws-транспорт: path и Host обязательны для работоспособности туннеля;
        // раньше терялись молча (TrojanFmt читает их из query).
        if (sbTransportType(root) == "ws") {
            val transport = root.optJSONObject("transport")
            transport?.optString("path")?.takeIf { it.isNotEmpty() }?.let { query["path"] = it }
            transport?.optJSONObject("headers")?.optString("Host")?.takeIf { it.isNotEmpty() }
                ?.let { query["host"] = it }
        }
        val queryStr = query.entries.sortedBy { it.key }.joinToString("&") {
            "${it.key}=${URLEncoder.encode(it.value, "UTF-8")}"
        }
        val encPass = URLEncoder.encode(password, "UTF-8")
        val encRem = URLEncoder.encode(rem, "UTF-8").replace("+", "%20")
        "trojan://$encPass@$address:$port?$queryStr#$encRem"
    } catch (_: Exception) {
        null
    }

    private fun buildSbShadowsocks(root: JSONObject, rem: String): String? = try {
        val method = root.optString("method")
        val password = root.optString("password")
        val address = root.optString("server")
        val port = root.optInt("server_port")
        if (method.isEmpty() || address.isEmpty() || port <= 0) return null
        val ui = android.util.Base64.encodeToString("$method:$password".toByteArray(), android.util.Base64.NO_WRAP)
        val encRem = URLEncoder.encode(rem, "UTF-8").replace("+", "%20")
        // plugin: obfs-local переносим через plugin_opts, прочее — честный
        // отказ (профиль форка не имеет поля plugin, ShadowsocksFmt знает
        // только obfs=http). Молчаливая потеря плагина недопустима.
        val sbPlugin = root.optString("plugin", "")
        if (sbPlugin.isNotEmpty() && sbPlugin != "obfs-local") return null
        val plugin = if (sbPlugin == "obfs-local") root.optString("plugin_opts", "") else sbPlugin
        val pluginQ = if (plugin.isEmpty()) "" else "/?plugin=" + URLEncoder.encode(plugin, "UTF-8")
        "ss://$ui@$address:$port$pluginQ#$encRem"
    } catch (_: Exception) {
        null
    }

    private fun buildSbHysteria2(root: JSONObject, rem: String): String? = try {
        val password = root.optString("password") ?: ""
        val address = root.optString("server")
        val port = root.optInt("server_port")
        if (address.isEmpty() || port <= 0) return null

        val obfs = root.optJSONObject("obfs")
        val sbTls2 = root.optJSONObject("tls")
        val sni = sbTls2?.optString("server_name")
        val sbAlpnArr2 = sbTls2?.optJSONArray("alpn")
        val sbAlpn2 = sbAlpnArr2?.let { a -> (0 until a.length()).mapNotNull { a.optString(it) }
            .filter { it.isNotEmpty() }.joinToString(",") } ?: ""

        val query = StringBuilder()
        obfs?.optString("type")?.takeIf { it.isNotEmpty() }?.let { query.append("&obfs=").append(URLEncoder.encode(it, "UTF-8")) }
        obfs?.optString("password")?.takeIf { it.isNotEmpty() }?.let { query.append("&obfs-password=").append(URLEncoder.encode(it, "UTF-8")) }
        sni?.takeIf { it.isNotEmpty() }?.let { query.append("&sni=").append(URLEncoder.encode(it, "UTF-8")) }
        if (sbAlpn2.isNotEmpty()) query.append("&alpn=").append(URLEncoder.encode(sbAlpn2, "UTF-8"))
        if (sbTls2?.optBoolean("insecure", false) == true) query.append("&insecure=1")
        root.optString("pinSHA256").takeIf { it.isNotEmpty() }
            ?.let { query.append("&pinSHA256=").append(URLEncoder.encode(it, "UTF-8")) }

        val queryString = if (query.isNotEmpty()) "?" + query.substring(1) else ""
        val encRem = URLEncoder.encode(rem, "UTF-8").replace("+", "%20")
        "hysteria2://$password@$address:$port/$queryString#$encRem"
    } catch (_: Exception) {
        null
    }

    /** socks/http share links; v2rayNG parses user:pass@host:port natively. */
    private fun buildUserPassLink(scheme: String, root: JSONObject, rem: String): String? = try {
        val address = root.optString("server")
        val port = root.optInt("server_port")
        if (address.isEmpty() || port <= 0) return null
        val user = root.optString("username")
        val pass = root.optString("password")
        val userinfo = if (user.isEmpty() && pass.isEmpty()) "" else "$user:$pass@"
        val encRem = URLEncoder.encode(rem, "UTF-8").replace("+", "%20")
        "$scheme://$userinfo$address:$port#$encRem"
    } catch (_: Exception) {
        null
    }
    //endregion
}
