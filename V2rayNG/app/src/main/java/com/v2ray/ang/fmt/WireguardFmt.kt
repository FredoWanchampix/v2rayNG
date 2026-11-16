package com.v2ray.ang.fmt

import com.v2ray.ang.AppConfig
import com.v2ray.ang.dto.entities.ProfileItem
import com.v2ray.ang.enums.EConfigType
import com.v2ray.ang.extension.idnHost
import com.v2ray.ang.extension.nullIfBlank
import com.v2ray.ang.extension.removeWhiteSpace
import com.v2ray.ang.util.NoiseProfileUtil
import com.v2ray.ang.util.Utils
import java.net.URI

object WireguardFmt : FmtBase() {
    /**
     * Parses a URI string into a ProfileItem object.
     *
     * @param str the URI string to parse
     * @return the parsed ProfileItem object, or null if parsing fails
     */
    fun parse(str: String): ProfileItem? {
        val config = ProfileItem.create(EConfigType.WIREGUARD)

        val uri = URI(Utils.fixIllegalUrl(str))
        if (uri.rawQuery.isNullOrEmpty()) return null
        val queryParam = getQueryParam(uri)

        config.remarks = Utils.decodeURIComponent(uri.fragment.orEmpty()).let { it.ifEmpty { "none" } }
        config.server = uri.idnHost
        config.serverPort = uri.port.toString()

        config.secretKey = uri.userInfo.orEmpty()
        config.localAddress = queryParam["address"] ?: ""
        config.publicKey = queryParam["publickey"].orEmpty()
        config.preSharedKey = queryParam["presharedkey"]?.nullIfBlank()
        config.mtu = Utils.parseInt(queryParam["mtu"] ?: AppConfig.WIREGUARD_LOCAL_MTU)
        config.remoteDNS = queryParam["dns"] ?: ""
        config.reserved = queryParam["reserved"] ?: "0,0,0"
        config.finalMask = (queryParam["fm"] ?: queryParam["finalmask"] ?: queryParam["finalMask"])?.nullIfBlank()
        // Шум DPI-защиты: явный ключ noises приоритетнее noise-части fm; если
        // задан только fm, список шумов восстанавливается из него, чтобы поле
        // шума в редакторе было заполнено сразу после импорта из буфера.
        // ОПЦИОНАЛЬНОСТЬ: битый явный noises НЕ может лишить владельца профиля.
        // Шум — надстройка: если его список повреждён, импортируем профиль с
        // fm как есть (шум восстановится из fm, если fm валиден), причину
        // фиксируем в логе. Отказ импорта остаётся только для битой ссылки
        // целиком (нет обязательных wireguard-полей).
        val rawNoises = queryParam["noises"]?.nullIfBlank()
        try {
            val (noises, fm) = NoiseProfileUtil.syncProfileFields(rawNoises, config.finalMask)
            config.noisesJson = noises
            config.finalMask = fm
        } catch (_: IllegalArgumentException) {
            runCatching {
                com.v2ray.ang.util.LogUtil.w(
                    "WireguardFmt",
                    "ссылка несёт повреждённый ключ noises; профиль импортирован без явного списка шума (fm как есть)"
                )
            }
            config.noisesJson = NoiseProfileUtil.extractNoises(config.finalMask)
        }

        return config
    }

    /**
     * Parses a Wireguard configuration file string into a ProfileItem object.
     *
     * @param str the Wireguard configuration file string to parse
     * @return the parsed ProfileItem object, or null if parsing fails
     */
    fun parseWireguardConfFile(str: String): ProfileItem {
        val config = ProfileItem.create(EConfigType.WIREGUARD)

        val interfaceParams: MutableMap<String, String> = mutableMapOf()
        val peerParams: MutableMap<String, String> = mutableMapOf()

        var currentSection: String? = null

        str.lines().forEach { line ->
            val trimmedLine = line.trim()

            if (trimmedLine.isEmpty() || trimmedLine.startsWith("#")) {
                return@forEach
            }

            when {
                trimmedLine.startsWith("[Interface]", ignoreCase = true) -> currentSection = "Interface"
                trimmedLine.startsWith("[Peer]", ignoreCase = true) -> currentSection = "Peer"
                else -> {
                    if (currentSection != null) {
                        val parts = trimmedLine.split("=", limit = 2).map { it.trim() }
                        if (parts.size == 2) {
                            val key = parts[0].lowercase()
                            val value = parts[1]
                            when (currentSection) {
                                "Interface" -> interfaceParams[key] = value
                                "Peer" -> peerParams[key] = value
                            }
                        }
                    }
                }
            }
        }

        config.secretKey = interfaceParams["privatekey"].orEmpty()
        config.remarks = System.currentTimeMillis().toString()
        config.localAddress = interfaceParams["address"] ?: ""
        config.mtu = Utils.parseInt(interfaceParams["mtu"] ?: AppConfig.WIREGUARD_LOCAL_MTU)
        config.remoteDNS = interfaceParams["dns"] ?: ""
        config.publicKey = peerParams["publickey"].orEmpty()
        config.preSharedKey = peerParams["presharedkey"]?.nullIfBlank()
        val endpoint = peerParams["endpoint"].orEmpty()
        val (server, port) = when {
            // IPv6
            endpoint.startsWith("[") ->
                endpoint.substringAfter("[").substringBefore("]") to
                        endpoint.substringAfter("]").removePrefix(":")
            // Domain/IPv4
            endpoint.count { it == ':' } == 1 ->
                endpoint.substringBefore(":") to endpoint.substringAfter(":")
            // No port
            else -> endpoint to ""
        }
        config.server = server
        config.serverPort = port
        config.reserved = peerParams["reserved"] ?: "0,0,0"
        config.finalMask = (peerParams["finalmask"] ?: peerParams["fm"] ?: interfaceParams["finalmask"] ?: interfaceParams["fm"])?.nullIfBlank()
        val rawNoises = (peerParams["noises"] ?: interfaceParams["noises"])?.nullIfBlank()
        runCatching {
            val (noises, fm) = NoiseProfileUtil.syncProfileFields(rawNoises, config.finalMask)
            config.noisesJson = noises
            config.finalMask = fm
        }
        // .conf остаётся пригодным и при битом списке шумов: поля просто
        // не синхронизируются, fm хранится как есть (runCatching, не try/catch).

        return config
    }


    /**
     * Converts a ProfileItem object to a URI string.
     *
     * @param config the ProfileItem object to convert
     * @return the converted URI string
     */
    fun toUri(config: ProfileItem): String {
        val dicQuery = HashMap<String, String>()

        dicQuery["publickey"] = config.publicKey.orEmpty()
        if (config.reserved != null) {
            dicQuery["reserved"] = config.reserved.removeWhiteSpace().orEmpty()
        }
        dicQuery["address"] = config.localAddress.removeWhiteSpace().orEmpty()
        if (config.mtu != null) {
            dicQuery["mtu"] = config.mtu.toString()
        }
        if (config.preSharedKey != null) {
            dicQuery["presharedkey"] = config.preSharedKey.removeWhiteSpace().orEmpty()
        }
        if (config.remoteDNS != null) {
            dicQuery["dns"] = config.remoteDNS.removeWhiteSpace().orEmpty()
        }
        // «Весь контекст»: экспортируем и полный fm, и явный список шумов.
        // Инвариант (noisesJson == noise-часть fm) поддерживается при импорте
        // и сохранении; здесь только экспорт, без мутации полей. Если профиль
        // старый и noisesJson пуст — список восстанавливается из fm.
        config.finalMask?.nullIfBlank()?.let { dicQuery["fm"] = it }
        (NoiseProfileUtil.normalizeNoises(config.noisesJson)
            ?: NoiseProfileUtil.extractNoises(config.finalMask))
            ?.let { dicQuery["noises"] = it }

        return toUri(config, config.secretKey, dicQuery)
    }
}
