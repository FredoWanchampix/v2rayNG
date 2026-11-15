package com.v2ray.ang.dto

import com.google.gson.JsonObject
import com.google.gson.JsonParser

/**
 * Снимок loopback-прокси, который ядро ДЕЙСТВИТЕЛЬНО подняло при старте.
 *
 * Зачем он нужен вместо SettingsManager.getHttpPort()
 * ---------------------------------------------------
 * Адрес, порт и учётные данные пользователь может изменить в любой момент, в том
 * числе ПОСЛЕ запуска профиля. Запущенное ядро при этом продолжает слушать ТЕ
 * значения, с которыми его подняли: конфиг генерируется один раз в
 * CoreConfigManager.getV2rayConfig() и передаётся в coreController.startLoop().
 * Поэтому чтение «живых» настроек даёт адрес/порт, которые никто не слушает, и
 * функция «через активный профиль» ложно сообщает, что профиль выключен.
 *
 * При динамическом порте ошибка ещё жёстче: SettingsManager.getSocksPort()
 * генерирует случайный порт в ПЕРЕМЕННОЙ ПРОЦЕССА, так что :main и :tasks
 * получили бы свои собственные порты, не совпадающие с портом демона :daemon.
 *
 * Снимок публикуется демоном в MMKV сразу после успешного старта ядра и читается
 * из любого процесса. Значения берутся РАЗБОРОМ того самого JSON, который ушёл в
 * ядро, поэтому они верны для любого сочетания режимов и настроек:
 * hev-tun, root, root+LAN, proxy-only, обычный VPN-tun, per-app bypass/allow-only,
 * маршрутизация по process (routeOnly), общий или раздельный порт, TCP/UDP.
 *
 * @property host адрес подключения. Если inbound поднят на 0.0.0.0 или ::
 *   («поделиться прокси» по LAN), для подключения из самого приложения
 *   используется loopback - слушатель при этом тот же самый.
 * @property port порт HTTP inbound из рабочего конфига (не socks+1 из настроек).
 * @property username учётные данные, которые inbound реально требует
 *   (null, если профиль поднят без аутентификации).
 * @property password см. [username].
 * @property udpEnabled включён ли UDP на SOCKS inbound рабочего конфига.
 * @property routeOnly включён ли sniffing.routeOnly (маршрутизация по доменам,
 *   нужна для process-маршрутизации на Android 10+).
 * @property configType тип запущенного профиля.
 */
data class RunningProxyEndpoint(
    val host: String,
    val port: Int,
    val username: String? = null,
    val password: String? = null,
    val udpEnabled: Boolean = false,
    val routeOnly: Boolean = false,
    val configType: String? = null,
) {
    companion object {
        /** Значения listen, которые означают «слушаем на всех интерфейсах». */
        private val WILDCARD_LISTEN = setOf("", "0.0.0.0", "::", "[::]")

        /**
         * Разбирает JSON конфига, который РЕАЛЬНО передан в ядро, и возвращает
         * снимок запущенного loopback-прокси.
         *
         * HTTP inbound ищется по протоколу (а не по имени тега), потому что тег
         * может отличаться; учётные данные берутся с того inbound, который их
         * действительно задаёт (HTTP inbound в конфиге форка клонируется с SOCKS
         * и наследует accounts). Если аутентификация не включена, креды равны
         * null и запрос уходит без Proxy-Authorization.
         *
         * @param configJson содержимое конфига, ушедшее в coreController.startLoop.
         * @param configType тип запущенного профиля (для логов и диагностики).
         * @return снимок или null, если в конфиге нет HTTP inbound
         *   (например, профиль поднят без локального прокси).
         */
        fun fromCoreConfig(configJson: String?, configType: String? = null): RunningProxyEndpoint? {
            if (configJson.isNullOrBlank()) return null
            // Разбор нарочно самодостаточный: без JsonUtil/LogUtil, которые тянут
            // MMKV и android.util.Log и потому падают в unit-тестах (и маскируют
            // ошибку как IllegalStateException вместо честного null). Некорректный
            // JSON -> null, без логов и исключений.
            val root: JsonObject = try {
                val parsed = JsonParser.parseString(configJson)
                if (parsed.isJsonObject) parsed.asJsonObject else null
            } catch (e: Exception) {
                null
            } ?: return null
            val inbounds = root.get("inbounds")?.takeIf { it.isJsonArray }?.asJsonArray ?: return null

            var httpPort: Int? = null
            var httpListen: String? = null
            var socksUdp = false
            var routeOnly = false
            var user: String? = null
            var pass: String? = null

            for (element in inbounds) {
                if (!element.isJsonObject) continue
                val inbound = element.asJsonObject
                val protocol = inbound.get("protocol")?.takeIf { it.isJsonPrimitive }?.asString ?: continue
                val port = inbound.get("port")?.takeIf { it.isJsonPrimitive }?.asInt

                if (protocol == "http" && port != null && port > 0 && httpPort == null) {
                    httpPort = port
                    httpListen = inbound.get("listen")?.takeIf { it.isJsonPrimitive }?.asString
                }

                val sniffing = inbound.get("sniffing")?.takeIf { it.isJsonObject }?.asJsonObject
                sniffing?.get("routeOnly")?.takeIf { it.isJsonPrimitive }?.asBoolean?.let {
                    if (it) routeOnly = true
                }

                val settings = inbound.get("settings")?.takeIf { it.isJsonObject }?.asJsonObject ?: continue
                settings.get("udp")?.takeIf { it.isJsonPrimitive }?.asBoolean?.let {
                    if (it) socksUdp = true
                }
                val accounts = settings.get("accounts")?.takeIf { it.isJsonArray }?.asJsonArray
                if (accounts != null && accounts.size() > 0 && accounts[0].isJsonObject) {
                    val account = accounts[0].asJsonObject
                    val u = account.get("user")?.takeIf { it.isJsonPrimitive }?.asString
                    val p = account.get("pass")?.takeIf { it.isJsonPrimitive }?.asString
                    if (!u.isNullOrEmpty() && !p.isNullOrEmpty() && user == null) {
                        user = u
                        pass = p
                    }
                }
            }

            val resolvedPort = httpPort ?: return null
            val host = if (httpListen.isNullOrEmpty() || httpListen in WILDCARD_LISTEN) {
                "127.0.0.1"
            } else {
                httpListen!!
            }
            return RunningProxyEndpoint(
                host = host,
                port = resolvedPort,
                username = user,
                password = pass,
                udpEnabled = socksUdp,
                routeOnly = routeOnly,
                configType = configType,
            )
        }
    }
}
