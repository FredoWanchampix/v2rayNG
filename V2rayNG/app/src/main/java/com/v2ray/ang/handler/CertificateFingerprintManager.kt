package com.v2ray.ang.handler

import com.v2ray.ang.AppConfig
import com.v2ray.ang.dto.CertSha256Request
import com.v2ray.ang.dto.CertSha256Result
import com.v2ray.ang.dto.entities.ProfileItem
import com.v2ray.ang.enums.EConfigType
import com.v2ray.ang.util.HttpUtil
import com.v2ray.ang.util.JsonUtil
import com.v2ray.ang.util.LogUtil
import com.v2ray.ang.util.TlsCertFetcher
import com.v2ray.ang.util.Utils
import libv2ray.Libv2ray

/**
 * Получение отпечатка сертификата (SHA-256 leaf, 64 hex) для профиля.
 *
 * Два пути рукопожатия:
 *  - QUIC (Hysteria v1/v2) — нативная [Libv2ray.fetchQuicCertSha256].
 *    UDP в ограничительных сетях проходит и напрямую (вещдок логов 20.11.2026),
 *    но для Hysteria2 с обфускацией чистого рукопожатия НЕДОСТАТОЧНО: сервер с
 *    salamander/gecko игнорирует необфусцированные пакеты. Поэтому в запрос
 *    передаются obfs/obfsPassword/min-max из профиля, а применяет их либа форка
 *    кодом самого xray-core (см. KDoc [fetchQuic]);
 *  - TLS — собственный рукопожатчик [TlsCertFetcher.fetchTls] БЕЗ проверки цепочки
 *    (trust-all) и с возможностью идти через loopback-прокси активного профиля.
 *    Прежняя нативная [Libv2ray.fetchTlsCertSha256] проверяла цепочку и не умела
 *    прокси: при MITM-анализе трафика (пользовательский CA) она возвращала ошибку
 *    x509, а прямые TLS-соединения к зарубежным серверам рвались — отпечатки не
 *    получались (вещдоки логов владельца 20.11.2026 и A/B-пробы: 8/8 хостов
 *    напрямую провал, 8/8 через профиль успех, формат 64 hex совпал побайтово).
 *
 * Формат результата обоих путей одинаков: 64 строчных hex SHA-256 от DER leaf —
 * значение идёт в [ProfileItem.pinnedCA256] и затем в pinnedPeerCertSha256 ядра.
 */
object CertificateFingerprintManager {
    private const val TIMEOUT_MS = 5000L

    /**
     * Прежняя точка входа (кнопка «Получить отпечаток сертификата»): маршрут
     * напрямую, поведение сохранено. [fetchWithRoute] — расширенная версия.
     */
    fun fetchForManualFill(profile: ProfileItem): String? =
        fetchWithRoute(profile, null, listOf(SubscriptionCertPolicy.FetchAttempt.DIRECT))

    /**
     * Получение отпечатка по списку попыток, заданному вызывающим кодом.
     *
     * План попыток строит [SubscriptionCertPolicy.planFetchAttempts] по маршруту и
     * типу рукопожатия. Смысл попыток (вещдоки логов и сетевых проб от 20.11.2026):
     *  - через профиль снимается НАСТОЯЩИЙ сертификат сервера (issuer Google Trust
     *    Services / Let's Encrypt), потому что соединение идёт тем же путём, каким
     *    реально работает профиль (loopback → ядро → outbound);
     *  - напрямую сертификат может быть ПОДМЕНЁН системным анализатором трафика:
     *    один и тот же сервер 192.0.2.1:443 напрямую вернул сертификат с issuer
     *    «AdGuard Personal Intermediate», а через профиль — настоящий. Поэтому
     *    запасной прямой попытки при маршруте «через профиль» НЕТ: записанный
     *    отпечаток перехватчика не совпал бы с тем, что ядро увидит при работе,
     *    и pinning сломал бы профиль.
     *
     * Адрес попытки берётся ИЗ ПРОФИЛЯ (`server`), а не из sni: у профилей server
     * часто задан IP (во многих подписках TLS-профили заданы IP), а
     * sni при этом — маскирующий домен ЧУЖОГО хоста (server=192.0.2.1,
     * sni=…example.invalid). Подмена адреса на sni сняла бы отпечаток не с того
     * сервера. Домен, когда он есть, лучше IP: при CONNECT по IP ядро
     * восстанавливает домен сниффингом ClientHello и применяет СВОИ правила
     * маршрутизации — вещдок лога: «CONNECT Host [198.51.100.1:443]» →
     * «sniffed domain: example.invalid» → «taking detour [block]».
     *
     * @param proxyRoute параметры loopback-прокси профиля; null — попытка DIRECT.
     * @param attempts упорядоченный список попыток; пустой — не делать ничего.
     * @return 64 строчных hex SHA-256 от DER leaf-сертификата либо null.
     */
    fun fetchWithRoute(
        profile: ProfileItem,
        proxyRoute: TlsCertFetcher.ProxyRoute?,
        attempts: List<SubscriptionCertPolicy.FetchAttempt>,
    ): String? {
        val server = profile.server?.trim()?.takeIf { it.isNotEmpty() } ?: run {
            LogUtil.w(AppConfig.TAG, "Cert fetch skipped: empty server (${profile.remarks})")
            return null
        }
        val port = profile.serverPort?.toIntOrNull()?.takeIf { it > 0 } ?: AppConfig.DEFAULT_PORT
        val serverName = inferServerName(profile)

        val useQuic = usesQuicFor(profile)

        if (!useQuic && profile.security != AppConfig.TLS) {
            // Прежнее условие поддержки сохранено: прочие протоколы отпечаток не
            // поддерживают, сеть звать незачем.
            return null
        }

        // IP нужен только QUIC-попытке и прямой TLS-попытке; попытка VIA_PROFILE
        // всегда идёт по server из профиля (см. KDoc выше).
        val needsIp = useQuic || attempts.any { it == SubscriptionCertPolicy.FetchAttempt.DIRECT }
        val dialAddress = if (needsIp) resolveDialAddress(server) else server

        for (attempt in attempts) {
            val sha256 = when {
                useQuic -> fetchQuic(dialAddress, port, serverName, profile)
                attempt == SubscriptionCertPolicy.FetchAttempt.VIA_PROFILE && proxyRoute != null ->
                    TlsCertFetcher.fetchTls(
                        address = server,
                        port = port,
                        serverName = serverName,
                        timeoutMs = TIMEOUT_MS,
                        proxy = proxyRoute,
                    )
                else -> TlsCertFetcher.fetchTls(
                    address = dialAddress,
                    port = port,
                    serverName = serverName,
                    timeoutMs = TIMEOUT_MS,
                    proxy = null,
                )
            }
            if (!sha256.isNullOrBlank()) return sha256
        }
        // Сводная строка отказа. Дополнительно объясняет ВЕРОЯТНУЮ причину,
        // чтобы отказ не выглядел поломкой функции (вещдок лога владельца
        // 22.11.2026: три профиля с SNI-маской чужого домена —
        // ядро отправило их в detour [direct] мимо туннеля, сервер рвал TLS;
        // в логе клиента было только «no result», а причина — лишь в GoLog).
        LogUtil.w(
            AppConfig.TAG,
            "Cert fetch: no result after ${attempts.size} attempt(s) " +
                "(${attempts.joinToString("/") { it.label }}) for ${profile.remarks} " +
                "[$server:$port sni=$serverName quic=$useQuic]" +
                failureHint(profile, server, serverName, useQuic, attempts)
        )
        return null
    }

    /**
     * Подсказка о вероятной причине отказа — ЧИСТАЯ функция (без сети/Android),
     * доказывается JVM-тестом [CertificateFingerprintManagerTest].
     *
     * Не меняет поведение: маршрут, число попыток и запись отпечатка остаются
     * прежними. Только объясняет уже случившийся отказ, чтобы пользователь не
     * сопоставлял лог клиента с GoLog вручную.
     *
     * Главный случай (вещдок 22.11.2026, профили группы): server задан IP, а sni —
     * маскирующий домен ЧУЖОГО хоста. Ядро сниффирует этот домен из ClientHello
     * и применяет СВОИ правила маршрутизации; если домен попадает в direct-правило
     * (например, российский CDN), соединение уходит МИМО туннеля профиля и
     * сервер рвёт рукопожатие. Это НЕ поломка получения отпечатка.
     */
    internal fun failureHint(
        profile: ProfileItem,
        server: String,
        serverName: String?,
        useQuic: Boolean,
        attempts: List<SubscriptionCertPolicy.FetchAttempt>,
    ): String {
        val viaProfile = attempts.any { it == SubscriptionCertPolicy.FetchAttempt.VIA_PROFILE }
        val sniDiffersFromServer = !serverName.isNullOrBlank() &&
            !serverName.equals(server, ignoreCase = true)
        val parts = ArrayList<String>()

        if (useQuic && !quicObfuscationFor(profile).type.isEmpty()) {
            parts += "obfs=${quicObfuscationFor(profile).type}: сервер требует обфусцированное " +
                "рукопожатие; отказ возможен, если пароль/тип не совпадают с сервером"
        }
        if (viaProfile && sniDiffersFromServer && Utils.isPureIpAddress(server)) {
            parts += "server=IP, sni — маскирующий домен: ядро может применить к нему СВОЁ " +
                "правило маршрутизации и отправить запрос в direct мимо туннеля " +
                "(см. GoLog: «sniffed domain» → «taking detour [direct]»)"
        }
        if (viaProfile && !sniDiffersFromServer) {
            parts += "запрос шёл через профиль: проверьте, доступен ли сервер из туннеля"
        }
        return if (parts.isEmpty()) "" else " — вероятно: " + parts.joinToString("; ")
    }

    /**
     * Подсказка о причине отказа для ПРОФИЛЯ — обёртка над [failureHint] для
     * вызывающих, у которых нет уже разобранных адреса/SNI (например
     * `AngConfigManager.applyCertPolicies`, который пишет видимую владельцем
     * строку «Subscription cert NOT fetched»).
     *
     * Зачем: отказ читался в ДВУХ разных строках лога — сводная «NOT fetched»
     * была без причины, а причина уходила в «no result after N attempt(s)».
     * Вещдок лога владельца 22.11.2026: три строки «NOT fetched … tried:
     * profile» БЕЗ объяснения, при этом GoLog рядом показывает настоящую
     * причину (SNI-маска чужого домена → «taking detour [direct]» → разрыв TLS).
     * Поверхностей у симптома несколько (см. метод аудита), поэтому причина
     * обязана быть в каждой видимой строке отказа, а не только в одной.
     *
     * Пустой server даёт пустую подсказку: на таком профиле [fetchWithRoute]
     * отказывается ещё до попыток и пишет свою строку.
     *
     * @param profile профиль, по которому получен отказ.
     * @param attempts список фактически сделанных попыток.
     * @return « — вероятно: …» либо пустая строка.
     */
    fun failureHintFor(
        profile: ProfileItem,
        attempts: List<SubscriptionCertPolicy.FetchAttempt>,
    ): String {
        val server = profile.server?.trim().orEmpty()
        if (server.isEmpty()) return ""
        return failureHint(
            profile = profile,
            server = server,
            serverName = inferServerName(profile),
            useQuic = usesQuicFor(profile),
            attempts = attempts,
        )
    }

    /**
     * Параметры обфускации QUIC, которые уйдут в нативный запрос.
     *
     * @param type "salamander" / "gecko" либо пустая строка (без обфускации —
     *   прежнее поведение нативной функции).
     * @param password PSK обфускации.
     * @param minPacketSize / maxPacketSize размеры фрагментов gecko; значимы
     *   только для gecko, иначе 0 (нативная сторона заменит нули умолчаниями
     *   xray-core 512/1200, а для salamander размеры не используются вовсе).
     */
    data class QuicObfuscation(
        val type: String,
        val password: String,
        val minPacketSize: Int,
        val maxPacketSize: Int,
    ) {
        companion object {
            /** Отсутствие обфускации. */
            val None = QuicObfuscation(type = "", password = "", minPacketSize = 0, maxPacketSize = 0)

            /** Умолчания gecko, совпадают с xray-core (geckoDefaultMinPacket/MaxPacket). */
            const val GECKO_DEFAULT_MIN_PACKET = 512
            const val GECKO_DEFAULT_MAX_PACKET = 1200
        }
    }

    /**
     * Какую обфускацию передать нативному QUIC-рукопожатию — ЧИСТАЯ функция
     * (без сети, без Android), доказывается JVM-тестом
     * [com.v2ray.ang.handler.CertificateFingerprintManagerTest].
     *
     * Обфускация включается только при ВСЕХ условиях:
     *  1. профиль — [EConfigType.HYSTERIA2]. У Hysteria v1 поле obfsPassword
     *     несёт obfs-СТРОКУ mihomo (это не PSK salamander), а поле obfs для v1
     *     вообще обнуляется редактором (ServerUiState.toProfileItem), поэтому
     *     передача обфускации для v1 была бы неверной;
     *  2. obfsPassword непустой — salamander без PSK не работает (xray-core
     *     требует не менее 4 байт);
     *  3. obfs не равен "none" — явное отключение обфускации в профиле.
     *
     * Тип gecko выбирается по [ProfileItem.isGeckoObfs]: obfs == "gecko" ИЛИ
     * заполнен min/max packet size. Это ровно тот критерий, по которому ядро
     * отличает GeckoConfig от salamander Config (вещдок: отдельного типа
     * «gecko» в xray-core нет, различие — в наличии MinPacketSize/MaxPacketSize).
     *
     * Если обфускация НЕ включена, возвращается [QuicObfuscation.None] —
     * нативная функция делает чистое рукопожатие, как раньше.
     */
    fun quicObfuscationFor(profile: ProfileItem): QuicObfuscation {
        val enabled = profile.configType == EConfigType.HYSTERIA2 &&
            !profile.obfsPassword.isNullOrBlank() &&
            !profile.obfs.equals("none", ignoreCase = true)
        if (!enabled) return QuicObfuscation.None

        val gecko = profile.isGeckoObfs()
        return QuicObfuscation(
            type = if (gecko) "gecko" else "salamander",
            password = profile.obfsPassword.orEmpty(),
            minPacketSize = if (gecko) {
                profile.minPacketSize?.toIntOrNull() ?: QuicObfuscation.GECKO_DEFAULT_MIN_PACKET
            } else {
                0
            },
            maxPacketSize = if (gecko) {
                profile.maxPacketSize?.toIntOrNull() ?: QuicObfuscation.GECKO_DEFAULT_MAX_PACKET
            } else {
                0
            },
        )
    }

    /**
     * QUIC-рукопожатие — нативная функция либы форка.
     * Возвращает отпечаток либо null; причина всегда в логе.
     *
     * ОБФУСКАЦИЯ (вещдок 20.11.2026). Нативная функция делала ЧИСТОЕ
     * QUIC-рукопожатие, а серверы Hysteria2 с obfs=salamander/gecko ждут
     * обфусцированные пакеты и молча роняют рукопожатие. Результат: 21 из 21
     * QUIC-отказа у профилей с obfs и 4 из 4 успеха у профилей без него
     * (дамп 135 HY2-профилей владельца + его лог 11:50–11:53). Ядро при этом
     * работает, потому что применяет obfs из настроек профиля — поэтому
     * владелец пользовался профилем, а отпечаток не получался.
     *
     * Теперь обфускация передаётся в нативный вызов, и там её применяет код
     * САМОГО xray-core (пакет transport/internet/finalmask/salamander), то есть
     * байт-в-байт так же, как при работе профиля. Ничего на серверах
     * провайдеров менять не нужно: сервер видит ровно то же рукопожатие, что
     * видел бы от работающего профиля.
     *
     * Гейт строго по [EConfigType.HYSTERIA2]: у Hysteria v1 поле obfsPassword
     * несёт obfs-СТРОКУ mihomo (не пароль salamander), а поле obfs не
     * используется вовсе (ServerUiState.toProfileItem обнуляет его для не-hy2),
     * поэтому передача обфускации для v1 была бы неверной.
     */
    private fun fetchQuic(
        address: String,
        port: Int,
        serverName: String?,
        profile: ProfileItem,
    ): String? {
        val obfs = quicObfuscationFor(profile)
        val requestJson = JsonUtil.toJson(
            CertSha256Request(
                address = address,
                port = port,
                serverName = serverName,
                timeoutMs = TIMEOUT_MS,
                obfs = obfs.type,
                obfsPassword = obfs.password,
                minPacketSize = obfs.minPacketSize,
                maxPacketSize = obfs.maxPacketSize,
            )
        )
        val result = try {
            JsonUtil.fromJsonSafe(
                Libv2ray.fetchQuicCertSha256(requestJson),
                CertSha256Result::class.java,
            )
        } catch (e: UnsatisfiedLinkError) {
            LogUtil.e(AppConfig.TAG, "Fetch quic cert SHA-256 API missing in libv2ray", e)
            null
        } catch (e: Exception) {
            LogUtil.e(AppConfig.TAG, "Fetch quic cert SHA-256 failed", e)
            null
        }
        return result
            ?.takeIf { it.error.isBlank() }
            ?.sha256
            ?.takeIf { it.isNotBlank() }
            ?: run {
                LogUtil.w(
                    AppConfig.TAG,
                    "QUIC cert fetch returned nothing for $address:$port " +
                        "(obfs=${obfs.type.ifEmpty { "none" }}, " +
                        "error=${result?.error ?: "null"})"
                )
                null
            }
    }

    /**
     * QUIC-протоколы форка: отпечаток сертификата берётся QUIC-рукопожатием
     * (Libv2ray.fetchQuicCertSha256), а не TLS. Hysteria v1 — QUIC, как и
     * Hysteria2 (эксперимент: mihomo поднимает v1 по QUIC-схеме).
     */
    internal fun usesQuicHandshake(type: EConfigType): Boolean =
        type == EConfigType.HYSTERIA2 || type == EConfigType.HYSTERIA

    /**
     * Каким рукопожатием снимается отпечаток ЭТОГО профиля: QUIC или TLS.
     *
     * Вынесено из тела запроса, потому что от ответа зависит ПЛАН ПОПЫТОК
     * (см. [SubscriptionCertPolicy.planFetchAttempts]): QUIC через HTTP CONNECT
     * не туннелируется, поэтому для QUIC единственный возможный маршрут — прямой.
     * Правило прежнее: QUIC для Hysteria v1/v2, а MASQUE — по alpn («h2» значит
     * TLS, иначе QUIC). Функция чистая, доказывается JVM-тестом.
     */
    fun usesQuicFor(profile: ProfileItem): Boolean {
        // alpn может быть списком "h2,http/1.1", поэтому разбиваем по частям.
        val alpn = profile.alpn.orEmpty().split(",").map { it.trim() }
        return usesQuicHandshake(profile.configType) ||
            (profile.configType == EConfigType.MASQUE && ("h2" !in alpn || "h3" in alpn))
    }

    private fun resolveDialAddress(server: String): String {
        if (Utils.isPureIpAddress(server) || !Utils.isDomainName(server)) return server

        val preferIpv6 = MmkvManager.decodeSettingsBool(AppConfig.PREF_PREFER_IPV6, false)
        return HttpUtil.resolveHostToIP(server, preferIpv6)
            ?.firstOrNull()
            ?.takeIf { it.isNotBlank() }
            ?: server
    }

    private fun inferServerName(profile: ProfileItem): String? {
        val sni = profile.sni?.takeIf { it.isNotBlank() }
        return sni?.takeUnless { Utils.isPureIpAddress(it) }
    }
}
