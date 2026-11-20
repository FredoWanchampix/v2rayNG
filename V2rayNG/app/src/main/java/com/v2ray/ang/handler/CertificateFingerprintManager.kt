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
 *  - QUIC (Hysteria v1/v2) — нативная [Libv2ray.fetchQuicCertSha256] (без изменений:
 *    UDP в ограничительных сетях проходит и напрямую, вещдок логов 20.11.2026);
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
     *    один и тот же сервер 104.21.7.43:2053 напрямую вернул сертификат с issuer
     *    «AdGuard Personal Intermediate», а через профиль — настоящий. Поэтому
     *    запасной прямой попытки при маршруте «через профиль» НЕТ: записанный
     *    отпечаток перехватчика не совпал бы с тем, что ядро увидит при работе,
     *    и pinning сломал бы профиль.
     *
     * Адрес попытки берётся ИЗ ПРОФИЛЯ (`server`), а не из sni: у профилей server
     * часто задан IP (в подписках владельца 776 TLS-профилей из 1051 — по IP), а
     * sni при этом — маскирующий домен ЧУЖОГО хоста (server=104.21.7.43,
     * sni=…workers.dev). Подмена адреса на sni сняла бы отпечаток не с того
     * сервера. Домен, когда он есть, лучше IP: при CONNECT по IP ядро
     * восстанавливает домен сниффингом ClientHello и применяет СВОИ правила
     * маршрутизации — вещдок лога: «CONNECT Host [178.176.128.203:443]» →
     * «sniffed domain: media.ipcheak.online» → «taking detour [block]».
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
                useQuic -> fetchQuic(dialAddress, port, serverName)
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
        LogUtil.w(
            AppConfig.TAG,
            "Cert fetch: no result after ${attempts.size} attempt(s) " +
                "(${attempts.joinToString("/") { it.label }}) for ${profile.remarks} " +
                "[$server:$port sni=$serverName quic=$useQuic]"
        )
        return null
    }

    /**
     * QUIC-рукопожатие — нативная функция (не изменена, хрупкая).
     * Возвращает отпечаток либо null; причина всегда в логе.
     */
    private fun fetchQuic(address: String, port: Int, serverName: String?): String? {
        val requestJson = JsonUtil.toJson(
            CertSha256Request(
                address = address,
                port = port,
                serverName = serverName,
                timeoutMs = TIMEOUT_MS,
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
                    "QUIC cert fetch returned nothing for $address:$port (error=${result?.error ?: "null"})"
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
