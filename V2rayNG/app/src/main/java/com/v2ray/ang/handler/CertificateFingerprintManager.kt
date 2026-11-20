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
    fun fetchForManualFill(profile: ProfileItem): String? = fetchWithRoute(profile, null)

    /**
     * Получение отпечатка с явным маршрутом.
     *
     * @param proxyRoute маршрут loopback-прокси активного профиля для TLS-ветки.
     *   Не-null только когда вызывающий хочет идти через активный профиль (свитч
     *   подписки «получать отпечатки через включённый профиль»); null = напрямую.
     *   QUIC-ветка параметр игнорирует: QUIC через HTTP-прокси не туннелируется,
     *   но UDP в ограничительных сетях и так проходит напрямую (вещдок логов).
     */
    fun fetchWithRoute(profile: ProfileItem, proxyRoute: TlsCertFetcher.ProxyRoute?): String? {
        val server = profile.server?.trim()?.takeIf { it.isNotEmpty() } ?: run {
            LogUtil.w(AppConfig.TAG, "Cert fetch skipped: empty server (${profile.remarks})")
            return null
        }
        val port = profile.serverPort?.toIntOrNull()?.takeIf { it > 0 } ?: AppConfig.DEFAULT_PORT
        val serverName = inferServerName(profile)
        val address = resolveDialAddress(server)

        // alpn может быть списком "h2,http/1.1" — как в прежней реализации кнопки.
        val alpn = profile.alpn.orEmpty().split(",").map { it.trim() }
        val useQuic = usesQuicHandshake(profile.configType) ||
            (profile.configType == EConfigType.MASQUE && ("h2" !in alpn || "h3" in alpn))

        return if (useQuic) {
            fetchQuic(address, port, serverName)
        } else {
            // TLS: только для security == tls (прежнее условие поддержки сохранено:
            // остальные протоколы отпечаток не поддерживают и сеть звать незачем).
            if (profile.security != AppConfig.TLS) {
                null
            } else {
                TlsCertFetcher.fetchTls(
                    address = address,
                    port = port,
                    serverName = serverName,
                    timeoutMs = TIMEOUT_MS,
                    proxy = proxyRoute,
                )
            }
        }
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
