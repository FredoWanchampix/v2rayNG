package com.v2ray.ang.handler

import com.v2ray.ang.AppConfig
import com.v2ray.ang.dto.entities.ProfileItem
import com.v2ray.ang.util.Utils

/**
 * Автоматическое получение отпечатка сертификата при обновлении/добавлении подписки.
 *
 * Свитч подписки [com.v2ray.ang.dto.entities.SubscriptionItem.autoFetchCertSha256]
 * включает ДОЗАПОЛНЕНИЕ отпечатка у тех профилей подписки, где его ещё нет.
 * Саму сетевую функцию получения отпечатка ([CertificateFingerprintManager.fetchForManualFill],
 * та же, что стоит за кнопкой «Получить отпечаток сертификата» в редакторе профиля)
 * этот объект НЕ меняет и НЕ дублирует: он только решает, КОГО и В КАКОМ ПОРЯДКЕ звать.
 *
 * ЖЁСТКИЙ ПОРЯДОК (требование владельца):
 *  1. профиль уже несёт отпечаток из подписки — НИЧЕГО не делаем: сертификат
 *     подписки лучше автоматически полученного, перезапись запрещена;
 *  2. отпечатка нет и протокол его поддерживает — получаем отпечаток сетевой функцией;
 *  3. ТОЛЬКО ПОСЛЕ шага 2 применяется свитч «Авто-allowInsecure если есть
 *     сертификат SHA-256» ([applyAutoInsecure]), иначе он не увидел бы
 *     только что полученный отпечаток и профиль остался бы с проверкой сертификата.
 *
 * Порядок и гейты вынесены в чистые функции, чтобы доказываться JVM-тестом
 * ([com.v2ray.ang.handler.SubscriptionCertPolicyTest]) без сети и без ядра:
 * ошибка здесь означает либо перезапись сертификата подписки, либо пропуск
 * авто-allowInsecure, либо сетевой запрос там, где его быть не должно.
 */
object SubscriptionCertPolicy {

    /**
     * Есть ли у профиля отпечаток сертификата, пришедший ВМЕСТЕ С ПОДПИСКОЙ.
     *
     * Проверяются оба поля: актуальное [ProfileItem.pinnedCA256] и устаревшее
     * [ProfileItem.pinSHA256] (Hysteria v1/Hysteria2 несут `pinSHA256`; миграция
     * SettingsManager переносит его в pinnedCA256 позже). Ровно то же условие
     * использует существующий авто-allowInsecure, поэтому гейты согласованы.
     */
    fun hasCertificateFromSubscription(profile: ProfileItem): Boolean =
        !profile.pinnedCA256.isNullOrBlank() || !profile.pinSHA256.isNullOrBlank()

    /**
     * Поддерживает ли профиль получение отпечатка сертификата.
     *
     * Условие ТОЧНО совпадает с приватным `isFetchable` внутри
     * [CertificateFingerprintManager] (QUIC-рукопожатие Hysteria v1/v2 ИЛИ
     * security == tls). Это фильтр «не звать сеть заведомо зря»: WireGuard,
     * Shadowsocks, SOCKS, REALITY и прочие не-TLS профили не опрашиваются.
     * Решение о самом рукопожатии по-прежнему принимает менеджер отпечатков.
     */
    fun supportsCertificateFetch(profile: ProfileItem): Boolean =
        CertificateFingerprintManager.usesQuicHandshake(profile.configType) ||
            profile.security == AppConfig.TLS

    /**
     * Шаг 1–2: надо ли ПОЛУЧАТЬ отпечаток для этого профиля.
     *
     * true только когда свитч включён, протокол поддерживается и отпечатка
     * из подписки НЕТ. Профиль с сертификатом подписки не трогаем никогда.
     */
    fun shouldFetchCertificate(profile: ProfileItem, autoFetchEnabled: Boolean): Boolean =
        autoFetchEnabled &&
            !hasCertificateFromSubscription(profile) &&
            supportsCertificateFetch(profile)

    /**
     * Шаг 2 (запись результата): куда класть полученный отпечаток.
     *
     * Пишем в актуальное поле pinnedCA256 — как это делает кнопка в редакторе
     * профиля. Устаревшее pinSHA256 НЕ трогаем: его миграция — отдельная
     * ответственность SettingsManager.
     *
     * @return true, если отпечаток записан; false, если он пуст или у профиля
     *   уже есть сертификат (защита от перезаписи при гонке/повторном проходе).
     */
    fun applyFetchedCertificate(profile: ProfileItem, fetchedSha256: String?): Boolean {
        if (fetchedSha256.isNullOrBlank()) return false
        if (hasCertificateFromSubscription(profile)) return false
        profile.pinnedCA256 = fetchedSha256
        return true
    }

    /**
     * Ключ эндпоинта для дедупликации сетевых запросов внутри одного обновления.
     *
     * Отпечаток сертификата определяется ТИПОМ РУКОПОЖАТИЯ и тем, К КОМУ и С КАКИМ
     * SNI оно идёт. Тип рукопожатия зависит от протокола: Hysteria v1/v2 берут
     * отпечаток QUIC-рукопожатием, остальные — TLS (см. выбор внутри
     * [CertificateFingerprintManager.fetchForManualFill]). Поэтому configType
     * ОБЯЗАТЕЛЬНО входит в ключ: иначе VLESS-TLS и Hysteria2 на одном host:port
     * поделили бы один кэш и второй получил бы ЧУЖОЙ отпечаток (TLS вместо QUIC).
     *
     * Поле alpn входит в ключ потому, что для MASQUE менеджер отпечатков выбирает
     * QUIC или TLS по содержимому alpn («h2»/«h3»): без alpn два MASQUE-профиля
     * на одном host:port с разным alpn поделили бы кэш и получили чужой отпечаток.
     * Адрес, порт и serverName тоже входят; пароль, транспорт и прочие поля на
     * сертификат сервера не влияют — десятки профилей одного протокола на одном
     * хосте дают ОДИН запрос вместо десятков. Переразбиение ключа безопасно
     * (лишний запрос), а недоразбиение дало бы ЧУЖОЙ сертификат — поэтому ключ
     * включает ВСЁ, от чего зависит результат рукопожатия.
     *
     * Порт нормализуется так же, как в менеджере отпечатков: пустой/невалидный
     * порт означает [AppConfig.DEFAULT_PORT]. SNI, равный IP-адресу, менеджер
     * отпечатков не отправляет — здесь он тоже обнуляется, чтобы профили
     * «sni=IP» и «sni пусто» не порождали два запроса к одному эндпоинту.
     */
    fun endpointKey(profile: ProfileItem): String {
        val server = profile.server?.trim().orEmpty()
        val port = profile.serverPort?.toIntOrNull()?.takeIf { it > 0 } ?: AppConfig.DEFAULT_PORT
        val sni = profile.sni?.takeIf { it.isNotBlank() }?.takeUnless { Utils.isPureIpAddress(it) }
        return "${profile.configType}|$server|$port|${sni.orEmpty()}|${profile.alpn.orEmpty()}"
    }

    /**
     * Шаг 3: свитч «Авто-allowInsecure если есть сертификат SHA-256».
     *
     * Вызывается ПОСЛЕ того, как отпечатки получены, и только если сам свитч
     * включён. Условие применения не изменено: есть pinnedCA256 ИЛИ pinSHA256.
     * Профиль без сертификата остаётся как был (проверка сертификата не снимается).
     *
     * @return true, если allowInsecure был включён этим вызовом.
     */
    fun applyAutoInsecure(profile: ProfileItem, autoInsecureEnabled: Boolean): Boolean {
        if (!autoInsecureEnabled) return false
        if (!hasCertificateFromSubscription(profile)) return false
        if (profile.insecure == true) return false
        profile.insecure = true
        return true
    }
}
