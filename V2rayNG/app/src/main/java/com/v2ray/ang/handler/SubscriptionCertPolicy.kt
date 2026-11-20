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
     * SettingsManager переносит его в pinnedCA256 позже).
     *
     * Пробельное значение сертификатом НЕ считается (isNullOrBlank): оно не может
     * быть валидным отпечатком SHA-256 (64 hex-символа), а значит не должно ни
     * блокировать получение настоящего отпечатка, ни защищаться от перезаписи.
     * Для существующего свитча авто-allowInsecure сохранено прежнее условие
     * (!isNullOrEmpty) — см. [applyAutoInsecure]: его поведение не менялось.
     */
    fun hasCertificateFromSubscription(profile: ProfileItem): Boolean =
        !profile.pinnedCA256.isNullOrBlank() || !profile.pinSHA256.isNullOrBlank()

    /**
     * Поддерживает ли профиль получение отпечатка сертификата.
     *
     * Условие совпадает с тем, что умеет [CertificateFingerprintManager]
     * (QUIC-рукопожатие Hysteria v1/v2 ИЛИ security == tls). Это фильтр
     * «не звать сеть заведомо зря»: WireGuard, Shadowsocks, SOCKS, REALITY
     * и прочие не-TLS профили не опрашиваются. Решение о самом рукопожатии
     * по-прежнему принимает менеджер отпечатков.
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
     * Есть ли у профиля НЕПУСТОЕ значение в любом из полей сертификата.
     *
     * В отличие от [hasCertificateFromSubscription] пробельное значение («   »)
     * здесь сертификатом СЧИТАЕТСЯ — ровно как в прежней реализации
     * авто-allowInsecure (`!isNullOrEmpty()`), которая до появления автополучения
     * жила в AngConfigManager.parseConfig. Поведение существующего свитча
     * сохранено ПОСЛОВНО: ничего, что работало раньше, не меняется.
     */
    // Обращение к deprecated pinSHA256 здесь ОБЯЗАТЕЛЬНО: метод побуквенно
    // воспроизводит прежнюю проверку parseConfig, которая тоже читала оба поля.
    // Подавление локальное — базовая линия warnings проекта (76) не сдвигается.
    @Suppress("DEPRECATION")
    private fun hasCertificateLiteral(profile: ProfileItem): Boolean =
        !profile.pinnedCA256.isNullOrEmpty() || !profile.pinSHA256.isNullOrEmpty()

    /** Каким маршрутом получать отпечаток в этом обновлении подписки. */
    enum class FetchRoute {
        /** Напрямую с устройства (свитч «через профиль» выключен ИЛИ профиль — системный TUN). */
        DIRECT,

        /** Через loopback HTTP-прокси активного профиля (HTTP CONNECT). */
        VIA_PROFILE,

        /** Не получать вовсе: свитч требует профиль, а пригодного маршрута нет. */
        SKIP,
    }

    /**
     * Решение о маршруте получения отпечатков — чистая функция (без Android/MMKV),
     * повторяющая матрицу режимов [com.v2ray.ang.util.ActiveProfileRoute] для
     * задачи получения сертификата. Доказывается JVM-тестом.
     *
     * @param viaProfileEnabled свитч подписки «получать отпечатки через включённый профиль».
     * @param portListening loopback HTTP inbound профиля отвечает (LOCAL_HTTP_PROXY).
     * @param tunnelOnly профиль — системный TUN, приложение ВНУТРИ него (FPTN).
     * @param profileRunning профиль запущен хоть в каком-то виде.
     *
     * Правило (то же, что у обновления подписки/проверки обновлений/загрузчика):
     *  - свитч ВЫКЛ → DIRECT (прежнее поведение, ничего не меняется);
     *  - свитч ВКЛ и loopback-прокси слушает → VIA_PROFILE;
     *  - свитч ВКЛ и профиль это системный TUN без прокси → DIRECT, но это
     *    ФИЗИЧЕСКИ через профиль (приложение внутри fptn0), поэтому корректно;
     *  - свитч ВКЛ, профиль работает, но прокси нет и это не TUN → SKIP:
     *    прямой запрос обошёл бы профиль (приложение исключено из собственного
     *    туннеля), а сертификат, полученный в обход профиля, в ограничительной
     *    сети может оказаться сертификатом перехватывающего узла;
     *  - свитч ВКЛ и профиль не запущен → SKIP (требование владельца: строго
     *    через профиль — как у «обновлять только через включённый профиль»).
     */
    fun decideFetchRoute(
        viaProfileEnabled: Boolean,
        portListening: Boolean,
        tunnelOnly: Boolean,
        profileRunning: Boolean,
    ): FetchRoute = when {
        !viaProfileEnabled -> FetchRoute.DIRECT
        portListening -> FetchRoute.VIA_PROFILE
        profileRunning && tunnelOnly -> FetchRoute.DIRECT
        else -> FetchRoute.SKIP
    }

    /**
     * Чем именно пытаться получить отпечаток и в каком порядке.
     *
     * Метки используются в логе, чтобы было видно, какие попытки реально
     * выполнялись (а не какие «планировались» политикой): это единственное,
     * что позволяет отличить «заблокировано ядром профиля» от «сервер мёртв».
     */
    enum class FetchAttempt(val label: String) {
        /** Через loopback HTTP-прокси активного профиля (HTTP CONNECT). */
        VIA_PROFILE("profile"),

        /** Напрямую с устройства. */
        DIRECT("direct"),
    }

    /**
     * Список попыток получения отпечатка для ОДНОГО профиля — чистая функция,
     * доказывается JVM-тестом.
     *
     * Правила (по вещдокам логов и сетевых проб устройства от 20.11.2026):
     *  - QUIC (Hysteria v1/v2) — ВСЕГДА [DIRECT]: HTTP CONNECT туннелирует только
     *    TCP, UDP через него не проходит, поэтому «через профиль» для QUIC
     *    невыполнимо физически. Прежний код при этом писал в лог «via VIA_PROFILE»,
     *    то есть врал о маршруте.
     *  - маршрут VIA_PROFILE для TLS — СТРОГО [VIA_PROFILE], без запасной прямой
     *    попытки. Запасной прямой путь ЗАПРЕЩЁН намеренно: на устройстве может
     *    работать системный перехват TLS (вещдок: прямой запрос к 104.21.7.43:2053
     *    вернул сертификат с issuer «AdGuard Personal Intermediate», а тот же
     *    запрос через профиль — настоящий «Google Trust Services»). Прямая попытка
     *    записала бы отпечаток ПЕРЕХВАТЧИКА, тогда как ядро при работе через
     *    профиль увидит настоящий сертификат — pinning не совпадёт и профиль
     *    перестанет соединяться. Лучше не получить отпечаток вовсе (с явной
     *    строкой в логе), чем записать заведомо чужой.
     *  - маршрут DIRECT — [DIRECT] (прежнее поведение кнопки): при выключенном
     *    профиле ядро тоже ходит напрямую, поэтому отпечаток прямого пути для
     *    этого режима корректен.
     *  - SKIP — пустой список (вызывающий код не доходит до попыток).
     */
    fun planFetchAttempts(route: FetchRoute, isQuic: Boolean): List<FetchAttempt> = when {
        route == FetchRoute.SKIP -> emptyList()
        isQuic -> listOf(FetchAttempt.DIRECT)
        route == FetchRoute.VIA_PROFILE -> listOf(FetchAttempt.VIA_PROFILE)
        else -> listOf(FetchAttempt.DIRECT)
    }

    /**
     * Шаг 3: свитч «Авто-allowInsecure если есть сертификат SHA-256».
     *
     * Вызывается ПОСЛЕ того, как отпечатки получены, и только если сам свитч
     * включён. Условие применения ПЕРЕНЕСЕНО ИЗ parseConfig БЕЗ ИЗМЕНЕНИЙ
     * (`!pinnedCA256.isNullOrEmpty() || !pinSHA256.isNullOrEmpty()`) — см.
     * [hasCertificateLiteral]. Профиль без сертификата остаётся как был
     * (проверка сертификата не снимается).
     *
     * @return true, если allowInsecure был включён этим вызовом.
     */
    fun applyAutoInsecure(profile: ProfileItem, autoInsecureEnabled: Boolean): Boolean {
        if (!autoInsecureEnabled) return false
        if (!hasCertificateLiteral(profile)) return false
        if (profile.insecure == true) return false
        profile.insecure = true
        return true
    }
}
