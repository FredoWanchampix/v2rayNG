package com.v2ray.ang.core

import android.content.Context
import com.v2ray.ang.AppConfig
import com.v2ray.ang.dto.entities.ProfileItem
import com.v2ray.ang.handler.SettingsManager
import com.v2ray.ang.root.RootManager
import com.v2ray.ang.root.RootShell
import com.v2ray.ang.util.HttpUtil
import com.v2ray.ang.util.LogUtil
import java.util.concurrent.atomic.AtomicInteger
import kotlin.math.roundToLong

/**
 * Измерение профиля FPTN в ИЗОЛИРОВАННОМ network namespace.
 *
 * ## Почему для FPTN нужен отдельный механизм измерения
 *
 * Все остальные профили измеряются временным ядром Xray: [WhitelistSpeedTester]
 * поднимает Xray с loopback SOCKS inbound на свободном порту и качает через него
 * тестовый файл. С FPTN так сделать нельзя в принципе:
 *  - `fptn-client` не имеет локального SOCKS/HTTP-порта. В его CLI 19 параметров
 *    и среди них НЕТ ни одного порта локального прокси - только TUN-параметры
 *    (`--tun-interface-name`, `--tun-interface-ip`, `--mtu-size`);
 *  - он работает как L3-туннель и сам управляет маршрутами устройства
 *    (`fptn::routing::RouteManager`);
 *  - Xray-конфиг для FPTN не строится вовсе, поэтому временного ядра, через
 *    которое можно было бы мерить, не существует.
 *
 * ## Почему запуск пробного клиента в основной сети недопустим
 *
 * Если запустить `fptn-client` прямо в основном сетевом пространстве, он
 * перехватит дефолтный маршрут ВСЕГО устройства. Тогда все параллельные проверки
 * остальных профилей пойдут через этот пробный туннель, результаты станут
 * неверными, а сеть устройства - нестабильной. Именно поэтому проба выполняется
 * в отдельном netns.
 *
 * ## Что доказано экспериментально на устройстве (не предположения)
 *
 *  1. `ip netns add` + veth-пара + NAT дают netns полноценный выход в интернет;
 *  2. TUN внутри netns создаётся (`ip tuntap add` под `ip netns exec`) и НЕ виден
 *     из основного пространства;
 *  3. маршруты и дефолтный маршрут основного пространства не изменяются;
 *  4. системный resolver Android внутри netns возвращает FAKE-IP активного VPN
 *     (198.18.x.x из диапазона AppConfig.ROOT_TUN_ADDR_V4) - то есть без своего
 *     резолвера домены резолвились бы в адреса, маршрутизируемые в чужой туннель;
 *  5. bind-mount `/etc/resolv.conf` внутри `unshare -m` РАБОТАЕТ: getaddrinfo
 *     начинает резолвить через указанный нами сервер (проверено: реальный IP
 *     вместо fake-IP);
 *  6. `dnsproxy` (собранный этим форком под android/arm64), поднятый внутри netns
 *     на 127.0.0.1:53 с upstream `quic://<адрес из настроек пользователя>`,
 *     успешно резолвит домены и обеспечивает curl HTTP 200 со скачиванием 1 МБ.
 *
 * ## DNS - только из настроек пользователя
 *
 * DNS-серверы берутся ИСКЛЮЧИТЕЛЬНО из [SettingsManager.getRemoteDnsServers],
 * то есть из настройки «Удалённый DNS» самого клиента. Никакой подмены и никаких
 * жёстко заданных провайдеров: что пользователь указал, то и используется.
 *
 * Строка настройки передаётся в `dnsproxy --upstream` практически как есть,
 * поэтому поддерживаются все транспорты, которые умеет задавать пользователь:
 * udp, tcp, tls:// (DoT), https:// (DoH), quic:// (DoQ), sdns:// (DNSCrypt).
 * Это принципиально важно: простой `nameserver <ip>` в resolv.conf НЕ работает для
 * DoQ/DoT/DoH, потому что системный резолвер ходит только на UDP/TCP порт 53, а
 * например `94.140.14.14` на порту 53 не отвечает вовсе (проверено: таймаут).
 * Поэтому внутри netns поднимается локальный форвардер, который говорит с
 * upstream на языке пользователя, а приложениям отдаёт обычный DNS на 127.0.0.1:53.
 *
 * ## Защита от DNS-цикла
 *
 * `resolv.conf` указывает на 127.0.0.1, где слушает dnsproxy. Значит в upstream
 * не должно быть ничего, что резолвится через тот же 127.0.0.1:53:
 *  - значение `localhost` из настроек ИСКЛЮЧАЕТСЯ из upstream (иначе dnsproxy
 *    спрашивал бы сам себя - бесконечная рекурсия);
 *  - `--bootstrap` принимает ТОЛЬКО IP-литералы (никогда домены), иначе для
 *    резолва bootstrap снова понадобился бы DNS;
 *  - IP всех DNS-эндпоинтов добавляются в `--exclude-tunnel-networks`, чтобы
 *    DNS-трафик шёл напрямую через veth, а не через проверяемый туннель. Иначе
 *    замер измерял бы сам себя, а при сбое туннеля DNS умер бы вместе с ним и мы
 *    получили бы ложный ноль вместо честного результата.
 *
 * ## Остановка пробных процессов
 *
 * PID namespace в Android общий для всех netns, поэтому `pkill -f fptn-client`
 * убил бы ОСНОВНОЙ рабочий профиль пользователя. Так делать нельзя. Каждый
 * пробный процесс останавливается по сохранённому PID и только после двойной
 * проверки:
 *  1. `/proc/<pid>/cmdline` содержит имя бинарника и уникальный маркер этой пробы
 *     (имя TUN для fptn-client, порт для dnsproxy);
 *  2. `/proc/<pid>/ns/net` совпадает с inode сетевого пространства пробы,
 *     зафиксированным сразу после запуска.
 * Если PID был переиспользован другим процессом, условия не сойдутся и чужой
 * процесс затронут не будет. Дополнительно очистка висит на `trap ... EXIT INT
 * TERM`, сам скрипт ограничен внешним `timeout`, а временные файлы удаляются.
 *
 * ## Настройки - только из клиента
 *
 * Все параметры измерения берутся из раздела «Поиск по белым спискам»
 * ([WhitelistSpeedTester.Settings], заполняется из SettingsManager.getWl*):
 * размер тестового файла, таймаут скачивания и число попыток. Никаких
 * захардкоженных значений: FPTN измеряется по тем же правилам, что и остальные
 * профили, поэтому результаты сопоставимы между собой.
 *
 * ## Параллельность
 *
 * Одновременно допускается НЕ БОЛЕЕ ОДНОЙ пробы FPTN ([probeLock]). Причина не в
 * перестраховке, а в том, что проба настраивает ресурсы, общие для всего
 * устройства и не допускающие двух владельцев: приоритеты `ip rule`, правила в
 * общих цепочках iptables (FORWARD/INPUT/nat POSTROUTING) и флаг ip_forward.
 * Вызывающий код дополнительно выделяет FPTN отдельную последовательную дорожку.
 */
internal object FptnProbeRunner {

    /** Счётчик для уникальных имён ресурсов внутри одного процесса. */
    private val counter = AtomicInteger(0)

    /**
     * Глобальная блокировка всех проб FPTN в пределах процесса. Удерживается на
     * всё время пробы: создание netns, подъём dnsproxy и клиента, замеры, очистка.
     */
    private val probeLock = Any()

    /** Сколько секунд ждать появления TUN внутри netns. */
    private const val TUN_WAIT_SECONDS = 25

    /** Сколько секунд ждать запуска dnsproxy на 127.0.0.1:53 внутри netns. */
    private const val DNS_WAIT_SECONDS = 10

    /**
     * Резерв времени на создание netns, NAT, запуск dnsproxy и fptn-client,
     * а также на разбор после замеров, сек.
     */
    private const val OVERHEAD_SECONDS = 90L

    /** Порт локального DNS-форвардера внутри netns. */
    private const val LOCAL_DNS_PORT = 53

    /**
     * Одна попытка замера, как её вернул скрипт.
     *
     * @property bytes сколько байт реально скачано (поле `<bytes>` у speedprobe);
     * @property timeMs длительность попытки в миллисекундах (поле `<seconds>`).
     */
    internal data class Attempt(val bytes: Long, val timeMs: Long)

    /**
     * Меряет скорость скачивания профиля FPTN в изолированном netns.
     *
     * Возвращает тот же контракт, что и [WhitelistSpeedTester] для остальных
     * профилей, поэтому вызывающий код и агрегирование результатов одинаковы:
     *  - скорость в байт/сек, 0 если измерить не удалось (скорость никогда не
     *    бывает отрицательной, чтобы UI показывал число, а не прочерк);
     *  - stable == true только если КАЖДАЯ попытка скачала полный тестовый файл.
     *    Именно это отличает профиль за «белым списком второго типа» (шейпинг):
     *    пинг у него отличный, а файл не докачивается.
     *
     * Число попыток, размер файла и таймаут берутся из [settings], то есть из
     * настроек клиента.
     *
     * @param urls те же тестовые зеркала, что используются для прочих профилей.
     */
    fun measureSpeed(
        context: Context,
        profile: ProfileItem,
        settings: WhitelistSpeedTester.Settings,
        urls: List<String>,
    ): Pair<Long, Boolean> {
        if (!ensureUsable(context, profile)) return Pair(0L, false)

        // Только одна проба FPTN на весь процесс: см. [probeLock].
        synchronized(probeLock) {
            val targetBytes = settings.downloadSizeMb.toLong() * 1024L * 1024L
            val attemptTimeout = settings.downloadTimeoutSeconds.toLong()
            val attempts = settings.downloadAttempts.coerceAtLeast(1)
            val timeoutSeconds = OVERHEAD_SECONDS + attempts * (attemptTimeout + 5L)

            val script = buildScript(
                context = context,
                profile = profile,
                dnsServers = SettingsManager.getRemoteDnsServers(),
                timeoutSeconds = timeoutSeconds,
                measureBlock = buildSpeedMeasureBlock(
                    urls = urls,
                    targetBytes = targetBytes,
                    attemptTimeoutSeconds = attemptTimeout,
                    attempts = attempts,
                ),
            )
            if (script.isEmpty()) return Pair(0L, false)

            val result = RootShell.runScript(context, "fptn_probe_speed.sh", script, timeoutSeconds)
            if (!result.success) {
                LogUtil.w(
                    AppConfig.TAG,
                    "FptnProbe: измерение скорости не удалось (code ${result.code}): " +
                        summarizeProbeOutput(result.output)
                )
                return Pair(0L, false)
            }
            val parsed = parseAttempts(result.output)
            if (parsed.isEmpty()) {
                LogUtil.w(AppConfig.TAG, "FptnProbe: скрипт не вернул ни одной строки ATTEMPT")
                return Pair(0L, false)
            }
            return aggregate(parsed, targetBytes, attempts)
        }
    }

    /**
     * Меряет задержку профиля FPTN в изолированном netns.
     *
     * Задержка берётся как время до первого байта ответа (TTFB, режим `-mode=delay`
     * у speedprobe)
     * на тестовый URL из настроек клиента - то есть это честный «real ping» через
     * туннель профиля, а не TCP-коннект до сервера из JWT.
     *
     * @return задержка в миллисекундах либо -1, если измерить не удалось.
     */
    fun measureDelayMs(context: Context, profile: ProfileItem, url: String): Long {
        if (!ensureUsable(context, profile)) return -1L
        if (url.isBlank()) return -1L

        synchronized(probeLock) {
            val timeoutSeconds = OVERHEAD_SECONDS + 30L
            val script = buildScript(
                context = context,
                profile = profile,
                dnsServers = SettingsManager.getRemoteDnsServers(),
                timeoutSeconds = timeoutSeconds,
                measureBlock = buildDelayMeasureBlock(url),
            )
            if (script.isEmpty()) return -1L

            val result = RootShell.runScript(context, "fptn_probe_delay.sh", script, timeoutSeconds)
            if (!result.success) {
                LogUtil.w(
                    AppConfig.TAG,
                    "FptnProbe: измерение задержки не удалось (code ${result.code}): " +
                        summarizeProbeOutput(result.output)
                )
                return -1L
            }
            return parseDelay(result.output)
        }
    }

    // ------------------------------------------------------------------ guards

    /**
     * Проверяет предпосылки: root доступен, оба бинарника на месте, токен профиля
     * задан. Возвращает false с понятным логом, чтобы вызывающий код честно
     * сообщил «измерить не удалось», а не записал фиктивное значение.
     */
    private fun ensureUsable(context: Context, profile: ProfileItem): Boolean {
        if (!RootManager.cachedRoot() && !RootManager.isRootAvailable()) {
            LogUtil.w(AppConfig.TAG, "FptnProbe: нет root-доступа, измерение FPTN невозможно")
            return false
        }
        // Бинарники исполняются из nativeLibraryDir (lib*.so, извлечённые
        // установщиком из APK): SELinux на Android 10+ запрещает execve из
        // filesDir, поэтому копий в data-каталоге больше нет. Абсолютный путь к
        // APK не используется нигде - он меняется при каждом обновлении, а
        // nativeLibraryDir всегда указывает на актуальную установку.
        if (SidecarEngineManager.engineBinary(context, SidecarEngineManager.ENGINE_FPTN) == null) {
            LogUtil.e(AppConfig.TAG, "FptnProbe: бинарь fptn-client отсутствует в сборке для этого ABI")
            return false
        }
        if (SidecarEngineManager.engineBinary(context, SidecarEngineManager.ENGINE_DNSPROXY) == null) {
            LogUtil.e(AppConfig.TAG, "FptnProbe: бинарь dnsproxy отсутствует в сборке для этого ABI")
            return false
        }
        if (SidecarEngineManager.engineBinary(context, SidecarEngineManager.ENGINE_SPEEDPROBE) == null) {
            LogUtil.e(AppConfig.TAG, "FptnProbe: бинарь speedprobe отсутствует в сборке для этого ABI")
            return false
        }
        if (profile.fptnToken.isNullOrBlank()) {
            LogUtil.e(AppConfig.TAG, "FptnProbe: у профиля нет access token")
            return false
        }
        return true
    }

    /**
     * Сжимает вывод скрипта до Diagnostically значимых строк, чтобы в лог не
     * попадал весь вывод (и уж тем более токен). Учитываются только наши маркеры.
     */
    private fun summarizeProbeOutput(output: String): String {
        val markers = output.lineSequence()
            .map { it.trim() }
            .filter {
                it.startsWith("PROBE_ERROR") || it.startsWith("PROBE_NET") ||
                    it.startsWith("PROBE_STAGE")
            }
            .take(6)
            .toList()
        return if (markers.isEmpty()) "нет диагностических маркеров в выводе" else markers.joinToString(" | ")
    }

    // ------------------------------------------------------------------ parsing

    /**
     * Разбирает строки `ATTEMPT <bytes> <seconds>` из вывода скрипта.
     * Внутренняя функция - покрыта unit-тестом без root и без сети.
     */
    internal fun parseAttempts(output: String): List<Attempt> {
        val out = ArrayList<Attempt>()
        for (line in output.lineSequence()) {
            val trimmed = line.trim()
            if (!trimmed.startsWith("ATTEMPT ")) continue
            val parts = trimmed.removePrefix("ATTEMPT ").trim().split(' ')
            if (parts.size < 2) continue
            val bytes = parts[0].toLongOrNull() ?: continue
            val seconds = parts[1].toDoubleOrNull() ?: continue
            if (seconds <= 0.0) continue
            out.add(Attempt(bytes.coerceAtLeast(0L), (seconds * 1000.0).toLong().coerceAtLeast(1L)))
        }
        return out
    }

    /**
     * Считает итоговую скорость и признак стабильности по тем же правилам, что и
     * [WhitelistSpeedTester.runDownloadAttempts]: суммарные байты делятся на
     * суммарное время, а stable требует полного файла в КАЖДОЙ попытке.
     */
    internal fun aggregate(
        attempts: List<Attempt>,
        targetBytes: Long,
        expectedAttempts: Int,
    ): Pair<Long, Boolean> {
        if (attempts.isEmpty()) return Pair(0L, false)
        val totalBytes = attempts.sumOf { it.bytes }
        val totalMs = attempts.sumOf { it.timeMs }
        if (totalBytes <= 0L || totalMs <= 0L) return Pair(0L, false)
        val completed = attempts.count { targetBytes > 0L && it.bytes >= targetBytes }
        val stable = expectedAttempts > 0 && completed >= expectedAttempts
        return Pair(totalBytes * 1000L / totalMs, stable)
    }

    /** Разбирает строку `DELAY <seconds>` в миллисекунды; -1 если её нет. */
    /**
     * Разбирает строку `DELAY <секунды>` (TTFB, напечатанная speedprobe) в
     * миллисекунды.
     *
     * Конвертация - ОКРУГЛЕНИЕ до ближайшего целого, а не усечение: значение
     * попадает в поле задержки профиля и показывается пользователю, поэтому
     * ошибка обязана быть не больше 0.5 мс. При усечении 119.646 мс
     * превращались в 119, то есть показанная задержка систематически
     * занижалась. Спецификация зафиксирована тестом
     * `parses delay in seconds into milliseconds` (0.119646 -> 120).
     *
     * `coerceAtLeast(1L)` нужен для измеримо малого, но ненулевого TTFB:
     * 0.0004 с -> 0.4 мс. Ноль здесь был бы неотличим от сбоя, а отрицательное
     * значение - тем более: MmkvManager.removeInvalidServer() удаляет профили с
     * testDelayMillis < 0, то есть фиктивный ноль/минус стоил бы пользователю
     * рабочего профиля.
     *
     * Обратите внимание на отличие от [parseAttempts]: там секунды усекаются, и
     * это осознанно - длительность попытки используется только как знаменатель
     * в расчёте скорости (totalBytes * 1000 / totalMs), где погрешность в 1 мс
     * при типичных 300-2000 мс несущественна, а её спецификация зафиксирована
     * отдельным тестом. Различие задокументировано здесь, чтобы его не приняли
     * за опечатку и не «исправили» в одну сторону без проверки обоих тестов.
     */
    internal fun parseDelay(output: String): Long {
        for (line in output.lineSequence()) {
            val trimmed = line.trim()
            if (!trimmed.startsWith("DELAY ")) continue
            val seconds = trimmed.removePrefix("DELAY ").trim().toDoubleOrNull() ?: continue
            if (seconds <= 0.0) continue
            return (seconds * 1000.0).roundToLong().coerceAtLeast(1L)
        }
        return -1L
    }

    // ------------------------------------------------------- DNS configuration

    /**
     * Значение настройки «Удалённый DNS», которое нельзя отдавать dnsproxy в
     * качестве upstream, потому что оно замыкает резолвинг на сам форвардер.
     */
    private const val LOOPBACK_UPSTREAM = "localhost"

    /**
     * Приводит строки настройки «Удалённый DNS» к аргументам `dnsproxy --upstream`.
     *
     * Правила (все - ради того, чтобы использовать ИМЕННО пользовательский DNS):
     *  - пустые строки отбрасываются;
     *  - `localhost` отбрасывается: в netns на 127.0.0.1:53 слушает сам dnsproxy,
     *    поэтому такой upstream дал бы бесконечную рекурсию;
     *  - запись со схемой (`udp://`, `tcp://`, `tls://`, `https://`, `quic://`,
     *    `sdns://`) передаётся как есть - dnsproxy понимает все эти транспорты;
     *  - голый IP или `ip:port` получает явную схему `udp://`, потому что системный
     *    резолвер и некоторые парсеры трактуют голый адрес неоднозначно;
     *  - домены без схемы (`dns.example.com`) приводятся к `udp://<домен>`: их
     *    резолвом займётся bootstrap (см. [pickBootstrapServers]).
     *
     * Порядок сохраняется (LinkedHashSet), дубликаты убираются.
     */
    internal fun buildDnsProxyUpstreams(entries: List<String>): List<String> {
        val result = LinkedHashSet<String>()
        for (raw in entries) {
            val text = raw.trim()
            if (text.isEmpty()) continue
            if (text.equals(LOOPBACK_UPSTREAM, ignoreCase = true)) continue
            val hasScheme = SCHEME_PREFIXES.any { text.startsWith(it, ignoreCase = true) }
            if (hasScheme) {
                result.add(text)
                continue
            }
            result.add("udp://$text")
        }
        return result.toList()
    }

    private val SCHEME_PREFIXES = listOf(
        "udp://", "tcp://", "tls://", "https://", "quic://", "sdns://", "doq://",
    )

    /**
     * Извлекает IP-адреса DNS-эндпоинтов из строк настройки. Нужны для двух целей:
     *  1. `--bootstrap` у dnsproxy (резолв доменных upstream);
     *  2. `--exclude-tunnel-networks` у fptn-client (DNS-трафик мимо туннеля).
     *
     * Возвращаются ТОЛЬКО IP-литералы, явно указанные пользователем в настройке:
     *  - голый IP (`94.140.14.14`) -> как есть;
     *  - IP внутри URI (`quic://94.140.14.14:853`) -> хост без порта.
     *
     * Доменные upstream сюда не попадают намеренно: их IP неизвестен без резолва,
     * а подставлять в bootstrap домен нельзя (для его резолва снова нужен DNS -
     * цикл). Доменные адреса обрабатываются отдельно в [resolveBootstrapForDomains].
     */
    internal fun extractLiteralDnsIps(entries: List<String>): List<String> {
        val result = LinkedHashSet<String>()
        for (raw in entries) {
            val text = raw.trim()
            if (text.isEmpty()) continue
            if (text.equals(LOOPBACK_UPSTREAM, ignoreCase = true)) continue
            val host = if (SCHEME_PREFIXES.any { text.startsWith(it, ignoreCase = true) }) {
                stripScheme(text)
            } else {
                text
            }
            if (host.isNotEmpty() && isPlainIp(host)) result.add(host)
        }
        return result.toList()
    }

    /** Отделяет хост от схемы и порта/пути: `quic://1.2.3.4:853` -> `1.2.3.4`. */
    private fun stripScheme(value: String): String {
        var text = value
        val idx = text.indexOf("://")
        if (idx >= 0) text = text.substring(idx + 3)
        // путь (DoH) и порт
        text = text.substringBefore('/').substringBefore('?').substringBefore('#')
        // IPv6 в скобках: [2606:4700::1111]:853
        if (text.startsWith("[")) {
            val end = text.indexOf(']')
            if (end > 0) return text.substring(1, end)
        }
        // IPv4 или hostname с портом
        val colon = text.lastIndexOf(':')
        if (colon > 0 && text.indexOf(':') == colon) {
            return text.substring(0, colon)
        }
        return text
    }

    /** Строгая проверка IP-литерала (v4 или v6) без обращения к сети. */
    internal fun isPlainIp(value: String): Boolean {
        val text = value.trim()
        if (text.isEmpty()) return false
        if (text.contains(':')) {
            // IPv6: только шестнадцатеричные группы и "::"
            if (text.contains('/')) return false
            val parts = text.split(':')
            if (parts.size < 3 || parts.size > 8) return false
            return parts.all { it.isEmpty() || it.length <= 4 && it.all { c -> c.isDigit() || c.lowercaseChar() in 'a'..'f' } }
        }
        if (text.contains('/')) return false
        val octets = text.split('.')
        if (octets.size != 4) return false
        return octets.all { part ->
            part.isNotEmpty() && part.length <= 3 && part.all { it.isDigit() } && part.toInt() <= 255
        }
    }

    /**
     * Доменные upstream требуют bootstrap-IP, иначе dnsproxy не сможет их
     * разрешить внутри netns (системный резолвер там указывает на сам dnsproxy).
     *
     * Домен резолвится средствами КЛИЕНТА (HttpUtil) до запуска пробы - это не
     * подмена DNS: резолвится именно то имя, которое пользователь указал в
     * настройке, а полученный IP используется только как bootstrap-подсказка.
     * Сам upstream при этом остаётся доменным, как задал пользователь.
     *
     * @return IP для bootstrap; пустой список, если доменов нет или резолв не удался.
     */
    private fun resolveBootstrapForDomains(entries: List<String>): List<String> {
        val domains = LinkedHashSet<String>()
        for (raw in entries) {
            val text = raw.trim()
            if (text.isEmpty()) continue
            if (text.equals(LOOPBACK_UPSTREAM, ignoreCase = true)) continue
            val host = if (SCHEME_PREFIXES.any { text.startsWith(it, ignoreCase = true) }) {
                stripScheme(text)
            } else {
                text
            }
            if (host.isNotEmpty() && !isPlainIp(host)) domains.add(host)
        }
        if (domains.isEmpty()) return emptyList()

        val ips = LinkedHashSet<String>()
        for (domain in domains) {
            val resolved = try {
                HttpUtil.resolveHostToIP(domain, ipv6Preferred = false)
            } catch (e: Exception) {
                LogUtil.w(AppConfig.TAG, "FptnProbe: не удалось разрешить DNS-хост настройки: ${e.message}")
                null
            }
            resolved?.forEach { candidate ->
                if (isPlainIp(candidate) && !candidate.contains(':')) ips.add(candidate)
            }
        }
        return ips.toList()
    }

    /**
     * Сети, которые fptn-client обязан обходить мимо туннеля.
     *
     * ВАЖНО про дефолт: у `--exclude-tunnel-networks` в fptn-client 0.4.6 есть
     * встроенное значение `10.0.0.0/8,192.168.0.0/16` (задано в CMakeLists.txt
     * как FPTN_CLIENT_DEFAULT_EXCLUDE_NETWORKS). Передача своего значения
     * ПОЛНОСТЬЮ ЗАМЕНЯЕТ дефолт, а не дополняет его. Поэтому дефолт обязательно
     * сохраняется в списке - иначе клиент потерял бы обход LAN, и DNS-запросы
     * пробы (а с ними и весь замер) пошли бы в туннель.
     *
     * Дополнительно исключаются:
     *  - IP DNS-эндпоинтов из настройки пользователя: DNS пробы обязан идти
     *    напрямую. Иначе замер измерял бы сам себя, а при сбое туннеля DNS умер
     *    бы вместе с ним и мы получили бы ложный ноль вместо честного результата;
     *  - подсеть veth-пары (10.x.0.0/30): это единственный выход netns наружу,
     *    и если его затянуть в туннель, сетевое пространство пробы окажется
     *    изолированным от интернета.
     *
     * @param vethSubnet подсеть veth в CIDR (например 10.128.0.0/30).
     */
    internal fun buildExcludeNetworks(
        dnsIps: List<String>,
        vethSubnet: String,
    ): String {
        val all = LinkedHashSet<String>()
        // Дефолт fptn-client - сохраняем всегда (см. docstring).
        all.addAll(FPTN_DEFAULT_EXCLUDE_NETWORKS)
        // Подсеть veth: выход netns в интернет.
        if (vethSubnet.isNotEmpty()) all.add(vethSubnet)
        // IPv4 DNS-эндпоинтов из настроек пользователя.
        all.addAll(dnsIps.filter { it.isNotEmpty() && !it.contains(':') })
        return all.joinToString(",")
    }

    /**
     * Значение по умолчанию из fptn-client 0.4.6 (CMakeLists.txt,
     * FPTN_CLIENT_DEFAULT_EXCLUDE_NETWORKS). Дублируется здесь осознанно: CLI
     * не умеет дополнять дефолт, а потерять обход LAN нельзя.
     */
    private val FPTN_DEFAULT_EXCLUDE_NETWORKS = listOf("10.0.0.0/8", "192.168.0.0/16")

    /**
     * Содержимое `/etc/resolv.conf` для приватного mount namespace пробы.
     * Всегда указывает на локальный dnsproxy - других резолверов в netns нет.
     */
    internal fun buildResolvConf(): String = "nameserver 127.0.0.1\noptions timeout:3 attempts:2\n"

    // ------------------------------------------------------------------ script

    /**
     * Блок замеров: выполняется ВНУТРИ netns после того, как туннель поднялся.
     * Отделён от каркаса, чтобы скорость и задержка использовали один и тот же
     * (и одинаково безопасно разбираемый) netns.
     */
    private fun buildSpeedMeasureBlock(
        urls: List<String>,
        targetBytes: Long,
        attemptTimeoutSeconds: Long,
        attempts: Int,
    ): String = buildString {
        appendLine("TARGET_BYTES=$targetBytes")
        appendLine("ATTEMPT_TIMEOUT=$attemptTimeoutSeconds")
        appendLine("ATTEMPTS=$attempts")
        // URL приходят из кода форка (список зеркал WhitelistSpeedTester), не из
        // пользовательского ввода; одинарные кавычки вырезаются защитно.
        appendLine("URLS='${urls.joinToString(" ") { it.replace("'", "") }}'")
        appendLine("OUTF=\"\$PROBE_DIR/attempt.txt\"")
        appendLine("echo \"PROBE_STAGE measure-start attempts=\$ATTEMPTS bytes=\$TARGET_BYTES\"")
        appendLine("i=1")
        appendLine("while [ \"\$i\" -le \"\$ATTEMPTS\" ]; do")
        appendLine("  bytes=0; secs=0")
        // Зеркало выбирается так же, как в Xray-пути: остаёмся на том, что отдаёт
        // байты, и переключаемся только при нулевом результате.
        appendLine("  for u in \$URLS; do")
        appendLine("    case \"\$u\" in")
        appendLine("      *=) full=\"\${u}\${TARGET_BYTES}\" ;;")
        appendLine("      *)  full=\"\$u\" ;;")
        appendLine("    esac")
        // Замер выполняется СОБСТВЕННЫМ бинарником speedprobe, а не системным curl.
        //
        // Почему нельзя curl: он НЕ входит в состав toybox и появился в AOSP только
        // с Android 8.0, тогда как minSdk приложения - 24 (Android 7.0). На части
        // устройств его просто нет, и функция молча перестала бы работать. То же
        // касается awk, которым раньше разбирали вывод curl.
        //
        // Используются только команды, гарантированно присутствующие в toybox на
        // любом Android: sed, cat, rm, sleep.
        //
        // --dns не передаётся намеренно: внутри netns файл /etc/resolv.conf уже
        // указывает на локальный dnsproxy (127.0.0.1:53), поэтому штатный резолв
        // speedprobe и есть путь к DNS из настроек пользователя.
        appendLine("    rm -f \"\$OUTF\"")
        appendLine("    \"\$SPEEDPROBE\" -mode=speed -insecure \\")
        appendLine("        -timeout \"\$ATTEMPT_TIMEOUT\" -bytes \"\$TARGET_BYTES\" -url \"\$full\" \\")
        appendLine("        > \"\$OUTF\" 2>/dev/null || true")
        appendLine("    line=\"\$(sed -n 's/^ATTEMPT \\([0-9]*\\) \\([0-9.]*\\).*\\$/\\1 \\2/p' \"\$OUTF\" | head -1)\"")
        appendLine("    bytes=\"\$(printf '%s' \"\$line\" | cut -d' ' -f1)\"")
        appendLine("    secs=\"\$(printf '%s' \"\$line\" | cut -d' ' -f2)\"")
        appendLine("    case \"\$bytes\" in ''|*[!0-9]*) bytes=0 ;; esac")
        appendLine("    [ -n \"\$secs\" ] || secs=0")
        appendLine("    if [ \"\$bytes\" -gt 0 ] 2>/dev/null; then break; fi")
        appendLine("  done")
        // Ровно одна строка ATTEMPT на попытку: parseAttempts трактует каждую такую
        // строку как отдельную попытку, поэтому лишние строки исказили бы агрегат.
        appendLine("  echo \"ATTEMPT \$bytes \$secs\"")
        appendLine("  rm -f \"\$OUTF\"")
        appendLine("  i=\$((i+1))")
        appendLine("done")
        appendLine("echo \"PROBE_STAGE measure-done\"")
    }

    /**
     * Блок замера задержки: время до первого байта (TTFB) на тестовый URL настроек.
     *
     * Как и в блоке скорости, используется собственный speedprobe, а не системный
     * curl (которого может не быть на устройствах с minSdk 24).
     */
    private fun buildDelayMeasureBlock(url: String): String = buildString {
        // URL приходит из настройки «Тестовый URL задержки»; одинарные кавычки
        // вырезаются, чтобы значение не могло разорвать строку скрипта.
        val safe = url.replace("'", "")
        appendLine("echo \"PROBE_STAGE delay-start\"")
        appendLine("rm -f \"\$PROBE_DIR/delay.txt\"")
        appendLine("\"\$SPEEDPROBE\" -mode=delay -insecure -url '$safe' \\")
        appendLine("    -timeout 20 > \"\$PROBE_DIR/delay.txt\" 2>/dev/null || true")
        appendLine("secs=\"\$(sed -n 's/^DELAY \\([0-9.]*\\).*\\$/\\1/p' \"\$PROBE_DIR/delay.txt\" | head -1)\"")
        appendLine("[ -n \"\$secs\" ] || secs=0")
        appendLine("echo \"DELAY \$secs\"")
        appendLine("rm -f \"\$PROBE_DIR/delay.txt\"")
        appendLine("echo \"PROBE_STAGE delay-done\"")
    }

    /**
     * Каркас скрипта пробы.
     *
     * Структура:
     *  1. внешний скрипт (root) создаёт netns + veth, настраивает NAT и правила,
     *     готовит файлы resolv.conf и inner.sh;
     *  2. inner.sh запускается через `ip netns exec ... unshare -m`, то есть уже
     *     внутри netns и в приватном mount namespace: монтирует tmpfs на /etc,
     *     bind-ит наш resolv.conf, поднимает dnsproxy и fptn-client, ждёт TUN и
     *     выполняет замеры - всё в ОДНОМ пространстве имён, поэтому и клиент, и
     *     curl видят один и тот же резолвер;
     *  3. очистка внешнего скрипта гарантированно убивает оба процесса по
     *     PID-файлам с двойной проверкой и удаляет netns/правила.
     *
     * Все имена (netns, veth, TUN, порты) уникальны на каждый вызов, поэтому две
     * пробы не столкнулись бы даже без блокировки, а основная сеть устройства не
     * затрагивается.
     */
    private fun buildScript(
        context: Context,
        profile: ProfileItem,
        dnsServers: List<String>,
        timeoutSeconds: Long,
        measureBlock: String,
    ): String {
        val upstreams = buildDnsProxyUpstreams(dnsServers)
        if (upstreams.isEmpty()) {
            LogUtil.e(
                AppConfig.TAG,
                "FptnProbe: в настройках «Удалённый DNS» нет ни одного пригодного сервера"
            )
            return ""
        }

        // Bootstrap: сначала IP-литералы из самой настройки, затем - IP доменных
        // upstream, разрешённые средствами клиента. Bootstrap обязан состоять только
        // из IP, иначе для его резолва снова понадобится DNS (цикл).
        val literalIps = extractLiteralDnsIps(dnsServers)
        val domainIps = resolveBootstrapForDomains(dnsServers)
        val bootstrap = (literalIps + domainIps).filter { !it.contains(':') }.distinct()

        val n = counter.incrementAndGet()
        val stamp = System.currentTimeMillis() % 100000L
        val suffix = "${stamp}_$n"
        val ns = "vfp$suffix"
        val vh = "vph$suffix"
        val vn = "vpn$suffix"
        val tun = "fppr$n"
        val dnsPort = LOCAL_DNS_PORT
        // /30 подсеть в приватном диапазоне 10.128-10.254: не пересекается с
        // типовыми LAN (192.168/10.0/172.16), с fake-IP диапазоном 198.18.0.0/15
        // и с адресами самого профиля.
        val second = 128 + (stamp % 120).toInt()
        val hostIp = "10.$second.0.1"
        val nsIp = "10.$second.0.2"
        val subnet = "10.$second.0.0/30"
        val mark = String.format("0x%04x", 0x2100 + (n % 0x100))

        val filesDir = context.filesDir.absolutePath.replace("'", "")
        val runtimeDir = "$filesDir/${AppConfig.ROOT_RUNTIME_DIR}"
        val probeDir = "$runtimeDir/fptn_probe_$suffix"
        val resolvFile = "$probeDir/resolv.conf"
        val resolvBackup = "$probeDir/resolv.conf.fptn-backup"
        val innerScript = "$probeDir/inner.sh"
        val clientLog = "$probeDir/fptn-client.log"
        // Имя лога dnsproxy содержит УНИКАЛЬНЫЙ маркер пробы: оно попадает в
        // cmdline через --output и используется cleanup как маркер процесса
        // (см. kill_probe). Без маркера в cmdline cleanup не нашёл бы процесс.
        val dnsMarker = "dnsprobe-$suffix"
        val dnsLog = "$probeDir/$dnsMarker.log"
        // Отдельный файл для stdout/stderr оболочки: НЕЛЬЗЯ направлять его в тот
        // же dnsLog, что и --output, иначе shell-редирект усечёт файл (O_TRUNC),
        // который dnsproxy ведёт сам, и проверка запуска по логу даст ложный сбой.
        val dnsStderr = "$probeDir/$dnsMarker.err"
        val clientPidFile = "$probeDir/fptn.pid"
        val dnsPidFile = "$probeDir/dnsproxy.pid"
        val nsFile = "$probeDir/ns.inode"

        // Бинарники берутся из nativeLibraryDir: SELinux на Android 10+
        // запрещает исполнять файлы из filesDir (контекст app_data_file), а
        // из nativeLibraryDir (apk_data_file) разрешено и root-домену ksu,
        // под которым работает весь скрипт пробы.
        val nativeDir = context.applicationInfo.nativeLibraryDir.replace("'", "")
        val clientBinary = "$nativeDir/${AppConfig.ENGINE_FPTN_BIN}"
        val dnsBinary = "$nativeDir/${AppConfig.ENGINE_DNSPROXY_BIN}"
        val probeBinary = "$nativeDir/${AppConfig.ENGINE_SPEEDPROBE_BIN}"
        val token = profile.fptnToken.orEmpty().replace("'", "")
        val mtu = SettingsManager.getVpnMtu()
        val preferred = profile.server?.trim()?.takeIf { it.isNotBlank() && !it.contains('\'') }
        val sni = profile.sni?.trim()?.takeIf { it.isNotBlank() && !it.contains('\'') }

        // DNS-эндпоинты исключаются из туннеля: DNS пробы обязан идти напрямую,
        // иначе замер измерял бы сам себя, а при сбое туннеля умер бы и DNS.
        // Подсеть veth целиком (не только адрес шлюза): весь трафик netns наружу
        // идёт через неё, поэтому она обязана обходить туннель.
        val excludeNetworks = buildExcludeNetworks(literalIps + domainIps, subnet)

        val upstreamArgs = upstreams.joinToString(" ") { "--upstream='$it'" }
        val bootstrapArg = if (bootstrap.isEmpty()) {
            // Доменные upstream без bootstrap работать не смогут - честно сообщаем.
            if (upstreams.any { !isPlainIp(stripScheme(it)) }) {
                LogUtil.e(
                    AppConfig.TAG,
                    "FptnProbe: DNS в настройках задан доменом, но получить его IP для bootstrap не удалось"
                )
                return ""
            }
            ""
        } else {
            bootstrap.joinToString(" ") { "--bootstrap='$it'" }
        }

        return buildString {
            appendLine("set -u")
            appendLine("NS='$ns'")
            appendLine("VH='$vh'")
            appendLine("VN='$vn'")
            appendLine("TUN='$tun'")
            appendLine("HOSTIP='$hostIp'")
            appendLine("NSIP='$nsIp'")
            appendLine("SUBNET='$subnet'")
            appendLine("MARK='$mark'")
            appendLine("PRIO_SUB=8990")
            appendLine("PRIO_MARK=9000")
            appendLine("PROBE_DIR='$probeDir'")
            // Путь к бинарнику speedprobe. Берётся из nativeLibraryDir - его
            // заполняет установщик из lib/<abi>/ ТЕКУЩЕГО APK, поэтому
            // переустановка приложения со сменой пути /data/app/... ничего не ломает.
            appendLine("SPEEDPROBE='$probeBinary'")
            appendLine("CLIENT_PIDF='$clientPidFile'")
            appendLine("DNS_PIDF='$dnsPidFile'")
            appendLine("NSF='$nsFile'")
            appendLine("INNER='$innerScript'")
            appendLine("EXPECTED_NS=''")
            appendLine("DEVIFF=''")
            appendLine("DEVTAB=''")
            appendLine()
            appendLine("# Каждый пробный процесс убивается ТОЛЬКО по своему PID-файлу и только после")
            appendLine("# двойной проверки: cmdline содержит уникальный маркер этой пробы, а inode")
            appendLine("# сетевого пространства совпадает с inode пробы. pkill по имени бинарника")
            appendLine("# применять нельзя: PID namespace в Android общий, и он убил бы ОСНОВНОЙ")
            appendLine("# рабочий профиль пользователя.")
            appendLine("kill_probe() {")
            appendLine("  pidfile=\"\$1\"; marker=\"\$2\"")
            appendLine("  [ -f \"\$pidfile\" ] || return 0")
            appendLine("  P=\$(cat \"\$pidfile\" 2>/dev/null)")
            appendLine("  [ -n \"\$P\" ] || return 0")
            appendLine("  [ -d \"/proc/\$P\" ] || return 0")
            appendLine("  CMD=\$(tr '\\0' ' ' < \"/proc/\$P/cmdline\" 2>/dev/null)")
            appendLine("  NSNOW=\$(readlink \"/proc/\$P/ns/net\" 2>/dev/null)")
            appendLine("  case \"\$CMD\" in")
            appendLine("    *\"\$marker\"*)")
            appendLine("      if [ -z \"\$EXPECTED_NS\" ] || [ \"\$NSNOW\" = \"\$EXPECTED_NS\" ]; then")
            appendLine("        kill -TERM \"\$P\" 2>/dev/null")
            appendLine("        i=0")
            appendLine("        while [ \$i -lt 10 ] && [ -d \"/proc/\$P\" ]; do sleep 0.3; i=\$((i+1)); done")
            appendLine("        [ -d \"/proc/\$P\" ] && kill -KILL \"\$P\" 2>/dev/null")
            appendLine("      fi")
            appendLine("      ;;")
            appendLine("  esac")
            appendLine("  rm -f \"\$pidfile\" 2>/dev/null")
            appendLine("}")
            appendLine()
            appendLine("# --- очистка: всегда, включая сигнал и ошибку ---")
            appendLine("cleanup() {")
            appendLine("  kill_probe \"\$CLIENT_PIDF\" \"\$TUN\"")
            appendLine("  kill_probe \"\$DNS_PIDF\" \"$dnsMarker\"")
            appendLine("  # Удаление netns уничтожает и TUN, и veth-конец внутри него.")
            appendLine("  ip netns delete \"\$NS\" >/dev/null 2>&1")
            appendLine("  ip link del \"\$VH\" >/dev/null 2>&1")
            appendLine("  if [ -n \"\$DEVIFF\" ]; then")
            appendLine("    iptables -t nat -D POSTROUTING -s \"\$SUBNET\" -o \"\$DEVIFF\" -j MASQUERADE >/dev/null 2>&1")
            appendLine("  fi")
            appendLine("  iptables -D FORWARD -i \"\$VH\" -j ACCEPT >/dev/null 2>&1")
            appendLine("  iptables -D FORWARD -o \"\$VH\" -j ACCEPT >/dev/null 2>&1")
            appendLine("  iptables -D INPUT -i \"\$VH\" -j ACCEPT >/dev/null 2>&1")
            appendLine("  iptables -D OUTPUT -o \"\$VH\" -j ACCEPT >/dev/null 2>&1")
            appendLine("  iptables -t mangle -D PREROUTING -i \"\$VH\" -j MARK --set-xmark \"\$MARK\" >/dev/null 2>&1")
            appendLine("  ip rule del to \"\$SUBNET\" lookup main prio \"\$PRIO_SUB\" >/dev/null 2>&1")
            appendLine("  if [ -n \"\$DEVTAB\" ]; then")
            appendLine("    ip rule del fwmark \"\$MARK\" lookup \"\$DEVTAB\" prio \"\$PRIO_MARK\" >/dev/null 2>&1")
            appendLine("  fi")
            appendLine("  # Временные файлы пробы (включая inner.sh с токеном) удаляются.")
            appendLine("  rm -rf \"\$PROBE_DIR\" >/dev/null 2>&1")
            appendLine("}")
            appendLine("trap cleanup EXIT INT TERM")
            appendLine()
            appendLine("# --- активный физический интерфейс и его таблица маршрутов ---")
            appendLine("# В Android default-маршрут лежит в таблице интерфейса (wlan0/rmnet_data0),")
            appendLine("# а НЕ в main - поэтому одного правила lookup main недостаточно.")
            appendLine("# Туннельные интерфейсы исключаются намеренно: если сейчас активен VPN или")
            appendLine("# FPTN, default указывает на его tun, и проба полезла бы туннелем поверх")
            appendLine("# туннеля - замер стал бы бессмысленным, а нагрузка на профиль выросла бы.")
            appendLine("DEFLINE=\$(ip route show table all 2>/dev/null | grep -E '^default ' | grep -vE 'dummy0|scope link|tun|utun|fptn|ppp|wg' | head -1)")
            appendLine("DEVIFF=\$(printf '%s' \"\$DEFLINE\" | sed -n 's/.* dev \\([^ ]*\\).*/\\1/p')")
            appendLine("DEVTAB=\$(printf '%s' \"\$DEFLINE\" | sed -n 's/.* table \\([^ ]*\\).*/\\1/p')")
            appendLine("if [ -z \"\$DEVIFF\" ]; then")
            appendLine("  # Запасной путь: спрашиваем у ядра, через какой интерфейс идёт пакет наружу.")
            appendLine("  DEVIFF=\$(ip route get 8.8.8.8 2>/dev/null | head -1 | sed -n 's/.* dev \\([^ ]*\\).*/\\1/p')")
            appendLine("fi")
            appendLine("[ -z \"\$DEVIFF\" ] && DEVIFF=wlan0")
            appendLine("[ -z \"\$DEVTAB\" ] && DEVTAB=\"\$DEVIFF\"")
            appendLine("ip route show table \"\$DEVTAB\" 2>/dev/null | grep -q '^default' || DEVTAB=\"\$DEVIFF\"")
            appendLine("echo \"PROBE_NET: dev=\$DEVIFF table=\$DEVTAB subnet=\$SUBNET\"")
            appendLine()
            appendLine("# предварительная очистка на случай остатков предыдущей пробы")
            appendLine("cleanup >/dev/null 2>&1")
            appendLine()
            appendLine("# --- изолированное сетевое пространство ---")
            appendLine("mkdir -p \"\$PROBE_DIR\" || { echo 'PROBE_ERROR: cannot create probe dir'; exit 3; }")
            appendLine("chmod 700 \"\$PROBE_DIR\"")
            appendLine("ip netns add \"\$NS\" || { echo 'PROBE_ERROR: cannot create netns'; exit 3; }")
            appendLine("ip link add \"\$VH\" type veth peer name \"\$VN\" || { echo 'PROBE_ERROR: cannot create veth'; exit 3; }")
            appendLine("ip link set \"\$VN\" netns \"\$NS\" || { echo 'PROBE_ERROR: cannot move veth'; exit 3; }")
            appendLine("ip addr add \"\${HOSTIP}/30\" dev \"\$VH\" >/dev/null 2>&1")
            appendLine("ip link set \"\$VH\" up")
            appendLine("ip netns exec \"\$NS\" ip link set lo up")
            appendLine("ip netns exec \"\$NS\" ip addr add \"\${NSIP}/30\" dev \"\$VN\" >/dev/null 2>&1")
            appendLine("ip netns exec \"\$NS\" ip link set \"\$VN\" up")
            appendLine("ip netns exec \"\$NS\" ip route add default via \"\$HOSTIP\" >/dev/null 2>&1")
            appendLine("echo 1 > /proc/sys/net/ipv4/ip_forward")
            appendLine()
            appendLine("# ДВА правила маршрутизации: входящие в подсеть veth идут в main (там лежит")
            appendLine("# подключённая подсеть), а исходящие маркируются и идут в таблицу активного")
            appendLine("# интерфейса, где есть default. Без второго немаркированный трафик отбросит")
            appendLine("# catch-all правило Android 'unreachable'.")
            appendLine("ip rule add to \"\$SUBNET\" lookup main prio \"\$PRIO_SUB\" >/dev/null 2>&1")
            appendLine("iptables -t mangle -A PREROUTING -i \"\$VH\" -j MARK --set-xmark \"\$MARK\" >/dev/null 2>&1")
            appendLine("ip rule add fwmark \"\$MARK\" lookup \"\$DEVTAB\" prio \"\$PRIO_MARK\" >/dev/null 2>&1")
            appendLine("iptables -t nat -A POSTROUTING -s \"\$SUBNET\" -o \"\$DEVIFF\" -j MASQUERADE >/dev/null 2>&1")
            appendLine("iptables -I FORWARD -i \"\$VH\" -j ACCEPT >/dev/null 2>&1")
            appendLine("iptables -I FORWARD -o \"\$VH\" -j ACCEPT >/dev/null 2>&1")
            appendLine("iptables -I INPUT -i \"\$VH\" -j ACCEPT >/dev/null 2>&1")
            appendLine("iptables -I OUTPUT -o \"\$VH\" -j ACCEPT >/dev/null 2>&1")
            appendLine()
            appendLine("# Проверка выхода в интернет ДО поднятия туннеля: без него клиент не сможет")
            appendLine("# даже авторизоваться, и молчаливый ноль был бы ложным вердиктом.")
            appendLine("ip netns exec \"\$NS\" ping -c 1 -W 5 8.8.8.8 >/dev/null 2>&1 || \\")
            appendLine("  { echo 'PROBE_ERROR: netns has no internet (ping)'; exit 4; }")
            appendLine("echo 'PROBE_STAGE netns-ready'")
            appendLine()
            appendLine("# --- resolv.conf пробы: всегда локальный dnsproxy ---")
            // Содержимое берётся из buildResolvConf(), чтобы источник правды был
            // один и тот же и для скрипта, и для unit-теста. Каждая строка пишется
            // отдельным echo: встраивание многострочного значения в Kotlin-литерал
            // дало бы реальный перевод строки внутри строки и ошибку компиляции.
            // Файл ОБЯЗАТЕЛЬНО очищается перед записью: без этого `>>` дописал бы
            // строки к уже существующему файлу, nameserver оказался бы продублирован,
            // и резолвер вёл бы себя непредсказуемо.
            appendLine(": > \"\$PROBE_DIR/resolv.conf\"")
            buildResolvConf().lineSequence()
                .filter { it.isNotBlank() }
                .forEach { line ->
                    // Одинарные кавычки экранируются по правилам POSIX sh, чтобы
                    // значение из кода не могло разорвать строку скрипта.
                    val safe = line.replace("'", "'\\''")
                    appendLine("echo '$safe' >> \"\$PROBE_DIR/resolv.conf\"")
                }
            appendLine("cp \"\$PROBE_DIR/resolv.conf\" \"\$PROBE_DIR/resolv.conf.fptn-backup\"")
            appendLine("chmod 600 \"\$PROBE_DIR/resolv.conf\" \"\$PROBE_DIR/resolv.conf.fptn-backup\"")
            appendLine()
            appendLine("# --- inner.sh: всё выполняется внутри netns + приватного mount namespace ---")
            // heredoc с ОДИНАРНЫМИ кавычками: переменные внешнего скрипта в него
            // не подставляются, а inner.sh запускается отдельным `sh`. Поэтому все
            // значения, нужные внутри (пути к бинарникам и каталогу пробы), пишутся
            // сюда ЛОВКО через Kotlin-интерполяцию как литералы. При `set -u`
            // обращение к необъявленной переменной немедленно роняет скрипт, так что
            // это не косметика: без этих двух строк замеры упали бы.
            appendLine("cat > \"\$INNER\" <<'INNER_EOF'")
            appendLine("set -u")
            appendLine("PROBE_DIR='$probeDir'")
            appendLine("SPEEDPROBE='$probeBinary'")
            appendLine("mount -t tmpfs tmpfs /etc 2>/dev/null || true")
            appendLine("mkdir -p /etc")
            appendLine("touch /etc/resolv.conf /etc/resolv.conf.fptn-backup /etc/hosts")
            appendLine("mount --bind '$resolvFile' /etc/resolv.conf || { echo 'PROBE_ERROR: cannot bind resolv.conf'; exit 9; }")
            appendLine("mount --bind '$resolvBackup' /etc/resolv.conf.fptn-backup || { echo 'PROBE_ERROR: cannot bind resolv backup'; exit 9; }")
            appendLine("printf '127.0.0.1 localhost\\n' > /etc/hosts 2>/dev/null || true")
            appendLine("# Семантика HealStaleResolvConf() из FPTN 0.4.6: если backup есть, он")
            appendLine("# копируется поверх resolv.conf. Оба файла - наши, поэтому восстановление")
            appendLine("# сохраняет DNS пользователя, а не подменяет его.")
            appendLine("if [ -e /etc/resolv.conf.fptn-backup ]; then")
            appendLine("  chattr -i /etc/resolv.conf 2>/dev/null || true")
            appendLine("  cp -f /etc/resolv.conf.fptn-backup /etc/resolv.conf 2>/dev/null || true")
            appendLine("fi")
            appendLine("[ -s /etc/resolv.conf ] || { echo 'PROBE_ERROR: empty resolv.conf'; exit 10; }")
            appendLine()
            appendLine("# 1) локальный DNS-форвардер: upstream - ТОЧНО настройка пользователя")
            // --output несёт УНИКАЛЬНЫЙ путь лога этой пробы и одновременно служит
            // маркером в cmdline: cleanup ищет процесс по нему, поэтому без маркера
            // dnsproxy не был бы найден и остался бы работать после пробы.
            appendLine("nohup '$dnsBinary' --listen=127.0.0.1 --port=$dnsPort \\")
            appendLine("  --output='$dnsLog' \\")
            appendLine("  $upstreamArgs \\")
            if (bootstrapArg.isNotEmpty()) {
                appendLine("  $bootstrapArg \\")
            }
            appendLine("  --ratelimit=0 --cache --cache-size=4194304 \\")
            appendLine("  > '$dnsStderr' 2>&1 &")
            appendLine("echo \$! > '$dnsPidFile'")
            appendLine()
            appendLine("# ждём, пока dnsproxy займёт 127.0.0.1:$dnsPort")
            appendLine("i=0")
            appendLine("while [ \$i -lt ${DNS_WAIT_SECONDS * 4} ]; do")
            // toybox grep НЕ поддерживает BRE-альтернативу '\\|' (проверено на
            // устройстве: возвращает «нет совпадений»), поэтому используется -E.
            appendLine("  if grep -qE 'listening to udp|listener loop' '$dnsLog' 2>/dev/null; then break; fi")
            appendLine("  [ -d \"/proc/\$(cat '$dnsPidFile' 2>/dev/null)\" ] || { echo 'PROBE_ERROR: dnsproxy exited early'; tail -5 '$dnsLog' 2>/dev/null; exit 11; }")
            appendLine("  sleep 0.25; i=\$((i+1))")
            appendLine("done")
            appendLine("grep -qE 'listening to udp' '$dnsLog' 2>/dev/null || { echo 'PROBE_ERROR: dnsproxy did not start'; tail -5 '$dnsLog' 2>/dev/null; exit 11; }")
            appendLine("echo 'PROBE_STAGE dnsproxy-ready'")
            appendLine()
            appendLine("# 2) пробный fptn-client")
            appendLine("[ -x '$clientBinary' ] || { echo 'PROBE_ERROR: fptn-client binary missing'; exit 5; }")
            appendLine("ARGS=\"--access-token '$token' --tun-interface-name '$tun' --mtu-size $mtu\"")
            appendLine("ARGS=\"\$ARGS --out-network-interface '$vn' --gateway-ip '$hostIp'\"")
            if (excludeNetworks.isNotEmpty()) {
                appendLine("ARGS=\"\$ARGS --exclude-tunnel-networks '$excludeNetworks'\"")
            }
            if (preferred != null) appendLine("ARGS=\"\$ARGS --preferred-server '$preferred'\"")
            if (sni != null) appendLine("ARGS=\"\$ARGS --sni '$sni'\"")
            appendLine("nohup sh -c \"exec '$clientBinary' \$ARGS\" > '$clientLog' 2>&1 &")
            appendLine("echo \$! > '$clientPidFile'")
            appendLine()
            appendLine("# 3) ждём появления TUN - признак, что туннель действительно поднят")
            appendLine("i=0")
            appendLine("while [ \$i -lt ${TUN_WAIT_SECONDS * 2} ]; do")
            appendLine("  ip link show '$tun' >/dev/null 2>&1 && break")
            appendLine("  [ -d \"/proc/\$(cat '$clientPidFile' 2>/dev/null)\" ] || { echo 'PROBE_ERROR: fptn-client exited early'; tail -5 '$clientLog' 2>/dev/null; exit 6; }")
            appendLine("  sleep 0.5; i=\$((i+1))")
            appendLine("done")
            appendLine("ip link show '$tun' >/dev/null 2>&1 || { echo 'PROBE_ERROR: tun did not come up'; tail -5 '$clientLog' 2>/dev/null; exit 7; }")
            appendLine("echo 'PROBE_STAGE tun-up'")
            appendLine()
            appendLine("# 4) прогрев туннеля: первые пакеты идут мимо установленного соединения")
            appendLine("sleep 3")
            appendLine()
            appendLine("# 5) замеры (те же настройки и зеркала, что у остальных профилей)")
            append(measureBlock)
            appendLine("INNER_EOF")
            appendLine("chmod 700 \"\$INNER\"")
            appendLine()
            appendLine("# Фиксируем inode сетевого пространства пробы: по нему cleanup сверяет PID")
            appendLine("# перед kill и никогда не тронет основной профиль или чужой процесс.")
            appendLine("EXPECTED_NS=\$(ip netns exec \"\$NS\" readlink /proc/self/ns/net 2>/dev/null)")
            appendLine("echo \"\$EXPECTED_NS\" > \"\$NSF\" 2>/dev/null || true")
            appendLine()
            appendLine("# Запускаем inner.sh внутри netns и приватного mount namespace.")
            appendLine("ip netns exec \"\$NS\" unshare -m sh \"\$INNER\"")
            appendLine("INNER_RC=\$?")
            appendLine("echo \"PROBE_STAGE inner-exit rc=\$INNER_RC\"")
            appendLine("exit \$INNER_RC")
        }
    }
}
