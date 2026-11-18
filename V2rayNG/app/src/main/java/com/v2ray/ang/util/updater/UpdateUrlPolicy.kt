package com.v2ray.ang.util.updater

import java.net.URI

/**
 * Ограничение загрузчика обновлений доверенными адресами.
 *
 * Владелец требует (пункт 10): «только https, только домены github.com /
 * objects.githubusercontent.com (allowlist), запрет redirect за пределы
 * allowlist». Живой замер 17.11.2026 показал важную деталь: ассеты релизов
 * GitHub сейчас редиректят 302 на `release-assets.githubusercontent.com`
 * (исторически был `objects.githubusercontent.com`, а до того — S3/Azure).
 * Поэтому allowlist строится по СУФФИКСУ `.githubusercontent.com`, что покрывает
 * любой текущий и будущий поддомен CDN релизов, не открывая при этом произвольные
 * хосты.
 *
 * Логика чистая (только java.net.URI), поэтому доказуема JVM-тестом: ошибка
 * allowlist = загрузка APK с произвольного хоста.
 */
object UpdateUrlPolicy {

    /** Схема обязана быть https: никакого cleartext для исполняемого файла. */
    const val REQUIRED_SCHEME = "https"

    /** Точные имена хостов GitHub, откуда приходят ссылки на ассеты релизов. */
    private val EXACT_HOSTS = setOf(
        "github.com",
        "api.github.com",
        "codeload.github.com",
    )

    /**
     * Суффикс для CDN GitHub. Точка в начале обязательна: без неё
     * `evilgithubusercontent.com` прошёл бы проверку как «оканчивающийся на».
     */
    private val HOST_SUFFIXES = listOf(
        ".githubusercontent.com",
    )

    /**
     * Проверяет один URL целиком: схема https + хост в allowlist.
     *
     * @return true, если по этому URL разрешено качать обновление.
     */
    fun isAllowed(url: String?): Boolean {
        if (url.isNullOrBlank()) return false
        val host = hostOf(url) ?: return false
        return isSchemeHttps(url) && isHostAllowed(host)
    }

    /** Разрешён ли хост (без учёта схемы) — для проверок редиректов. */
    fun isHostAllowed(host: String?): Boolean {
        val h = normalizeHost(host) ?: return false
        if (h in EXACT_HOSTS) return true
        return HOST_SUFFIXES.any { h.endsWith(it) }
    }

    /** Схема URL — именно https. */
    fun isSchemeHttps(url: String?): Boolean {
        if (url.isNullOrBlank()) return false
        val scheme = try {
            URI(url).scheme
        } catch (e: Exception) {
            null
        }
        return scheme != null && scheme.equals(REQUIRED_SCHEME, ignoreCase = true)
    }

    /**
     * Разрешает ли переход по редиректу [from] -> [to].
     *
     * Правило владельца: редирект не должен выводить за пределы allowlist.
     * Проверяем и схему, и хост ЦЕЛЕВОГО URL; исходный тоже обязан быть
     * разрешён (страховка от подмены начальной ссылки). Относительные Location
     * здесь не встречаются: вызывающий код резолвит их в абсолютный URL до
     * вызова, а null/пустой [to] трактуем как запрет.
     */
    fun isRedirectAllowed(from: String?, to: String?): Boolean = isAllowed(from) && isAllowed(to)

    /**
     * Извлекает хост из URL. Возвращает null для некорректного URL, чтобы
     * «не смогли разобрать» никогда не трактовалось как «разрешено».
     */
    fun hostOf(url: String?): String? {
        if (url.isNullOrBlank()) return null
        return try {
            URI(url).host
        } catch (e: Exception) {
            null
        }
    }

    /** Нормализует хост: нижний регистр, убираем точку FQDN и порт/скобки IPv6. */
    private fun normalizeHost(host: String?): String? {
        var h = host?.trim()?.lowercase() ?: return null
        if (h.isEmpty()) return null
        // IPv6 в скобках: [::1] -> ::1 (не наш случай для CDN, но разберём корректно)
        if (h.startsWith("[") && h.endsWith("]")) {
            h = h.substring(1, h.length - 1)
        }
        // URI.getHost() уже возвращает без порта; убираем возможную конечную точку FQDN.
        if (h.endsWith(".")) h = h.substring(0, h.length - 1)
        return h.ifEmpty { null }
    }
}
