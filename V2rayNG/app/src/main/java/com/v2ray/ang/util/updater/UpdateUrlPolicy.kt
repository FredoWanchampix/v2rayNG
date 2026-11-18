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

    // ---------------------------------------------------------------------
    // Проверка Content-Type (пункт 10 требований: «проверка content-type»)
    // ---------------------------------------------------------------------

    /**
     * Допустимые Content-Type для APK.
     *
     * Живой замер 18.11.2026 для релиза форка: GitHub отдаёт
     * `Content-Type: application/vnd.android.package-archive` (CDN
     * release-assets.githubusercontent.com, 206 Partial Content). Остальные два
     * значения добавлены потому, что CDN/промежуточные кэши в разных регионах
     * иногда отдают исполняемые артефакты как generic octet-stream; это не
     * причина ломать загрузку пользователю.
     */
    val ALLOWED_APK_CONTENT_TYPES = setOf(
        "application/vnd.android.package-archive",
        "application/octet-stream",
        "application/java-archive",
    )

    /**
     * Проверяет Content-Type скачиваемого APK (требование безопасности 10).
     *
     * Смысл проверки — отсечь НЕ apk, а подмену содержимого: если вместо APK
     * сервер (или подменённый прокси) вернул `text/html` со страницей ошибки или
     * captive-portal, продолжать закачку бессмысленно, а файл гарантированно не
     * установится. Особо опасен случай, когда captive-portal отдаёт 200 с HTML:
     * без этой проверки мы бы честно скачали HTML и обнаружили проблему только
     * на SHA-256 (поздно и непонятно для пользователя).
     *
     * Правила:
     *  - заголовок отсутствует/пуст -> разрешено (сервер не обязан его отдавать;
     *    окончательный гарант целостности — SHA-256, а не MIME);
     *  - параметры после `;` (charset и т.п.) отбрасываются;
     *  - сравнение регистронезависимое;
     *  - любой MIME семейства text (html, plain и т.п.), равно как и всё, чего
     *    нет в [ALLOWED_APK_CONTENT_TYPES], -> отказ.
     *
     * ВАЖНО: в этом KDoc намеренно не пишется маска MIME со звёздочкой сразу
     * после слэша — в Kotlin блочные комментарии ВЛАГАЮТСЯ, поэтому такая
     * последовательность внутри комментария открыла бы вложенный комментарий и
     * сломала бы разбор всего файла (эта ловушка уже стоила одного падения CI).
     *
     * @return null, если Content-Type приемлем; иначе — человекочитаемая причина.
     */
    fun checkApkContentType(contentType: String?): String? {
        if (contentType.isNullOrBlank()) return null
        val mime = contentType.substringBefore(';').trim().lowercase()
        if (mime.isEmpty()) return null
        if (mime in ALLOWED_APK_CONTENT_TYPES) return null
        return "unexpected Content-Type: $contentType"
    }

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
