package com.v2ray.ang.util.updater

/**
 * Разбор манифеста `SHA256SUMS.txt`, который публикуется вместе с каждым релизом
 * форка (его генерирует шаг Publish: `sha256sum` по всем ассетам).
 *
 * Формат строки — стандарт GNU coreutils sha256sum:
 * ```
 * <64 hex>  <path>
 * <64 hex> *<path>      // бинарный режим: звёздочка вместо второго пробела
 * ```
 * Разделитель — ДВА пробела (текстовый режим) или пробел и `*` (бинарный).
 * В релизах форка путь предваряется `./`, например:
 * ```
 * 3fc877a6…65b  ./v2rayNG_2.4.2_arm64-v8a.apk
 * ```
 *
 * Этот объект НАМЕРЕННО чистый (нет android.*, LogUtil, MMKV), чтобы разбор
 * эталонных хэшей можно было доказать JVM-тестом: именно он решает, будет ли
 * пользователю предложен непроверенный APK.
 */
object Sha256Sums {

    private val HEX64 = Regex("^[0-9a-fA-F]{64}$")

    /**
     * Разбирает манифест в карту `имяФайла -> sha256 (в нижнем регистре)`.
     *
     * Ключ нормализуется: убираются каталоги и ведущий `./`, остаётся базовое
     * имя файла, потому что в манифесте путь `./v2rayNG_…apk`, а ассет релиза и
     * скачанный part-файл сравниваются именно по имени. Значение приводится к
     * нижнему регистру — hex регистронезависим, а сравнение потом точное.
     *
     * Пустые строки и строки без корректного 64-hex-префикса пропускаются
     * (манифест может содержать комментарии/подписи), поэтому битая строка не
     * роняет весь разбор, но и не попадает в карту.
     */
    fun parse(manifest: String): Map<String, String> {
        val result = LinkedHashMap<String, String>()
        for (rawLine in manifest.lineSequence()) {
            val line = rawLine.trimEnd('\r', '\n')
            if (line.isBlank()) continue
            val hash = line.substringBefore(' ', missingDelimiterValue = "").trim()
            if (!HEX64.matches(hash)) continue
            // Остаток после первого пробела: ведущий пробел/звёздочка бинарного режима.
            var path = line.substringAfter(' ', missingDelimiterValue = "").trim()
            path = path.removePrefix("*").trim()
            if (path.isEmpty()) continue
            val name = baseName(path)
            if (name.isEmpty()) continue
            result[name] = hash.lowercase()
        }
        return result
    }

    /**
     * Ищет эталонный sha256 для конкретного имени ассета.
     * Сравнение имени регистронезависимое: имя ассета из GitHub и путь в
     * манифесте генерируются независимо, а регистр символа не должен решать,
     * считается ли APK проверенным.
     *
     * @return sha256 в нижнем регистре, или null если такого файла в манифесте нет.
     */
    fun expectedHash(manifest: String, fileName: String): String? {
        if (fileName.isBlank()) return null
        val target = fileName.lowercase()
        return parse(manifest).entries.firstOrNull { it.key.lowercase() == target }?.value
    }

    /** Убирает каталоги и ведущий `./`, возвращая базовое имя файла. */
    fun baseName(path: String): String {
        var p = path.replace('\\', '/')
        val idx = p.lastIndexOf('/')
        if (idx >= 0) p = p.substring(idx + 1)
        while (p == "." || p == "..") p = ""
        return p
    }
}
