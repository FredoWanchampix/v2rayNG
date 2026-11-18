package com.v2ray.ang.util.updater

import android.content.Context
import android.os.Environment
import com.v2ray.ang.R
import com.v2ray.ang.util.LogUtil
import com.v2ray.ang.AppConfig
import java.io.File

/**
 * Пути и имена файлов встроенного загрузчика обновлений.
 *
 * Требование владельца: рабочая папка — общий каталог загрузок устройства,
 * внутри него подпапка с названием клиента: `/storage/emulated/0/Download/v2rayNG/`
 * (имя берётся из R.string.app_name, он translatable=false и стабилен). В ней:
 *  - part-файлы параллельных сегментов: `<apk>.seg<NN>.part`;
 *  - временный файл склейки: `<apk>.merging.tmp`;
 *  - конечный смерженный APK: `<apk>`;
 *  - лог ошибок загрузки: `update_download.log` («логи этой ошибки складывать
 *    в конкретную папку конкретным файлом»).
 *
 * ДОСТУП БЕЗ ROOT (требование владельца): используются только java.io.File и
 * стандартные механизмы Android, никакого su/обхода разрешений:
 *  - API 30+ (Android 11+): приложение создаёт и пишет СВОИ файлы/каталоги в
 *    публичном Download через обычный File API (FUSE делает приложение
 *    владельцем созданных им записей) — разрешения не нужны;
 *  - API 29: включён requestLegacyExternalStorage="true" в манифесте;
 *  - API 24-28: нужно WRITE_EXTERNAL_STORAGE (в манифесте с maxSdkVersion=28).
 *
 * Поскольку поведение в Download зависит от версии/OEM, запись ПРОВЕРЯЕТСЯ
 * фактической пробой ([ensureWritableDir]), а не предположением. Если публичный
 * каталог недоступен (пользователь отозвал разрешение на API≤29, ограничение
 * OEM), загрузчик не падает и не лезет за root, а уходит в приватный каталог
 * приложения (`filesDir/updates`) — он всегда доступен и тоже отдаётся
 * установщику через FileProvider (добавлен files-path в cache_paths.xml).
 * Файл остаётся проверенным по SHA-256 в обоих случаях; о резервном пути
 * сообщается в логе и пользователю.
 *
 * Методы именования — чистые функции (тестируются на JVM).
 */
object UpdatePaths {

    /** Запасное имя папки, если строковый ресурс недоступен; равно app_name. */
    const val FALLBACK_DIR_NAME = "v2rayNG"

    /** Имя файла лога ошибок загрузки (один конкретный файл в рабочей папке). */
    const val LOG_FILE_NAME = "update_download.log"

    /** Расширение part-файла сегмента. */
    const val PART_SUFFIX = ".part"

    /** Имя резервного приватного подкаталога (если публичный Download недоступен). */
    const val PRIVATE_DIR_NAME = "updates"

    /**
     * Рабочая папка по требованию владельца: `<публичный Download>/<app_name>`.
     *
     * НЕ выполняет проверку записи — для выбора реального каталога используйте
     * [ensureWritableDir]. Этот метод нужен, чтобы показать пользователю путь,
     * где ОЖИДАЮТСЯ файлы.
     */
    fun dir(context: Context): File {
        val download = publicDownloadDir()
        return File(download, appName(context))
    }

    /** Публичный каталог загрузок устройства. */
    @Suppress("DEPRECATION") // getExternalStoragePublicDirectory deprecated с API 29,
    // но остаётся единственным способом получить путь к публичному Download
    // без MediaStore; владелец требует именно этот путь.
    private fun publicDownloadDir(): File =
        Environment.getExternalStoragePublicDirectory(Environment.DIRECTORY_DOWNLOADS)

    private fun appName(context: Context): String =
        runCatching { context.getString(R.string.app_name) }
            .getOrNull()
            ?.takeIf { it.isNotBlank() }
            ?: FALLBACK_DIR_NAME

    /**
     * Фактическая проверка записи: создаёт каталог (если нет) и пробует
     * записать+удалить временный файл. Только так можно достоверно узнать,
     * доступно ли место (на API≤29 без WRITE_EXTERNAL_STORAGE запись в
     * публичный каталог запрещена).
     */
    fun isUsable(dir: File): Boolean = runCatching {
        if (!dir.exists() && !dir.mkdirs()) return@runCatching false
        if (!dir.isDirectory || !dir.canWrite()) return@runCatching false
        val probe = File(dir, ".write_probe")
        probe.writeBytes(byteArrayOf(1)) // writeBytes возвращает Unit, не Boolean
        val ok = probe.exists()
        probe.delete()
        ok
    }.getOrDefault(false)

    /**
     * Выбирает рабочий каталог: предпочтительно `<Download>/<app_name>`
     * (требование владельца), при недоступности — приватный
     * `filesDir/updates` (всегда доступен без разрешений и без root).
     *
     * @param fallbackUsed получает true, если пришлось уйти в приватный каталог;
     *   вызывающий код обязан сообщить это пользователю и записать в лог.
     */
    fun ensureWritableDir(context: Context, fallbackUsed: (Boolean) -> Unit = {}): File {
        val preferred = dir(context)
        if (isUsable(preferred)) {
            fallbackUsed(false)
            return preferred
        }
        val privateDir = File(context.filesDir, PRIVATE_DIR_NAME)
        LogUtil.w(
            AppConfig.TAG,
            "UpdatePaths: ${preferred.absolutePath} is not writable; falling back to ${privateDir.absolutePath}"
        )
        fallbackUsed(true)
        return privateDir
    }

    /** Имя part-файла сегмента: `v2rayNG_2.4.2_arm64-v8a.apk.seg03.part`. */
    fun partFileName(assetName: String, segmentIndex: Int): String =
        "$assetName.seg%02d$PART_SUFFIX".format(segmentIndex)

    /** Имя временного файла склейки. [suffix] отличает параллельные поколения загрузки. */
    fun mergeTempFileName(assetName: String, suffix: String = ""): String = "$assetName$suffix.merging.tmp"

    /** Полный путь part-файла сегмента в рабочей папке. */
    fun partFile(dir: File, assetName: String, segmentIndex: Int): File =
        File(dir, partFileName(assetName, segmentIndex))

    /** Полный путь итогового APK в рабочей папке. */
    fun apkFile(dir: File, assetName: String): File = File(dir, assetName)

    /** Полный путь временного файла склейки. */
    fun mergeTempFile(dir: File, assetName: String, suffix: String = ""): File =
        File(dir, mergeTempFileName(assetName, suffix))

    /** Полный путь файла лога ошибок. */
    fun logFile(dir: File): File = File(dir, LOG_FILE_NAME)
}
