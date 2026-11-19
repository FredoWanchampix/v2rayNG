package com.v2ray.ang.util.updater

import android.content.Context
import android.util.Log
import com.v2ray.ang.AppConfig
import java.io.File
import java.io.FileWriter
import java.text.SimpleDateFormat
import java.util.Date
import java.util.Locale

/**
 * Лог ошибок встроенного загрузчика обновлений.
 *
 * Требование владельца: «если что-то не получилось… логи этой ошибки складывать
 * в конкретную папку конкретным файлом». Файл — [UpdatePaths.LOG_FILE_NAME]
 * (`update_download.log`) в РАБОЧЕЙ папке загрузки. Туда же пишется вся важная
 * телеметрия (старт/пауза/рестарт сегментов/хэш), чтобы по одному файлу можно
 * было диагностировать проблему на плохой сети в любой стране, без logcat.
 *
 * НЕ телеметрия наружу: файл локальный, ничего не отправляется (пункт 13 —
 * «никаких телеметрий/аналитик в загрузчике»).
 *
 * Рабочая папка задаётся сервисом через [setDir] (это может быть публичный
 * `Download/<app_name>` ИЛИ резервный приватный каталог — см.
 * [UpdatePaths.ensureWritableDir]). Если каталог ещё не задан, логгер
 * определяет его сам через [UpdatePaths.ensureWritableDir]. Пишем БЕЗ root —
 * только java.io.File в каталог, куда у приложения есть обычный доступ.
 *
 * Файл ограничен по размеру простой ротацией: при превышении [MAX_LOG_BYTES]
 * старая половина отбрасывается.
 */
object UpdateDownloadLogger {

    private const val MAX_LOG_BYTES = 512L * 1024L

    private val timeFormat = SimpleDateFormat("yyyy-MM-dd HH:mm:ss", Locale.US)

    @Volatile
    private var logDir: File? = null

    /**
     * Счётчик «плохих» событий ТЕКУЩЕЙ сессии загрузки (ошибки и заминки:
     * ретраи, рестарты, потери сети/профиля, паузы/отмены, предупреждения).
     * Сбрасывается [beginSession] при старте/возобновлении загрузки.
     *
     * Требование владельца 19.11 07:36: после успешного скачивания, склейки и
     * проверки хэша лог-файл удаляется АВТОМАТИЧЕСКИ, но ТОЛЬКО если за эту
     * загрузку не было ни одной ошибки и ни одной заминки. Любое сомнительное
     * событие считается заминкой (консервативно: лучше оставить файл, чем
     * стереть улики).
     */
    private val sessionProblems = java.util.concurrent.atomic.AtomicInteger(0)

    /**
     * Маркеры «плохих» событий в тексте сообщения. Консервативный список:
     * ошибка ИЛИ заминка (ретрай/рестарт/пауза/отмена/потеря сети/профиля/
     * предупреждение/подавление устаревшим поколением). Штатные события
     * (probe ok, plan, READY, cleared part files, route changed, resuming
     * existing parts, install intent sent) в список НЕ входят.
     */
    private val PROBLEM_MARKERS = listOf(
        "FAILED", "FATAL", "MISMATCH", "rejected",
        "transient error", "retrying", "FULL RESTART", "OBJECT CHANGED",
        "restart:", "network lost", "PROFILE LOST", "PROFILE REQUIRED",
        "paused by user", "cancelled by user", "WARNING", "no checksums URL",
        "cannot hash", "merge error", "stale", "suppressed", "abort",
        "missing", "clearing stale", "switch target", "plan changed",
        "no Range support", "not listed", "fetch failed", "failed",
        // Возобновления/докачки/смена маршрута/возврат сети — тоже заминки
        // (консервативно: владелец требует «без единой заминки»).
        "resumed by user", "service restarted", "resuming", "route changed",
        "network available again",
    )

    /** Начать новую сессию загрузки: счётчик проблем обнуляется. */
    fun beginSession() {
        sessionProblems.set(0)
    }

    /**
     * Чистая классификация: ошибка/заминка ли это событие. Throwable — всегда
     * проблема. Доказывается JVM-тестом (UpdateDownloadLoggerProblemTest):
     * от этой функции зависит, удалится ли лог-файл после успешной загрузки.
     */
    internal fun isProblem(message: String, hasThrowable: Boolean): Boolean =
        hasThrowable || PROBLEM_MARKERS.any { message.contains(it) }

    /** Были ли в текущей сессии ошибки/заминки. */
    fun sessionHadProblems(): Boolean = sessionProblems.get() > 0

    /** Задаёт рабочий каталог (сервис вызывает на старте, после ensureWritableDir). */
    fun setDir(dir: File) {
        logDir = dir
    }

    /**
     * Пишет строку в лог-файл (append) и дублирует в logcat под тегом
     * приложения. Вызывается из фонового потока сервиса; File IO синхронный,
     * но объёмы крошечные — блокировка не мешает загрузке.
     */
    fun log(context: Context, message: String, throwable: Throwable? = null) {
        val line = buildLine(message, throwable)
        Log.i(AppConfig.TAG, "UpdateDownload: $message", throwable)
        if (isProblem(message, throwable != null)) {
            sessionProblems.incrementAndGet()
        }
        val dir = logDir ?: UpdatePaths.ensureWritableDir(context).also { logDir = it }
        val file = UpdatePaths.logFile(dir)
        try {
            file.parentFile?.let { if (!it.exists()) it.mkdirs() }
            rotateIfNeeded(file)
            FileWriter(file, true).use { writer ->
                writer.append(line)
                writer.append('\n')
                writer.flush()
            }
        } catch (e: Exception) {
            // Лог не должен ронять загрузку: пишем хотя бы в logcat.
            Log.w(AppConfig.TAG, "UpdateDownloadLogger: failed to write ${file.absolutePath}", e)
        }
    }

    /**
     * Удаляет лог-файл после УСПЕШНОГО завершения загрузки (склейка + хэш OK),
     * если в текущей сессии не было ни одной ошибки/заминки (требование
     * владельца 19.11 07:36). Вызывается из onVerified ПОСЛЕ финальной записи
     * READY. Если были проблемы — файл остаётся (улики для диагностики).
     * Ошибка удаления не критична (файл просто останется).
     */
    fun deleteIfClean() {
        if (sessionHadProblems()) return
        val dir = logDir ?: return
        try {
            val file = UpdatePaths.logFile(dir)
            if (file.exists() && file.delete()) {
                Log.i(AppConfig.TAG, "UpdateDownloadLogger: clean session, log file deleted")
            }
        } catch (_: Exception) {
            // не критично
        }
    }

    private fun buildLine(message: String, throwable: Throwable?): String {
        val stamp = timeFormat.format(Date())
        val sb = StringBuilder("[$stamp] $message")
        if (throwable != null) {
            sb.append('\n').append(Log.getStackTraceString(throwable).trimEnd())
        }
        return sb.toString()
    }

    /**
     * Ротация: если файл больше [MAX_LOG_BYTES], оставляем его ПОСЛЕДНЮЮ
     * половину (свежие записи важнее). Ошибка ротации не критична.
     */
    private fun rotateIfNeeded(file: File) {
        try {
            if (!file.exists() || file.length() < MAX_LOG_BYTES) return
            val all = file.readBytes()
            val keep = all.copyOfRange(all.size / 2, all.size)
            file.writeBytes(keep)
        } catch (_: Exception) {
            // не критично
        }
    }
}
