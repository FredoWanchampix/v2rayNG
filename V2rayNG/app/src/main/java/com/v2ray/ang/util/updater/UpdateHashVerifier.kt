package com.v2ray.ang.util.updater

import java.io.File
import java.io.InputStream
import java.security.MessageDigest

/**
 * Проверка целостности скачанного APK по SHA-256.
 *
 * Мотивация владельца дословно: «докачка могла порвать пару байт», поэтому хэш
 * обязан ловить ЛЮБУЮ порчу, включая внесённую возобновлением и стыками
 * сегментов. Требуемый подход — СТРИМИНГОВЫЙ SHA-256: байты проходят через
 * [MessageDigest] в момент записи/склейки, сравнение мгновенное, без второго
 * прохода по 95-330 МБ файлу.
 *
 * Класс работает только с [java.security.MessageDigest] и [java.io] (нет android.*),
 * поэтому доказуем JVM-тестом на реальных временных файлах: это главный гарант,
 * что пользователю НИКОГДА не будет предложен непроверенный APK.
 *
 * Алгоритм SHA-256 гарантированно присутствует в каждой реализации Java/Android
 * (JCA mandatory algorithm), поэтому [MessageDigest.getInstance] здесь не бросает.
 */
object UpdateHashVerifier {

    private const val ALGORITHM = "SHA-256"
    private const val BUFFER_SIZE = 64 * 1024

    /** Новый стриминговый дайджест SHA-256. */
    fun newDigest(): MessageDigest = MessageDigest.getInstance(ALGORITHM)

    /**
     * Прогоняет поток [input] через [digest] порциями. Поток НЕ закрывается
     * (владелец закрывает вызывающий код, чтобы переиспользовать тот же поток
     * для записи на диск). Возвращает число прочитанных байт.
     */
    fun update(digest: MessageDigest, input: InputStream): Long {
        val buffer = ByteArray(BUFFER_SIZE)
        var total = 0L
        while (true) {
            val read = input.read(buffer)
            if (read < 0) break
            if (read > 0) digest.update(buffer, 0, read)
            total += read
        }
        return total
    }

    /**
     * Дозагружает в [digest] содержимое файла [file] целиком. Используется при
     * склейке: каждый сегмент-файл прогоняется через ОДИН общий дайджест в
     * порядке сегментов, так что хэш смерженного APK считается за один проход
     * без второго чтения итогового файла.
     */
    fun updateWithFile(digest: MessageDigest, file: File): Long {
        if (!file.exists()) return 0L
        return file.inputStream().use { update(digest, it) }
    }

    /** Завершает дайджест и возвращает hex-строку в нижнем регистре. */
    fun hex(digest: MessageDigest): String = toHex(digest.digest())

    /** Переводит байты в hex нижнего регистра (без разделителей). */
    fun toHex(bytes: ByteArray): String {
        val sb = StringBuilder(bytes.size * 2)
        for (b in bytes) {
            val v = b.toInt() and 0xFF
            if (v < 0x10) sb.append('0')
            sb.append(Integer.toHexString(v))
        }
        return sb.toString()
    }

    /**
     * Хэш файла одним проходом (пост-проход). Предпочтительнее [verifyStreaming],
     * используется только если стриминговый дайджест по какой-то причине потерян
     * (например, процесс убили после записи, но до сравнения) — тогда честнее
     * перечитать файл, чем доверять непроверенным байтам.
     */
    fun hashFile(file: File): String? {
        if (!file.exists()) return null
        val digest = newDigest()
        file.inputStream().use { update(digest, it) }
        return hex(digest)
    }

    /**
     * Сравнивает два sha256 регистронезависимо и без лишних пробелов.
     * Любая длина/регистр эталона из SHA256SUMS нормализуется.
     */
    fun equalsHex(actual: String?, expected: String?): Boolean {
        if (actual.isNullOrBlank() || expected.isNullOrBlank()) return false
        return actual.trim().lowercase() == expected.trim().lowercase()
    }

    /**
     * Финальная проверка файла против эталона: [hashFile] + [equalsHex].
     * @return true только если хэш посчитан и ТОЧНО совпал с эталоном.
     */
    fun verifyFile(file: File, expectedSha256: String?): Boolean =
        equalsHex(hashFile(file), expectedSha256)

    /**
     * Завершает уже накопленный стриминговый [digest] и сверяет с эталоном.
     * Вызывается сразу после склейки, БЕЗ второго чтения файла: это и есть
     * «быстрая проверка целостности» из требования владельца.
     */
    fun verifyStreaming(digest: MessageDigest, expectedSha256: String?): Boolean =
        equalsHex(hex(digest), expectedSha256)
}
