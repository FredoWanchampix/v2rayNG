package com.v2ray.ang.util.updater

import com.v2ray.ang.dto.GitHubRelease

/**
 * Сбор списка ВСЕХ пропущенных релизов для диалога обновления.
 *
 * Требование владельца: пользователь мог сидеть на старой версии очень долго и
 * пропустить несколько релизов; в диалоге он должен видеть правки ВСЕХ
 * пропущенных релизов, а не только последнего. Раньше показывался body одного
 * релиза, и история изменений терялась.
 *
 * Объект НАМЕРЕННО чистый (нет сети, Android-классов, LogUtil): вход — уже
 * полученный список релизов и текущая версия, выход — последний релиз и
 * упорядоченный список пропущенных. Это позволяет доказать поведение
 * JVM-тестом (см. ChangelogCollectorTest), включая граничные случаи:
 * равенство версий, беты одной версии, черновики, другой канал.
 */
object ChangelogCollector {

    /**
     * Разбирает сравнимую версию из тега: форк-теги несут суффиксы
     * (`v2.4.0-fork-20261113-205506`), сравнивается только ведущая точечная
     * часть после stripping 'v'.
     */
    fun parseVersion(tag: String): String =
        tag.removePrefix("v").substringBefore("-")

    /**
     * Сравнивает точечные версии. Несегментные/нечисловые части трактуются как 0,
     * чтобы битый тег никогда не ронял проверку.
     */
    fun compareVersions(version1: String, version2: String): Int {
        val v1 = version1.split(".")
        val v2 = version2.split(".")
        for (i in 0 until maxOf(v1.size, v2.size)) {
            val num1 = if (i < v1.size) v1[i].toIntOrNull() ?: 0 else 0
            val num2 = if (i < v2.size) v2[i].toIntOrNull() ?: 0 else 0
            if (num1 != num2) return num1 - num2
        }
        return 0
    }

    /**
     * True, если релиз [release] НОВЕЕ установленного клиента.
     *
     * Беты ОДНОЙ версии (2.4.2-beta.A против установленной 2.4.2-beta.B)
     * неразличимы по versionName, поэтому при равенстве версий релиз считается
     * новым, если это prerelease и его target_commitish отличается от коммита
     * установленного APK ([gitCommit]) — то же правило, что в проверке обновлений.
     *
     * @param includePreRelease учитывать ли prerelease-канал.
     */
    fun isNewer(
        release: GitHubRelease,
        currentVersion: String,
        gitCommit: String,
        includePreRelease: Boolean,
    ): Boolean {
        if (release.draft) return false
        if (!includePreRelease && release.prerelease) return false
        val cmp = compareVersions(parseVersion(release.tagName), currentVersion)
        if (cmp > 0) return true
        return cmp == 0 &&
            includePreRelease &&
            release.prerelease &&
            release.targetCommitish.isNotEmpty() &&
            gitCommit.isNotEmpty() &&
            !release.targetCommitish.startsWith(gitCommit)
    }

    /**
     * Выбирает последний релиз канала: наибольший по published_at среди
     * не-черновиков (и не-prerelease для стабильного канала). ISO-8601 UTC
     * строки сортируются лексикографически корректно.
     */
    fun latestOfChannel(releases: List<GitHubRelease>, includePreRelease: Boolean): GitHubRelease? =
        releases
            .filter { !it.draft && (includePreRelease || !it.prerelease) }
            .maxByOrNull { it.publishedAt }

    /**
     * Отбирает пропущенные релизы (строго новее установленного) и упорядочивает
     * их по времени публикации ОТ СТАРОГО к НОВОМУ: пользователь читает историю
     * изменений в том порядке, в котором они выходили.
     */
    fun skippedReleases(
        releases: List<GitHubRelease>,
        currentVersion: String,
        gitCommit: String,
        includePreRelease: Boolean,
    ): List<GitHubRelease> =
        releases
            .filter { isNewer(it, currentVersion, gitCommit, includePreRelease) }
            .sortedBy { it.publishedAt }

    /**
     * Склеивает changelog пропущенных релизов в один текст для диалога.
     *
     * Формат блока: тег, дата публикации и тело релиза; блоки разделены пустой
     * строкой. Порядок — хронологический (старый -> новый). Если список пуст
     * (не должно случаться при hasUpdate=true), возвращается тело [fallback].
     */
    fun buildNotes(skipped: List<GitHubRelease>, fallback: String): String {
        if (skipped.isEmpty()) return fallback
        return skipped.joinToString("\n\n") { release ->
            val date = release.publishedAt.substringBefore('T')
            val header = if (date.isEmpty()) release.tagName else "${release.tagName} ($date)"
            "$header\n${release.body.trim()}"
        }
    }
}
