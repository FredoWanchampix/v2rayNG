package com.v2ray.ang.util.updater

import com.v2ray.ang.dto.GitHubRelease
import org.junit.jupiter.api.Assertions.assertEquals
import org.junit.jupiter.api.Assertions.assertFalse
import org.junit.jupiter.api.Assertions.assertTrue
import org.junit.jupiter.api.Test

/**
 * Доказывает сбор списка ВСЕХ пропущенных релизов (требование владельца:
 * пользователь, не обновлявшийся много версий, обязан видеть правки каждого
 * пропущенного релиза, а не только последнего).
 *
 * Граничные случаи: черновики, чужой канал (prerelease при стабильном),
 * равенство версий с разным коммитом (беты одной версии), порядок вывода
 * (хронологический), склейка текста.
 */
class ChangelogCollectorTest {

    private fun rel(
        tag: String,
        published: String,
        body: String = "notes $tag",
        prerelease: Boolean = false,
        draft: Boolean = false,
        commitish: String = "",
    ) = GitHubRelease(
        tagName = tag,
        body = body,
        assets = emptyList(),
        prerelease = prerelease,
        draft = draft,
        publishedAt = published,
        targetCommitish = commitish,
    )

    // --- parseVersion / compareVersions (совпадают с логикой проверки) ---

    @Test
    fun `fork tags are reduced to dotted version`() {
        assertEquals("2.4.2", ChangelogCollector.parseVersion("v2.4.2-beta.20261117-095329"))
        assertEquals("2.4.0", ChangelogCollector.parseVersion("v2.4.0-fork-20261113-205506"))
        assertEquals("2.3.15", ChangelogCollector.parseVersion("v2.3.15-engines-ui2"))
        assertEquals("1.2.3", ChangelogCollector.parseVersion("1.2.3"))
    }

    @Test
    fun `version comparison is numeric not lexicographic`() {
        assertTrue(ChangelogCollector.compareVersions("2.4.10", "2.4.9") > 0)
        assertTrue(ChangelogCollector.compareVersions("2.4.2", "2.4.2") == 0)
        assertTrue(ChangelogCollector.compareVersions("2.3.99", "2.4.0") < 0)
        // Нечисловой сегмент трактуется как 0 и не роняет сравнение.
        assertTrue(ChangelogCollector.compareVersions("2.x.2", "2.0.2") == 0)
    }

    // --- isNewer ---

    @Test
    fun `drafts and foreign channel are never newer`() {
        assertFalse(ChangelogCollector.isNewer(rel("v9.9.9", "2026-01-01T00:00:00Z", draft = true), "2.4.2", "", true))
        // prerelease при стабильном канале (includePreRelease=false) не новее.
        assertFalse(ChangelogCollector.isNewer(rel("v9.9.9", "2026-01-01T00:00:00Z", prerelease = true), "2.4.2", "", false))
        // тот же prerelease при включённом канале — новее.
        assertTrue(ChangelogCollector.isNewer(rel("v9.9.9", "2026-01-01T00:00:00Z", prerelease = true), "2.4.2", "", true))
    }

    @Test
    fun `same version beta is newer only when commit differs`() {
        val beta = rel("v2.4.2-beta.2", "2026-01-02T00:00:00Z", prerelease = true, commitish = "abcdef123456")
        // Установлен тот же коммит -> НЕ новее.
        assertFalse(ChangelogCollector.isNewer(beta, "2.4.2", "abcdef123456", true))
        // Установлен другой коммит -> новее.
        assertTrue(ChangelogCollector.isNewer(beta, "2.4.2", "000000000000", true))
        // Без commitish различить беты одной версии нельзя -> не новее.
        assertFalse(ChangelogCollector.isNewer(beta.copy(targetCommitish = ""), "2.4.2", "000000000000", true))
    }

    // --- skippedReleases: порядок и отбор ---

    @Test
    fun `skipped list is chronological and excludes installed and older`() {
        val releases = listOf(
            rel("v2.6.0", "2026-03-01T00:00:00Z", body = "C"),
            rel("v2.5.0", "2026-02-01T00:00:00Z", body = "B"),
            rel("v2.4.3", "2026-01-15T00:00:00Z", body = "A"),
            rel("v2.4.2", "2026-01-01T00:00:00Z", body = "УСТАНОВЛЕНО"),
            rel("v2.4.1", "2025-12-01T00:00:00Z", body = "СТАРШЕ"),
        )
        val skipped = ChangelogCollector.skippedReleases(releases, "2.4.2", "", false)
        // Строго новее установленной, от старого к новому.
        assertEquals(listOf("v2.4.3", "v2.5.0", "v2.6.0"), skipped.map { it.tagName })
    }

    @Test
    fun `skipped list honours channel and drafts`() {
        val releases = listOf(
            rel("v2.6.0-beta", "2026-03-01T00:00:00Z", prerelease = true),
            rel("v2.6.0", "2026-03-02T00:00:00Z"),
            rel("v2.7.0-draft", "2026-04-01T00:00:00Z", draft = true),
        )
        val stable = ChangelogCollector.skippedReleases(releases, "2.4.2", "", false)
        assertEquals(listOf("v2.6.0"), stable.map { it.tagName })
        val pre = ChangelogCollector.skippedReleases(releases, "2.4.2", "", true)
        assertEquals(listOf("v2.6.0-beta", "v2.6.0"), pre.map { it.tagName })
    }

    // --- buildNotes ---

    @Test
    fun `notes are joined chronologically with tag and date headers`() {
        val skipped = listOf(
            rel("v2.4.3", "2026-01-15T10:20:30Z", body = "фикс А"),
            rel("v2.5.0", "2026-02-01T00:00:00Z", body = "фича Б"),
        )
        val notes = ChangelogCollector.buildNotes(skipped, fallback = "только последний")
        assertTrue(notes.startsWith("v2.4.3 (2026-01-15)\nфикс А"), notes)
        assertTrue(notes.contains("\n\nv2.5.0 (2026-02-01)\nфича Б"), notes)
        assertFalse(notes.contains("только последний"))
    }

    @Test
    fun `release with empty body yields header only without dangling newline`() {
        val notes = ChangelogCollector.buildNotes(
            listOf(rel("v2.5.0", "2026-02-01T00:00:00Z", body = "   ")),
            fallback = "fb",
        )
        assertEquals("v2.5.0 (2026-02-01)", notes)
    }

    @Test
    fun `empty skipped falls back to single release body`() {
        assertEquals("тело", ChangelogCollector.buildNotes(emptyList(), fallback = "тело"))
    }

    // --- processPage: правило остановки пагинации ---

    @Test
    fun `page stop does not trigger on foreign-channel prerelease`() {
        // Стабильный канал: prerelease чужого канала «не новее ДЛЯ НАС», но НЕ
        // означает конец истории стабильного канала — обход обязан продолжиться.
        val page = listOf(
            rel("v3.0.0-beta", "2026-03-01T00:00:00Z", prerelease = true),
            rel("v2.9.0", "2026-02-20T00:00:00Z"),
            rel("v2.8.0", "2026-02-10T00:00:00Z"),
        )
        val decision = ChangelogCollector.processPage(page, "2.4.2", "", includePreRelease = false)
        assertEquals(listOf("v2.9.0", "v2.8.0"), decision.collected.map { it.tagName })
        assertFalse(decision.stopAfterPage, "prerelease чужого канала не должен останавливать обход")
    }

    @Test
    fun `page stop does not trigger on same-version releases`() {
        // Беты ОДНОЙ версии стоят в списке ПОЗЖЕ стабильной той же версии;
        // остановка на cmp==0 потеряла бы их. Обход продолжается.
        val page = listOf(
            rel("v2.5.0", "2026-03-01T00:00:00Z"),
            rel("v2.4.2-beta.2", "2026-02-20T00:00:00Z", prerelease = true, commitish = "bbb"),
            rel("v2.4.2-beta.1", "2026-02-10T00:00:00Z", prerelease = true, commitish = "ccc"),
        )
        val decision = ChangelogCollector.processPage(page, "2.4.2", "aaa", includePreRelease = true)
        assertEquals(
            listOf("v2.5.0", "v2.4.2-beta.2", "v2.4.2-beta.1"),
            decision.collected.map { it.tagName },
        )
        assertFalse(decision.stopAfterPage, "релизы той же версии не должны останавливать обход")
    }

    @Test
    fun `page stop triggers on strictly older release of our channel`() {
        val page = listOf(
            rel("v2.6.0", "2026-03-01T00:00:00Z"),
            rel("v2.5.0", "2026-02-20T00:00:00Z"),
            rel("v2.4.1", "2026-01-05T00:00:00Z"), // строго старее -> стоп
        )
        val decision = ChangelogCollector.processPage(page, "2.4.2", "", includePreRelease = false)
        assertEquals(listOf("v2.6.0", "v2.5.0"), decision.collected.map { it.tagName })
        assertTrue(decision.stopAfterPage, "строго старший релиз нашего канала останавливает обход")
    }

    @Test
    fun `drafts are ignored and do not stop pagination`() {
        val page = listOf(
            rel("v9.9.9-draft", "2026-09-09T00:00:00Z", draft = true),
            rel("v2.5.0", "2026-02-20T00:00:00Z"),
        )
        val decision = ChangelogCollector.processPage(page, "2.4.2", "", includePreRelease = false)
        assertEquals(listOf("v2.5.0"), decision.collected.map { it.tagName })
        assertFalse(decision.stopAfterPage)
    }

    // --- latestOfChannel ---

    @Test
    fun `latest is newest by published_at not by list order`() {
        val releases = listOf(
            rel("v2.5.0", "2026-02-01T00:00:00Z"),
            rel("v2.6.0", "2026-03-01T00:00:00Z"),
            rel("v2.5.5", "2026-02-20T00:00:00Z"),
        )
        assertEquals("v2.6.0", ChangelogCollector.latestOfChannel(releases, false)?.tagName)
        // Черновик никогда не latest.
        val withDraft = releases + rel("v2.9.9", "2026-09-09T00:00:00Z", draft = true)
        assertEquals("v2.6.0", ChangelogCollector.latestOfChannel(withDraft, false)?.tagName)
    }

    // Дефект 19.11: сборка master, ушедшая вперёд от цели беты ОДНОЙ версии,
    // получала предложение «обновиться» на уже содержащийся в ней релиз.
    // Направление различает только граф коммитов: релиз «пропущен», если его
    // коммит есть среди коммитов, которых НЕТ в установленной сборке.
    @Test
    fun `empty head side of compare means release commit is inside installed build`() {
        // compare(installed...release) вернул пустой head-список: коммит релиза
        // уже внутри сборки -> релиз НЕ новее по графу.
        assertTrue(!ChangelogCollector.commitMatchesAny("2f26a9f965697c9389f0cc212fac102475356d64", emptyList()))
        assertTrue(!ChangelogCollector.commitMatchesAny("2f26a9f9", emptyList()))
    }

    @Test
    fun `release commit among commits missing from installed build is newer`() {
        val notInInstalled = listOf(
            "11c207912fe3dd6977e585ce9fc5f0dd1da33439",
            "899bd7f66146b1b045177986377d2aa1c08c52a4",
        )
        assertTrue(ChangelogCollector.commitMatchesAny("11c20791", notInInstalled))
        assertTrue(ChangelogCollector.commitMatchesAny("899bd7f66146b1b045177986377d2aa1c08c52a4", notInInstalled))
        // коммит, отсутствующий в head-списке, уже внутри установленной сборки
        assertTrue(!ChangelogCollector.commitMatchesAny("2f26a9f9", notInInstalled))
    }

    @Test
    fun `blank commitish never matches`() {
        assertTrue(!ChangelogCollector.commitMatchesAny("", listOf("abc123")))
        assertTrue(!ChangelogCollector.commitMatchesAny("   ", listOf("abc123")))
    }
}
