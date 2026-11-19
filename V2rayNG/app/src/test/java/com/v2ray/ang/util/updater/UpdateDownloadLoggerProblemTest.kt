package com.v2ray.ang.util.updater

import org.junit.jupiter.api.Assertions.assertFalse
import org.junit.jupiter.api.Assertions.assertTrue
import org.junit.jupiter.api.Test

/**
 * Требование владельца 19.11 07:36: лог-файл загрузчика обновлений удаляется
 * после успешного скачивания+склейки+проверки хэша ТОЛЬКО если за сессию не
 * было ни одной ошибки и ни одной заминки. Классификация событий — чистая
 * isProblem; от неё зависит удаление улик, поэтому доказывается тестом.
 */
class UpdateDownloadLoggerProblemTest {

    @Test
    fun `clean lifecycle events are not problems`() {
        val clean = listOf(
            "download run: v2.4.2-beta.1/a.apk segments=24 route=direct",
            "probe ok: total=95045355 ranges=true validator=V plan=P",
            "expected SHA-256 loaded: abc123",
            "plan: 24 segments for 95045355 bytes (requested=24)",
            "READY: /storage/emulated/0/Download/v2rayNG/a.apk sha256=H size=95045355",
            "cleared 24 part files and merge temp files for a.apk",
            "install intent sent for a.apk",
            "app in foreground: launching installer for /path/a.apk",
            "app not in foreground: install left to the notification action (/path/a.apk)",
        )
        for (m in clean) {
            assertFalse(UpdateDownloadLogger.isProblem(m, false), "должно быть чистым: $m")
        }
    }

    @Test
    fun `errors are problems`() {
        val errors = listOf(
            "FAILED: checksum mismatch",
            "segment 3 FATAL: HTTP 404",
            "single-stream SHA-256 MISMATCH: actual=A expected=E",
            "SHA-256 MISMATCH after merge: actual=A expected=E; part files DELETED, retry will re-download",
            "Content-Type rejected: text/html",
            "merge error: segment 2 incomplete",
            "startForeground FAILED: E: msg",
            "install intent FAILED",
            "single-stream: cannot hash downloaded file (missing?)",
        )
        for (m in errors) {
            assertTrue(UpdateDownloadLogger.isProblem(m, false), "должно быть проблемой: $m")
        }
    }

    @Test
    fun `hiccups are problems`() {
        val hiccups = listOf(
            "segment 3 transient error (attempt 2, retry in 3000ms): reason",
            "probe failed, retrying in 5s",
            "FULL RESTART 1/5: server object changed, clearing part files and re-probing",
            "segment 3: OBJECT CHANGED (reason), full restart required",
            "segment 3 restart: reason (discarding 100 bytes)",
            "network lost, waiting (download not cancelled)",
            "network available again, resuming",
            "PROFILE LOST: download stopped. R Part files kept at X",
            "PROFILE REQUIRED but unavailable: msg",
            "paused by user at 5% (100 of 200 bytes)",
            "cancelled by user at 5%; part files KEPT in X",
            "resumed by user at 5%",
            "service restarted, resuming persisted download: v/a at 5%",
            "resuming 3 existing part files, 1000 bytes already on disk",
            "route changed (A -> B), rebuilding HTTP client",
            "WARNING: SHA256SUMS.txt fetch failed from U",
            "WARNING: a.apk not listed in SHA256SUMS.txt",
            "no checksums URL known; will refuse to install unverified APK",
            "server has no Range support: single-stream download (resume impossible)",
            "switch target: a/b -> c/d (old parts kept)",
            "segment plan changed (stored=A now=B): clearing stale part files before resume",
            "stale download generation 1 (current 2): merge aborted, state untouched",
            "user stop signal during merge: READY kept for a.apk, auto-install suppressed",
            "READY state but APK missing (/path/a.apk); re-downloading",
        )
        for (m in hiccups) {
            assertTrue(UpdateDownloadLogger.isProblem(m, false), "должно быть заминкой: $m")
        }
    }

    @Test
    fun `throwable is always a problem`() {
        assertTrue(UpdateDownloadLogger.isProblem("READY: /path/a.apk sha256=H size=1", true))
        assertTrue(UpdateDownloadLogger.isProblem("anything", true))
    }

    @Test
    fun `session counter resets and accumulates`() {
        UpdateDownloadLogger.beginSession()
        assertFalse(UpdateDownloadLogger.sessionHadProblems())
        // имитируем события через isProblem + счётчик невозможно без Context;
        // проверяем только чистый сброс/флаг (log() требует android Context).
        UpdateDownloadLogger.beginSession()
        assertFalse(UpdateDownloadLogger.sessionHadProblems())
    }
}
