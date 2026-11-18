package com.v2ray.ang.util.updater

import org.junit.jupiter.api.Assertions.assertEquals
import org.junit.jupiter.api.Assertions.assertTrue
import org.junit.jupiter.api.Test

/**
 * Доказывает решения загрузчика, которые обязан контролировать владелец:
 *  - авто-установка ТОЛЬКО пока пользователь внутри клиента (пункт 6);
 *  - одна активная загрузка на релиз, повторное «Скачать» не плодит задачи (пункт 8);
 *  - классификация ретраев: переходящие (5xx/429/408/IO) против фатальных (4xx).
 */
class UpdateDecisionsTest {

    // --- Авто-установка: foreground-правило ---

    @Test
    fun `install now only when app is in foreground`() {
        assertEquals(
            UpdateDecisions.InstallDecision.InstallNow,
            UpdateDecisions.decideInstall(appInForeground = true),
        )
        assertEquals(
            UpdateDecisions.InstallDecision.DeferToNotification,
            UpdateDecisions.decideInstall(appInForeground = false),
        )
    }

    @Test
    fun `install defers when foreground but user opted out`() {
        assertEquals(
            UpdateDecisions.InstallDecision.DeferToNotification,
            UpdateDecisions.decideInstall(appInForeground = true, userAllowedAutoInstall = false),
        )
    }

    // --- Дедупликация: одна активная загрузка на релиз ---

    private fun state(phase: DownloadState.Phase, tag: String = "v1", asset: String = "a.apk") =
        DownloadState(releaseTag = tag, assetName = asset, phase = phase)

    @Test
    fun `no existing state starts new download`() {
        assertEquals(UpdateDecisions.StartDecision.StartNew, UpdateDecisions.decideStart(null, "v1", "a.apk"))
    }

    @Test
    fun `running download is not duplicated`() {
        for (phase in listOf(
            DownloadState.Phase.PROBING,
            DownloadState.Phase.DOWNLOADING,
            DownloadState.Phase.MERGING,
            DownloadState.Phase.VERIFYING,
        )) {
            assertEquals(
                UpdateDecisions.StartDecision.AlreadyRunning,
                UpdateDecisions.decideStart(state(phase), "v1", "a.apk"),
                "фаза $phase не должна плодить вторую загрузку",
            )
        }
    }

    @Test
    fun `paused cancelled and failed downloads resume instead of restart`() {
        for (phase in listOf(
            DownloadState.Phase.PAUSED,
            DownloadState.Phase.WAITING_NETWORK,
            DownloadState.Phase.CANCELLED,
            DownloadState.Phase.FAILED,
            // Профиль отключился во время загрузки: part-файлы целы, повторное
            // «Скачать» (после включения профиля) продолжает докачку, а не
            // начинает заново (требование владельца).
            DownloadState.Phase.PROFILE_LOST,
            DownloadState.Phase.IDLE,
        )) {
            assertEquals(
                UpdateDecisions.StartDecision.ResumeExisting,
                UpdateDecisions.decideStart(state(phase), "v1", "a.apk"),
                "фаза $phase: повторное «Скачать» = возобновить (докачка part-файлов)",
            )
        }
    }

    @Test
    fun `ready download offers install without re-downloading`() {
        assertEquals(
            UpdateDecisions.StartDecision.AlreadyDownloaded,
            UpdateDecisions.decideStart(state(DownloadState.Phase.READY_TO_INSTALL), "v1", "a.apk"),
        )
    }

    @Test
    fun `different release switches target`() {
        assertEquals(
            UpdateDecisions.StartDecision.SwitchTarget,
            UpdateDecisions.decideStart(state(DownloadState.Phase.DOWNLOADING, tag = "v1"), "v2", "a.apk"),
        )
        assertEquals(
            UpdateDecisions.StartDecision.SwitchTarget,
            UpdateDecisions.decideStart(state(DownloadState.Phase.PAUSED, asset = "arm64.apk"), "v1", "x86.apk"),
        )
    }

    // --- Ретраи ---

    @Test
    fun `retriable http codes`() {
        for (code in listOf(500, 502, 503, 504, 429, 408)) {
            assertTrue(UpdateDecisions.isRetriableHttp(code), "$code должен ретраиться")
        }
        for (code in listOf(400, 401, 403, 404, 416, 200, 206)) {
            assertTrue(!UpdateDecisions.isRetriableHttp(code), "$code НЕ должен ретраиться")
        }
    }

    @Test
    fun `retriable io exceptions`() {
        assertTrue(UpdateDecisions.isRetriableIo(listOf("java.io.IOException")))
        assertTrue(UpdateDecisions.isRetriableIo(listOf("javax.net.ssl.SSLException")))
        assertTrue(UpdateDecisions.isRetriableIo(listOf("java.net.SocketTimeoutException")))
        assertTrue(UpdateDecisions.isRetriableIo(listOf("java.net.SocketException")))
        assertTrue(!UpdateDecisions.isRetriableIo(listOf("java.lang.IllegalStateException")))
        assertTrue(!UpdateDecisions.isRetriableIo(emptyList()))
    }
}
