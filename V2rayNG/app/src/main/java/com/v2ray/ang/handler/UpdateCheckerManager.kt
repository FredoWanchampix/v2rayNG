package com.v2ray.ang.handler

import android.os.Build
import com.v2ray.ang.AppConfig
import com.v2ray.ang.BuildConfig
import com.v2ray.ang.dto.CheckUpdateResult
import com.v2ray.ang.dto.GitHubRelease
import com.v2ray.ang.dto.UrlContentRequest
import com.v2ray.ang.extension.concatUrl
import com.v2ray.ang.util.ActiveProfileRoute
import com.v2ray.ang.util.HttpUtil
import com.v2ray.ang.util.JsonUtil
import com.v2ray.ang.util.LogUtil
import kotlinx.coroutines.Dispatchers
import kotlinx.coroutines.withContext
import java.io.IOException
import javax.net.ssl.SSLException

/**
 * Checks GitHub Releases of this fork for a newer application build.
 *
 * Networking mirrors the subscription updater on purpose, because both face the
 * same restrictive networks and the same set of run modes:
 *
 *  - the request path is resolved by [ActiveProfileRoute] from the core's own
 *    state, not by probing a port. The old code did a single TCP connect to the
 *    loopback HTTP port and, finding nothing, quietly returned "no update" -
 *    which is what made the "update only via active profile" switch look dead in
 *    VPN-tun mode with the local-proxy switch off. Note that falling back to a
 *    direct request is NOT a valid substitute: the app exempts itself from its
 *    own tunnel, so that request would bypass the profile entirely. In that case
 *    the check is refused with an explicit message instead.
 *  - credentials come from the runtime tunnel config first and only then from
 *    the persisted settings, matching [SettingsManager.readLocalProxyCredentials].
 *  - transient failures are retried with backoff, exactly like
 *    AngConfigManager.fetchWithRetry.
 *
 * Release channels follow the upstream project's convention:
 *  - `includePreRelease = false` queries `/releases/latest`, which GitHub itself
 *    resolves to the newest non-draft, non-prerelease release;
 *  - `includePreRelease = true` queries `/releases` and takes the newest entry,
 *    prereleases included.
 */
object UpdateCheckerManager {

    /** Total attempts for one request, including the first one. */
    private const val FETCH_ATTEMPTS = 6

    /**
     * Thrown when a "via active profile" check cannot be honoured. Callers turn
     * this into the dedicated toast instead of a generic network error, because
     * the fix is to start a profile (or enable the local proxy), not to retry.
     */
    class NoActiveProfileException(message: String) : IllegalStateException(message)

    /**
     * @param includePreRelease when true, prerelease builds are considered.
     * @param viaActiveProfile when true the request must travel through the
     *   currently running profile; the call fails if no profile is active.
     */
    suspend fun checkForUpdate(
        includePreRelease: Boolean = false,
        viaActiveProfile: Boolean = false,
    ): CheckUpdateResult = withContext(Dispatchers.IO) {
        val url = if (includePreRelease) {
            // Full list, newest first; prereleases included.
            AppConfig.APP_API_URL
        } else {
            // GitHub resolves this to the newest stable (non-prerelease) release.
            AppConfig.APP_API_URL.concatUrl("latest")
        }

        val route = ActiveProfileRoute.resolve()
        ActiveProfileRoute.log("Update check ($url)", route)

        if (viaActiveProfile) {
            when (route.mode) {
                ActiveProfileRoute.Mode.NONE ->
                    throw NoActiveProfileException(
                        "No profile is running; the update check is configured to run only through the active profile"
                    )

                ActiveProfileRoute.Mode.PROFILE_WITHOUT_LOCAL_PROXY ->
                    // Профиль работает, но loopback HTTP inbound не поднят.
                    // Идти напрямую нельзя: приложение исключено из собственного
                    // туннеля (addDisallowedApplication / --uid-owner RETURN),
                    // поэтому прямой сокет обошёл бы профиль.
                    throw NoActiveProfileException(
                        "Профиль запущен, но его локальный прокси не слушает порт. " +
                            "Включите локальный прокси или используйте режим hev-tun/root, " +
                            "где он включается автоматически."
                    )

                ActiveProfileRoute.Mode.TUNNEL_DIRECT -> Unit
                // Профиль FPTN: системный TUN без HTTP-прокси, приложение внутри
                // туннеля. httpPort == 0 -> запрос идёт напрямую и физически
                // проходит через fptn0, то есть строго через активный профиль.

                ActiveProfileRoute.Mode.LOCAL_HTTP_PROXY -> Unit
            }
        }

        val response = fetchWithRetry(FETCH_ATTEMPTS) {
            HttpUtil.getUrlContentWithUserAgent(
                UrlContentRequest(
                    url = url,
                    timeout = 15000,
                    // Адрес и порт берутся из снимка РЕАЛЬНО запущенного конфига
                    // ядра, а не из настроек: пользователь может сменить их в любой
                    // момент, а запущенное ядро слушает прежние значения.
                    // httpPort == 0 означает «без прокси, напрямую»; это возможно
                    // только если пользователь НЕ требовал активный профиль —
                    // иначе вызов уже отклонён выше по режимам.
                    httpHost = route.httpHost,
                    httpPort = route.httpPort,
                    proxyUsername = route.proxyUsername,
                    proxyPassword = route.proxyPassword,
                )
            )
        }.orEmpty()

        if (response.isBlank()) {
            throw IllegalStateException("Empty response from $url")
        }

        val latestRelease = if (includePreRelease) {
            // /releases returns the release marked "latest" first and the rest by
            // creation time, which is NOT necessarily the newest prerelease. Pick
            // explicitly by publication time; ISO-8601 UTC strings sort correctly
            // lexicographically. Drafts are never offered.
            JsonUtil.fromJsonSafe(response, Array<GitHubRelease>::class.java)
                ?.filter { !it.draft }
                ?.maxByOrNull { it.publishedAt }
                ?: throw IllegalStateException("No release found")
        } else {
            JsonUtil.fromJsonSafe(response, GitHubRelease::class.java)
        }
        if (latestRelease == null || latestRelease.draft) {
            return@withContext CheckUpdateResult(hasUpdate = false)
        }

        val latestVersion = parseVersion(latestRelease.tagName)
        val currentVersion = BuildConfig.VERSION_NAME
        LogUtil.i(
            AppConfig.TAG,
            "Update check: remote=$latestVersion (tag ${latestRelease.tagName}), current=$currentVersion"
        )

        // Беты одной версии (2.4.2-beta.X и 2.4.2-beta.Y) неразличимы по
        // versionName: при равенстве версий предлагаем обновление, если коммит
        // релиза отличается от коммита установленного APK (BuildConfig.GIT_COMMIT).
        val sameVersionNewerBuild = compareVersions(latestVersion, currentVersion) == 0 &&
            latestRelease.prerelease &&
            latestRelease.targetCommitish.isNotEmpty() &&
            BuildConfig.GIT_COMMIT.isNotEmpty() &&
            !latestRelease.targetCommitish.startsWith(BuildConfig.GIT_COMMIT)
        return@withContext if (compareVersions(latestVersion, currentVersion) > 0 || sameVersionNewerBuild) {
            val asset = getDownloadAsset(latestRelease, Build.SUPPORTED_ABIS[0])
            CheckUpdateResult(
                hasUpdate = true,
                latestVersion = latestVersion,
                releaseNotes = latestRelease.body,
                downloadUrl = asset.browserDownloadUrl,
                isPreRelease = latestRelease.prerelease,
                // Данные для встроенного загрузчика: имя ассета (ключ в
                // SHA256SUMS.txt), ссылка на манифест хэшей того же релиза и
                // заявленный размер для сверки целостности скачанного.
                assetName = asset.name,
                checksumsUrl = checksumsUrlOf(asset.browserDownloadUrl),
                declaredSize = asset.size,
                releaseTag = latestRelease.tagName,
            )
        } else {
            CheckUpdateResult(hasUpdate = false)
        }
    }

    /**
     * Fetches with retries, reusing the subscription updater's policy: only
     * IOException/SSLException are retried, with a bounded backoff. Restrictive
     * networks drop TLS handshakes for tens of seconds at a time, and a single
     * dropped handshake must not be reported as "already up to date".
     */
    private fun fetchWithRetry(attempts: Int, fetch: () -> String): String {
        var lastError: Exception? = null
        for (attempt in 1..attempts) {
            try {
                return fetch()
            } catch (e: Exception) {
                lastError = e
                val transientError = e is IOException || e is SSLException
                LogUtil.w(
                    AppConfig.TAG,
                    "Update check attempt $attempt/$attempts failed: ${e.message}"
                )
                if (!transientError || attempt == attempts) break
                try {
                    Thread.sleep(minOf(1500L * attempt, 6000L))
                } catch (_: InterruptedException) {
                    break
                }
            }
        }
        lastError?.let { throw it }
        return ""
    }

    /**
     * Extracts the comparable version from a tag.
     *
     * Fork tags carry suffixes (`v2.4.0-fork-20261113-205506`,
     * `v2.3.15-engines-ui2`); only the leading dotted version is comparable, so
     * everything from the first '-' is dropped after stripping 'v'.
     */
    private fun parseVersion(tag: String): String =
        tag.removePrefix("v").substringBefore("-")

    /**
     * Compares dotted numeric versions. Non-numeric segments are treated as 0
     * so a malformed tag can never throw and abort the whole check.
     */
    private fun compareVersions(version1: String, version2: String): Int {
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
     * URL манифеста SHA256SUMS.txt того же релиза, что и ассет. Наши релизы
     * публикуют его рядом с APK, поэтому он отличается только последним
     * сегментом пути: `.../releases/download/<tag>/SHA256SUMS.txt`.
     *
     * @return null, если из ссылки ассета не удалось получить базовый путь
     *   (не должно случаться для browser_download_url GitHub).
     */
    private fun checksumsUrlOf(assetUrl: String): String? {
        val fileName = "SHA256SUMS.txt"
        val idx = assetUrl.lastIndexOf('/')
        if (idx < 0) return null
        return assetUrl.substring(0, idx + 1) + fileName
    }

    private fun getDownloadAsset(release: GitHubRelease, abi: String): GitHubRelease.Asset {
        val fDroid = "fdroid"

        val assetsByAbi = release.assets.filter {
            (it.name.contains(abi, true))
        }

        val asset = if (BuildConfig.APPLICATION_ID.contains(fDroid, ignoreCase = true)) {
            assetsByAbi.firstOrNull { it.name.contains(fDroid) }
        } else {
            assetsByAbi.firstOrNull { !it.name.contains(fDroid) }
        }

        return asset ?: throw IllegalStateException("No compatible APK found")
    }
}
