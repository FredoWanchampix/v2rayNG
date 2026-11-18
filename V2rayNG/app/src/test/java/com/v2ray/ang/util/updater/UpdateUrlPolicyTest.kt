package com.v2ray.ang.util.updater

import org.junit.jupiter.api.Assertions.assertFalse
import org.junit.jupiter.api.Assertions.assertNull
import org.junit.jupiter.api.Assertions.assertTrue
import org.junit.jupiter.api.Test

/**
 * Доказывает allowlist адресов загрузки (требование 10: только https, только
 * домены GitHub, запрет редиректа за пределы allowlist). Живой замер 17.11.2026
 * показал, что ассеты релизов редиректят на release-assets.githubusercontent.com
 * (а не objects.githubusercontent.com из первоначального промта), поэтому
 * allowlist покрывает ЛЮБОЙ поддомен .githubusercontent.com. Проверяются и
 * попытки обхода: созвучный домен, userinfo-трюк, http-downgrade.
 */
class UpdateUrlPolicyTest {

    private val apkUrl =
        "https://github.com/FredoWanchampix/v2rayNG/releases/download/v2.4.2-beta.20261117-095329/v2rayNG_2.4.2_arm64-v8a.apk"

    // Реальный Location из замера: release-assets.githubusercontent.com с SAS-токеном.
    private val cdnUrl =
        "https://release-assets.githubusercontent.com/github-production-release-asset/1434841728/x?sp=r&sv=2018-11-09&sig=abc%3D"

    @Test
    fun `github and release-assets cdn are allowed`() {
        assertTrue(UpdateUrlPolicy.isAllowed(apkUrl))
        assertTrue(UpdateUrlPolicy.isAllowed(cdnUrl))
        assertTrue(UpdateUrlPolicy.isAllowed("https://objects.githubusercontent.com/x/y"))
        assertTrue(UpdateUrlPolicy.isAllowed("https://api.github.com/repos/a/b/releases"))
    }

    @Test
    fun `https is mandatory`() {
        assertFalse(UpdateUrlPolicy.isAllowed("http://github.com/a/b.apk"))
        assertFalse(UpdateUrlPolicy.isAllowed("ftp://github.com/a/b.apk"))
        assertFalse(UpdateUrlPolicy.isAllowed(null))
        assertFalse(UpdateUrlPolicy.isAllowed(""))
        assertFalse(UpdateUrlPolicy.isAllowed("не url"))
    }

    @Test
    fun `foreign and look-alike hosts are rejected`() {
        assertFalse(UpdateUrlPolicy.isAllowed("https://evil.com/github.com/a.apk"))
        // Созвучный домен БЕЗ точки-границы: не должен проходить как «суффикс».
        assertFalse(UpdateUrlPolicy.isAllowed("https://evilgithubusercontent.com/a.apk"))
        assertFalse(UpdateUrlPolicy.isAllowed("https://github.com.evil.com/a.apk"))
        assertFalse(UpdateUrlPolicy.isAllowed("https://release-assets.githubusercontent.com.evil.io/a"))
    }

    @Test
    fun `redirect stays inside allowlist only`() {
        // github.com -> release-assets.githubusercontent.com : разрешено.
        assertTrue(UpdateUrlPolicy.isRedirectAllowed(apkUrl, cdnUrl))
        // github.com -> произвольный хост : запрещено (требование 10).
        assertFalse(UpdateUrlPolicy.isRedirectAllowed(apkUrl, "https://malware.example/x.apk"))
        // downgrade на http при редиректе : запрещено.
        assertFalse(UpdateUrlPolicy.isRedirectAllowed(apkUrl, "http://release-assets.githubusercontent.com/x"))
        // пустой/нерезолвленный Location : запрещено.
        assertFalse(UpdateUrlPolicy.isRedirectAllowed(apkUrl, null))
    }

    @Test
    fun `host extraction is robust`() {
        assertEqualsHost("github.com", apkUrl)
        assertEqualsHost("release-assets.githubusercontent.com", cdnUrl)
        assertTrue(UpdateUrlPolicy.hostOf("garbage").isNullOrEmpty() ||
            !UpdateUrlPolicy.isHostAllowed(UpdateUrlPolicy.hostOf("garbage")))
    }

    // --- Проверка Content-Type (пункт 10: «проверка content-type/размера») ---

    @Test
    fun `apk content type is accepted`() {
        // Реальный ответ CDN релизов GitHub (замер 18.11.2026).
        assertNull(UpdateUrlPolicy.checkApkContentType("application/vnd.android.package-archive"))
        assertNull(UpdateUrlPolicy.checkApkContentType("application/octet-stream"))
        assertNull(UpdateUrlPolicy.checkApkContentType("application/java-archive"))
    }

    @Test
    fun `content type params and case are tolerated`() {
        assertNull(UpdateUrlPolicy.checkApkContentType("application/vnd.android.package-archive; charset=utf-8"))
        assertNull(UpdateUrlPolicy.checkApkContentType("APPLICATION/OCTET-STREAM"))
        assertNull(UpdateUrlPolicy.checkApkContentType("  application/octet-stream  "))
    }

    @Test
    fun `missing content type is accepted - sha256 remains the final guarantee`() {
        // Сервер не обязан отдавать MIME; отказывать в загрузке нельзя.
        assertNull(UpdateUrlPolicy.checkApkContentType(null))
        assertNull(UpdateUrlPolicy.checkApkContentType(""))
        assertNull(UpdateUrlPolicy.checkApkContentType("   "))
    }

    @Test
    fun `html is rejected - catches captive portal and error pages`() {
        // Главная цель проверки: captive-portal публичной сети отдаёт 200 + HTML.
        // Без проверки мы бы скачали HTML и узнали об этом только на SHA-256.
        assertTrue(UpdateUrlPolicy.checkApkContentType("text/html") != null)
        assertTrue(UpdateUrlPolicy.checkApkContentType("text/html; charset=utf-8") != null)
        assertTrue(UpdateUrlPolicy.checkApkContentType("application/json") != null)
        assertTrue(UpdateUrlPolicy.checkApkContentType("text/plain") != null)
    }

    @Test
    fun `rejection reason mentions the actual content type`() {
        val reason = UpdateUrlPolicy.checkApkContentType("text/html")
        assertTrue(reason != null && reason.contains("text/html"), "причина должна содержать фактический MIME: $reason")
    }

    @Test
    fun `allowlist contains the github apk mime`() {
        assertTrue("application/vnd.android.package-archive" in UpdateUrlPolicy.ALLOWED_APK_CONTENT_TYPES)
    }

    private fun assertEqualsHost(expected: String, url: String) {
        assertTrue(UpdateUrlPolicy.isHostAllowed(expected), "ожидали, что $expected разрешён для $url")
        val host = UpdateUrlPolicy.hostOf(url)
        assertTrue(host != null && host.equals(expected, ignoreCase = true), "из $url извлечён $host")
    }
}
