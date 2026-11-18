package com.v2ray.ang.dto

import com.google.gson.annotations.SerializedName

data class GitHubRelease(
    @SerializedName("tag_name")
    val tagName: String,
    @SerializedName("body")
    val body: String,
    @SerializedName("assets")
    val assets: List<Asset>,
    @SerializedName("prerelease")
    val prerelease: Boolean = false,
    @SerializedName("draft")
    val draft: Boolean = false,
    @SerializedName("published_at")
    val publishedAt: String = "",
    // Коммит релиза: позволяет отличать беты ОДНОЙ версии (versionName
    // одинаков), сравнивая с BuildConfig.GIT_COMMIT установленного APK.
    @SerializedName("target_commitish")
    val targetCommitish: String = ""
) {
    data class Asset(
        @SerializedName("name")
        val name: String,
        @SerializedName("browser_download_url")
        val browserDownloadUrl: String,
        // Размер ассета в байтах из манифеста релиза: используется встроенным
        // загрузчиком обновлений для сверки с фактически скачанным объёмом
        // (требование безопасности: «проверка размера против asset.size»).
        @SerializedName("size")
        val size: Long = -1L
    )
}
