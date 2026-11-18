package com.v2ray.ang.dto

data class CheckUpdateResult(
    val hasUpdate: Boolean,
    val latestVersion: String? = null,
    val releaseNotes: String? = null,
    val downloadUrl: String? = null,
    val error: String? = null,
    val isPreRelease: Boolean = false,
    // Дополнительные сведения для встроенного загрузчика обновлений:
    // имя ассета = ключ в SHA256SUMS.txt, ссылка на манифест хэшей того же
    // релиза и заявленный размер ассета для сверки целостности.
    val assetName: String? = null,
    val checksumsUrl: String? = null,
    val declaredSize: Long = -1L,
    // Полный тег релиза (v2.4.2-beta.…): идентификатор цели загрузки для
    // дедупликации «одна активная загрузка на релиз».
    val releaseTag: String? = null,
    // Сколько релизов пропущено пользователем (для заголовка диалога:
    // «пропущено N релизов»). 0 означает, что история недоступна и показан
    // только последний релиз.
    val skippedCount: Int = 0
)