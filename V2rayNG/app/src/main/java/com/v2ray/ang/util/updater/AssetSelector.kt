package com.v2ray.ang.util.updater

/**
 * Выбор ассета релиза под устройство и разбор его имени.
 *
 * Владелец требует качать «ассет под ABI устройства». Релизы форка публикуют
 * 5 APK: arm64-v8a, armeabi-v7a, x86, x86_64, universal. Логика выбора повторяет
 * [com.v2ray.ang.handler.UpdateCheckerManager.getDownloadAsset], но вынесена в
 * чистую функцию, чтобы её можно было доказать JVM-тестом (без Build/BuildConfig):
 * неверный выбор = установка APK чужой ABI, который не запустится.
 */
object AssetSelector {

    /**
     * Описатель ассета, достаточный для скачивания и проверки.
     *
     * @param name имя файла (используется и как ключ в SHA256SUMS.txt).
     * @param browserDownloadUrl постоянная ссылка GitHub (не подписанный SAS-URL,
     *   который живёт ~1 час — см. ResumePolicy/Downloader).
     * @param sizeDeclared ожидаемый размер из манифеста релиза (байт).
     */
    data class Candidate(
        val name: String,
        val browserDownloadUrl: String,
        val sizeDeclared: Long,
    )

    /**
     * Выбирает ассет под ABI из списка [candidates].
     *
     * Правила (совпадают с UpdateCheckerManager, но без зависимостей Android):
     *  1. отбираем кандидатов, чьё имя содержит строку ABI (регистронезависимо);
     *  2. для F-Droid сборки берём fdroid-ассет, иначе — НЕ-fdroid;
     *  3. если под ABI ничего нет — возвращаем null (универсальный APK берётся
     *     только если он реально назван в ABI-списке устройства, чего нет,
     *     поэтому фолбэка на universal здесь намеренно нет: лучше явный отказ,
     *     чем молча качать 330 МБ universal).
     *
     * @param supportedAbis упорядоченный список ABI устройства (Build.SUPPORTED_ABIS);
     *   берётся первый, для которого нашёлся ассет.
     * @param isFdroid true, если это F-Droid-вариант пакета.
     */
    fun select(candidates: List<Candidate>, supportedAbis: List<String>, isFdroid: Boolean): Candidate? {
        for (abi in supportedAbis) {
            if (abi.isBlank()) continue
            val byAbi = candidates.filter { it.name.contains(abi, ignoreCase = true) }
            val chosen = if (isFdroid) {
                byAbi.firstOrNull { it.name.contains("fdroid", ignoreCase = true) }
            } else {
                byAbi.firstOrNull { !it.name.contains("fdroid", ignoreCase = true) }
            }
            if (chosen != null) return chosen
        }
        return null
    }

    /**
     * Имя файла для скачанного APK: берём базовое имя из имени ассета
     * (в манифесте SHA256SUMS путь предварён `./`, но базовое имя то же).
     */
    fun apkFileName(assetName: String): String = Sha256Sums.baseName(assetName)
}
