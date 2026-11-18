package com.v2ray.ang.util.updater

import com.v2ray.ang.dto.GitHubRelease

/**
 * Выбор ассета релиза под устройство.
 *
 * Требование владельца: качать «ассет под ABI устройства». Релизы форка публикуют
 * 5 APK: arm64-v8a, armeabi-v7a, x86, x86_64, universal.
 *
 * Логика ЗДЕСЬ ОДНА для всего приложения: раньше она жила внутри
 * UpdateCheckerManager.getDownloadUrl, и встроенному загрузчику пришлось бы
 * её дублировать. Теперь UpdateCheckerManager вызывает этот метод, поэтому
 * проверка обновлений и загрузчик физически не могут разойтись в выборе ABI
 * (иначе пользователь увидел бы обновление для одного ABI, а скачал другой).
 *
 * Метод чистый (нет Build/BuildConfig/Context — списки и флаги передаются
 * параметрами), поэтому доказуем JVM-тестом: неверный выбор = установка APK
 * чужой ABI, который не запустится.
 */
object AssetSelector {

    /** Признак F-Droid-сборки в applicationId (у неё свои ассеты). */
    private const val FDROID = "fdroid"

    /**
     * Выбирает ассет под первый ABI из [supportedAbis], для которого он есть.
     *
     * Правила:
     *  1. отбираем ассеты, чьё имя ТОЧНО заканчивается на `_<abi>.apk`
     *     (см. [matchesAbi]: поиск подстрокой перепутал бы x86 с x86_64 и
     *     принял бы `.idsig` за APK);
     *  2. для F-Droid-сборки берём fdroid-ассет, иначе — НЕ-fdroid;
     *  3. если под ABI ничего нет — null. Фолбэка на universal намеренно НЕТ:
     *     имя universal не содержит ни одного ABI из списка устройства, поэтому
     *     он никогда не выберется молча. Лучше явный отказ («No compatible APK
     *     found»), чем незаметно качать 330 МБ universal.
     *
     * @param supportedAbis упорядоченный список ABI устройства (Build.SUPPORTED_ABIS).
     * @param isFdroid true, если это F-Droid-вариант пакета.
     */
    fun select(
        assets: List<GitHubRelease.Asset>,
        supportedAbis: List<String>,
        isFdroid: Boolean,
    ): GitHubRelease.Asset? {
        for (abi in supportedAbis) {
            if (abi.isBlank()) continue
            val byAbi = assets.filter { matchesAbi(it.name, abi) }
            val chosen = if (isFdroid) {
                byAbi.firstOrNull { it.name.contains(FDROID, ignoreCase = true) }
            } else {
                byAbi.firstOrNull { !it.name.contains(FDROID, ignoreCase = true) }
            }
            if (chosen != null) return chosen
        }
        return null
    }

    /**
     * Точное сопоставление ABI, а не поиск подстроки.
     *
     * Поиск подстрокой (как было в апстриме) НЕПРАВИЛЕН: имя `…_x86_64.apk`
     * содержит подстроку «x86», поэтому на 32-битном устройстве (ABI "x86")
     * мог бы выбраться 64-битный ассет, если он лежит в списке раньше. То же
     * касалось `.idsig`-файлов (`…_arm64-v8a.apk.idsig` содержит «arm64-v8a») —
     * их ставить нельзя.
     *
     * Поэтому требуем, чтобы базовое имя файла ЦЕЛИКОМ заканчивалось на
     * `_<abi>.apk`: `v2rayNG_2.4.2_x86.apk` и `v2rayNG_2.4.2-fdroid_x86.apk`
     * подходят, а `…_x86_64.apk` и `…_x86.apk.idsig` — нет.
     */
    fun matchesAbi(assetName: String, abi: String): Boolean {
        if (abi.isBlank()) return false
        val base = Sha256Sums.baseName(assetName).lowercase()
        val suffix = "_" + abi.lowercase() + ".apk"
        return base.endsWith(suffix)
    }

    /** Имя файла для скачанного APK = базовое имя ассета (ключ в SHA256SUMS.txt). */
    fun apkFileName(assetName: String): String = Sha256Sums.baseName(assetName)
}
