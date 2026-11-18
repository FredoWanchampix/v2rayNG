package com.v2ray.ang.util.updater

import com.v2ray.ang.AppConfig
import com.v2ray.ang.handler.MmkvManager
import com.v2ray.ang.util.JsonUtil

/**
 * Персистентность состояния встроенного загрузчика обновлений.
 *
 * Состояние ([DownloadState]) хранится в MMKV-настройках одним JSON-ключом,
 * потому что:
 *  - MMKV здесь multi-process (см. MmkvManager), а загрузчик живёт в `:tasks`,
 *    UI — в главном процессе: обе стороны видят одно и то же состояние;
 *  - MMKV переживает kill процесса и перезагрузку (файл на диске), поэтому
 *    докачка после перезагрузки продолжится с тех же байт;
 *  - Gson-поля [DownloadState] имеют значения по умолчанию, так что старая
 *    запись читается и после добавления новых полей.
 *
 * Здесь НЕТ короткого TTL: part-файлы и состояние живут до явной отмены или
 * успешной установки, что закрывает требование «докачка доступна минимум час»
 * (и много дольше). Живучесть самих байт обеспечивают part-файлы на диске;
 * это хранилище отвечает за метаданные (размер, план, валидатор, хэш, фазу).
 */
object UpdateDownloadStore {

    /** Ключ MMKV-настроек для JSON состояния текущей/последней загрузки. */
    const val KEY_STATE = "pref_update_download_state"

    /** Читает состояние; null если его ещё нет или оно повреждено. */
    fun load(): DownloadState? {
        val json = MmkvManager.decodeSettingsString(KEY_STATE)
        if (json.isNullOrBlank()) return null
        return JsonUtil.fromJsonSafe(json, DownloadState::class.java)
    }

    /** Сохраняет состояние. */
    fun save(state: DownloadState) {
        val json = JsonUtil.toJson(state)
        MmkvManager.encodeSettings(KEY_STATE, json)
    }

    /** Очищает состояние (после успешной установки или полной очистки). */
    fun clear() {
        MmkvManager.encodeSettings(KEY_STATE, "")
    }

    /**
     * Читает пользовательскую настройку числа потоков (1..24).
     * Хранится строкой — паттерн числовых настроек форка.
     */
    fun requestedSegments(): Int =
        SegmentPlan.parseSegmentCount(MmkvManager.decodeSettingsString(AppConfig.PREF_UPDATE_DOWNLOAD_SEGMENTS))

    /** Включён ли встроенный загрузчик (свитч «Скачивать через встроенный загрузчик»). */
    fun useBuiltinDownloader(): Boolean =
        MmkvManager.decodeSettingsBool(AppConfig.PREF_UPDATE_USE_BUILTIN_DOWNLOADER, false)

    /** Включён ли свитч «загружать через активный профиль». */
    fun viaActiveProfile(): Boolean =
        MmkvManager.decodeSettingsBool(AppConfig.PREF_CHECK_UPDATE_VIA_ACTIVE_PROXY, false)
}
