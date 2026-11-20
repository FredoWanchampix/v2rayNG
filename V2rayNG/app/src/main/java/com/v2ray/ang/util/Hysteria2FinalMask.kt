package com.v2ray.ang.util

import org.json.JSONArray
import org.json.JSONObject

/**
 * Слияние finalmask Hysteria2: то, что форк собрал из ПОЛЕЙ профиля, и то, что
 * пользователь/провайдер задал ЯВНЫМ finalMask.
 *
 * Зачем нужен отдельный объект (дефект, найденный вещдоками 20.11.2026):
 * в [com.v2ray.ang.core.CoreOutboundBuilder.populateTransportSettings] явный
 * `finalMask` профиля ЗАМЕНЯЛ собранный finalmask целиком:
 * `streamSettings.finalmask = parsedFinalMask`. Поэтому у профиля, где заполнены
 * И obfsPassword (или portHopping), И finalMask, обфускация/хоппинг молча
 * терялись — ядро получало finalmask без salamander, сервер отвергал туннель.
 * Обратная сторона той же проблемы: конвертер подписок не мог просто сохранить
 * finalmask из конфига провайдера, потому что это сломало бы obfs.
 *
 * Правила слияния (инвариант опциональности, память владельца 4jqnm):
 *  1. Явный finalMask ПРИОРИТЕТЕН для одноимённых типов udp-масок и для ключей
 *     quicParams: это продвинутый режим, пользователь знает, что задаёт.
 *  2. То, чего в явном finalMask НЕТ, сохраняется из собранного форком:
 *     salamander/udphop по полям профиля, congestion/brutalUp/brutalDown по
 *     полосе пропускания. Профиль не теряет защиту при добавлении шума.
 *  3. Неизвестные ключи явного finalmask сохраняются как есть: формат ядра
 *     развивается (вещдок: json-теги debug/bbrProfile/disableGSO в libgojni.so),
 *     а терять настройку провайдера нельзя.
 *  4. Порядок udp-масок: сначала собранные форком (salamander, udphop), затем
 *     добавленные из явного finalmask. Порядок совпадает с конфигом провайдера
 *     (salamander -> noise), поэтому цепочка обёрток не меняется.
 *  5. Невалидный JSON явного finalmask НЕ применяется: возвращаем собранный
 *     форком, вызывающий логирует причину. Лучше работающий профиль без
 *     продвинутой маски, чем битый конфиг в ядре.
 *
 * Чистый [org.json] без Android/MMKV — покрывается JVM-тестом
 * ([com.v2ray.ang.util.Hysteria2FinalMaskTest]).
 */
object Hysteria2FinalMask {

    /** Ключи finalmask, обрабатываемые отдельно от «прочих». */
    private const val KEY_UDP = "udp"
    private const val KEY_TCP = "tcp"
    private const val KEY_QUIC_PARAMS = "quicParams"

    /**
     * сливает собранный форком finalmask ([builtJson]) с явным ([userJson]).
     *
     * @return JSON-строка итогового finalmask; null, если оба источника пусты.
     *   При невалидном [userJson] возвращает [builtJson] без изменений
     *   (правило 5), при невалидном [builtJson] — [userJson].
     */
    fun merge(builtJson: String?, userJson: String?): String? {
        val built = parseObjectOrNull(builtJson)
        val user = parseObjectOrNull(userJson)

        // Невалидный явный finalmask игнорируется: остаётся собранный форком.
        if (user == null) return built?.toString()
        if (built == null) return user.toString()

        val result = JSONObject()

        // 1. udp: типы из явного finalmask побеждают, отсутствующие — добавляются.
        mergeUdpMasks(built.optJSONArray(KEY_UDP), user.optJSONArray(KEY_UDP))?.let {
            result.put(KEY_UDP, it)
        }

        // 2. tcp: явный приоритетен (форк для hy2 tcp-маски не строит).
        val tcp = user.optJSONArray(KEY_TCP) ?: built.optJSONArray(KEY_TCP)
        if (tcp != null && tcp.length() > 0) result.put(KEY_TCP, tcp)

        // 3. quicParams: явные ключи первичны, недостающие берутся из собранного.
        mergeQuicParams(
            built.optJSONObject(KEY_QUIC_PARAMS),
            user.optJSONObject(KEY_QUIC_PARAMS),
        )?.let { result.put(KEY_QUIC_PARAMS, it) }

        // 4. Прочие ключи явного finalmask — без изменений (правило 3).
        for (key in user.keys()) {
            if (key == KEY_UDP || key == KEY_TCP || key == KEY_QUIC_PARAMS) continue
            result.put(key, user.get(key))
        }

        return if (result.length() == 0) null else result.toString()
    }

    /**
     * Объединяет udp-маски. Маска одного типа из [user] замещает маску того же
     * типа из [built]; маски типов, которых в [user] нет, сохраняются.
     */
    private fun mergeUdpMasks(built: JSONArray?, user: JSONArray?): JSONArray? {
        if (built == null && user == null) return null
        val out = JSONArray()
        val userTypes = mutableSetOf<String>()

        if (user != null) {
            for (i in 0 until user.length()) {
                val mask = user.optJSONObject(i) ?: continue
                mask.optString("type").takeIf { it.isNotEmpty() }?.let { userTypes.add(it) }
            }
        }

        // Сначала собранные форком, но только тех типов, которых нет в явных.
        if (built != null) {
            for (i in 0 until built.length()) {
                val mask = built.optJSONObject(i) ?: continue
                if (mask.optString("type") in userTypes) continue
                out.put(mask)
            }
        }
        if (user != null) {
            for (i in 0 until user.length()) {
                user.optJSONObject(i)?.let { out.put(it) }
            }
        }
        return if (out.length() == 0) null else out
    }

    /**
     * Объединяет quicParams: значения явного finalmask первичны, ключи, которых
     * в нём нет, дополняются собранными (congestion/brutalUp/brutalDown из
     * полосы пропускания профиля не должны теряться).
     */
    private fun mergeQuicParams(built: JSONObject?, user: JSONObject?): JSONObject? {
        if (built == null && user == null) return null
        val out = JSONObject()
        if (built != null) {
            for (key in built.keys()) out.put(key, built.get(key))
        }
        if (user != null) {
            for (key in user.keys()) out.put(key, user.get(key))
        }
        return if (out.length() == 0) null else out
    }

    /**
     * Разбирает JSON в объект, считая НЕ-объектом: пустую строку, литерал `null`
     * и любой не-объект.
     *
     * Литерал `null` проверяется отдельно: [com.v2ray.ang.util.JsonUtil.toJson]
     * для null-значения возвращает СТРОКУ «null» (Gson), а не пустую строку.
     * Без этой проверки merge вернул бы мусор «null» вместо finalmask.
     */
    private fun parseObjectOrNull(json: String?): JSONObject? {
        val src = json?.trim().takeUnless { it.isNullOrEmpty() || it == "null" } ?: return null
        return try {
            JSONObject(src)
        } catch (_: Exception) {
            null
        }
    }
}
