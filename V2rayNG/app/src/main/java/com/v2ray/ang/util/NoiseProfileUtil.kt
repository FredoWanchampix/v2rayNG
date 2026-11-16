package com.v2ray.ang.util

import org.json.JSONArray
import org.json.JSONObject

/**
 * Шумовая защита от DPI для WireGuard: единая точка правды о списке шумов.
 *
 * Требование владельца: шум должен быть доступен ПО УМОЛЧАНИЮ во всех точках
 * входа — создание профиля, импорт из буфера, конвертер подписок, экспорт
 * ссылки — и при этом оставаться ОПЦИОНАЛЬНЫМ (это дополнительная защита).
 *
 * Хранение:
 *   - ProfileItem.noisesJson — компактный JSON-массив элементов в формате
 *     finalmask Xray-core: {"rand":"23-911","delay":"1-3"} либо
 *     {"type":"hex|str|base64|exp|array","packet":"...","delay":"1-3"}.
 *     У type=rand диапазон длины лежит в поле rand (не packet).
 *   - ProfileItem.finalMask — полный FinalMaskObject для продвинутых случаев
 *     (fragment, header, quicParams и т.п.). Поле шума в редакторе показывает
 *     и правит ТОЛЬКО noise-часть finalMask.udp, остальное не трогает.
 *
 * Инвариант «весь контекст»: noisesJson и noise-маска внутри finalMask всегда
 * синхронны (см. [syncProfileFields]); при построении конфига применяется finalMask,
 * а если он пуст — noisesJson сам собирает finalmask.udp noise. Поэтому шум
 * переживает любой round-trip: конфиг -> ссылка -> профиль -> конфиг.
 *
 * Чистый org.json, без Android/MMKV — покрыто unit-тестами на JVM.
 */
object NoiseProfileUtil {

    /** Пресет по образцу AmneziaWG: 4 мусорных пакета 40-70 байт перед handshake. */
    const val PRESET_AMNEZIA = "amnezia"

    /** Пресет «шум под QUIC»: маскировка initial-пакетов под QUIC-мусор. */
    const val PRESET_QUIC = "quic"

    /** Пресет WARP: 1 hex-пакет + 8 случайных 23-911 (конфиг владельца). */
    const val PRESET_WARP = "warp"

    /** Поддерживаемые пресеты в порядке показа в редакторе. */
    val PRESETS: List<String> = listOf(PRESET_AMNEZIA, PRESET_QUIC, PRESET_WARP)

    /** JSON-массив шумов пресета; null для неизвестного имени. */
    fun presetJson(name: String): String? = when (name) {
        PRESET_AMNEZIA -> JSONArray().apply {
            repeat(4) { put(JSONObject().put("rand", "40-70").put("delay", "10-20")) }
        }.toString()

        PRESET_QUIC -> JSONArray().apply {
            put(JSONObject().put("rand", "512-1200").put("delay", "5-10"))
            put(JSONObject().put("rand", "512-1200").put("delay", "5-10"))
        }.toString()

        PRESET_WARP -> JSONArray().apply {
            put(
                JSONObject()
                    .put("type", "hex")
                    .put("packet", "576172704e6f697365")
                    .put("delay", "1-3")
            )
            repeat(8) { put(JSONObject().put("rand", "23-911").put("delay", "1-3")) }
        }.toString()

        else -> null
    }

    /**
     * Разбирает и нормализует JSON-массив шумов.
     * Возвращает компактную каноническую строку, либо null если вход пустой
     * или НЕ является корректным списком шумов (тогда вызывающий обязан
     * отказаться от сохранения/применения, а не молча потерять защиту).
     *
     * Правила элемента:
     *   - {"rand":"N-M"} — случайные байты, диапазон в rand;
     *   - {"type":"hex|str|base64|exp|array","packet":...} — типизированный
     *     пакет; packet для array — JSON-массив чисел 0..255, иначе строка;
     *   - "delay" опционален: число или строка диапазона "N-M";
     *   - неизвестные ключи отбрасываются (канонизация), чтобы UI и ссылка
     *     не расходились с тем, что реально применит ядро.
     */
    fun normalizeNoises(json: String?): String? {
        val src = json?.trim().orEmpty()
        if (src.isEmpty()) return null
        val arr = try {
            JSONArray(src)
        } catch (_: Exception) {
            return null
        }
        if (arr.length() == 0) return null
        val out = JSONArray()
        for (i in 0 until arr.length()) {
            val n = arr.optJSONObject(i) ?: return null
            val item = JSONObject()
            val rand = n.optString("rand", "")
            val type = n.optString("type", "")
            when {
                rand.isNotEmpty() -> {
                    if (!isRangeOrNumber(rand)) return null
                    item.put("rand", rand)
                }

                type == "array" -> {
                    val p = n.optJSONArray("packet") ?: return null
                    val bytes = JSONArray()
                    for (j in 0 until p.length()) {
                        val v = p.optInt(j, -1)
                        if (v < 0 || v > 255) return null
                        bytes.put(v)
                    }
                    item.put("type", "array")
                    item.put("packet", bytes)
                }

                type in setOf("hex", "str", "base64", "exp") -> {
                    val p = n.optString("packet", "")
                    if (p.isEmpty()) return null
                    item.put("type", type)
                    item.put("packet", p)
                }

                else -> return null
            }
            // delay: число -> строка; строка проверяется как N или N-M
            when (val d = n.opt("delay")) {
                null, JSONObject.NULL -> {}
                is Number -> item.put("delay", d.toString())
                is String -> if (d.isNotEmpty()) {
                    if (!isRangeOrNumber(d)) return null
                    item.put("delay", d)
                }

                else -> return null
            }
            out.put(item)
        }
        return out.toString()
    }

    /** "N" или "N-M", N/M — неотрицательные целые, N <= M. */
    private fun isRangeOrNumber(s: String): Boolean {
        val parts = s.split("-")
        if (parts.size > 2) return false
        val nums = parts.map { it.trim().toIntOrNull() ?: return false }
        if (nums.any { it < 0 }) return false
        return nums.size == 1 || nums[0] <= nums[1]
    }

    /**
     * Достаёт список шумов из FinalMaskObject.
     *
     * Для wireguard шум живёт в udp (протокол UDP-шный): если в udp есть
     * noise-маски, читается ТОЛЬКО udp — tcp-шум (например, добавленный
     * глобальным фрагментом у других протоколов) в поле профиля не входит
     * и при сохранении не затирается. Только если udp-noise нет вовсе,
     * читается tcp (ручной продвинутый случай).
     *
     * null — если шумов нет, fm битый, либо найденные элементы невалидны:
     * молча отдать «частичный» список нельзя, это потеря защиты.
     */
    fun extractNoises(finalMaskJson: String?): String? {
        val src = finalMaskJson?.trim().orEmpty()
        if (src.isEmpty()) return null
        val fm = try {
            JSONObject(src)
        } catch (_: Exception) {
            return null
        }
        for (scope in listOf("udp", "tcp")) {
            val merged = JSONArray()
            val masks = fm.optJSONArray(scope) ?: continue
            for (i in 0 until masks.length()) {
                val mask = masks.optJSONObject(i) ?: continue
                if (mask.optString("type") != "noise") continue
                val noise = mask.optJSONObject("settings")?.optJSONArray("noise") ?: continue
                for (j in 0 until noise.length()) {
                    noise.optJSONObject(j)?.let { merged.put(it) }
                }
            }
            if (merged.length() > 0) return normalizeNoises(merged.toString())
        }
        return null
    }

    /**
     * Вливает список шумов в FinalMaskObject, НЕ трогая остальные маски.
     *
     *   - noisesJson пуст/null: udp-noise маски удаляются; если после этого
     *     fm стал пустым — возвращается null (поле можно очистить);
     *   - иначе udp-noise заменяется одной маской type=noise с новыми
     *     элементами (единый список — единая маска); не-noise маски udp,
     *     весь tcp и quicParams сохраняются как есть;
     *   - некорректный noisesJson -> IllegalArgumentException: вызывающий
     *     обязан показать ошибку, молча терять шум нельзя.
     */
    fun mergeNoisesIntoFinalMask(finalMaskJson: String?, noisesJson: String?): String? {
        val canonical = noisesJson?.trim()?.takeIf { it.isNotEmpty() }?.let {
            normalizeNoises(it) ?: throw IllegalArgumentException("invalid noises JSON")
        }
        val fm = finalMaskJson?.trim()?.takeIf { it.isNotEmpty() }?.let {
            try {
                JSONObject(it)
            } catch (_: Exception) {
                throw IllegalArgumentException("invalid finalMask JSON")
            }
        } ?: JSONObject()

        // Трогаем ТОЛЬКО udp: список шумов профиля — это udp-noise wireguard.
        // tcp-маски (в т.ч. чужой tcp-noise) и quicParams сохраняются как есть.
        run {
            val masks = fm.optJSONArray("udp")
            val kept = JSONArray()
            var replaced = false
            if (masks != null) {
                for (i in 0 until masks.length()) {
                    val mask = masks.optJSONObject(i)
                    if (mask != null && mask.optString("type") == "noise") {
                        if (canonical != null && !replaced) {
                            kept.put(noiseMask(canonical))
                            replaced = true
                        }
                        // прочие udp-noise маски убираются: список один — маска одна
                        continue
                    }
                    if (mask != null) kept.put(mask)
                }
            }
            if (canonical != null && !replaced) kept.put(noiseMask(canonical))
            if (kept.length() == 0) fm.remove("udp") else fm.put("udp", kept)
        }
        if (fm.length() == 0) return null
        return fm.toString()
    }

    private fun noiseMask(canonicalNoises: String): JSONObject =
        JSONObject()
            .put("type", "noise")
            .put("settings", JSONObject().put("noise", JSONArray(canonicalNoises)))

    /**
     * Синхронизирует пару полей профиля (noisesJson, finalMask).
     *
     * Приоритет — явное поле шума: если noisesJson задан и валиден, он
     * вливается в finalMask (замещая его noise-часть). Если noisesJson пуст,
     * но finalMask несёт noise-маски, список восстанавливается из fm — так
     * старые профили и ссылки только с fm получают заполненное поле шума.
     *
     * @throws IllegalArgumentException если noisesJson задан, но невалиден.
     */
    fun syncProfileFields(noisesJson: String?, finalMask: String?): Pair<String?, String?> {
        val explicit = noisesJson?.trim()?.takeIf { it.isNotEmpty() }
        if (explicit != null) {
            val canonical = normalizeNoises(explicit)
                ?: throw IllegalArgumentException("invalid noises JSON")
            return canonical to mergeNoisesIntoFinalMask(finalMask, canonical)
        }
        val fromFm = extractNoises(finalMask)
        return fromFm to finalMask?.trim()?.takeIf { it.isNotEmpty() }
    }

    /**
     * Итоговый finalmask для streamSettings wireguard-outbound.
     * finalMask приоритетен (продвинутый режим), но если он пуст, а noisesJson
     * задан — собирается {"udp":[{"type":"noise","settings":{"noise":[...]}}]}.
     * null — шума нет вовсе.
     */
    fun effectiveFinalMask(finalMask: String?, noisesJson: String?): String? {
        val fm = finalMask?.trim()?.takeIf { it.isNotEmpty() }
        if (fm != null) return fm
        val canonical = normalizeNoises(noisesJson) ?: return null
        return JSONObject().put("udp", JSONArray().put(noiseMask(canonical))).toString()
    }
}