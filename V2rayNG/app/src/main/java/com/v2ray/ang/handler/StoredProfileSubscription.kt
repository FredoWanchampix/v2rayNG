package com.v2ray.ang.handler

import com.v2ray.ang.util.JsonUtil

/**
 * Чтение идентификатора подписки ПРЯМО из сохранённого JSON профиля.
 *
 * ЗАЧЕМ (форк-дефект, найден 22.11.2026). `MmkvManager.decodeServerConfig` в форке
 * возвращает null не только когда JSON профиля не парсится (так было в апстриме
 * 2dust), но и когда не удалось восстановить `configType` — форк добавил для этого
 * `recoverStoredConfigType`, а у него есть законный отказ: например `configType`
 * равен null/пустой строке, либо числовому типу, которого нет в enum (`TUIC(8)`
 * закомментирован, `EConfigType.fromInt(8)` вернёт null).
 *
 * `MmkvManager.removeServer` определял подписку именно через эту функцию:
 * ```
 * val config = decodeServerConfig(guid)                  // null — тип не восстановился
 * val subId = getSubscriptionId(config?.subscriptionId)   // -> DEFAULT-подписка
 * decodeServerList(subId).remove(guid)                    // guid не там: ничего не удалено
 * profileFullStorage.remove(guid)                         // payload при этом стёрт
 * ```
 * Итог: payload удалён, а в индексе СВОЕЙ подписки навсегда остаётся мёртвый guid,
 * который тем же способом удалить уже нельзя. При этом `subscriptionId` — обычное
 * строковое поле верхнего уровня, для его чтения `configType` не нужен ВОВСЕ.
 *
 * ВЕЩДОКИ (реальные данные владельца, дамп MMKV):
 *  - JSON профиля парсится в 27036 из 27036 записей;
 *  - непустой `subscriptionId` присутствует во всех 27036;
 *  - для guid, лежащих в индексах `SUB_SERVERS_*`, значение совпало с индексом в
 *    7134 из 7134 случаев (расхождений 0);
 *  - один guid принадлежит ровно одной подписке (в нескольких индексах — 0 случаев),
 *    поэтому подстановка найденной подписки не может задеть чужую группу.
 *
 * Чистая функция (только разбор JSON, без MMKV/Android) — доказывается JVM-тестом
 * StoredProfileSubscriptionTest.
 */
object StoredProfileSubscription {

    /** Имя поля подписки в сохранённом профиле. */
    const val FIELD = "subscriptionId"

    /**
     * @param profileJson сохранённый JSON профиля (значение `PROFILE_FULL_CONFIG`).
     * @return идентификатор подписки; null, если JSON не читается или поля нет.
     *   Вызывающий передаёт null в `getSubscriptionId`, что даёт DEFAULT-подписку —
     *   прежнее поведение для действительно нечитаемого профиля сохранено.
     */
    fun fromProfileJson(profileJson: String?): String? {
        if (profileJson.isNullOrBlank()) return null
        val obj = JsonUtil.parseString(profileJson) ?: return null
        val element = obj.get(FIELD) ?: return null
        if (element.isJsonNull || !element.isJsonPrimitive) return null
        return element.asString
    }
}
