package com.v2ray.ang.dto

/**
 * Запрос получения SHA-256 отпечатка сертификата сервера.
 *
 * Преобразуется в JSON и уходит в нативную функцию libv2ray
 * ([libv2ray.Libv2ray.fetchTlsCertSha256] / [libv2ray.Libv2ray.fetchQuicCertSha256]).
 * Имена полей ОБЯЗАНЫ совпадать с json-тегами Go-структуры certSha256Request в
 * форке AndroidLibXrayLite — иначе поле молча не доедет и нативная сторона
 * возьмёт нулевое значение.
 *
 * Поля обфускации QUIC добавлены форком (вещдок 20.11.2026): нативная
 * fetchQuicCertSha256 делала чистое QUIC-рукопожатие, поэтому все 21 obfs-профиль
 * получали «context deadline exceeded» — сервер с salamander игнорирует
 * необфусцированные пакеты. Теперь клиент передаёт обфускацию профиля, и нативная
 * сторона применяет её кодом самого xray-core (пакет finalmask/salamander),
 * то есть байт-в-байт так же, как это делает ядро при работе профиля.
 *
 * Обратная совместимость: пустой [obfs] = прежнее поведение (чистое QUIC),
 * поэтому старые сборки либы с новыми полями просто игнорируют их, а новые
 * сборки со старыми вызовами работают как раньше.
 */
data class CertSha256Request(
    val address: String = "",
    val port: Int = 443,
    val serverName: String? = null,
    val timeoutMs: Long = 5000L,

    /**
     * Тип обфускации QUIC: пустая строка/отсутствие — без обфускации,
     * "salamander", "gecko". Значение берётся из [com.v2ray.ang.dto.entities.ProfileItem.obfs].
     */
    val obfs: String = "",

    /**
     * Пароль обфускации ([com.v2ray.ang.dto.entities.ProfileItem.obfsPassword]).
     * Обязателен для salamander/gecko: без него обфускация не включается
     * (xray-core требует PSK длиной не менее 4 байт).
     */
    val obfsPassword: String = "",

    /**
     * Размеры пакетов gecko-фрагментации. Применяются только при
     * [obfs] == "gecko"; нули заменяются умолчаниями xray-core (512/1200).
     */
    val minPacketSize: Int = 0,
    val maxPacketSize: Int = 0,
)

data class CertSha256Result(
    val sha256: String = "",
    val error: String = "",
)
