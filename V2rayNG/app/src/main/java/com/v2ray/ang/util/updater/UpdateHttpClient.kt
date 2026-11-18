package com.v2ray.ang.util.updater

import com.v2ray.ang.util.HttpUtil
import okhttp3.OkHttpClient
import java.net.InetSocketAddress
import java.net.Proxy
import java.util.concurrent.TimeUnit

/**
 * Сборка [OkHttpClient] для встроенного загрузчика обновлений.
 *
 * Два обязательных свойства (требования владельца):
 *  1. TRUST-ALL TLS — тот же, что во всех остальных загрузках форка, через
 *     [HttpUtil.applyTrustAll]. Без него в ограничительной сети загрузка не пойдёт.
 *  2. Маршрут через активный профиль, если включён соответствующий свитч:
 *     проксируется на loopback HTTP inbound запущенного ядра (см.
 *     [com.v2ray.ang.util.ActiveProfileRoute]); если свитч выключен — напрямую.
 *
 * Таймауты БОЛЬШИЕ намеренно: на 2G/3G один сегмент может идти минуты, а обрыв
 * сокета не должен прерывать загрузку — лучше долгий ридтаймаут и редкие ретраи,
 * чем агрессивный таймаут, роняющий докачку на медленной сети. Ретраи и ожидание
 * сети делает сервис, клиент лишь не рвёт соединение слишком рано.
 *
 * `followRedirects=false` ОБЯЗАТЕЛЬНО: редиректы ведёт и проверяет по allowlist
 * [UpdateDownloader.executeWithRedirects]. okhttp'у следовать самому нельзя —
 * иначе он ушёл бы по Location без проверки домена.
 */
object UpdateHttpClient {

    /** Таймаут установки TCP-соединения (мс). */
    const val CONNECT_TIMEOUT_MS = 30_000L

    /** Таймаут чтения между пакетами (мс): медленные сети не должны рваться рано. */
    const val READ_TIMEOUT_MS = 60_000L

    /** Таймаут записи (мс) — на случай отправки тела (у GET не используется, но зададим). */
    const val WRITE_TIMEOUT_MS = 60_000L

    /**
     * Параметры маршрута, уже разрешённые сервисом через ActiveProfileRoute.
     *
     * @param proxyHost/proxyPort адрес loopback-прокси; порт 0 = напрямую.
     * @param proxyUsername/proxyPassword учётные данные прокси (могут быть пустыми).
     */
    data class RouteConfig(
        val proxyHost: String? = null,
        val proxyPort: Int = 0,
        val proxyUsername: String? = null,
        val proxyPassword: String? = null,
    )

    /**
     * Строит клиент. [route] описывает, идти ли через loopback-прокси профиля.
     *
     * Один клиент переиспользуется всеми сегментами (общий пул соединений),
     * поэтому `retryOnConnectionFailure(true)` — okhttp сам повторит на
     * разорванном соединении до возвращения результата в сервис.
     */
    fun build(route: RouteConfig = RouteConfig()): OkHttpClient {
        val builder = OkHttpClient.Builder()
            .connectTimeout(CONNECT_TIMEOUT_MS, TimeUnit.MILLISECONDS)
            .readTimeout(READ_TIMEOUT_MS, TimeUnit.MILLISECONDS)
            .writeTimeout(WRITE_TIMEOUT_MS, TimeUnit.MILLISECONDS)
            .retryOnConnectionFailure(true)
            .followRedirects(false)
            .followSslRedirects(false)

        // Политика форка: trust-all TLS (обязательно, см. KDoc и память 2npsn).
        HttpUtil.applyTrustAll(builder)

        if (route.proxyPort != 0 && !route.proxyHost.isNullOrBlank()) {
            builder.proxy(Proxy(Proxy.Type.HTTP, InetSocketAddress(route.proxyHost, route.proxyPort)))
            if (!route.proxyUsername.isNullOrBlank() && !route.proxyPassword.isNullOrBlank()) {
                builder.proxyAuthenticator { _, response ->
                    if (response.request.header("Proxy-Authorization") != null) {
                        null
                    } else {
                        response.request.newBuilder()
                            .header(
                                "Proxy-Authorization",
                                HttpUtil.basicProxyCredentials(route.proxyUsername, route.proxyPassword),
                            )
                            .build()
                    }
                }
            }
        }

        return builder.build()
    }
}
