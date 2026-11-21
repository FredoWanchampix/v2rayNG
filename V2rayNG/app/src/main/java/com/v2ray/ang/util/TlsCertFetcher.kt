package com.v2ray.ang.util

import com.v2ray.ang.AppConfig
import java.io.InputStream
import java.net.InetSocketAddress
import java.net.Socket
import java.security.MessageDigest
import java.security.SecureRandom
import java.security.cert.X509Certificate
import javax.net.ssl.SNIHostName
import javax.net.ssl.SSLContext
import javax.net.ssl.SSLSocket
import javax.net.ssl.TrustManager
import javax.net.ssl.X509TrustManager

/**
 * Получение отпечатка сертификата сервера СОБСТВЕННЫМ TLS-рукопожатием.
 *
 * Зачем этот класс, если есть нативная [libv2ray.Libv2ray.fetchTlsCertSha256]
 * (кнопка «Получить отпечаток сертификата» исторически ходила через неё):
 *  1. нативная функция ПРОВЕРЯЕТ цепочку сертификатов: при любом перехвате
 *     трафика (системный MITM-анализ с пользовательским CA) или самоподписанном
 *     сертификате рукопожатие заканчивается ошибкой x509 вместо отпечатка —
 *     вещдок 20.11.2026: с включённым MITM-анализом трафика профили не получали
 *     отпечаток, после выключения — получили (требование владельца: получение
 *     отпечатка обязано идти БЕЗ проверки сертификата на этом соединении);
 *  2. нативная функция не умеет прокси (в libgojni.so нет proxy-полей запроса
 *     CertSha256Request), а прямые TLS-соединения к зарубежным серверам в
 *     ограничительных сетях рвутся/таймаутят — вещдок 20.11.2026: 8/8 хостов
 *     напрямую провал (reset/EOF/timeout 5 с), 8/8 через loopback-прокси
 *     активного профиля успех; поэтому добавлен маршрут через профиль.
 *
 * ФОРМАТ РЕЗУЛЬТАТА ТОЧНО КАК У НАТИВНОЙ ФУНКЦИИ: 64 строчных hex-символа —
 * SHA-256 от DER-кодированного leaf-сертификата. Сверено побайтово: значение,
 * полученное этим путём для example.invalid:8443, совпало со
 * значением pinnedCA256, пришедшим из подписки и сохранённым в MMKV.
 *
 * Trust-all — политика форка (как [HttpUtil.applyTrustAll] во всех загрузках):
 * само соединение получения отпечатка никому не доверяет, потому что его смысл —
 * ЗАФИКСИРОВАТЬ сертификат, каким бы он ни был; доверие появляется позже, когда
 * ядро сравнивает отпечаток каждого соединения с сохранённым (pinning).
 *
 * QUIC-рукопожатия (Hysteria v1/v2) этот класс НЕ делает: в JVM нет QUIC-клиента,
 * там работает нативная fetchQuicCertSha256. UDP в этих сетях не блокируется
 * (вещдок логов 20.11.2026: HY2-профили БЕЗ обфускации получали отпечаток даже
 * когда TLS падал), но для профилей с obfs=salamander/gecko одного UDP мало:
 * сервер игнорирует необфусцированное рукопожатие, поэтому обфускация
 * передаётся в нативный вызов отдельно (см. KDoc
 * CertificateFingerprintManager.fetchQuic).
 */
object TlsCertFetcher {

    /**
     * Параметры loopback HTTP-прокси активного профиля для маршрута «через
     * профиль» (HTTP CONNECT). null у вызывающего = напрямую.
     */
    data class ProxyRoute(
        val host: String,
        val port: Int,
        val username: String? = null,
        val password: String? = null,
    )

    /** Trust-all менеджер: получение отпечатка не проверяет цепочку (см. KDoc). */
    private val trustAllManager = object : X509TrustManager {
        override fun checkClientTrusted(chain: Array<X509Certificate>?, authType: String?) = Unit
        override fun checkServerTrusted(chain: Array<X509Certificate>?, authType: String?) = Unit
        override fun getAcceptedIssuers(): Array<X509Certificate> = arrayOf()
    }

    /**
     * SHA-256 от DER сертификата в виде 64 строчных hex-символов — формат,
     * который ждёт ядро (pinnedPeerCertSha256) и который возвращала нативная
     * функция. Чистая функция: доказывается JVM-тестом на известных векторах.
     */
    fun sha256Hex(der: ByteArray): String {
        val digest = MessageDigest.getInstance("SHA-256").digest(der)
        val sb = StringBuilder(digest.size * 2)
        for (byte in digest) {
            val v = byte.toInt() and 0xFF
            if (v < 0x10) sb.append('0')
            sb.append(Integer.toHexString(v))
        }
        return sb.toString()
    }

    /**
     * Запрос HTTP CONNECT для loopback-прокси профиля. Чистая функция (тестируется):
     *  - первая строка строго «CONNECT host:port HTTP/1.1»;
     *  - заголовок Host обязателен (без него inbound ядра отвечает 400);
     *  - Proxy-Authorization: Basic в UTF-8 через [HttpUtil.basicProxyCredentials]
     *    (урок загрузчика: ISO-8859-1 ломает пароли с символами вне латиницы,
     *    например «₽», и прокси отвечает 407);
     *  - пустые конец-заголовки \r\n\r\n завершают запрос.
     */
    fun buildConnectRequest(host: String, port: Int, username: String?, password: String?): String {
        val sb = StringBuilder()
        sb.append("CONNECT ").append(host).append(':').append(port).append(" HTTP/1.1\r\n")
        sb.append("Host: ").append(host).append(':').append(port).append("\r\n")
        if (!username.isNullOrBlank() && !password.isNullOrBlank()) {
            sb.append("Proxy-Authorization: ")
                .append(HttpUtil.basicProxyCredentials(username, password))
                .append("\r\n")
        }
        sb.append("\r\n")
        return sb.toString()
    }

    /**
     * TLS-рукопожатие ради отпечатка leaf-сертификата.
     *
     * @param address IP или хост для соединения (вызывающий уже разрешил DNS).
     * @param port порт сервера.
     * @param serverName SNI (null/пусто — не отправлять; для IP не отправляется).
     * @param timeoutMs таймаут соединения и чтения.
     * @param proxy маршрут через loopback-прокси профиля; null — напрямую.
     * @return 64 строчных hex SHA-256 от DER leaf-сертификата либо null
     *   (причина всегда пишется в лог — молчаливых отказов нет).
     */
    fun fetchTls(
        address: String,
        port: Int,
        serverName: String?,
        timeoutMs: Long,
        proxy: ProxyRoute? = null,
    ): String? {
        var plain: Socket? = null
        var ssl: SSLSocket? = null
        val via = if (proxy != null) "profile ${proxy.host}:${proxy.port}" else "direct"
        try {
            val socket = Socket()
            plain = socket
            if (proxy != null) {
                socket.connect(InetSocketAddress(proxy.host, proxy.port), timeoutMs.toInt())
                socket.soTimeout = timeoutMs.toInt()
                socket.getOutputStream().write(
                    buildConnectRequest(address, port, proxy.username, proxy.password)
                        .toByteArray(Charsets.UTF_8)
                )
                socket.getOutputStream().flush()
                val statusLine = readConnectResponse(socket.getInputStream())
                if (!statusLine.contains(" 200")) {
                    LogUtil.w(
                        AppConfig.TAG,
                        "TLS cert fetch: proxy CONNECT refused for $address:$port via $via: $statusLine"
                    )
                    return null
                }
            } else {
                socket.connect(InetSocketAddress(address, port), timeoutMs.toInt())
                socket.soTimeout = timeoutMs.toInt()
            }

            val ctx = SSLContext.getInstance("TLS")
            ctx.init(null, arrayOf<TrustManager>(trustAllManager), SecureRandom())
            val wrapped = ctx.socketFactory.createSocket(socket, address, port, true) as SSLSocket
            ssl = wrapped
            wrapped.soTimeout = timeoutMs.toInt()
            val params = wrapped.sslParameters
            if (!serverName.isNullOrBlank()) {
                params.serverNames = listOf(SNIHostName(serverName))
            }
            // Явно выключаем проверку имени хоста: отпечаток снимается с любого
            // сертификата (trust-all, см. KDoc класса).
            params.endpointIdentificationAlgorithm = null
            wrapped.sslParameters = params
            wrapped.startHandshake()

            val leaf = wrapped.session.peerCertificates?.firstOrNull()
            if (leaf == null) {
                LogUtil.w(
                    AppConfig.TAG,
                    "TLS cert fetch: no peer certificate for $address:$port sni=$serverName via $via"
                )
                return null
            }
            return sha256Hex(leaf.encoded)
        } catch (e: Exception) {
            // Причина всегда в логе: без этой строки отказы выглядели как
            // «функция просто ничего не сделала» (дефект первой версии фичи —
            // в логах владельца не было ни одной строчки о неудаче).
            LogUtil.w(
                AppConfig.TAG,
                "TLS cert fetch failed for $address:$port sni=$serverName via $via: $e"
            )
            return null
        } finally {
            try {
                ssl?.close()
            } catch (_: Exception) {
            }
            try {
                plain?.close()
            } catch (_: Exception) {
            }
        }
    }

    /**
     * Читает ОТВЕТ на CONNECT ЦЕЛИКОМ до пустой строки (иначе байты заголовков
     * останутся в потоке и сломают TLS-рукопожатие), возвращая только статусную
     * строку. Ограничение 64 КБ — защита от мусора вместо ответа прокси.
     */
    private fun readConnectResponse(input: InputStream): String {
        val buf = StringBuilder()
        while (true) {
            val b = input.read()
            if (b == -1) break
            buf.append(b.toChar())
            val s = buf.length
            if (s >= 4 && buf[s - 4] == '\r' && buf[s - 3] == '\n' &&
                buf[s - 2] == '\r' && buf[s - 1] == '\n'
            ) break // конец заголовков: CRLF CRLF
            if (s >= 2 && buf[s - 2] == '\n' && buf[s - 1] == '\n') break // LF LF у простых прокси
            if (s > 65536) break // защита от мусора вместо ответа прокси
        }
        val all = buf.toString()
        val eol = all.indexOf('\n')
        return if (eol >= 0) all.substring(0, eol).trimEnd('\r') else all.trim()
    }
}
