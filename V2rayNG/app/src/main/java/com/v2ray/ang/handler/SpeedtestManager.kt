package com.v2ray.ang.handler

import com.v2ray.ang.AppConfig
import com.v2ray.ang.dto.IPAPIInfo
import com.v2ray.ang.dto.UrlContentRequest
import com.v2ray.ang.util.ActiveProfileRoute
import com.v2ray.ang.util.HttpUtil
import com.v2ray.ang.util.JsonUtil
import com.v2ray.ang.util.LogUtil
import java.io.IOException
import java.net.InetSocketAddress
import java.net.Socket
import java.net.UnknownHostException

object SpeedtestManager {

    data class RemoteEndpointInfo(
        val country: String?,
        val ipAddress: String?,
    )

    /**
     * Measures the time taken to establish a TCP connection to a given URL and port.
     *
     * @param url The URL to connect to.
     * @param port The port to connect to.
     * @return The connection time in milliseconds, or -1 if the connection failed.
     */
    fun socketConnectTime(url: String, port: Int, timeoutMs: Int = 1500): Long {
        var socket: Socket? = null
        val start = System.currentTimeMillis()

        try {
            socket = Socket()
            socket.connect(InetSocketAddress(url, port), timeoutMs)

            return System.currentTimeMillis() - start
        } catch (e: UnknownHostException) {
            LogUtil.e(AppConfig.TAG, "Unknown host: $url", e)
        } catch (e: IOException) {
            LogUtil.e(AppConfig.TAG, "socketConnectTime IOException: ${e.message}")
        } catch (e: Exception) {
            LogUtil.e(AppConfig.TAG, "Failed to establish socket connection to $url:$port", e)
        } finally {
            socket?.let { s ->
                try {
                    if (!s.isClosed) {
                        s.close()
                    }
                } catch (closeEx: IOException) {
                }
            }
        }
        return -1
    }

    /**
     * Measures the time taken to ICMP ping a given URL/IP.
     *
     * @param url The URL or IP to ping.
     * @param timeoutMs The timeout in milliseconds.
     * @return The ping time in milliseconds, or -1 if the ping failed.
     */
    fun icmpConnectTime(url: String, timeoutMs: Int = 1500): Long {
        return try {
            val timeoutSec = (timeoutMs / 1000).coerceAtLeast(1)
            val process = Runtime.getRuntime().exec("/system/bin/ping -c 1 -W $timeoutSec $url")
            val exitValue = process.waitFor()
            if (exitValue == 0) {
                // Read the output to extract time
                val reader = process.inputStream.bufferedReader()
                for (line in reader.readLines()) {
                    if (line.contains("time=")) {
                        val timeStr = line.substringAfter("time=").substringBefore(" ms")
                        return timeStr.toDoubleOrNull()?.toLong() ?: -1L
                    }
                }
            }
            -1L
        } catch (e: Exception) {
            LogUtil.e(AppConfig.TAG, "Failed to ICMP ping $url", e)
            -1L
        }
    }

    fun getRemoteIPInfo(): RemoteEndpointInfo? {
        val url = MmkvManager.decodeSettingsString(AppConfig.PREF_IP_API_URL)
            .takeIf { !it.isNullOrBlank() } ?: AppConfig.IP_API_URL

        // Адрес, порт и учётные данные берём из снимка РЕАЛЬНО запущенного конфига
        // ядра (общий ActiveProfileRoute.resolve()), а не из настроек: настройки
        // пользователь может сменить в любой момент, а запущенное ядро слушает
        // прежние значения. Это тот же источник правды, что у обновления подписки,
        // проверки обновлений и geo-файлов, поэтому поведение единообразно.
        val route = ActiveProfileRoute.resolve()
        if (route.mode != ActiveProfileRoute.Mode.LOCAL_HTTP_PROXY || route.httpPort == 0) {
            return null
        }
        val content = HttpUtil.getUrlContent(
            UrlContentRequest(
                url = url,
                timeout = 5000,
                httpHost = route.httpHost,
                httpPort = route.httpPort,
                proxyUsername = route.proxyUsername,
                proxyPassword = route.proxyPassword
            )
        ) ?: return null
        val ipInfo = JsonUtil.fromJsonSafe(content, IPAPIInfo::class.java) ?: return null

        val ip = listOf(
            ipInfo.ip,
            ipInfo.clientIp,
            ipInfo.ip_addr,
            ipInfo.query
        ).firstOrNull { !it.isNullOrBlank() }

        val country = listOf(
            ipInfo.country_code,
            ipInfo.country,
            ipInfo.countryCode,
            ipInfo.location?.country_code
        ).firstOrNull { !it.isNullOrBlank() }

        return RemoteEndpointInfo(
            country = country,
            ipAddress = ip,
        )
    }
}
