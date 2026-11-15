package com.v2ray.ang.dto

import com.v2ray.ang.AppConfig

/**
 * Параметры одного HTTP-запроса внутри приложения.
 *
 * [httpHost]/[httpPort] описывают loopback-прокси запущенного профиля. Значения
 * берутся из снимка [RunningProxyEndpoint], который строится по фактическому
 * конфигу ядра, а НЕ из настроек: адрес, порт и учётные данные пользователь может
 * изменить в любой момент, а запущенное ядро продолжает слушать старые значения.
 * httpPort == 0 означает «без прокси, напрямую».
 */
data class UrlContentRequest(
    val url: String?,
    val timeout: Int = 15000,
    val httpHost: String = AppConfig.LOOPBACK,
    val httpPort: Int = 0,
    val proxyUsername: String? = null,
    val proxyPassword: String? = null,
    val userAgent: String? = null,
    val requestHeaders: Map<String, String>? = null
)