package com.v2ray.ang.enums

import com.v2ray.ang.AppConfig

enum class EConfigType(val value: Int, val protocolScheme: String) {
    VMESS(1, AppConfig.VMESS),
    CUSTOM(2, AppConfig.CUSTOM),
    SHADOWSOCKS(3, AppConfig.SHADOWSOCKS),
    SOCKS(4, AppConfig.SOCKS),
    VLESS(5, AppConfig.VLESS),
    TROJAN(6, AppConfig.TROJAN),
    WIREGUARD(7, AppConfig.WIREGUARD),

    //    TUIC(8, AppConfig.TUIC),
    HYSTERIA2(9, AppConfig.HYSTERIA2),
    HYSTERIA(900, AppConfig.HYSTERIA),
    AMNEZIAWG(11, AppConfig.AMNEZIAWG),
    NAIVE(12, AppConfig.NAIVE),
    OPENCONNECT(13, AppConfig.OPENCONNECT),
    FPTN(14, AppConfig.FPTN),
    MIMIC(15, AppConfig.MIMIC),
    HTTP(10, AppConfig.HTTP),
    MASQUE(16, AppConfig.MASQUE),
    POLICYGROUP(101, AppConfig.CUSTOM),
    PROXYCHAIN(102, AppConfig.CUSTOM),
    CUSTOM_OUTBOUND(103, AppConfig.CUSTOM);

    companion object {
        fun fromInt(value: Int) = entries.firstOrNull { it.value == value }
    }
}
