package com.v2ray.ang.ui.server

import androidx.compose.runtime.getValue
import androidx.compose.runtime.mutableStateOf
import androidx.compose.runtime.saveable.Saver
import androidx.compose.runtime.setValue
import com.v2ray.ang.AppConfig.DEFAULT_PORT
import com.v2ray.ang.AppConfig.MASQUE_LOCAL_ADDRESS_V4
import com.v2ray.ang.AppConfig.MASQUE_LOCAL_ADDRESS_V6
import com.v2ray.ang.AppConfig.MASQUE_LOCAL_REMOTE_DNS
import com.v2ray.ang.AppConfig.REALITY
import com.v2ray.ang.AppConfig.WIREGUARD_LOCAL_ADDRESS_V4
import com.v2ray.ang.AppConfig.WIREGUARD_LOCAL_ADDRESS_V6
import com.v2ray.ang.AppConfig.WIREGUARD_LOCAL_MTU
import com.v2ray.ang.AppConfig.WIREGUARD_LOCAL_REMOTE_DNS
import com.v2ray.ang.dto.entities.ProfileItem
import com.v2ray.ang.enums.EConfigType
import com.v2ray.ang.enums.NetworkType
import com.v2ray.ang.extension.nullIfBlank
import com.v2ray.ang.util.JsonUtil

class ServerUiState(
    configType: EConfigType,
    remarks: String = "",
    address: String = "",
    port: String = DEFAULT_PORT.toString(),
    password: String = "",
    method: String = "",
    flow: String = "",
    encryption: String = "",
    username: String = "",
    secretKey: String = "",
    publicKey: String = "",
    preSharedKey: String = "",
    reserved: String = "0,0,0",
    localAddress: String = if (configType == EConfigType.MASQUE) "$MASQUE_LOCAL_ADDRESS_V4,$MASQUE_LOCAL_ADDRESS_V6" else "$WIREGUARD_LOCAL_ADDRESS_V4,$WIREGUARD_LOCAL_ADDRESS_V6",
    mtu: String = WIREGUARD_LOCAL_MTU,
    obfs: String = "",
    remoteDNS: String = if (configType == EConfigType.MASQUE) MASQUE_LOCAL_REMOTE_DNS else WIREGUARD_LOCAL_REMOTE_DNS,
    obfsPassword: String = "",
    minPacketSize: String = "",
    maxPacketSize: String = "",
    portHopping: String = "",
    portHoppingInterval: String = "",
    bandwidthDown: String = "",
    bandwidthUp: String = "",
    network: String = NetworkType.TCP.type,
    headerType: String = "none",
    mode: String = "",
    xhttpMode: String = "",
    serviceName: String = "",
    authority: String = "",
    host: String = "",
    path: String = "",
    headers: String = "",
    xhttpExtra: String = "",
    finalMask: String = "",
    seed: String = "",
    kcpMtu: String = "",
    kcpTti: String = "",
    browserDialerMode: String = "",
    streamSecurity: String = "",
    sni: String = "",
    allowInsecure: Boolean = false,
    fingerPrint: String = "",
    alpn: String = "",
    publicKeyReality: String = "",
    shortId: String = "",
    spiderX: String = "",
    mldsa65Verify: String = "",
    echConfigList: String = "",
    verifyPeerCertByName: String = "",
    pinnedCA256: String = "",
    isFetchingCert: Boolean = false,
    hy2Transport: String = "",
    mimicDomains: String = "",
    ocFlavor: String = "anyconnect",
    ocAuthGroup: String = "",
    fptnToken: String = "",
    awgVersion: String = "3",
    awgJc: String = "",
    awgJmin: String = "",
    awgJmax: String = "",
    awgS1: String = "",
    awgS2: String = "",
    awgS3: String = "",
    awgS4: String = "",
    awgH1: String = "",
    awgH2: String = "",
    awgH3: String = "",
    awgH4: String = "",
    awgI1: String = "",
    awgI2: String = "",
    awgI3: String = "",
    awgI4: String = "",
    awgI5: String = "",
    awgJ1: String = "",
    awgJ2: String = "",
    awgJ3: String = "",
    awgItime: String = "",
    awgHeaderProtectionKey: String = "",
    awgContentPaddingAddition: String = "",
    awgRekeyAfterTime: String = "",
    awgRekeyTimeout: String = "",
    awgRejectAfterTime: String = "",
    awgKeepaliveTimeout: String = "",
    awgMaxHandshakeAttempts: String = "",
    awgRandomTrailers: Boolean = false,
    awgDisableCookies: Boolean = false
) {
    var configType by mutableStateOf(configType)
    var remarks by mutableStateOf(remarks)
    var address by mutableStateOf(address)
    var port by mutableStateOf(port)
    var password by mutableStateOf(password)
    var method by mutableStateOf(method)
    var flow by mutableStateOf(flow)
    var encryption by mutableStateOf(encryption)
    var username by mutableStateOf(username)
    var secretKey by mutableStateOf(secretKey)
    var publicKey by mutableStateOf(publicKey)
    var preSharedKey by mutableStateOf(preSharedKey)
    var reserved by mutableStateOf(reserved)
    var localAddress by mutableStateOf(localAddress)
    var mtu by mutableStateOf(mtu)
    var remoteDNS by mutableStateOf(remoteDNS)
    var obfs by mutableStateOf(obfs)
    var obfsPassword by mutableStateOf(obfsPassword)
    var minPacketSize by mutableStateOf(minPacketSize)
    var maxPacketSize by mutableStateOf(maxPacketSize)
    var portHopping by mutableStateOf(portHopping)
    var portHoppingInterval by mutableStateOf(portHoppingInterval)
    var bandwidthDown by mutableStateOf(bandwidthDown)
    var bandwidthUp by mutableStateOf(bandwidthUp)
    var network by mutableStateOf(network)
    var headerType by mutableStateOf(headerType)
    var mode by mutableStateOf(mode)
    var xhttpMode by mutableStateOf(xhttpMode)
    var serviceName by mutableStateOf(serviceName)
    var authority by mutableStateOf(authority)
    var host by mutableStateOf(host)
    var path by mutableStateOf(path)
    var headers by mutableStateOf(headers)
    var xhttpExtra by mutableStateOf(xhttpExtra)
    var finalMask by mutableStateOf(finalMask)
    var seed by mutableStateOf(seed)
    var kcpMtu by mutableStateOf(kcpMtu)
    var kcpTti by mutableStateOf(kcpTti)
    var browserDialerMode by mutableStateOf(browserDialerMode)
    var streamSecurity by mutableStateOf(streamSecurity)
    var sni by mutableStateOf(sni)
    var allowInsecure by mutableStateOf(allowInsecure)
    var fingerPrint by mutableStateOf(fingerPrint)
    var alpn by mutableStateOf(alpn)
    var publicKeyReality by mutableStateOf(publicKeyReality)
    var shortId by mutableStateOf(shortId)
    var spiderX by mutableStateOf(spiderX)
    var mldsa65Verify by mutableStateOf(mldsa65Verify)
    var echConfigList by mutableStateOf(echConfigList)
    var verifyPeerCertByName by mutableStateOf(verifyPeerCertByName)
    var pinnedCA256 by mutableStateOf(pinnedCA256)
    var isFetchingCert by mutableStateOf(isFetchingCert)
    var hy2Transport by mutableStateOf(hy2Transport)
    var mimicDomains by mutableStateOf(mimicDomains)
    var ocFlavor by mutableStateOf(ocFlavor)
    var ocAuthGroup by mutableStateOf(ocAuthGroup)
    var fptnToken by mutableStateOf(fptnToken)
    var awgVersion by mutableStateOf(awgVersion)
    var awgJc by mutableStateOf(awgJc)
    var awgJmin by mutableStateOf(awgJmin)
    var awgJmax by mutableStateOf(awgJmax)
    var awgS1 by mutableStateOf(awgS1)
    var awgS2 by mutableStateOf(awgS2)
    var awgS3 by mutableStateOf(awgS3)
    var awgS4 by mutableStateOf(awgS4)
    var awgH1 by mutableStateOf(awgH1)
    var awgH2 by mutableStateOf(awgH2)
    var awgH3 by mutableStateOf(awgH3)
    var awgH4 by mutableStateOf(awgH4)
    var awgI1 by mutableStateOf(awgI1)
    var awgI2 by mutableStateOf(awgI2)
    var awgI3 by mutableStateOf(awgI3)
    var awgI4 by mutableStateOf(awgI4)
    var awgI5 by mutableStateOf(awgI5)
    var awgJ1 by mutableStateOf(awgJ1)
    var awgJ2 by mutableStateOf(awgJ2)
    var awgJ3 by mutableStateOf(awgJ3)
    var awgItime by mutableStateOf(awgItime)
    var awgHeaderProtectionKey by mutableStateOf(awgHeaderProtectionKey)
    var awgContentPaddingAddition by mutableStateOf(awgContentPaddingAddition)
    var awgRekeyAfterTime by mutableStateOf(awgRekeyAfterTime)
    var awgRekeyTimeout by mutableStateOf(awgRekeyTimeout)
    var awgRejectAfterTime by mutableStateOf(awgRejectAfterTime)
    var awgKeepaliveTimeout by mutableStateOf(awgKeepaliveTimeout)
    var awgMaxHandshakeAttempts by mutableStateOf(awgMaxHandshakeAttempts)
    var awgRandomTrailers by mutableStateOf(awgRandomTrailers)
    var awgDisableCookies by mutableStateOf(awgDisableCookies)

    var isRemarksError by mutableStateOf(false)
    var isAddressError by mutableStateOf(false)
    var isPortError by mutableStateOf(false)
    var isPasswordError by mutableStateOf(false)

    fun toProfileItem(initialConfig: ProfileItem): ProfileItem {
        val isVmess = configType == EConfigType.VMESS
        val isVless = configType == EConfigType.VLESS
        val isShadowsocks = configType == EConfigType.SHADOWSOCKS
        val isSocksOrHttp = configType == EConfigType.SOCKS || configType == EConfigType.HTTP
        val isWireguard = configType == EConfigType.WIREGUARD
        val isMasque = configType == EConfigType.MASQUE
        val isHysteria2 = configType == EConfigType.HYSTERIA2

        return initialConfig.copy(
            configType = configType,
            remarks = remarks,
            server = address,
            serverPort = port,
            password = password,
            method = when {
                isVmess || isShadowsocks -> method
                isVless -> encryption
                else -> null
            },
            flow = if (isVless) flow else null,
            username = if (isSocksOrHttp) username else null,
            secretKey = if (isWireguard || isMasque) secretKey else null,
            publicKey = when {
                isWireguard || isMasque -> publicKey
                streamSecurity == REALITY -> publicKeyReality
                else -> null
            },
            preSharedKey = if (isWireguard) preSharedKey else null,
            reserved = if (isWireguard) reserved else null,
            localAddress = if (isWireguard || isMasque) localAddress else null,
            mtu = if (isWireguard) mtu.toIntOrNull() else null,
            remoteDNS = if (isWireguard || isMasque) remoteDNS else null,
            obfs = if (isHysteria2) obfs.nullIfBlank() else null,
            obfsPassword = if (isHysteria2) obfsPassword else null,
            minPacketSize = if (isHysteria2) minPacketSize.nullIfBlank() else null,
            maxPacketSize = if (isHysteria2) maxPacketSize.nullIfBlank() else null,
            portHopping = if (isHysteria2) portHopping else null,
            portHoppingInterval = if (isHysteria2) portHoppingInterval else null,
            bandwidthDown = if (isHysteria2) bandwidthDown else null,
            bandwidthUp = if (isHysteria2) bandwidthUp else null,
            network = network,
            headerType = headerType,
            mode = mode.nullIfBlank(),
            xhttpMode = xhttpMode.nullIfBlank(),
            serviceName = serviceName.nullIfBlank(),
            authority = authority.nullIfBlank(),
            host = host,
            path = path,
            headers = if (isMasque) headers.nullIfBlank() else null,
            xhttpExtra = xhttpExtra.nullIfBlank(),
            finalMask = finalMask.nullIfBlank(),
            seed = seed.nullIfBlank(),
            kcpMtu = kcpMtu.toIntOrNull(),
            kcpTti = kcpTti.toIntOrNull(),
            browserDialerMode = if (network in listOf(NetworkType.WS.type, NetworkType.XHTTP.type)) {
                browserDialerMode.nullIfBlank()
            } else {
                null
            },
            security = streamSecurity,
            sni = sni,
            insecure = allowInsecure,
            fingerPrint = fingerPrint,
            alpn = alpn,
            shortId = shortId,
            spiderX = spiderX,
            mldsa65Verify = mldsa65Verify,
            echConfigList = echConfigList,
            verifyPeerCertByName = verifyPeerCertByName,
            pinnedCA256 = pinnedCA256,
            mimicDomains = mimicDomains.nullIfBlank(),
            ocservFlavor = ocFlavor.nullIfBlank(),
            ocservAuthGroup = ocAuthGroup.nullIfBlank(),
            fptnToken = fptnToken.nullIfBlank(),
            amneziaOptions = buildAmneziaOptions().nullIfBlank()
        ).let { profile ->
            // Mimic is a Hysteria2 transport: the editor keeps one form, the
            // stored type follows the chosen transport.
            if (profile.configType == EConfigType.HYSTERIA2 && hy2Transport == "mimic") {
                profile.copy(configType = EConfigType.MIMIC)
            } else if (profile.configType == EConfigType.MIMIC && hy2Transport != "mimic") {
                profile.copy(configType = EConfigType.HYSTERIA2)
            } else {
                profile
            }
        }
    }

    /**
     * Packs the non-blank AmneziaWG fields into the JSON blob the mihomo sidecar
     * consumes, keeping only the parameters valid for the selected version.
     *
     * mihomo runs two incompatible AmneziaWG implementations and rejects a mix:
     * version 3 accepts header-protection-key / content-padding-addition / the
     * five rekey-keepalive timings / random-trailers / disable-cookies and
     * *rejects* j1-j3 and itime, while the legacy v1.x/v2 implementation is the
     * other way round. The editor hides the irrelevant half, but the hidden
     * fields still hold their old values in this state object (for example after
     * importing an awg:// link and then switching the version), so they are
     * filtered here too - otherwise a profile would carry an invalid mix into
     * the generated config and mihomo would refuse to start it.
     *
     * s1-s4, jc/jmin/jmax, h1-h4 and i1-i5 are valid in both implementations.
     */
    private fun buildAmneziaOptions(): String {
        val opts = org.json.JSONObject()
        val version = awgVersion.trim()
        // mihomo: `3` selects the AmneziaWG v3 implementation; ANY other value
        // (including unset) selects the legacy v1.x/v2 implementation. So the
        // test is equality with "3", not inequality with "1".
        val isV3 = version == "3"
        version.toIntOrNull()?.let { opts.put("version", it) }

        // Integer knobs shared by every version. `itime` is v1.5-only, so it is
        // handled with the legacy block below instead.
        mapOf(
            "jc" to awgJc, "jmin" to awgJmin, "jmax" to awgJmax,
            "s1" to awgS1, "s2" to awgS2, "s3" to awgS3, "s4" to awgS4
        ).forEach { (k, v) -> v.toIntOrNull()?.let { opts.put(k, it) } }

        // String knobs shared by every version.
        mapOf(
            "h1" to awgH1, "h2" to awgH2, "h3" to awgH3, "h4" to awgH4,
            "i1" to awgI1, "i2" to awgI2, "i3" to awgI3, "i4" to awgI4, "i5" to awgI5
        ).forEach { (k, v) -> v.takeIf { it.isNotBlank() }?.let { opts.put(k, it) } }

        if (isV3) {
            // AmneziaWG 3.x parameters (3.1 for random-trailers/disable-cookies).
            mapOf(
                "header-protection-key" to awgHeaderProtectionKey,
                "content-padding-addition" to awgContentPaddingAddition,
                "rekey-after-time" to awgRekeyAfterTime,
                "rekey-timeout" to awgRekeyTimeout,
                "reject-after-time" to awgRejectAfterTime,
                "keepalive-timeout" to awgKeepaliveTimeout,
                "max-handshake-attempts" to awgMaxHandshakeAttempts
            ).forEach { (k, v) -> v.takeIf { it.isNotBlank() }?.let { opts.put(k, it) } }
            if (awgRandomTrailers) opts.put("randomTrailers", true)
            if (awgDisableCookies) opts.put("disableCookies", true)
        } else {
            // AmneziaWG 1.5-only junk packets and their cadence.
            mapOf(
                "j1" to awgJ1, "j2" to awgJ2, "j3" to awgJ3
            ).forEach { (k, v) -> v.takeIf { it.isNotBlank() }?.let { opts.put(k, it) } }
            awgItime.toIntOrNull()?.let { opts.put("itime", it) }
        }

        return if (opts.length() == 0) "" else opts.toString()
    }

    companion object {
        fun fromProfileItem(
            initialConfig: ProfileItem
        ): ServerUiState =
            ServerUiState(
                configType = initialConfig.configType,
                remarks = initialConfig.remarks,
                address = initialConfig.server ?: "",
                port = initialConfig.serverPort ?: DEFAULT_PORT.toString(),
                password = initialConfig.password ?: "",
                method = initialConfig.method ?: "",
                flow = initialConfig.flow ?: "",
                encryption = initialConfig.method ?: "",
                username = initialConfig.username ?: "",
                secretKey = initialConfig.secretKey ?: "",
                publicKey = initialConfig.publicKey ?: "",
                preSharedKey = initialConfig.preSharedKey ?: "",
                reserved = initialConfig.reserved ?: "0,0,0",
                localAddress = initialConfig.localAddress ?: "",
                mtu = initialConfig.mtu?.toString() ?: WIREGUARD_LOCAL_MTU,
                remoteDNS = initialConfig.remoteDNS ?: "",
                obfs = initialConfig.obfs ?: "",
                obfsPassword = initialConfig.obfsPassword ?: "",
                minPacketSize = initialConfig.minPacketSize ?: "",
                maxPacketSize = initialConfig.maxPacketSize ?: "",
                portHopping = initialConfig.portHopping ?: "",
                portHoppingInterval = initialConfig.portHoppingInterval ?: "",
                bandwidthDown = initialConfig.bandwidthDown ?: "",
                bandwidthUp = initialConfig.bandwidthUp ?: "",
                network = initialConfig.network ?: NetworkType.TCP.type,
                headerType = initialConfig.headerType ?: "none",
                mode = initialConfig.mode ?: "",
                xhttpMode = initialConfig.xhttpMode ?: "",
                serviceName = initialConfig.serviceName ?: "",
                authority = initialConfig.authority ?: "",
                host = initialConfig.host ?: "",
                path = initialConfig.path ?: "",
                headers = initialConfig.headers ?: "",
                xhttpExtra = initialConfig.xhttpExtra ?: "",
                finalMask = initialConfig.finalMask ?: "",
                seed = initialConfig.seed ?: "",
                kcpMtu = initialConfig.kcpMtu?.toString() ?: "",
                kcpTti = initialConfig.kcpTti?.toString() ?: "",
                browserDialerMode = initialConfig.browserDialerMode ?: "",
                streamSecurity = initialConfig.security ?: "",
                sni = initialConfig.sni ?: "",
                allowInsecure = initialConfig.insecure == true,
                fingerPrint = initialConfig.fingerPrint ?: "",
                alpn = initialConfig.alpn ?: "",
                publicKeyReality = initialConfig.publicKey ?: "",
                shortId = initialConfig.shortId ?: "",
                spiderX = initialConfig.spiderX ?: "",
                mldsa65Verify = initialConfig.mldsa65Verify ?: "",
                echConfigList = initialConfig.echConfigList ?: "",
                verifyPeerCertByName = initialConfig.verifyPeerCertByName ?: "",
                pinnedCA256 = initialConfig.pinnedCA256 ?: "",
                hy2Transport = if (initialConfig.configType == EConfigType.MIMIC) "mimic" else "",
                mimicDomains = initialConfig.mimicDomains ?: "",
                ocFlavor = initialConfig.ocservFlavor ?: "anyconnect",
                ocAuthGroup = initialConfig.ocservAuthGroup ?: "",
                fptnToken = initialConfig.fptnToken ?: ""
            ).apply {
                val opts = runCatching {
                    org.json.JSONObject(initialConfig.amneziaOptions.orEmpty())
                }.getOrNull()
                opts?.let { o ->
                    awgVersion = o.optInt("version", 3).toString()
                    listOf("jc", "jmin", "jmax", "s1", "s2", "s3", "s4", "itime").forEach { k ->
                        if (o.has(k)) {
                            val v = o.opt(k)?.toString().orEmpty()
                            when (k) {
                                "jc" -> awgJc = v; "jmin" -> awgJmin = v; "jmax" -> awgJmax = v
                                "s1" -> awgS1 = v; "s2" -> awgS2 = v; "s3" -> awgS3 = v
                                "s4" -> awgS4 = v; "itime" -> awgItime = v
                            }
                        }
                    }
                    listOf("h1","h2","h3","h4","i1","i2","i3","i4","i5","j1","j2","j3",
                        "header-protection-key","content-padding-addition","rekey-after-time",
                        "rekey-timeout","reject-after-time","keepalive-timeout","max-handshake-attempts"
                    ).forEach { k ->
                        if (o.has(k)) {
                            val v = o.optString(k)
                            when (k) {
                                "h1" -> awgH1 = v; "h2" -> awgH2 = v; "h3" -> awgH3 = v; "h4" -> awgH4 = v
                                "i1" -> awgI1 = v; "i2" -> awgI2 = v; "i3" -> awgI3 = v
                                "i4" -> awgI4 = v; "i5" -> awgI5 = v
                                "j1" -> awgJ1 = v; "j2" -> awgJ2 = v; "j3" -> awgJ3 = v
                                "header-protection-key" -> awgHeaderProtectionKey = v
                                "content-padding-addition" -> awgContentPaddingAddition = v
                                "rekey-after-time" -> awgRekeyAfterTime = v
                                "rekey-timeout" -> awgRekeyTimeout = v
                                "reject-after-time" -> awgRejectAfterTime = v
                                "keepalive-timeout" -> awgKeepaliveTimeout = v
                                "max-handshake-attempts" -> awgMaxHandshakeAttempts = v
                            }
                        }
                    }
                    awgRandomTrailers = o.optBoolean("randomTrailers", false)
                    awgDisableCookies = o.optBoolean("disableCookies", false)
                }
            }

        fun from(
            initialConfig: ProfileItem
        ): ServerUiState = fromProfileItem(initialConfig)

        val Saver: Saver<ServerUiState, String> = Saver(
            save = { JsonUtil.toJson(it.toProfileItem(ProfileItem.create(it.configType))) },
            restore = { saved ->
                JsonUtil.fromJsonSafe(saved, ProfileItem::class.java)?.let {
                    fromProfileItem(it)
                }
            }
        )
    }
}
