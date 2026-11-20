package com.v2ray.ang.ui.server

import androidx.compose.foundation.layout.padding
import androidx.compose.material3.Button
import androidx.compose.material3.Text
import androidx.compose.runtime.Composable
import androidx.compose.runtime.rememberCoroutineScope
import androidx.compose.runtime.saveable.rememberSaveable
import androidx.compose.ui.Modifier
import androidx.compose.ui.platform.LocalContext
import androidx.compose.ui.res.stringResource
import androidx.compose.ui.text.input.KeyboardType
import androidx.compose.ui.unit.dp
import com.v2ray.ang.AppConfig
import com.v2ray.ang.R
import com.v2ray.ang.dto.entities.ProfileItem
import com.v2ray.ang.enums.EConfigType
import com.v2ray.ang.extension.toast
import com.v2ray.ang.extension.toastSuccess
import com.v2ray.ang.handler.CertificateFingerprintManager
import com.v2ray.ang.ui.compose.FormDropdownField
import com.v2ray.ang.ui.compose.FormTextField
import com.v2ray.ang.ui.compose.SettingsSwitchItem
import kotlinx.coroutines.Dispatchers
import kotlinx.coroutines.launch
import kotlinx.coroutines.withContext

/**
 * Editor for Hysteria2 profiles, which also covers the Mimic transport.
 *
 * Hysteria2 and Mimic are two transports of the same protocol family, but they
 * are served by different cores and therefore consume a different set of
 * fields:
 *
 *  - transport "default" runs on the Xray core (native Hysteria2): obfs
 *    (none/salamander/gecko), obfs password, gecko packet sizes, port hopping,
 *    bandwidth hints, TLS (sni / allow-insecure / ech / pin / fetch-pin button)
 *    all take effect.
 *  - transport "mimic" runs on the standalone `mimic-client` sidecar. That
 *    engine only reads server:port, the password (used as the Mimic uuid) and
 *    the list of masking domains; every Hysteria2/TLS knob above is ignored by
 *    it, so the form hides them and shows the Mimic fields instead.
 *
 * The stored profile type follows the transport: HYSTERIA2 for "default",
 * MIMIC for "mimic" (see ServerUiState.toProfileItem / .from).
 */
class ServerHysteria2Activity : BaseServerActivity() {

    override val serverConfigType: EConfigType = EConfigType.HYSTERIA2

    @Composable
    override fun ScreenContent() {
        val uiState = rememberSaveable(saver = ServerUiState.Saver) {
            ServerUiState.from(
                initialConfig = initialConfig
            )
        }.apply {
            // The form is shared by HYSTERIA2 and MIMIC; the real type is
            // derived from hy2Transport when saving.
            configType = EConfigType.HYSTERIA2
        }

        val transportDefault = stringResource(R.string.server_hy2_transport_default)
        val transportMimic = stringResource(R.string.server_hy2_transport_mimic)
        val isMimic = uiState.hy2Transport == "mimic"

        ServerEditorScaffold(
            title = serverConfigType.toString(),
            onSaveClick = { saveServer(uiState) }
        ) {
            CommonBasicFields(uiState)

            // Transport selector. Everything below branches on it so the user
            // only ever sees fields the chosen engine actually consumes.
            FormDropdownField(
                label = stringResource(R.string.server_lab_hy2_transport),
                value = if (isMimic) transportMimic else transportDefault,
                options = listOf(transportDefault, transportMimic),
                supportingText = stringResource(R.string.server_lab_hy2_transport_hint),
                onValueChange = { picked ->
                    uiState.hy2Transport = if (picked == transportMimic) "mimic" else ""
                }
            )

            // Both transports authenticate with a secret: Hysteria2 calls it a
            // password, Mimic reuses it as the uuid. Show it once, always.
            FormTextField(
                label = stringResource(if (isMimic) R.string.mimic_lab_uuid else R.string.server_lab_id3),
                value = uiState.password,
                onValueChange = { uiState.password = it },
                isError = uiState.isPasswordError
            )

            if (isMimic) {
                MimicTransportFields(uiState)
            } else {
                Hysteria2ProtocolFields(uiState)
            }
        }
    }

    override fun validateProtocolConfig(config: ProfileItem): Boolean {
        if (config.password.isNullOrBlank()) {
            return false
        }
        // Mimic profiles have no Xray TLS layer; keep the default only for the
        // native Hysteria2 transport.
        if (config.configType == EConfigType.HYSTERIA2 && config.security.isNullOrBlank()) {
            config.security = AppConfig.TLS
        }
        return true
    }

    @Composable
    private fun MimicTransportFields(state: ServerUiState) {
        // Mimic masks traffic as one of the domains below; the rest of the
        // Hysteria2/TLS knobs are not read by the mimic-client sidecar, so they
        // are intentionally not shown here.
        FormTextField(
            label = stringResource(R.string.server_lab_mimic_domains),
            value = state.mimicDomains,
            onValueChange = { state.mimicDomains = it },
            supportingText = stringResource(R.string.server_lab_mimic_domains_hint)
        )
    }

    @Composable
    private fun Hysteria2ProtocolFields(state: ServerUiState) {
        val context = LocalContext.current
        val scope = rememberCoroutineScope()
        // Один вызов rememberFieldOptions на композицию: список значений uTLS
        // читается из ресурсов, повторный вызов на каждую рекомпозицию не нужен.
        val fieldOptions = rememberFieldOptions()
        val uTlsOptions = fieldOptions.uTlsOptions
        val alpnOptions = fieldOptions.alpnOptions

        val obfsOptions = listOf("none", "salamander", "gecko")
        val selectedObfs = when {
            state.obfs.equals("gecko", ignoreCase = true) -> "gecko"
            state.obfs.equals("salamander", ignoreCase = true) -> "salamander"
            state.obfsPassword.isNotBlank() && !state.obfs.equals("none", ignoreCase = true) -> "salamander"
            else -> "none"
        }
        FormDropdownField(
            label = stringResource(R.string.server_obfs_type),
            value = selectedObfs,
            options = obfsOptions,
            onValueChange = {
                state.obfs = if (it == "none") "" else it
                if (it == "none") {
                    state.obfsPassword = ""
                    state.minPacketSize = ""
                    state.maxPacketSize = ""
                }
            }
        )
        if (selectedObfs != "none") {
            FormTextField(
                stringResource(R.string.server_obfs_password),
                state.obfsPassword,
                { state.obfsPassword = it }
            )
            if (selectedObfs == "gecko") {
                FormTextField(
                    stringResource(R.string.server_lab_min_packet_size),
                    state.minPacketSize,
                    { state.minPacketSize = it },
                    keyboardType = KeyboardType.Number
                )
                FormTextField(
                    stringResource(R.string.server_lab_max_packet_size),
                    state.maxPacketSize,
                    { state.maxPacketSize = it },
                    keyboardType = KeyboardType.Number
                )
            }
        }
        FormTextField(
            stringResource(R.string.server_lab_port_hop),
            state.portHopping,
            { state.portHopping = it }
        )
        FormTextField(
            stringResource(R.string.server_lab_port_hop_interval),
            state.portHoppingInterval,
            { state.portHoppingInterval = it }
        )
        FormTextField(
            stringResource(R.string.server_lab_bandwidth_down),
            state.bandwidthDown,
            { state.bandwidthDown = it }
        )
        FormTextField(
            stringResource(R.string.server_lab_bandwidth_up),
            state.bandwidthUp,
            { state.bandwidthUp = it }
        )

        SettingsSwitchItem(
            title = stringResource(R.string.server_lab_allow_insecure),
            checked = state.allowInsecure,
            onCheckedChange = { state.allowInsecure = it }
        )
        FormTextField(
            stringResource(R.string.server_lab_sni),
            state.sni,
            { state.sni = it }
        )
        // ALPN — ТОЛЬКО ДЛЯ ЧТЕНИЯ, значение = "h3". Вещдок:
        // CoreOutboundBuilder.toOutboundHysteria2 БЕЗУСЛОВНО ставит
        // profileItem.alpn = "h3" при каждой сборке конфига (Hysteria2 = QUIC,
        // ALPN h3 обязателен), поэтому любое значение из профиля игнорируется.
        // Показывать state.alpn было бы «ложью UI»: поле могло бы содержать
        // не то, что реально уходит в ядро. Показываем фактическое h3 без
        // возможности правки. Если форсинг в ядре когда-нибудь снимут — это
        // поле и supportingText обновляются вместе с ним.
        FormDropdownField(
            label = stringResource(R.string.server_lab_stream_alpn),
            value = "h3",
            options = alpnOptions,
            onValueChange = { },
            enabled = false,
            supportingText = stringResource(R.string.server_lab_alpn_hy2_fixed),
        )
        // uTLS-отпечаток. Ядро получает его из ProfileItem.fingerPrint
        // (CoreOutboundBuilder.populateTlsSettings), а провайдеры задают его в
        // tlsSettings.fingerprint — раньше конвертер его не читал, а редактор
        // hy2 не показывал, поэтому настройка была невидима.
        FormDropdownField(
            label = stringResource(R.string.server_lab_stream_fingerprint),
            value = state.fingerPrint,
            options = uTlsOptions,
            onValueChange = { state.fingerPrint = it }
        )
        // TLS session resumption: ядро поддерживает enableSessionResumption
        // (вещдок: json-тег в TlsSettingsBean libgojni.so). Три состояния:
        // «не задано» (null — ядро решает само), включить, выключить.
        // Показываем всегда, чтобы настройка провайдера была видна и правима.
        val esrOptions = listOf(
            stringResource(R.string.server_lab_session_resumption_default),
            stringResource(R.string.server_lab_session_resumption_on),
            stringResource(R.string.server_lab_session_resumption_off),
        )
        val esrIndex = when (state.enableSessionResumption) {
            null -> 0
            true -> 1
            false -> 2
        }
        FormDropdownField(
            label = stringResource(R.string.server_lab_session_resumption),
            value = esrOptions[esrIndex],
            options = esrOptions,
            supportingText = stringResource(R.string.server_lab_session_resumption_hint),
            onValueChange = { picked ->
                // Сопоставление по ИНДЕКСУ, а не по тексту: локализации могут
                // совпадать (например, vi/zh дают одинаковые короткие слова),
                // и сравнение строк выбрало бы неверное значение.
                state.enableSessionResumption = when (esrOptions.indexOf(picked)) {
                    1 -> true
                    2 -> false
                    else -> null
                }
            }
        )
        FormTextField(
            stringResource(R.string.server_lab_ech_config_list),
            state.echConfigList,
            { state.echConfigList = it }
        )
        FormTextField(
            stringResource(R.string.server_lab_pinned_ca256),
            state.pinnedCA256,
            { state.pinnedCA256 = it }
        )

        FormTextField(
            stringResource(R.string.server_lab_final_mask),
            state.finalMask,
            { state.finalMask = it }
        )

        Button(
            onClick = {
                if (state.address.isBlank()) {
                    context.toast(R.string.server_lab_address)
                    return@Button
                }
                val temp = state.toProfileItem(initialConfig)
                scope.launch {
                    state.isFetchingCert = true
                    try {
                        val sha256 = withContext(Dispatchers.IO) {
                            CertificateFingerprintManager.fetchForManualFill(temp)
                        }
                        if (sha256.isNullOrBlank()) {
                            context.toast(R.string.toast_fetch_cert_sha256_failed)
                        } else {
                            state.pinnedCA256 = sha256
                            context.toastSuccess(R.string.toast_fetch_cert_sha256_success)
                        }
                    } finally {
                        state.isFetchingCert = false
                    }
                }
            },
            enabled = !state.isFetchingCert,
            modifier = Modifier.padding(start = 16.dp)
        ) {
            Text(stringResource(R.string.pinned_ca256_action_fetch))
        }
    }
}
