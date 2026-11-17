package com.v2ray.ang.ui.server

import androidx.compose.runtime.Composable
import androidx.compose.ui.res.stringResource
import androidx.compose.ui.text.input.KeyboardType
import com.v2ray.ang.R
import com.v2ray.ang.enums.EConfigType
import com.v2ray.ang.extension.toast
import com.v2ray.ang.ui.compose.FormDropdownField
import com.v2ray.ang.ui.compose.FormTextField
import com.v2ray.ang.ui.compose.SettingsSwitchItem

/**
 * Редактор Hysteria v1. Поля протокола v1 (схема ссылки hysteria://):
 * auth (строка), protocol (udp/wechat-video/faketcp), up/down mbps,
 * peer (SNI), insecure, alpn, obfs (строка обфускации), mport (port hopping).
 * Профиль обслуживается сайдкар-движком mihomo (Xray форка не имеет
 * hysteria v1, sing-box собран без QUIC — см. SidecarConfigBuilder.mihomoHysteria).
 */
class ServerHysteriaActivity : BaseServerActivity() {

    override val serverConfigType: EConfigType = EConfigType.HYSTERIA

    @Composable
    override fun ScreenContent() {
        val uiState = rememberServerUiState()

        ServerEditorScaffold(
            title = serverConfigType.toString(),
            onSaveClick = { saveServer(uiState) }
        ) {
            CommonBasicFields(uiState)
            HysteriaProtocolFields(uiState)
        }
    }

    @Composable
    private fun rememberServerUiState(): ServerUiState =
        androidx.compose.runtime.saveable.rememberSaveable(saver = ServerUiState.Saver) {
            ServerUiState.from(initialConfig = initialConfig)
        }.apply {
            configType = EConfigType.HYSTERIA
        }

    @Composable
    private fun HysteriaProtocolFields(state: ServerUiState) {
        FormTextField(
            stringResource(R.string.server_lab_hy1_auth),
            state.password,
            { state.password = it },
            supportingText = stringResource(R.string.server_lab_hy1_auth_hint)
        )
        FormDropdownField(
            stringResource(R.string.server_lab_hy1_protocol),
            state.method,
            listOf("udp", "wechat-video", "faketcp"),
            { state.method = it }
        )
        FormTextField(
            stringResource(R.string.server_lab_bandwidth_up),
            state.bandwidthUp,
            { state.bandwidthUp = it }
        )
        FormTextField(
            stringResource(R.string.server_lab_bandwidth_down),
            state.bandwidthDown,
            { state.bandwidthDown = it }
        )
        FormTextField(
            stringResource(R.string.server_lab_hy1_obfs),
            state.obfsPassword,
            { state.obfsPassword = it }
        )
        FormTextField(
            stringResource(R.string.server_lab_port_hop),
            state.portHopping,
            { state.portHopping = it }
        )
        FormTextField(
            stringResource(R.string.server_lab_sni),
            state.sni,
            { state.sni = it },
            supportingText = stringResource(R.string.server_lab_hy1_peer_hint)
        )
        FormTextField(
            stringResource(R.string.server_lab_stream_alpn),
            state.alpn,
            { state.alpn = it }
        )
        SettingsSwitchItem(
            title = stringResource(R.string.server_lab_allow_insecure),
            checked = state.allowInsecure,
            onCheckedChange = { state.allowInsecure = it }
        )
        FormTextField(
            stringResource(R.string.server_lab_hy1_recv_window_conn),
            state.hy1RecvWindowConn,
            { state.hy1RecvWindowConn = it },
            keyboardType = KeyboardType.Number
        )
        FormTextField(
            stringResource(R.string.server_lab_hy1_recv_window),
            state.hy1RecvWindow,
            { state.hy1RecvWindow = it },
            keyboardType = KeyboardType.Number
        )
        SettingsSwitchItem(
            title = stringResource(R.string.server_lab_hy1_disable_mtu),
            checked = state.hy1DisableMtuDiscovery,
            onCheckedChange = { state.hy1DisableMtuDiscovery = it }
        )
    }

    /**
     * mihomo ОТКАЗЫВАЕТ hysteria-outbound без up/down (эксперимент на
     * устройстве: "unset fields: down, up"), поэтому bandwidth обязателен
     * в редакторе: пустое поле = мёртвый профиль, сохраняем только валидное.
     */
    override fun validateProtocolConfig(config: com.v2ray.ang.dto.entities.ProfileItem): Boolean {
        if (config.bandwidthUp.isNullOrBlank() || config.bandwidthDown.isNullOrBlank()) {
            toast(R.string.server_lab_hy1_bandwidth_required)
            return false
        }
        return true
    }
}