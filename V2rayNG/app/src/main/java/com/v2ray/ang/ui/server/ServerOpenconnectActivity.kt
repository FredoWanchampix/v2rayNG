package com.v2ray.ang.ui.server

import androidx.compose.runtime.Composable
import androidx.compose.runtime.saveable.rememberSaveable
import androidx.compose.ui.res.stringResource
import com.v2ray.ang.R
import com.v2ray.ang.dto.entities.ProfileItem
import com.v2ray.ang.enums.EConfigType
import com.v2ray.ang.ui.compose.FormDropdownField
import com.v2ray.ang.ui.compose.FormTextField
import com.v2ray.ang.ui.compose.SettingsSwitchItem

/**
 * Editor for OpenConnect / Cisco AnyConnect profiles (engine: sing-box sidecar,
 * `openconnect` endpoint routed for all traffic).
 *
 * The fields map onto the sing-box openconnect endpoint schema: flavor selects
 * the VPN dialect (anyconnect / gp / fortinet / f5 / pulse / nc), auth_group
 * preselects a gateway group, and SNI + allow-insecure go into the endpoint's
 * own `tls` object (tls.server_name / tls.insecure) - sing-box does not accept
 * them as top-level keys, which is why the generic stream-security block is not
 * reused here.
 */
class ServerOpenconnectActivity : BaseServerActivity() {

    override val serverConfigType: EConfigType = EConfigType.OPENCONNECT

    @Composable
    override fun ScreenContent() {
        val uiState = rememberSaveable(saver = ServerUiState.Saver) {
            ServerUiState.from(initialConfig = initialConfig)
        }.apply { configType = EConfigType.OPENCONNECT }

        ServerEditorScaffold(
            title = serverConfigType.toString(),
            onSaveClick = { saveServer(uiState) }
        ) {
            CommonBasicFields(uiState)
            OpenconnectFields(uiState)
        }
    }

    override fun validateProtocolConfig(config: ProfileItem): Boolean =
        !config.server.isNullOrBlank() && !config.username.isNullOrBlank()

    @Composable
    private fun OpenconnectFields(s: ServerUiState) {
        FormTextField(stringResource(R.string.server_lab_security4), s.username, { s.username = it })
        FormTextField(stringResource(R.string.server_lab_id4), s.password, { s.password = it })
        FormDropdownField(
            label = stringResource(R.string.oc_lab_flavor),
            value = s.ocFlavor,
            // sing-box accepts nc (Juniper Network Connect) in addition to the
            // five dialects that were listed before.
            options = listOf("anyconnect", "gp", "fortinet", "f5", "pulse", "nc"),
            onValueChange = { s.ocFlavor = it }
        )
        FormTextField(stringResource(R.string.oc_lab_auth_group), s.ocAuthGroup, { s.ocAuthGroup = it })
        FormTextField(
            label = stringResource(R.string.server_lab_sni),
            value = s.sni,
            onValueChange = { s.sni = it },
            supportingText = stringResource(R.string.oc_lab_sni_hint)
        )
        SettingsSwitchItem(
            title = stringResource(R.string.server_lab_allow_insecure),
            checked = s.allowInsecure,
            onCheckedChange = { s.allowInsecure = it }
        )
    }
}
