package com.v2ray.ang.ui.server

import androidx.compose.runtime.Composable
import androidx.compose.runtime.saveable.rememberSaveable
import androidx.compose.ui.res.stringResource
import androidx.compose.ui.text.input.KeyboardType
import com.v2ray.ang.R
import com.v2ray.ang.dto.entities.ProfileItem
import com.v2ray.ang.enums.EConfigType
import com.v2ray.ang.ui.compose.FormTextField
import com.v2ray.ang.ui.compose.SettingsSwitchItem

import com.v2ray.ang.ui.compose.FormDropdownField

/**
 * Editor for OpenConnect / Cisco AnyConnect profiles (engine: sing-box
 * sidecar, openconnect endpoint routed for all traffic).
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
            options = listOf("anyconnect", "gp", "fortinet", "f5", "pulse"),
            onValueChange = { s.ocFlavor = it }
        )
        FormTextField(stringResource(R.string.oc_lab_auth_group), s.ocAuthGroup, { s.ocAuthGroup = it })
    }
}
