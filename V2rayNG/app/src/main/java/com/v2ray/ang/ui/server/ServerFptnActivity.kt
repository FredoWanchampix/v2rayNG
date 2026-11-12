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

/**
 * Editor for FPTN profiles (engine: fptn-client sidecar, root mode only).
 */
class ServerFptnActivity : BaseServerActivity() {

    override val serverConfigType: EConfigType = EConfigType.FPTN

    @Composable
    override fun ScreenContent() {
        val uiState = rememberSaveable(saver = ServerUiState.Saver) {
            ServerUiState.from(initialConfig = initialConfig)
        }.apply { configType = EConfigType.FPTN }

        ServerEditorScaffold(
            title = serverConfigType.toString(),
            onSaveClick = { saveServer(uiState) }
        ) {
            CommonBasicFields(uiState)
            FptnFields(uiState)
        }
    }

    override fun validateProtocolConfig(config: ProfileItem): Boolean =
        !config.fptnToken.isNullOrBlank()

    @Composable
    private fun FptnFields(s: ServerUiState) {
        FormTextField(stringResource(R.string.server_lab_security4), s.username, { s.username = it })
        FormTextField(stringResource(R.string.server_lab_id4), s.password, { s.password = it })
        FormTextField(
            label = stringResource(R.string.fptn_lab_token),
            value = s.fptnToken,
            onValueChange = { s.fptnToken = it },
            supportingText = stringResource(R.string.fptn_lab_token_hint)
        )
        FormTextField(stringResource(R.string.server_lab_sni), s.sni, { s.sni = it })
    }
}
