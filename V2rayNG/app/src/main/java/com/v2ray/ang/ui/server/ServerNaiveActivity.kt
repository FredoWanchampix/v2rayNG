package com.v2ray.ang.ui.server

import androidx.compose.runtime.Composable
import androidx.compose.runtime.rememberCoroutineScope
import androidx.compose.runtime.saveable.rememberSaveable
import androidx.compose.ui.res.stringResource
import androidx.compose.ui.text.input.KeyboardType
import com.v2ray.ang.R
import com.v2ray.ang.dto.entities.ProfileItem
import com.v2ray.ang.enums.EConfigType
import com.v2ray.ang.ui.compose.FormTextField
import kotlinx.coroutines.CoroutineScope
import com.v2ray.ang.ui.compose.SettingsSwitchItem

/**
 * Editor for NaiveProxy profiles (engine: sing-box sidecar, naive outbound).
 */
class ServerNaiveActivity : BaseServerActivity() {

    override val serverConfigType: EConfigType = EConfigType.NAIVE

    @Composable
    override fun ScreenContent() {
        val options = rememberFieldOptions()
        val scope = rememberCoroutineScope()
        val uiState = rememberSaveable(saver = ServerUiState.Saver) {
            ServerUiState.from(initialConfig = initialConfig)
        }.apply { configType = EConfigType.NAIVE }

        ServerEditorScaffold(
            title = serverConfigType.toString(),
            onSaveClick = { saveServer(uiState) }
        ) {
            CommonBasicFields(uiState)
            NaiveFields(uiState, options, scope)
        }
    }

    override fun validateProtocolConfig(config: ProfileItem): Boolean =
        !config.username.isNullOrBlank() && !config.password.isNullOrBlank()

    @Composable
    private fun NaiveFields(s: ServerUiState, options: FieldOptions, scope: CoroutineScope) {
        FormTextField(stringResource(R.string.server_lab_security4), s.username, { s.username = it })
        FormTextField(stringResource(R.string.server_lab_id4), s.password, { s.password = it })
        CommonStreamSecurityFields(
            state = s,
            options = options,
            scope = scope,
            buildProfileItem = { s.toProfileItem(initialConfig) }
        )
    }
}
