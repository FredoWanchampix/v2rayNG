package com.v2ray.ang.ui.server

import androidx.compose.runtime.Composable
import androidx.compose.runtime.saveable.rememberSaveable
import androidx.compose.ui.res.stringResource
import com.v2ray.ang.R
import com.v2ray.ang.dto.entities.ProfileItem
import com.v2ray.ang.enums.EConfigType
import com.v2ray.ang.ui.compose.FormTextField

/**
 * Editor for NaiveProxy profiles (engine: sing-box sidecar, `naive` outbound).
 *
 * sing-box's naive outbound only accepts `server_name`, `certificate`,
 * `certificate_path` and `ech` in its TLS block - it deliberately has no
 * insecure flag and no ALPN selector, because a self-signed certificate or a
 * non-browser ALPN changes the traffic profile that NaiveProxy exists to
 * imitate. The common stream-security block is therefore not reused here: it
 * would offer allow-insecure, ALPN, uTLS fingerprint, pinned CA and a
 * fetch-pin button that all do nothing for this protocol. Only SNI is exposed.
 */
class ServerNaiveActivity : BaseServerActivity() {

    override val serverConfigType: EConfigType = EConfigType.NAIVE

    @Composable
    override fun ScreenContent() {
        val uiState = rememberSaveable(saver = ServerUiState.Saver) {
            ServerUiState.from(initialConfig = initialConfig)
        }.apply { configType = EConfigType.NAIVE }

        ServerEditorScaffold(
            title = serverConfigType.toString(),
            onSaveClick = { saveServer(uiState) }
        ) {
            CommonBasicFields(uiState)
            NaiveFields(uiState)
        }
    }

    override fun validateProtocolConfig(config: ProfileItem): Boolean =
        !config.username.isNullOrBlank() && !config.password.isNullOrBlank()

    @Composable
    private fun NaiveFields(s: ServerUiState) {
        FormTextField(stringResource(R.string.server_lab_security4), s.username, { s.username = it })
        FormTextField(stringResource(R.string.server_lab_id4), s.password, { s.password = it })
        FormTextField(
            label = stringResource(R.string.server_lab_sni),
            value = s.sni,
            onValueChange = { s.sni = it },
            supportingText = stringResource(R.string.naive_lab_sni_hint)
        )
    }
}
