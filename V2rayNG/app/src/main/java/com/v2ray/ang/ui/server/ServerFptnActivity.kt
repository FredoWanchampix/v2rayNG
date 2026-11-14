package com.v2ray.ang.ui.server

import androidx.compose.runtime.Composable
import androidx.compose.runtime.saveable.rememberSaveable
import androidx.compose.ui.res.stringResource
import com.v2ray.ang.R
import com.v2ray.ang.dto.entities.ProfileItem
import com.v2ray.ang.enums.EConfigType
import com.v2ray.ang.ui.compose.FormTextField

/**
 * Editor for FPTN profiles (engine: fptn-client sidecar, root mode only).
 *
 * Only fields the real client consumes are offered. fptn-client-cli takes
 * `--access-token`, `--preferred-server` and `--sni`; it has NO username or
 * password flags - the JWT in the access token already carries the server list
 * and the credentials. The old editor exposed username/password fields that
 * ServerUiState.toProfileItem drops for every type except SOCKS/HTTP, so they
 * could not even be saved. They are gone.
 *
 * Mapping:
 *  - address (common field) -> `--preferred-server`, a server name from the
 *    token to connect to first (empty means any server);
 *  - sni -> `--sni`, the domain used to disguise the TLS handshake;
 *  - access token -> `--access-token`, the only required credential.
 *
 * The common block keeps remarks/address/port: address feeds --preferred-server,
 * and host:port round-trips through the fptn:// share-link format.
 *
 * FPTN owns its own TUN interface, so it requires root mode; CoreServiceManager
 * reports that explicitly when the profile is started.
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
        FormTextField(
            label = stringResource(R.string.fptn_lab_token),
            value = s.fptnToken,
            onValueChange = { s.fptnToken = it },
            supportingText = stringResource(R.string.fptn_lab_token_hint),
            isError = s.fptnToken.isBlank()
        )
        FormTextField(
            label = stringResource(R.string.server_lab_sni),
            value = s.sni,
            onValueChange = { s.sni = it },
            supportingText = stringResource(R.string.fptn_lab_sni_hint)
        )
    }
}
