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
 * Editor for AmneziaWG profiles (engine: mihomo sidecar).
 *
 * Exposes every obfuscation parameter the mihomo `amnezia-wg-option` block
 * understands: protocol version, jitter/packet-count knobs (jc, jmin, jmax,
 * s1-s4), the v1.5 string knobs (h1-h4, i1-i5, j1-j3, itime) and the v3
 * header-protection/rekey knobs, so a profile can be filled in by hand without
 * a share link.
 */
class ServerAmneziaActivity : BaseServerActivity() {

    override val serverConfigType: EConfigType = EConfigType.AMNEZIAWG

    @Composable
    override fun ScreenContent() {
        val uiState = rememberSaveable(saver = ServerUiState.Saver) {
            ServerUiState.from(initialConfig = initialConfig)
        }.apply { configType = EConfigType.AMNEZIAWG }

        ServerEditorScaffold(
            title = serverConfigType.toString(),
            onSaveClick = { saveServer(uiState) }
        ) {
            CommonBasicFields(uiState)
            AmneziaFields(uiState)
        }
    }

    override fun validateProtocolConfig(config: ProfileItem): Boolean =
        !config.secretKey.isNullOrBlank() && !config.publicKey.isNullOrBlank()

    @Composable
    private fun AmneziaFields(s: ServerUiState) {
        FormTextField(stringResource(R.string.server_lab_secret_key), s.secretKey, { s.secretKey = it })
        FormTextField(stringResource(R.string.server_lab_public_key), s.publicKey, { s.publicKey = it })
        FormTextField(stringResource(R.string.server_lab_preshared_key), s.preSharedKey, { s.preSharedKey = it })
        FormTextField(stringResource(R.string.server_lab_local_address), s.localAddress, { s.localAddress = it })
        FormTextField(stringResource(R.string.server_lab_reserved), s.reserved, { s.reserved = it })
        FormTextField(stringResource(R.string.server_lab_local_mtu), s.mtu, { s.mtu = it }, keyboardType = KeyboardType.Number)
        FormTextField(stringResource(R.string.server_lab_remote_dns), s.remoteDNS, { s.remoteDNS = it })

        FormTextField(stringResource(R.string.awg_lab_version), s.awgVersion, { s.awgVersion = it }, keyboardType = KeyboardType.Number)
        FormTextField(stringResource(R.string.awg_lab_jc), s.awgJc, { s.awgJc = it }, keyboardType = KeyboardType.Number)
        FormTextField(stringResource(R.string.awg_lab_jmin), s.awgJmin, { s.awgJmin = it }, keyboardType = KeyboardType.Number)
        FormTextField(stringResource(R.string.awg_lab_jmax), s.awgJmax, { s.awgJmax = it }, keyboardType = KeyboardType.Number)
        FormTextField(stringResource(R.string.awg_lab_s1), s.awgS1, { s.awgS1 = it }, keyboardType = KeyboardType.Number)
        FormTextField(stringResource(R.string.awg_lab_s2), s.awgS2, { s.awgS2 = it }, keyboardType = KeyboardType.Number)
        FormTextField(stringResource(R.string.awg_lab_s3), s.awgS3, { s.awgS3 = it }, keyboardType = KeyboardType.Number)
        FormTextField(stringResource(R.string.awg_lab_s4), s.awgS4, { s.awgS4 = it }, keyboardType = KeyboardType.Number)
        FormTextField(stringResource(R.string.awg_lab_h1), s.awgH1, { s.awgH1 = it })
        FormTextField(stringResource(R.string.awg_lab_h2), s.awgH2, { s.awgH2 = it })
        FormTextField(stringResource(R.string.awg_lab_h3), s.awgH3, { s.awgH3 = it })
        FormTextField(stringResource(R.string.awg_lab_h4), s.awgH4, { s.awgH4 = it })
        FormTextField(stringResource(R.string.awg_lab_i1), s.awgI1, { s.awgI1 = it })
        FormTextField(stringResource(R.string.awg_lab_i2), s.awgI2, { s.awgI2 = it })
        FormTextField(stringResource(R.string.awg_lab_i3), s.awgI3, { s.awgI3 = it })
        FormTextField(stringResource(R.string.awg_lab_i4), s.awgI4, { s.awgI4 = it })
        FormTextField(stringResource(R.string.awg_lab_i5), s.awgI5, { s.awgI5 = it })
        FormTextField(stringResource(R.string.awg_lab_header_protection_key), s.awgHeaderProtectionKey, { s.awgHeaderProtectionKey = it })
        FormTextField(stringResource(R.string.awg_lab_content_padding), s.awgContentPaddingAddition, { s.awgContentPaddingAddition = it })
        FormTextField(stringResource(R.string.awg_lab_rekey_after_time), s.awgRekeyAfterTime, { s.awgRekeyAfterTime = it })
        FormTextField(stringResource(R.string.awg_lab_rekey_timeout), s.awgRekeyTimeout, { s.awgRekeyTimeout = it })
        FormTextField(stringResource(R.string.awg_lab_reject_after_time), s.awgRejectAfterTime, { s.awgRejectAfterTime = it })
        FormTextField(stringResource(R.string.awg_lab_keepalive_timeout), s.awgKeepaliveTimeout, { s.awgKeepaliveTimeout = it })
        FormTextField(stringResource(R.string.awg_lab_max_handshake_attempts), s.awgMaxHandshakeAttempts, { s.awgMaxHandshakeAttempts = it })
        SettingsSwitchItem(
            title = stringResource(R.string.awg_lab_random_trailers),
            checked = s.awgRandomTrailers,
            onCheckedChange = { s.awgRandomTrailers = it }
        )
        SettingsSwitchItem(
            title = stringResource(R.string.awg_lab_disable_cookies),
            checked = s.awgDisableCookies,
            onCheckedChange = { s.awgDisableCookies = it }
        )
    }
}
