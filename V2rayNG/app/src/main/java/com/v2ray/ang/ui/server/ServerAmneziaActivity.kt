package com.v2ray.ang.ui.server

import androidx.compose.runtime.Composable
import androidx.compose.runtime.saveable.rememberSaveable
import androidx.compose.ui.res.stringResource
import androidx.compose.ui.text.input.KeyboardType
import com.v2ray.ang.R
import com.v2ray.ang.dto.entities.ProfileItem
import com.v2ray.ang.enums.EConfigType
import com.v2ray.ang.ui.compose.FormDropdownField
import com.v2ray.ang.ui.compose.FormTextField
import com.v2ray.ang.ui.compose.SettingsSwitchItem

/**
 * Editor for AmneziaWG profiles (engine: mihomo sidecar, `amnezia-wg-option`).
 *
 * The fields shown depend on the protocol version, because mihomo uses two
 * incompatible implementations and refuses to mix their parameters:
 *
 *  - version 3 (AmneziaWG 3.x): header-protection-key, content-padding-addition
 *    and the five rekey/keepalive timing fields; j1-j3 and itime are rejected.
 *  - version 1/2 (legacy): i1-i5, j1-j3 and itime; the v3 fields are rejected.
 *
 * h1-h4 exist in both, but v1.x only accepts a single decimal value while v2+
 * also accepts a `min-max` range. jc/jmin/jmax/s1-s4 apply to every version,
 * except s3/s4 which are v1.5+.
 *
 * Every parameter of the mihomo schema is reachable from this form, so a
 * profile can be filled in by hand without importing an `awg://` share link.
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
        // ---- WireGuard core parameters, identical for every version ----
        FormTextField(stringResource(R.string.server_lab_secret_key), s.secretKey, { s.secretKey = it })
        FormTextField(stringResource(R.string.server_lab_public_key), s.publicKey, { s.publicKey = it })
        FormTextField(stringResource(R.string.server_lab_preshared_key), s.preSharedKey, { s.preSharedKey = it })
        FormTextField(stringResource(R.string.server_lab_local_address), s.localAddress, { s.localAddress = it })
        FormTextField(stringResource(R.string.server_lab_reserved), s.reserved, { s.reserved = it })
        FormTextField(stringResource(R.string.server_lab_local_mtu), s.mtu, { s.mtu = it }, keyboardType = KeyboardType.Number)
        FormTextField(stringResource(R.string.server_lab_remote_dns), s.remoteDNS, { s.remoteDNS = it })

        // ---- Version selector: drives which obfuscation fields are shown ----
        // "3" is the default because AmneziaWG 3.x is what current panels hand
        // out; picking "1" switches the form to the legacy v1.x/v2 parameter set.
        val versionOptions = listOf("3", "2", "1")
        // mihomo selects the v3 implementation only for `version: 3`; any other
        // value (1, 2, unset) means the legacy implementation.
        val isV3 = s.awgVersion.trim() == "3"
        FormDropdownField(
            label = stringResource(R.string.awg_lab_version),
            value = s.awgVersion.ifBlank { "3" },
            options = versionOptions,
            supportingText = stringResource(R.string.awg_lab_version_hint),
            onValueChange = { s.awgVersion = it }
        )

        // ---- Shared obfuscation knobs (all versions) ----
        FormTextField(stringResource(R.string.awg_lab_jc), s.awgJc, { s.awgJc = it }, keyboardType = KeyboardType.Number)
        FormTextField(stringResource(R.string.awg_lab_jmin), s.awgJmin, { s.awgJmin = it }, keyboardType = KeyboardType.Number)
        FormTextField(stringResource(R.string.awg_lab_jmax), s.awgJmax, { s.awgJmax = it }, keyboardType = KeyboardType.Number)
        FormTextField(stringResource(R.string.awg_lab_s1), s.awgS1, { s.awgS1 = it }, keyboardType = KeyboardType.Number)
        FormTextField(stringResource(R.string.awg_lab_s2), s.awgS2, { s.awgS2 = it }, keyboardType = KeyboardType.Number)
        // s3/s4 are v1.5+ as well, so both versions accept them.
        FormTextField(stringResource(R.string.awg_lab_s3), s.awgS3, { s.awgS3 = it }, keyboardType = KeyboardType.Number)
        FormTextField(stringResource(R.string.awg_lab_s4), s.awgS4, { s.awgS4 = it }, keyboardType = KeyboardType.Number)
        // h1-h4 exist in both implementations (single value on v1.x, min-max on v2+).
        FormTextField(stringResource(R.string.awg_lab_h1), s.awgH1, { s.awgH1 = it }, keyboardType = KeyboardType.Number)
        FormTextField(stringResource(R.string.awg_lab_h2), s.awgH2, { s.awgH2 = it }, keyboardType = KeyboardType.Number)
        FormTextField(stringResource(R.string.awg_lab_h3), s.awgH3, { s.awgH3 = it }, keyboardType = KeyboardType.Number)
        FormTextField(stringResource(R.string.awg_lab_h4), s.awgH4, { s.awgH4 = it }, keyboardType = KeyboardType.Number)
        // i1-i5 are "special packets", introduced in v1.5 and still used by v3,
        // so they are available for both versions. Only j1-j3/itime are
        // v1.5-only and are hidden for version 3.
        FormTextField(stringResource(R.string.awg_lab_i1), s.awgI1, { s.awgI1 = it })
        FormTextField(stringResource(R.string.awg_lab_i2), s.awgI2, { s.awgI2 = it })
        FormTextField(stringResource(R.string.awg_lab_i3), s.awgI3, { s.awgI3 = it })
        FormTextField(stringResource(R.string.awg_lab_i4), s.awgI4, { s.awgI4 = it })
        FormTextField(stringResource(R.string.awg_lab_i5), s.awgI5, { s.awgI5 = it })

        if (isV3) {
            // ---- AmneziaWG 3.x only ----
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
        } else {
            // ---- AmneziaWG 1.5 only: junk packets and their cadence ----
            // j1-j3 are tag chains such as `<b 0xffffffff><c><b 0xf6ab><t><r 10>`
            // and were removed in v2, which is why the version selector hides
            // them (and itime) for version 3.
            FormTextField(stringResource(R.string.awg_lab_j1), s.awgJ1, { s.awgJ1 = it })
            FormTextField(stringResource(R.string.awg_lab_j2), s.awgJ2, { s.awgJ2 = it })
            FormTextField(stringResource(R.string.awg_lab_j3), s.awgJ3, { s.awgJ3 = it })
            FormTextField(stringResource(R.string.awg_lab_itime), s.awgItime, { s.awgItime = it }, keyboardType = KeyboardType.Number)
        }
    }
}
