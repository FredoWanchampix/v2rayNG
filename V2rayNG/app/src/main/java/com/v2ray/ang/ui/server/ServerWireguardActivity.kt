package com.v2ray.ang.ui.server

import androidx.compose.runtime.Composable
import androidx.compose.runtime.getValue
import androidx.compose.runtime.mutableStateOf
import androidx.compose.runtime.rememberCoroutineScope
import androidx.compose.runtime.saveable.rememberSaveable
import androidx.compose.runtime.setValue
import androidx.compose.ui.res.stringResource
import androidx.compose.ui.text.input.KeyboardType
import com.v2ray.ang.AppConfig
import com.v2ray.ang.R
import com.v2ray.ang.enums.EConfigType
import com.v2ray.ang.ui.compose.FormDropdownField
import com.v2ray.ang.ui.compose.FormTextField
import com.v2ray.ang.util.NoiseProfileUtil

class ServerWireguardActivity : BaseServerActivity() {

    override val serverConfigType: EConfigType = EConfigType.WIREGUARD

    @Composable
    override fun ScreenContent() {
        val scope = rememberCoroutineScope()
        val uiState = rememberSaveable(saver = ServerUiState.Saver) {
            ServerUiState.from(
                initialConfig = initialConfig
            )
        }.apply {
            configType = EConfigType.WIREGUARD
        }

        ServerEditorScaffold(
            title = serverConfigType.toString(),
            onSaveClick = { saveServer(uiState) }
        ) {
            CommonBasicFields(uiState)
            WireguardProtocolFields(uiState)

        }
    }

    @Composable
    private fun WireguardProtocolFields(state: ServerUiState) {
        FormTextField(
            stringResource(R.string.server_lab_secret_key),
            state.secretKey,
            { state.secretKey = it }
        )
        FormTextField(
            stringResource(R.string.server_lab_public_key),
            state.publicKey,
            { state.publicKey = it }
        )
        FormTextField(
            stringResource(R.string.server_lab_preshared_key),
            state.preSharedKey,
            { state.preSharedKey = it }
        )
        FormTextField(
            stringResource(R.string.server_lab_reserved),
            state.reserved,
            { state.reserved = it }
        )
        FormTextField(
            stringResource(R.string.server_lab_local_address),
            state.localAddress,
            { state.localAddress = it },
            supportingText = stringResource(
                R.string.server_lab_local_address_hint,
                "${AppConfig.WIREGUARD_LOCAL_ADDRESS_V4},${AppConfig.WIREGUARD_LOCAL_ADDRESS_V6}"
            )
        )
        FormTextField(
            stringResource(R.string.server_lab_local_mtu),
            state.mtu,
            { state.mtu = it },
            keyboardType = KeyboardType.Number
        )

        WireguardNoiseFields(state)

        FormTextField(
            stringResource(R.string.server_lab_final_mask),
            state.finalMask,
            {
                state.finalMask = it
                // Ручная правка сырого fm первична: поле шума отражает его
                // noise-часть, чтобы сохранение не затёрло правку старым
                // списком. Битый JSON поле не трогает — сохранение всё равно
                // отклонит validateCommonConfig по невалидному finalMask.
                val extracted = NoiseProfileUtil.extractNoises(it)
                when {
                    extracted != null -> state.noisesJson = extracted
                    it.isBlank() -> state.noisesJson = ""
                    runCatching { org.json.JSONObject(it) }.isSuccess -> state.noisesJson = ""
                }
            }
        )

        FormTextField(
            stringResource(R.string.server_lab_remote_dns),
            state.remoteDNS,
            { state.remoteDNS = it },
            supportingText = stringResource(
                R.string.server_lab_remote_dns_hint,
                AppConfig.WIREGUARD_LOCAL_REMOTE_DNS
            )
        )
    }

    /**
     * Шум (DPI-защита) — опциональное поле wireguard-профиля, доступное сразу
     * при создании профиля и заполняемое автоматически при импорте ссылки с
     * fm/noises. Список хранится в ProfileItem.noisesJson и при сохранении
     * вливается в noise-часть finalMask (остальные маски не трогаются).
     * Пресеты — готовые наборы по образцу AmneziaWG/QUIC/WARP.
     */
    @Composable
    private fun WireguardNoiseFields(state: ServerUiState) {
        val presetLabels = listOf(
            stringResource(R.string.noise_preset_none),
            stringResource(R.string.noise_preset_amnezia),
            stringResource(R.string.noise_preset_quic),
            stringResource(R.string.noise_preset_warp),
        )
        val presetKeys = listOf("", NoiseProfileUtil.PRESET_AMNEZIA, NoiseProfileUtil.PRESET_QUIC, NoiseProfileUtil.PRESET_WARP)
        var selectedPreset by rememberSaveable { mutableStateOf("") }
        FormDropdownField(
            label = stringResource(R.string.server_lab_noise_preset),
            value = presetLabels.getOrElse(presetKeys.indexOf(selectedPreset)) { presetLabels[0] },
            options = presetLabels,
            onValueChange = { label ->
                val idx = presetLabels.indexOf(label).coerceAtLeast(0)
                selectedPreset = presetKeys[idx]
                applyNoises(state, if (selectedPreset.isEmpty()) "" else NoiseProfileUtil.presetJson(selectedPreset).orEmpty())
            },
            supportingText = stringResource(R.string.server_lab_noise_preset_hint)
        )
        FormTextField(
            label = stringResource(R.string.server_lab_noises),
            value = state.noisesJson,
            onValueChange = { applyNoises(state, it) },
            placeholder = stringResource(R.string.server_lab_noises_placeholder),
            supportingText = stringResource(R.string.server_lab_noises_hint),
            maxLines = 10
        )
    }

    /**
     * Правка списка шумов синхронно обновляет noise-часть сырого finalMask:
     * очистка поля ДЕЙСТВИТЕЛЬНО убирает шум (иначе сохранение восстановило
     * бы его из fm), валидный список сразу виден в fm. Невалидный ввод поле
     * fm не трогает — сохранение отклонит validateCommonConfig.
     */
    private fun applyNoises(state: ServerUiState, noises: String) {
        state.noisesJson = noises
        runCatching {
            state.finalMask = NoiseProfileUtil.mergeNoisesIntoFinalMask(state.finalMask, noises).orEmpty()
        }
    }
}
