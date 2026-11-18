package com.v2ray.ang.enums

import androidx.annotation.StringRes
import com.v2ray.ang.R

/**
 * Enum defining different notification channels.
 * Each channel has a unique channelId, notificationId, and display name.
 */
enum class NotificationChannelType(
    val channelId: String,
    @StringRes val channelNameRes: Int,
    val notificationId: Int
) {
    SUBSCRIPTION_UPDATE(
        channelId = "subscription_update_channel",
        channelNameRes = R.string.notification_channel_subscription_updates,
        notificationId = 13
    ),
    CORE_TEST(
        channelId = "core_test_channel",
        channelNameRes = R.string.notification_channel_connection_checks,
        notificationId = 12
    ),

    /**
     * Канал встроенного загрузчика обновлений: foreground-уведомление с
     * прогрессом/скоростью/ETA, кнопками Пауза/Продолжить/Отмена/Установить.
     * IMPORTANCE_LOW: без звука, но видно в шторке; живёт и после выхода из
     * клиента (требование владельца).
     */
    UPDATE_DOWNLOAD(
        channelId = "update_download_channel",
        channelNameRes = R.string.notification_channel_update_download,
        notificationId = 14
    )
}
