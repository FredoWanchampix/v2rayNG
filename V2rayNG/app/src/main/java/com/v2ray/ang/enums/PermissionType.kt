package com.v2ray.ang.enums

import android.Manifest
import android.os.Build
import androidx.annotation.RequiresApi
import androidx.annotation.StringRes
import com.v2ray.ang.R

/**
 * Permission types used in the app, handling API level differences.
 */
enum class PermissionType {
    /** Camera permission (used for scanning QR codes) */
    CAMERA {
        override fun getPermission(): String = Manifest.permission.CAMERA
    },

    /** Notification permission (Android 13+) */
    POST_NOTIFICATIONS {
        @RequiresApi(Build.VERSION_CODES.TIRAMISU)
        override fun getPermission(): String = Manifest.permission.POST_NOTIFICATIONS
    },

    /** Local network access permission (Android 17+) */
    ACCESS_LOCAL_NETWORK {
        @RequiresApi(Build.VERSION_CODES.CINNAMON_BUN)
        override fun getPermission(): String = Manifest.permission.ACCESS_LOCAL_NETWORK
    },

    /**
     * Запись во внешнее хранилище (Android 8.1 и ниже).
     *
     * Нужна встроенному загрузчику обновлений: он пишет part-файлы и готовый
     * APK в публичный каталог Download/<app_name>. На API 29+ это не требует
     * разрешений (scoped storage + requestLegacyExternalStorage), а на
     * API 24-28 без runtime-разрешения запись молча не удалась бы и загрузчик
     * ушёл бы в резервный приватный каталог — пользователь потерял бы видимую
     * папку загрузки. Поэтому на старых API разрешение запрашивается явно.
     */
    STORAGE_WRITE {
        override fun getPermission(): String = Manifest.permission.WRITE_EXTERNAL_STORAGE
    };

    /** Return the actual Android permission string */
    abstract fun getPermission(): String

    /** Return the string resource for the human-readable permission label. */
    @StringRes
    fun getLabelRes(): Int {
        return when (this) {
            CAMERA -> R.string.permission_camera
            POST_NOTIFICATIONS -> R.string.permission_notification
            ACCESS_LOCAL_NETWORK -> R.string.permission_local_network
            STORAGE_WRITE -> R.string.permission_storage
        }
    }
}