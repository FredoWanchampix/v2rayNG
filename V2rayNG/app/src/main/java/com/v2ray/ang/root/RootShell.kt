package com.v2ray.ang.root

import android.content.Context
import com.v2ray.ang.AppConfig
import com.v2ray.ang.util.LogUtil
import java.io.File

/**
 * Minimal root command runner backed by the `su` binary.
 *
 * Scripts are written to the app's private root runtime dir and executed with
 * `su -c sh <file>` so shell quoting stays simple. stderr is merged into stdout to
 * avoid pipe-buffer deadlocks.
 */
object RootShell {

    data class Result(val code: Int, val output: String) {
        val success: Boolean get() = code == 0
    }

    /** Базовый таймаут обычного скрипта настройки/снятия правил, сек. */
    private const val DEFAULT_SCRIPT_TIMEOUT_SECONDS = 25L

    /** Write [script] to `<filesDir>/root/<name>` and run it as root. */
    fun runScript(
        context: Context,
        name: String,
        script: String,
        timeoutSeconds: Long = DEFAULT_SCRIPT_TIMEOUT_SECONDS,
    ): Result {
        val dir = File(context.filesDir, AppConfig.ROOT_RUNTIME_DIR).apply { mkdirs() }
        val file = File(dir, name).apply {
            writeText(script)
            setReadable(false, false)
            setReadable(true, true)
            setWritable(false, false)
            setWritable(true, true)
        }
        val safePath = file.absolutePath.replace("'", "'\\''")
        // Android toybox timeout owns the root shell, so killing the su client cannot leave
        // a timed-out setup shell installing rules after rollback has already started.
        //
        // Таймаут параметризован: измерение профиля FPTN поднимает изолированный
        // netns, запускает fptn-client и скачивает тестовый файл, поэтому 25 секунд
        // ему заведомо мало. Внешний timeout всегда чуть больше внутреннего бюджета
        // скрипта, чтобы очистка (trap EXIT) успела отработать до жёсткого SIGKILL.
        val outerTimeout = (timeoutSeconds + 10).coerceAtLeast(DEFAULT_SCRIPT_TIMEOUT_SECONDS)
        return exec(
            "timeout -s TERM -k 5 $timeoutSeconds sh '$safePath'",
            outerTimeout,
        )
    }

    private fun exec(command: String, timeoutSeconds: Long = 30): Result {
        return try {
            val outcome = RootProcessRunner.run(listOf("su", "-c", command), timeoutSeconds * 1000)
            val result = Result(outcome.code, outcome.output)
            if (!result.success) {
                LogUtil.w(AppConfig.TAG, "RootShell: root command exited ${result.code}: ${result.output.trim()}")
            }
            result
        } catch (e: Exception) {
            if (e is InterruptedException) Thread.currentThread().interrupt()
            LogUtil.e(AppConfig.TAG, "RootShell: root command failed", e)
            Result(-1, e.javaClass.simpleName)
        }
    }
}
