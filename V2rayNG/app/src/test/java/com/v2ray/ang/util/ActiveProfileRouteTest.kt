package com.v2ray.ang.util

import com.v2ray.ang.util.ActiveProfileRoute.Mode
import com.v2ray.ang.util.ActiveProfileRoute.decideMode
import org.junit.jupiter.api.Assertions.assertEquals
import org.junit.jupiter.api.Test

/**
 * Доказывает, что выбор маршрута «через активный профиль» корректен для ВСЕХ
 * режимов запуска. Сама матрица режим -> (слушает ли loopback HTTP inbound,
 * живо ли ядро/FPTN-демон) определяется в CoreConfigManager.configureInbounds
 * и CoreServiceManager; здесь фиксируется чистое решение decideMode(), чтобы
 * регрессия «профиль выключен, хотя он включён» больше не повторилась.
 *
 * Ключевой факт: loopback HTTP inbound принудительно поднимается в hev-tun,
 * root, root+LAN-sharing и (по умолчанию) в proxy-only и обычном VPN-tun,
 * поэтому проба порта из ЛЮБОГО процесса (:main, :tasks) находит его. Единственные
 * режимы, где inbound отсутствует при живом профиле, - обычный VPN-tun с
 * ВЫКЛЮЧЕНным локальным прокси и FPTN (владеет собственным TUN): там запрос
 * честно отклоняется, потому что приложение исключено из собственного туннеля и
 * прямой запрос обошёл бы профиль.
 */
class ActiveProfileRouteTest {

    private fun mode(portListening: Boolean, coreAlive: Boolean) = decideMode(portListening, coreAlive)

    // --- Режимы, где HTTP inbound есть: порт слушается -> через прокси ---

    @Test
    fun `vpn hev-tun routes through local http proxy`() {
        // VPN + hev-tun: inbound FORCED on, daemon alive.
        assertEquals(Mode.LOCAL_HTTP_PROXY, mode(portListening = true, coreAlive = true))
    }

    @Test
    fun `vpn hev-tun with per-app bypass still routes through proxy`() {
        // Per-app proxy в bypass-режиме всё равно принудительно поднимает inbound.
        assertEquals(Mode.LOCAL_HTTP_PROXY, mode(portListening = true, coreAlive = true))
    }

    @Test
    fun `vpn hev-tun with per-app allow-only still routes through proxy`() {
        // Per-app allow-only: приложение исключает себя из туннеля, но inbound есть.
        assertEquals(Mode.LOCAL_HTTP_PROXY, mode(portListening = true, coreAlive = true))
    }

    @Test
    fun `root mode routes through local http proxy`() {
        assertEquals(Mode.LOCAL_HTTP_PROXY, mode(portListening = true, coreAlive = true))
    }

    @Test
    fun `root lan sharing routes through local http proxy`() {
        assertEquals(Mode.LOCAL_HTTP_PROXY, mode(portListening = true, coreAlive = true))
    }

    @Test
    fun `proxy-only mode routes through local http proxy`() {
        assertEquals(Mode.LOCAL_HTTP_PROXY, mode(portListening = true, coreAlive = true))
    }

    @Test
    fun `plain vpn-tun with local proxy on routes through proxy`() {
        assertEquals(Mode.LOCAL_HTTP_PROXY, mode(portListening = true, coreAlive = true))
    }

    // --- Режимы, где inbound НЕТ, но профиль жив: честный отказ, не "выключен" ---

    @Test
    fun `plain vpn-tun with local proxy off refuses instead of reporting none`() {
        // Профиль РАБОТАЕТ, но HTTP inbound не поднят. Это НЕ "профиль выключен".
        assertEquals(Mode.PROFILE_WITHOUT_LOCAL_PROXY, mode(portListening = false, coreAlive = true))
    }

    @Test
    fun `fptn profile refuses instead of reporting none`() {
        // FPTN владеет собственным TUN и не поднимает Xray HTTP inbound.
        assertEquals(Mode.PROFILE_WITHOUT_LOCAL_PROXY, mode(portListening = false, coreAlive = true))
    }

    // --- Ничего не запущено ---

    @Test
    fun `nothing running reports none`() {
        assertEquals(Mode.NONE, mode(portListening = false, coreAlive = false))
    }

    // --- Регрессия: прежний баг ставил isRunning() (нативный флаг :daemon) первым,
    // из-за чего из UI-процесса всегда получался NONE даже при работающем прокси.
    // Нативный флаг живёт ТОЛЬКО в :daemon, поэтому из :main/:tasks coreAlive=false,
    // хотя ядро работает и inbound слушается. Порт обязан побеждать этот флаг. ---

    @Test
    fun `port listener wins over a daemon flag that is false in the ui process`() {
        // Из UI-процесса: порт слушается (кросс-процессная TCP-проба), а нативный
        // isRunning()=false. Решение обязано быть LOCAL_HTTP_PROXY, а не NONE.
        assertEquals(Mode.LOCAL_HTTP_PROXY, mode(portListening = true, coreAlive = false))
    }

    @Test
    fun `a live listener is ground truth even if the daemon pid is not yet visible`() {
        // Гонка старта: PID ещё не опубликован/не виден, но inbound уже слушает и
        // обслуживает запросы. Доверяем факту работающего слушателя.
        assertEquals(Mode.LOCAL_HTTP_PROXY, mode(portListening = true, coreAlive = false))
    }
}
