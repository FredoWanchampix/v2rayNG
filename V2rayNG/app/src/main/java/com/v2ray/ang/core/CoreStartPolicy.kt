package com.v2ray.ang.core

/**
 * Чистые правила запуска ядра: можно ли стартовать и что делать по результату.
 *
 * Зачем вынесено в отдельный объект (а не оставлено внутри
 * [CoreServiceManager]): запуск ядра стал АСИНХРОННЫМ — вся тяжёлая часть
 * (DNS-резолв, поднятие сайдкар-движка, нативный старт) выполняется на
 * IO-диспетчере, потому что на главном потоке StrictMode запрещает сеть
 * (вещдок 20.11.2026: NetworkOnMainThreadException в
 * CoreOutboundBuilder.getServerAddress, из-за которого настройка «резолвить
 * домен» не работала вовсе).
 *
 * Асинхронность открывает окно, в котором состояние может измениться:
 *  1. повторный onStartCommand до завершения первого старта;
 *  2. stop (или рестарт) во время идущего старта;
 *  3. провал старта — сервис обязан остановиться, иначе останется висеть
 *     foreground-уведомление о профиле, который не поднят.
 *
 * Правила вынесены сюда как ЧИСТЫЕ функции (без Android, корутин и MMKV),
 * поэтому каждая гонка доказывается JVM-тестом
 * ([com.v2ray.ang.core.CoreStartPolicyTest]) без запуска сервиса.
 */
object CoreStartPolicy {

    /**
     * Можно ли начинать запуск.
     *
     * @param coreRunning ядро уже поднято ([CoreServiceManager.isRunning]).
     * @param startInFlight запуск уже идёт (флаг ставится ДО входа в IO, иначе
     *   повторный запрос успеет пройти, пока isRunning ещё false).
     * @return true, если стартовать можно и нужно.
     */
    fun canStart(coreRunning: Boolean, startInFlight: Boolean): Boolean =
        !coreRunning && !startInFlight

    /**
     * Можно ли перезапустить ядро на месте (пересборка конфига после смены
     * сети — [com.v2ray.ang.service.NetworkMonitor.onHandover]).
     *
     * @param coreRunning ядро поднято. Без него перезапускать нечего.
     * @param alreadyReloading reload уже идёт (защита от повторного входа).
     * @param startInFlight идёт ПЕРВИЧНЫЙ запуск ядра.
     *
     * Третье условие обязательно после перевода запуска на IO-диспетчер:
     * существует окно, в котором [com.v2ray.ang.core.CoreServiceManager]
     * уже поднял ядро (`startLoop` вернул, isRunning()==true), но флаг
     * `isStarting` ещё не сброшен. Reload в этом окне выполнил бы второй
     * `launchCore` параллельно первому — два `startLoop` на одном
     * coreController. Пропуск безопасен: идущий старт строит конфиг заново на
     * уже сменившейся сети, то есть делает ровно то, ради чего вызван reload.
     */
    fun canReload(coreRunning: Boolean, alreadyReloading: Boolean, startInFlight: Boolean): Boolean =
        coreRunning && !alreadyReloading && !startInFlight

    /**
     * Что сделать сервису по завершении асинхронного запуска.
     */
    enum class StartOutcome {
        /** Ядро поднято — ничего не делать. */
        RUNNING,

        /**
         * Запуск провалился: сервис обязан остановиться и снять уведомление,
         * иначе пользователь видит «подключено» при неработающем профиле.
         */
        STOP_SERVICE,

        /**
         * Результат УСТАРЕЛ: за время запуска пришёл stop/рестарт (поколение
         * сменилось). Ничего не делать — stop уже отработал, а попытка
         * остановиться ещё раз сняла бы состояние нового запуска.
         */
        STALE,
    }

    /**
     * Решение по результату запуска.
     *
     * @param started вернул ли [CoreServiceManager.startCoreLoop] true.
     * @param generation поколение, с которым запускалась операция.
     * @param currentGeneration текущее поколение (stop его увеличивает).
     */
    fun decide(started: Boolean, generation: Int, currentGeneration: Int): StartOutcome = when {
        generation != currentGeneration -> StartOutcome.STALE
        started -> StartOutcome.RUNNING
        else -> StartOutcome.STOP_SERVICE
    }
}
