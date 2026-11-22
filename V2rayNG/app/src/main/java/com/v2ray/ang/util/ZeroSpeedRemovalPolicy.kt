package com.v2ray.ang.util

/**
 * Политика «удаления профилей с нулевой скоростью» (`removeZeroSpeedServer`).
 *
 * ДЕФЕКТ ФОРКА (не апстрима — вещдок: в 2dust/v2rayNG ни `removeZeroSpeedServer`,
 * ни полей `testSpeedBytesPerSec`/`testSpeedPresent` нет вовсе, они добавлены
 * форком). Прежнее условие удаляло профиль при `testSpeedBytesPerSec == 0L`, но
 * `0L` — это значение ПО УМОЛЧАНИЮ для профиля, у которого скорость НЕ измерялась.
 * Форк сам ввёл флаг [ServerAffiliationInfo.testSpeedPresent] именно чтобы
 * отличать «измерено, получено 0 байт/с» от «скорость никогда не мерилась»
 * (KDoc поля: «Distinguishes "probed, got N bytes/sec" from "never speed-tested"»),
 * но функция удаления этот флаг НЕ использовала.
 *
 * Сценарий потери данных: обычный тест задержки вызывает
 * `encodeServerTestDelayMillis`, который создаёт запись affiliation с
 * `testSpeedBytesPerSec = 0` и `testSpeedPresent = false` (скорость не мерилась).
 * Следом пункт меню «Удалить профили с нулевой скоростью» стирал ВСЕ такие
 * профили, включая полностью рабочие. Подтверждается UI: `MainServerPager`
 * рисует скорость только при `testSpeedPresent == true`, то есть для
 * неизмеренного профиля пользователь не видит «нулевую скорость» — а функция
 * его всё равно удаляла.
 *
 * Компилятор также указывал на вырожденность прежней проверки: warning
 * «Condition is always true» на `testSpeedBytesPerSec != null` (поле имеет тип
 * non-null `Long`), строки 659 и 667 MmkvManager.kt в прогоне CI.
 *
 * Чистая функция — доказывается JVM-тестом ZeroSpeedRemovalPolicyTest.
 */
object ZeroSpeedRemovalPolicy {

    /**
     * Удалять ли профиль как «имеющий нулевую скорость».
     *
     * Правила (инвариант: не терять неизмеренные и рабочие профили):
     *  - [testSpeedPresent] == false → НЕ удалять: скорость не измерялась,
     *    `0L` в поле — значение по умолчанию, а не результат пробы;
     *  - [testSpeedPresent] == true && [testSpeedBytesPerSec] == 0L → УДАЛЯТЬ:
     *    проба реально дала нулевую скорость (профиль не смог скачать ни байта);
     *  - [testSpeedPresent] == true && [testSpeedBytesPerSec] > 0L → НЕ удалять:
     *    скорость есть;
     *  - [testSpeedPresent] == true && [testSpeedBytesPerSec] < 0L → НЕ удалять:
     *    `-1` означает «проба не удалась» (сетевой сбой/таймаут), а не нулевую
     *    скорость; удалять по такому признаку небезопасно — профиль может быть
     *    рабочим. Это поведение сохранено прежним (предсуществующим) кодом.
     *
     * @param testSpeedPresent измерялась ли скорость этого профиля.
     * @param testSpeedBytesPerSec измеренная скорость, Б/с (0 — реально ноль,
     *   -1 — проба не удалась).
     * @return true, если профиль следует удалить.
     */
    fun shouldRemove(testSpeedPresent: Boolean, testSpeedBytesPerSec: Long): Boolean =
        testSpeedPresent && testSpeedBytesPerSec == 0L
}
