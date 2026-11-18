package com.v2ray.ang.util.updater

/**
 * Вычисление скорости загрузки по скользящему окну выборок.
 *
 * Требование владельца: показывать скорость «вплоть до гигабайт, мегабайт,
 * килобайт и байт в секунду» и ETA. Мгновенная скорость одного отсчёта на
 * плохих сетях (2G/3G) скачет от 0 до пика, поэтому скорость считается как
 * (байты за окно) / (время окна) по кольцевому буферу выборок — это математика
 * средней скорости за последние [windowMillis], сглаженная, но честная.
 *
 * Класс НАМЕРЕННО чистый (нет android.*, нет часов системы — время подаётся
 * параметром), поэтому доказуем JVM-тестом: скорость и ETA в уведомлении
 * обязаны быть корректными на любой сети.
 *
 * Форматирование строки — существующий [com.v2ray.ang.extension.toSpeedString]
 * (B/s..PB/s); здесь он не вызывается, чтобы объект оставался JVM-чистым,
 * сервис форматирует сам.
 */
class SpeedTracker(
    private val windowMillis: Long = 5_000L,
) {

    private class Sample(var timeMs: Long, var bytes: Long)

    private val samples = ArrayDeque<Sample>()
    private var totalBytesSeen = 0L

    /**
     * Регистрирует текущую точку: сколько байт скачано ВСЕГО с начала загрузки
     * (сумма по сегментам) на момент [nowMs]. Вызывается периодически (≈500 мс)
     * из сервиса; частые вызовы дёшевы (кольцевой буфер обрезается по окну).
     */
    fun record(totalDownloadedBytes: Long, nowMs: Long) {
        totalBytesSeen = totalDownloadedBytes
        samples.addLast(Sample(nowMs, totalDownloadedBytes))
        evict(nowMs)
    }

    /**
     * Текущая скорость в байтах в секунду по скользящему окну.
     *
     * Берём ВСЕ выборки внутри окна (а не две крайние): иначе окно схлопывается
     * до последнего интервала опроса и скорость завышается в разы — на 10 отсчётах
     * по 500 мс «1 МБ/с» показывалось бы как «10 МБ/с». Поэтому evict() держит
     * хотя бы две точки, но скорость считается между СТАРЕЙШЕЙ выборкой в окне и
     * последней, что даёт настоящую среднюю за ~[windowMillis].
     *
     * Скорость никогда не отрицательная: totalDownloadedBytes монотонно растёт
     * (сброс делает reset()), а при убывании возвращаем 0.
     */
    fun bytesPerSecond(nowMs: Long): Long {
        evict(nowMs)
        val first = samples.firstOrNull() ?: return 0L
        val last = samples.lastOrNull() ?: return 0L
        val dt = last.timeMs - first.timeMs
        if (dt <= 0L) return 0L
        val db = last.bytes - first.bytes
        if (db <= 0L) return 0L
        return db * 1000L / dt
    }

    /**
     * Оценка оставшегося времени в миллисекундах при текущей скорости.
     *
     * @param totalBytes полный размер файла (из Content-Range/Content-Length).
     * @return null, если скорость нулевая или размер неизвестен (ETA показывать
     *   нечего — лучше «—», чем ложное «0 секунд»).
     */
    fun etaMillis(nowMs: Long, totalBytes: Long): Long? {
        if (totalBytes <= 0L) return null
        val speed = bytesPerSecond(nowMs)
        if (speed <= 0L) return null
        val remaining = totalBytes - totalBytesSeen
        if (remaining <= 0L) return 0L
        return remaining * 1000L / speed
    }

    /** Сбрасывает окно (пауза/возобновление/смена цели — старая скорость неактуальна). */
    fun reset() {
        samples.clear()
        totalBytesSeen = 0L
    }

    /**
     * Выбрасывает выборки старше окна.
     *
     * Обязательно оставляем ОДНУ точку за пределами cutoff как якорь: без неё
     * интервал dt был бы короче окна, и средняя скорость считалась бы по
     * короткому отрезку (скачки на медленной сети). Размер не ограничиваем
     * жёстко — при тике раз в секунду и окне 5 с это ~6 точек.
     */
    private fun evict(nowMs: Long) {
        val cutoff = nowMs - windowMillis
        while (samples.size > 2 && samples.first().timeMs < cutoff) {
            samples.removeFirst()
        }
    }
}
