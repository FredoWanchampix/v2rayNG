package com.v2ray.ang.util

import org.json.JSONArray
import org.json.JSONObject

/**
 * Рекурсивное структурное сравнение JSON для unit-тестов.
 *
 * Почему не JSONObject.similar: в резолве org.json для unit-тестов этого
 * модуля метод similar отсутствует (компиляция падает с
 * "Unresolved reference 'similar'"), а порядок ключей org.json на JVM не
 * гарантирован, поэтому сравнивать строки toString() нельзя. Сравнение
 * структур не зависит ни от версии библиотеки, ни от порядка ключей.
 */
internal object TestJson {

    fun similar(a: Any?, b: Any?): Boolean = when {
        a === b -> true
        a == null || b == null -> false
        a is JSONObject && b is JSONObject -> {
            if (a.length() != b.length()) return false
            for (key in a.keys()) {
                if (!b.has(key)) return false
                if (!similar(a.opt(key), b.opt(key))) return false
            }
            true
        }

        a is JSONArray && b is JSONArray -> {
            if (a.length() != b.length()) return false
            for (i in 0 until a.length()) {
                if (!similar(a.opt(i), b.opt(i))) return false
            }
            true
        }

        else -> a.toString() == b.toString()
    }
}