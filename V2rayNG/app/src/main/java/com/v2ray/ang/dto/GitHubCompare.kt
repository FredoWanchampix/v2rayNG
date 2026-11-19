package com.v2ray.ang.dto

/**
 * Ответ GitHub compare API (`/compare/{base}...{head}`): статус родословной и
 * список коммитов, достижимых из head и не достижимых из base.
 *
 * Нужен загрузчику обновлений, чтобы отличать «релиз новее установленного»
 * от «установленная сборка уже содержит коммит релиза»: беты одной версии
 * неразличимы по versionName, а строки SHA без графа коммитов направления не
 * дают (дефект 19.11: сборка master предлагала «обновиться» на бету, которая
 * уже внутри неё).
 *
 * Поля nullable: Gson способен подставить null в обход kotlin-типов, а ответ
 * API может не содержать commits (список ограничен 250 записями и статусами).
 */
data class GitHubCompare(
    /** "identical" | "ahead" | "behind" | "diverged" — положение head относительно base. */
    val status: String? = null,
    /** Коммиты между base и head (head-сторона); может быть пустым или усечённым. */
    val commits: List<Commit>? = null,
) {
    data class Commit(val sha: String? = null)
}
