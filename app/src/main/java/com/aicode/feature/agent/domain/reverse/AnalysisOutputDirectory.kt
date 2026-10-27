package com.aicode.feature.agent.domain.reverse

import com.aicode.feature.workspace.domain.FileAccessProvider

internal data class AnalysisOutputDirectory(val path: String, val hasResults: Boolean)

internal fun isAnalysisOutputPath(path: String): Boolean {
    val name = path.removePrefix("/root/out/")
    return path.startsWith("/root/out/") && name.isNotBlank() && name != "." && name != ".." &&
        '/' !in name && '\\' !in name && name.none { it.isISOControl() }
}

internal fun hasAnalysisProducts(fileAccess: FileAccessProvider, path: String): Boolean {
    if (!fileAccess.isDirectory(path)) return false
    return listOf("pp.txt", "objs.txt").any {
        val file = "$path/$it"
        fileAccess.isFile(file) && fileAccess.fileSize(file) > 0L
    } || (fileAccess.isDirectory("$path/asm") &&
        fileAccess.listFilesRecursive("$path/asm", 12).any { fileAccess.fileSize("$path/asm/$it") > 0L })
}

internal fun listAnalysisOutputs(fileAccess: FileAccessProvider): List<AnalysisOutputDirectory> {
    if (!fileAccess.isDirectory("/root/out")) return emptyList()
    return fileAccess.listFiles("/root/out")
        .filter { it.isDirectory }
        .map { "/root/out/${it.name}" }
        .filter(::isAnalysisOutputPath)
        .sorted()
        .map { AnalysisOutputDirectory(it, hasAnalysisProducts(fileAccess, it)) }
}
