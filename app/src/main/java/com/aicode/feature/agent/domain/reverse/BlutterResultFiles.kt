package com.aicode.feature.agent.domain.reverse

import java.io.File
import java.io.InputStream
import java.nio.file.Files
import java.security.MessageDigest
import java.util.zip.ZipFile

internal fun hasBlutterProducts(outDir: File): Boolean {
    if (listOf("pp.txt", "objs.txt").any { File(outDir, it).let { file -> file.isFile && file.length() > 0 } }) return true
    val asm = File(outDir, "asm")
    if (!asm.isDirectory) return false
    return asm.walkTopDown().onEnter { !Files.isSymbolicLink(it.toPath()) }
        .any { it.isFile && !Files.isSymbolicLink(it.toPath()) && it.length() > 0 }
}

// 同名 APK 可能已经换版，复用前比较本轮 APK 与结果目录保存的两份 Flutter 输入库。
internal fun hasMatchingBlutterResult(apk: File, outDir: File): Boolean {
    val completed = File(outDir, ".aicode-blutter-completed")
    if (!apk.isFile || !hasBlutterProducts(outDir) ||
        runCatching { completed.readText() }.getOrNull() != "completed"
    ) return false
    return runCatching {
        ZipFile(apk).use { zip ->
            listOf("libapp.so", "libflutter.so").all { name ->
                val entryName = "lib/arm64-v8a/$name"
                val entry = zip.getEntry(entryName) ?: return@all false
                val extracted = File(outDir, entryName)
                if (!extracted.isFile || extracted.length() != entry.size) return@all false
                val current = zip.getInputStream(entry).use(::sha256)
                val previous = extracted.inputStream().use(::sha256)
                current.contentEquals(previous)
            }
        }
    }.getOrDefault(false)
}

internal fun recordBlutterCompletion(outDir: File, completed: Boolean) {
    val marker = File(outDir, ".aicode-blutter-completed")
    if (completed) {
        marker.writeText("completed")
    } else if (marker.exists() && !marker.delete()) {
        throw java.io.IOException("Cannot clear analysis completion marker")
    }
}

private fun sha256(input: InputStream): ByteArray {
    val digest = MessageDigest.getInstance("SHA-256")
    val buffer = ByteArray(DEFAULT_BUFFER_SIZE)
    while (true) {
        val count = input.read(buffer)
        if (count < 0) break
        digest.update(buffer, 0, count)
    }
    return digest.digest()
}
