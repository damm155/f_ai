package com.aicode.feature.agent.domain.reverse

import java.io.File
import java.io.IOException
import java.util.zip.CRC32
import java.util.zip.ZipFile

internal object BlutterAnalysisProducts {
    const val COMPLETED_MARKER = ".aicode-blutter-completed"

    fun hasProducts(outDir: File): Boolean {
        if (!listOf("pp.txt", "objs.txt").all { name ->
                File(outDir, name).let { it.isFile && it.length() > 0 }
            }) return false
        val asm = File(outDir, "asm")
        if (!asm.isDirectory) return false
        return asm.walkTopDown().any { file ->
            file.isFile && when (file.extension) {
                "dart" -> file.useLines { lines -> lines.any { it.contains("// ** addr:") } }
                "S" -> file.length() > 0
                else -> false
            }
        }
    }

    fun isReusable(outDir: File, apk: File): Boolean = runCatching {
        val marker = File(outDir, COMPLETED_MARKER)
        val completed = (marker.isFile && marker.readText().trim() == "completed") ||
            File(outDir, ".analyzed_meta").isFile
        if (!completed || !hasProducts(outDir)) return@runCatching false
        ZipFile(apk).use { zip ->
            listOf("libapp.so", "libflutter.so").all { name ->
                val entry = zip.getEntry("lib/arm64-v8a/$name") ?: return@all false
                val file = File(outDir, "lib/arm64-v8a/$name")
                if (!file.isFile || file.length() != entry.size) return@all false
                val checksum = CRC32()
                file.inputStream().use { input ->
                    val buffer = ByteArray(64 * 1024)
                    while (true) {
                        val count = input.read(buffer)
                        if (count < 0) break
                        checksum.update(buffer, 0, count)
                    }
                }
                checksum.value == entry.crc
            }
        }
    }.getOrDefault(false)

    fun markCompleted(outDir: File) {
        check(hasProducts(outDir)) { "Blutter output is incomplete" }
        val marker = File(outDir, COMPLETED_MARKER)
        if (marker.isFile && marker.readText().trim() == "completed") return
        val temporary = File.createTempFile(".aicode-completed-", ".tmp", outDir)
        try {
            temporary.writeText("completed\n")
            if (marker.exists() && !marker.delete()) {
                throw IOException("Could not replace invalid Blutter completion marker")
            }
            if (!temporary.renameTo(marker)) {
                throw IOException("Could not publish Blutter completion marker")
            }
        } finally {
            temporary.delete()
        }
    }

    fun publish(stageDir: File, outDir: File) {
        check(hasProducts(stageDir)) { "Blutter output is incomplete" }
        val backup = File(outDir.parentFile, ".${outDir.name}.previous-${System.nanoTime()}")
        val hadOutput = outDir.exists()
        if (hadOutput && !outDir.renameTo(backup)) {
            throw IOException("Could not preserve previous Blutter output")
        }
        try {
            if (!stageDir.renameTo(outDir)) throw IOException("Could not publish Blutter output")
        } catch (error: Throwable) {
            if (hadOutput && !outDir.exists()) backup.renameTo(outDir)
            throw error
        }
        if (hadOutput && !backup.deleteRecursively()) {
            File(backup, COMPLETED_MARKER).delete()
        }
    }
}
