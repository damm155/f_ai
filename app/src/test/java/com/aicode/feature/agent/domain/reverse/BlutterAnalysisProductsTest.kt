package com.aicode.feature.agent.domain.reverse

import org.junit.Assert.assertEquals
import org.junit.Assert.assertFalse
import org.junit.Assert.assertThrows
import org.junit.Assert.assertTrue
import org.junit.Rule
import org.junit.Test
import org.junit.rules.TemporaryFolder
import java.io.File
import java.util.zip.ZipEntry
import java.util.zip.ZipOutputStream

class BlutterAnalysisProductsTest {
    @get:Rule
    val temporary = TemporaryFolder()

    private fun products(): File = temporary.newFolder().apply {
        File(this, "pp.txt").writeText("pool")
        File(this, "objs.txt").writeText("objects")
        File(this, "asm/user_info/member.dart").apply {
            parentFile.mkdirs()
            writeText("// ** addr: 0x1000, size: 0x8\n")
        }
    }

    private fun apk(outDir: File): File = temporary.newFile().apply {
        ZipOutputStream(outputStream()).use { zip ->
            listOf("libapp.so", "libflutter.so").forEach { name ->
                val bytes = "fixture-$name".toByteArray()
                zip.putNextEntry(ZipEntry("lib/arm64-v8a/$name"))
                zip.write(bytes)
                zip.closeEntry()
                File(outDir, "lib/arm64-v8a/$name").apply {
                    parentFile.mkdirs()
                    writeBytes(bytes)
                }
            }
        }
    }

    @Test
    fun products_requireObjectPoolAndAssembly() {
        val outDir = temporary.newFolder()
        File(outDir, "pp.txt").writeText("pool")
        File(outDir, "asm/empty").mkdirs()
        assertFalse(BlutterAnalysisProducts.hasProducts(outDir))
        assertThrows(IllegalStateException::class.java) {
            BlutterAnalysisProducts.markCompleted(outDir)
        }
        assertFalse(File(outDir, BlutterAnalysisProducts.COMPLETED_MARKER).exists())
    }

    @Test
    fun products_rejectClassOnlyDartFile() {
        val outDir = products()
        File(outDir, "asm/user_info/member.dart").writeText("class Member {}\n")
        assertFalse(BlutterAnalysisProducts.hasProducts(outDir))
    }

    @Test
    fun completion_requiresValidProducts() {
        val outDir = products()
        File(outDir, BlutterAnalysisProducts.COMPLETED_MARKER).writeText("invalid")
        BlutterAnalysisProducts.markCompleted(outDir)
        BlutterAnalysisProducts.markCompleted(outDir)
        assertEquals("completed", File(outDir, BlutterAnalysisProducts.COMPLETED_MARKER).readText().trim())
        assertFalse(outDir.listFiles().orEmpty().any { it.name.endsWith(".tmp") })
    }

    @Test
    fun reuse_matchesApkLibrariesAndCompletion() {
        val outDir = products()
        val input = apk(outDir)
        assertFalse(BlutterAnalysisProducts.isReusable(outDir, input))
        BlutterAnalysisProducts.markCompleted(outDir)
        assertTrue(BlutterAnalysisProducts.isReusable(outDir, input))
    }

    @Test
    fun reuse_rejectsSameSizeDifferentLibrary() {
        val outDir = products()
        val input = apk(outDir)
        BlutterAnalysisProducts.markCompleted(outDir)
        val libapp = File(outDir, "lib/arm64-v8a/libapp.so")
        val bytes = libapp.readBytes()
        bytes[0] = (bytes[0].toInt() xor 1).toByte()
        libapp.writeBytes(bytes)
        assertFalse(BlutterAnalysisProducts.isReusable(outDir, input))
    }

    @Test
    fun reuse_rejectsCompletionWithMissingProducts() {
        val outDir = products()
        val input = apk(outDir)
        BlutterAnalysisProducts.markCompleted(outDir)
        File(outDir, "objs.txt").writeText("")
        assertFalse(BlutterAnalysisProducts.isReusable(outDir, input))
    }

    @Test
    fun publish_replacesPreviousOutputAfterValidation() {
        val parent = temporary.newFolder()
        val output = File(parent, "app").apply { mkdirs() }
        File(output, "old.txt").writeText("old")
        val stage = File(parent, ".app.runner").apply { mkdirs() }
        File(stage, "pp.txt").writeText("new pool")
        File(stage, "objs.txt").writeText("new objects")
        File(stage, "asm/package/code.dart").apply {
            parentFile.mkdirs()
            writeText("// ** addr: 0x1000\n")
        }
        BlutterAnalysisProducts.markCompleted(stage)
        BlutterAnalysisProducts.publish(stage, output)
        assertEquals("new pool", File(output, "pp.txt").readText())
        assertFalse(File(output, "old.txt").exists())
        assertFalse(stage.exists())
        assertFalse(parent.listFiles().orEmpty().any { it.name.contains("previous-") })
    }

    @Test
    fun publish_rejectsIncompleteStageAndPreservesPreviousOutput() {
        val parent = temporary.newFolder()
        val output = File(parent, "app").apply { mkdirs() }
        File(output, "old.txt").writeText("old")
        val stage = File(parent, ".app.runner").apply {
            mkdirs()
            File(this, "pp.txt").writeText("partial")
        }
        assertThrows(IllegalStateException::class.java) {
            BlutterAnalysisProducts.publish(stage, output)
        }
        assertEquals("old", File(output, "old.txt").readText())
        assertTrue(stage.exists())
    }

    @Test
    fun reuse_recognizesLegacyMarker() {
        val outDir = products()
        val input = apk(outDir)
        File(outDir, ".analyzed_meta").writeText("{}")
        assertTrue(BlutterAnalysisProducts.isReusable(outDir, input))
    }
}
