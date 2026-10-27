package com.aicode.feature.agent.domain.reverse

import io.mockk.mockk
import java.io.File
import java.util.zip.ZipEntry
import java.util.zip.ZipOutputStream
import org.junit.Assert.assertFalse
import org.junit.Assert.assertTrue
import org.junit.Rule
import org.junit.Test
import org.junit.rules.TemporaryFolder

class BlutterResultFilesTest {
    @get:Rule val temporary = TemporaryFolder()

    private fun apk(file: File, app: String, flutter: String) {
        ZipOutputStream(file.outputStream()).use { zip ->
            mapOf("libapp.so" to app, "libflutter.so" to flutter).forEach { (name, value) ->
                zip.putNextEntry(ZipEntry("lib/arm64-v8a/$name"))
                zip.write(value.toByteArray())
                zip.closeEntry()
            }
        }
    }

    private fun output(dir: File, app: String, flutter: String) {
        val libs = File(dir, "lib/arm64-v8a").apply { mkdirs() }
        File(libs, "libapp.so").writeText(app)
        File(libs, "libflutter.so").writeText(flutter)
        File(dir, "pp.txt").writeText("pool")
        recordBlutterCompletion(dir, true)
    }

    @Test
    fun identicalInputsAndProductsCanBeReusedWithoutChangingFiles() {
        val source = temporary.newFile("sample.apk")
        val dir = temporary.newFolder("out")
        apk(source, "AAAA", "engine")
        output(dir, "AAAA", "engine")
        assertTrue(hasMatchingBlutterResult(source, dir))
        assertTrue(File(dir, "pp.txt").readText() == "pool")
    }

    @Test
    fun sameNameAndSameSizeButChangedInputMustNotReuseOldResults() {
        val source = temporary.newFile("sample.apk")
        val dir = temporary.newFolder("out")
        apk(source, "BBBB", "engine")
        output(dir, "AAAA", "engine")
        assertFalse(hasMatchingBlutterResult(source, dir))
    }

    @Test
    fun freshExtractionReplacesOldLibrariesEvenWhenSizesAreEqual() {
        val source = temporary.newFile("sample.apk")
        val dir = temporary.newFolder("out")
        apk(source, "BBBB", "engine")
        output(dir, "AAAA", "engine")
        val executor = BlutterRunnerExecutor(mockk())
        val extracted = executor.extractFlutterLibs(source, dir)
        assertTrue(extracted != null)
        assertTrue(File(dir, "lib/arm64-v8a/libapp.so").readText() == "BBBB")
    }

    @Test
    fun matchingLibrariesAloneAreNotAnalysisProducts() {
        val source = temporary.newFile("sample.apk")
        val dir = temporary.newFolder("out")
        apk(source, "AAAA", "engine")
        val libs = File(dir, "lib/arm64-v8a").apply { mkdirs() }
        File(libs, "libapp.so").writeText("AAAA")
        File(libs, "libflutter.so").writeText("engine")
        assertFalse(hasMatchingBlutterResult(source, dir))
    }

    @Test
    fun emptyAsmSubdirectoryDoesNotMeanAnalysisProducedFiles() {
        val dir = temporary.newFolder("out")
        File(dir, "asm/empty").mkdirs()
        assertFalse(hasBlutterProducts(dir))
        File(dir, "asm/empty/library.dart").writeText("assembly")
        assertTrue(hasBlutterProducts(dir))
    }

    @Test
    fun failedOrCancelledRunIsNotReusableEvenWhenPartialFilesExist() {
        val source = temporary.newFile("sample.apk")
        val dir = temporary.newFolder("out")
        apk(source, "AAAA", "engine")
        output(dir, "AAAA", "engine")
        recordBlutterCompletion(dir, false)
        assertTrue(hasBlutterProducts(dir))
        assertFalse(hasMatchingBlutterResult(source, dir))
    }

    @Test
    fun outputsWithoutSavedInputLibrariesAreNotAutomaticallyReused() {
        val source = temporary.newFile("sample.apk")
        val dir = temporary.newFolder("out")
        apk(source, "AAAA", "engine")
        File(dir, "pp.txt").writeText("old pool")
        assertTrue(hasBlutterProducts(dir))
        assertFalse(hasMatchingBlutterResult(source, dir))
    }
}
