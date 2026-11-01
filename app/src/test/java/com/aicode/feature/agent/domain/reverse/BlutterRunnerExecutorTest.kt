package com.aicode.feature.agent.domain.reverse

import android.content.Context
import io.mockk.mockk
import org.junit.Assert.assertEquals
import org.junit.Assert.assertNull
import org.junit.Assert.assertTrue
import org.junit.Rule
import org.junit.Test
import org.junit.rules.TemporaryFolder
import java.io.File
import java.util.zip.ZipEntry
import java.util.zip.ZipOutputStream

class BlutterRunnerExecutorTest {
    @get:Rule
    val temporary = TemporaryFolder()

    private val executor = BlutterRunnerExecutor(mockk<Context>())

    private fun snapshot(size: Int, offset: Int): ByteArray = ByteArray(size).apply {
        byteArrayOf(0xf5.toByte(), 0xf5.toByte(), 0xdc.toByte(), 0xdc.toByte())
            .copyInto(this, offset)
        "0123456789abcdef0123456789abcdef".toByteArray().copyInto(this, offset + 20)
    }

    @Test(timeout = 5000)
    fun snapshotHash_shortFinalBlockTerminates() {
        val libapp = temporary.newFile().apply { writeBytes(snapshot(100, 4)) }
        assertEquals(setOf("0123456789abcdef0123456789abcdef"), executor.extractSnapshotHashes(libapp))
    }

    @Test(timeout = 5000)
    fun snapshotHash_spanningBlockBoundary() {
        val libapp = temporary.newFile().apply { writeBytes(snapshot(65580, 65520)) }
        assertEquals(setOf("0123456789abcdef0123456789abcdef"), executor.extractSnapshotHashes(libapp))
    }

    @Test(timeout = 5000)
    fun snapshotHash_missingMagicTerminates() {
        val libapp = temporary.newFile().apply { writeBytes(ByteArray(65)) }
        assertTrue(executor.extractSnapshotHashes(libapp).isEmpty())
    }

    @Test
    fun extraction_replacesSameSizeStaleLibraries() {
        val input = temporary.newFile()
        val output = temporary.newFolder()
        ZipOutputStream(input.outputStream()).use { zip ->
            listOf("libapp.so", "libflutter.so").forEach { name ->
                zip.putNextEntry(ZipEntry("lib/arm64-v8a/$name"))
                zip.write(byteArrayOf(1, 2, 3, 4))
                zip.closeEntry()
                File(output, "lib/arm64-v8a/$name").apply {
                    parentFile.mkdirs()
                    writeBytes(byteArrayOf(4, 3, 2, 1))
                }
            }
        }
        val result = executor.extractFlutterLibs(input, output)
        assertTrue(result != null)
        assertTrue(result!!.second.readBytes().contentEquals(byteArrayOf(1, 2, 3, 4)))
        assertTrue(result.third!!.readBytes().contentEquals(byteArrayOf(1, 2, 3, 4)))
    }

    @Test
    fun extraction_missingLibrariesDoesNotReuseStaleFiles() {
        val input = temporary.newFile()
        val output = temporary.newFolder()
        ZipOutputStream(input.outputStream()).use { }
        File(output, "lib/arm64-v8a/libapp.so").apply {
            parentFile.mkdirs()
            writeBytes(byteArrayOf(1, 2, 3, 4))
        }
        assertNull(executor.extractFlutterLibs(input, output))
    }
}
