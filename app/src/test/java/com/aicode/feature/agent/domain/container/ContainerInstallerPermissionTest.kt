package com.aicode.feature.agent.domain.container

import android.content.ContextWrapper
import android.system.Os
import io.mockk.every
import io.mockk.mockkStatic
import io.mockk.unmockkStatic
import org.apache.commons.compress.archivers.tar.TarArchiveEntry
import org.apache.commons.compress.archivers.tar.TarArchiveInputStream
import org.apache.commons.compress.archivers.tar.TarArchiveOutputStream
import org.apache.commons.compress.compressors.gzip.GzipCompressorInputStream
import org.apache.commons.compress.compressors.gzip.GzipCompressorOutputStream
import org.junit.After
import org.junit.Assert.assertEquals
import org.junit.Assert.assertFalse
import org.junit.Assert.assertTrue
import org.junit.Test
import java.io.ByteArrayInputStream
import java.io.ByteArrayOutputStream
import java.io.File
import java.nio.file.Files
import java.nio.file.attribute.PosixFilePermissions

/**
 * rootfs 解压与权限自愈的行为测试。
 *
 * 回归点：旧版 applyMode 只按「owner 位→全体」放宽权限（644→666、755→777），目录不设权限，
 * 硬链接 fallback 复制的副本又受 umask 影响变 600——容器内 unzip/perl 等因此权限错乱。
 * 单测开了 isReturnDefaultValues，Os.link 在 JVM 上是静默空操作，故用 mockk 让它抛错以覆盖 fallback。
 */
class ContainerInstallerPermissionTest {

    private val root = File(System.getProperty("java.io.tmpdir"), "installer-perm-${System.nanoTime()}")
    private val filesDir = File(root, "files").apply { mkdirs() }
    private val cacheDir = File(root, "cache").apply { mkdirs() }
    private val context = FakeContext(filesDir, cacheDir)
    private val installer = ContainerInstaller(context, ContainerOsDetector(context))

    @After
    fun tearDown() {
        runCatching { unmockkStatic(Os::class) }
        root.deleteRecursively()
    }

    private fun perms(file: File): String =
        PosixFilePermissions.toString(Files.getPosixFilePermissions(file.toPath()))

    private sealed interface Spec {
        val name: String
        val mode: Int
    }

    private data class Dir(override val name: String, override val mode: Int) : Spec

    private data class Reg(override val name: String, override val mode: Int, val data: String) : Spec

    private data class HardLink(override val name: String, override val mode: Int, val target: String) : Spec

    private fun tarGz(vararg specs: Spec): ByteArray {
        val bos = ByteArrayOutputStream()
        GzipCompressorOutputStream(bos).use { gz ->
            TarArchiveOutputStream(gz).use { tar ->
                tar.setLongFileMode(TarArchiveOutputStream.LONGFILE_GNU)
                for (spec in specs) {
                    val entry = when (spec) {
                        is Dir -> TarArchiveEntry(spec.name, TarArchiveEntry.LF_DIR)
                        is HardLink -> TarArchiveEntry(spec.name, TarArchiveEntry.LF_LINK).apply {
                            linkName = spec.target
                        }
                        is Reg -> TarArchiveEntry(spec.name).apply { size = spec.data.length.toLong() }
                    }
                    entry.mode = spec.mode
                    tar.putArchiveEntry(entry)
                    if (spec is Reg) tar.write(spec.data.toByteArray())
                    tar.closeArchiveEntry()
                }
            }
        }
        return bos.toByteArray()
    }

    @Test
    fun extractRootfsTo_精确恢复文件与目录权限() {
        val dest = File(root, "rootfs").apply { mkdirs() }
        installer.extractRootfsTo(
            dest,
            ByteArrayInputStream(
                tarGz(
                    Dir("usr", 0x1ED),                       // 0755
                    Dir("etc", 0x1C0),                       // 0700
                    Reg("usr/bin/hello", 0x1ED, "hi"),       // 0755
                    Reg("etc/secret", 0x180, "s")            // 0600
                )
            ),
            ContainerInstaller.CompressedFormat.GZIP
        )

        assertEquals("rwxr-xr-x", perms(File(dest, "usr")))
        assertEquals("rwx------", perms(File(dest, "etc")))
        assertEquals("rwxr-xr-x", perms(File(dest, "usr/bin/hello")))
        assertEquals("rw-------", perms(File(dest, "etc/secret")))
    }

    @Test
    fun extractRootfsTo_硬链接fallback复制_权限按tar恢复() {
        // 真机上 PRoot 文件系统常无法建硬链接；此时退化为复制，副本权限必须按 entry.mode 恢复，
        // 而不是由 JVM umask 决定（旧版 bug：副本变 600，与源文件权限不一致）。
        mockkStatic(Os::class)
        every { Os.link(any(), any()) } throws RuntimeException("hardlink unsupported")

        val dest = File(root, "rootfs-hardlink").apply { mkdirs() }
        installer.extractRootfsTo(
            dest,
            ByteArrayInputStream(
                tarGz(
                    Dir("usr/bin", 0x1ED),
                    Reg("usr/bin/tool", 0x1ED, "bin"),                      // 0755 实体
                    HardLink("usr/bin/tool-link", 0x1A4, "usr/bin/tool")    // 0644 硬链接条目
                )
            ),
            ContainerInstaller.CompressedFormat.GZIP
        )

        assertTrue("硬链接失败后应存在 fallback 副本", File(dest, "usr/bin/tool-link").isFile)
        assertEquals("rw-r--r--", perms(File(dest, "usr/bin/tool-link")))
    }

    @Test
    fun restoreLegacyModes_按tar恢复已存在文件权限_不创建缺失条目() {
        val rootfs = File(root, "rootfs-legacy").apply { mkdirs() }
        // 旧版解压留下的错乱权限
        val binDir = File(rootfs, "usr/bin").apply { mkdirs() }
        val etcDir = File(rootfs, "etc").apply { mkdirs() }
        val bin = File(binDir, "tool").apply { writeText("bin") }
        val conf = File(etcDir, "conf").apply { writeText("c") }
        Files.setPosixFilePermissions(bin.toPath(), PosixFilePermissions.fromString("rwxrwxrwx"))
        Files.setPosixFilePermissions(conf.toPath(), PosixFilePermissions.fromString("rw-rw-rw-"))

        val bytes = tarGz(
            Dir("usr", 0x1ED),
            Dir("etc", 0x1ED),
            Reg("usr/bin/tool", 0x1ED, "bin"),
            Reg("etc/conf", 0x1A4, "c"),
            Reg("etc/not-in-rootfs", 0x1A4, "x")   // rootfs 里不存在 → 跳过
        )
        val scanned = TarArchiveInputStream(
            GzipCompressorInputStream(ByteArrayInputStream(bytes))
        ).use { installer.restoreLegacyModes(rootfs, it) }

        assertEquals(5, scanned)
        assertEquals("rwxr-xr-x", perms(bin))
        assertEquals("rw-r--r--", perms(conf))
        assertEquals("rwxr-xr-x", perms(File(rootfs, "usr")))
        assertFalse("rootfs 缺失的条目不应被创建", File(rootfs, "etc/not-in-rootfs").exists())
    }

    private class FakeContext(private val files: File, private val cache: File) : ContextWrapper(null) {
        override fun getFilesDir(): File = files
        override fun getCacheDir(): File = cache
    }
}