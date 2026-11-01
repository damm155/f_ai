package com.aicode.feature.agent.domain.container

import android.content.Context
import android.content.res.AssetManager
import io.mockk.every
import io.mockk.mockk
import org.junit.Assert.assertEquals
import org.junit.Assert.assertFalse
import org.junit.Assert.assertTrue
import org.junit.Rule
import org.junit.Test
import org.junit.rules.TemporaryFolder
import java.io.File

class ReverseAssetsTest {
    @get:Rule
    val temporary = TemporaryFolder()

    private val required = listOf(
        "setup.sh", "blutter/blutter.py", "blutter/dartvm_fetch_build.py",
        "blutter/extract_dart_info.py", "blutter/blutter/src/DartTypes.cpp",
        "blutter/blutter/src/ElfHelper.cpp", "blutter/scripts/CMakeLists.txt",
        "patch_so.py", "fbox_gcc13_fix.py"
    )

    @Test
    fun upgrade_refreshesToolsAndPreservesBuildCache() {
        val rootfs = temporary.newFolder("rootfs")
        val aicode = temporary.newFolder("aicode")
        val data = temporary.newFolder("data")
        val assets = mockk<AssetManager>()
        val context = mockk<Context>()
        val installer = mockk<ContainerInstaller>()
        every { context.filesDir } returns data
        every { context.assets } returns assets
        every { installer.aicodeDir } returns aicode
        every { installer.rootfsDirFor(any()) } returns rootfs
        val assetFiles = mapOf(
            "reverse/w.js" to "w".repeat(128),
            "reverse/apk_tool/apk_tool.py" to "apk tool",
            "reverse/apk_tool/reapk/api.py" to "api",
            "reverse/so_tool/so_tool.py" to "so tool",
            "reverse/flutter-re.tar" to "archive",
            "reverse/skills/apk-re/SKILL.md" to "apk skill",
            "reverse/skills/flutter-re/SKILL.md" to "flutter skill",
            "reverse/blutter/runners.json" to "{}",
            "reverse/blutter/frida.template.js" to "frida"
        )
        every { assets.list(any()) } answers {
            val prefix = firstArg<String>().trimEnd('/') + "/"
            assetFiles.keys.filter { it.startsWith(prefix) }
                .map { it.removePrefix(prefix).substringBefore('/') }
                .distinct().toTypedArray()
        }
        every { assets.open(any()) } answers {
            assetFiles.getValue(firstArg()).byteInputStream()
        }
        var extractions = 0
        every {
            installer.extractRootfsTo(
                destDir = any(), input = any(), format = any(), onProgress = any()
            )
        } answers {
            val destination = firstArg<File>()
            required.forEach { name ->
                File(destination, name).apply {
                    parentFile.mkdirs()
                    writeText("updated")
                }
            }
            extractions++
            required.size
        }
        val flutter = File(rootfs, "root/flutter-re")
        required.forEach { name ->
            File(flutter, name).apply {
                parentFile.mkdirs()
                writeText("old")
            }
        }
        val cache = File(flutter, "blutter/bin/cached-runner").apply {
            parentFile.mkdirs()
            writeText("cached")
        }
        val marker = File(rootfs, "root/apk-tool/.version").apply {
            parentFile.mkdirs()
            writeText("rev-2")
        }
        val reverse = ReverseAssets(context, installer)
        reverse.ensureInstalled()
        assertEquals("rev-3", marker.readText())
        assertEquals("updated", File(flutter, "patch_so.py").readText())
        assertEquals("cached", cache.readText())
        assertEquals(1, extractions)
        reverse.ensureInstalled()
        assertEquals(1, extractions)
        assertTrue(File(aicode, "skills/flutter-re/SKILL.md").isFile)
        assertFalse(File(rootfs, ".provisioned").exists())
    }
}
