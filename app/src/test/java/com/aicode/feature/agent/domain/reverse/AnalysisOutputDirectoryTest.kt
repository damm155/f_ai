package com.aicode.feature.agent.domain.reverse

import com.aicode.feature.workspace.domain.FileAccessProvider
import com.aicode.feature.workspace.domain.FileEntry
import io.mockk.every
import io.mockk.mockk
import org.junit.Assert.assertEquals
import org.junit.Assert.assertFalse
import org.junit.Assert.assertTrue
import org.junit.Test

class AnalysisOutputDirectoryTest {
    @Test
    fun namesWithSpacesDotsAndVersionsAreKeptExactly() {
        val access = mockk<FileAccessProvider>(relaxed = true)
        every { access.isDirectory("/root/out") } returns true
        every { access.listFiles("/root/out") } returns listOf(
            FileEntry("123 云盘_3.3.0", true, 0L, 0L),
            FileEntry("JavDB-2", true, 0L, 0L),
            FileEntry("loose.txt", false, 10L, 0L)
        )
        val rows = listAnalysisOutputs(access)
        assertEquals(listOf("/root/out/123 云盘_3.3.0", "/root/out/JavDB-2"), rows.map { it.path })
        assertTrue(rows.none { it.hasResults })
    }

    @Test
    fun emptyOutputRootIsAValidEmptyList() {
        val access = mockk<FileAccessProvider>(relaxed = true)
        assertTrue(listAnalysisOutputs(access).isEmpty())
    }

    @Test
    fun onlyDirectOutputChildrenAreSelectable() {
        assertTrue(isAnalysisOutputPath("/root/out/123 云盘_3.3.0"))
        assertFalse(isAnalysisOutputPath("/root/out"))
        assertFalse(isAnalysisOutputPath("/root/out/"))
        assertFalse(isAnalysisOutputPath("/root/out/../apk"))
        assertFalse(isAnalysisOutputPath("/root/out/.."))
        assertFalse(isAnalysisOutputPath("/root/elsewhere"))
        assertFalse(isAnalysisOutputPath("/root/out/test\ncommand"))
    }

    @Test
    fun existingNonemptyProductIsReportedAsAFileSignal() {
        val access = mockk<FileAccessProvider>(relaxed = true)
        every { access.isDirectory("/root/out/app") } returns true
        every { access.isFile("/root/out/app/pp.txt") } returns true
        every { access.fileSize("/root/out/app/pp.txt") } returns 128L
        assertTrue(hasAnalysisProducts(access, "/root/out/app"))
        every { access.fileSize("/root/out/app/pp.txt") } returns 0L
        assertFalse(hasAnalysisProducts(access, "/root/out/app"))
    }
}
