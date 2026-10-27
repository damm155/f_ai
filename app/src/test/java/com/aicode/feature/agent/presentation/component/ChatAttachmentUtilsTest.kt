package com.aicode.feature.agent.presentation.component

import android.content.Context
import com.aicode.R
import com.aicode.feature.agent.domain.reverse.ApkTargetKind
import com.aicode.feature.agent.presentation.AgentAttachment
import com.aicode.feature.workspace.domain.FileAccessProvider
import io.mockk.Runs
import io.mockk.every
import io.mockk.just
import io.mockk.mockk
import io.mockk.verify
import java.io.File
import kotlinx.coroutines.test.runTest
import kotlinx.serialization.decodeFromString
import kotlinx.serialization.encodeToString
import kotlinx.serialization.json.Json
import org.junit.Assert.assertEquals
import org.junit.Assert.assertFalse
import org.junit.Assert.assertTrue
import org.junit.Rule
import org.junit.Test
import org.junit.rules.TemporaryFolder

class ChatAttachmentUtilsTest {
    @get:Rule
    val temporary = TemporaryFolder()

    private fun apk() = PendingUploadAttachment(
        fileName = "sample.apk",
        containerPath = "/root/uploads/sample.apk",
        localPath = "/data/project/.aicode/attachments/sample.apk",
        mimeType = "application/vnd.android.package-archive",
        sizeBytes = 128,
        apkKind = ApkTargetKind.NATIVE
    )

    @Test
    fun selectedTypeSurvivesPendingToPersistedJsonAndRewind() {
        val original = apk()
        val snapshot = Json.encodeToString(listOf(original).toAgentAttachments())
        val restored = Json.decodeFromString<List<AgentAttachment>>(snapshot).single().toPendingAttachment()
        assertEquals(original, restored)
    }

    @Test
    fun oldAttachmentMetadataDoesNotInventAUserChoice() {
        val snapshot = """[{"fileName":"sample.apk","containerPath":"/root/apk/sample.apk","localPath":"/data/sample.apk","mimeType":"application/vnd.android.package-archive","sizeBytes":128,"isImage":false}]"""
        val restored = Json.decodeFromString<List<AgentAttachment>>(snapshot).single().toPendingAttachment()
        assertEquals(null, restored.apkKind)
    }

    @Test
    fun manualSendAppendsContextWithoutChangingUserDraft() {
        val context = mockk<Context>()
        every { context.getString(R.string.chat_attachment_prefix) } returns "附件："
        val userText = "分析这个应用的会员逻辑"
        val request = appendAttachmentsToRequest(context, userText, listOf(apk()))
        assertTrue(request.startsWith("$userText\n\n（随消息附带文件：/root/uploads/sample.apk）"))
        assertTrue(request.contains("【系统提示】/root/uploads/sample.apk"))
        assertTrue(request.contains("loadSkill(\"apk-re\")"))
        assertEquals("分析这个应用的会员逻辑", userText)
        assertEquals("继续", appendAttachmentsToRequest(context, "继续", emptyList()))
    }

    @Test
    fun stagingCopiesFileAndUpdatesPathWithoutDeletingUpload() = runTest {
        val source = temporary.newFile("upload.apk").apply { writeText("test apk payload") }
        val target = File(temporary.root, "staged.apk")
        val access = mockk<FileAccessProvider>()
        every { access.exists("/root/apk/sample.apk") } returns false
        every { access.mkdirs("/root/apk") } just Runs
        every { access.copy("/root/uploads/sample.apk", "/root/apk/sample.apk", false) } answers {
            source.copyTo(target)
            Unit
        }
        every { access.copyToLocal("/root/apk/sample.apk") } returns target

        val staged = apk().copy(localPath = source.absolutePath).stageNativeApk(access)

        assertEquals("/root/apk/sample.apk", staged.containerPath)
        assertEquals(target.absolutePath, staged.localPath)
        assertEquals(ApkTargetKind.NATIVE, staged.apkKind)
        assertTrue(source.isFile)
        assertEquals(source.readText(), target.readText())
        verify(exactly = 0) { access.delete(any()) }
        verify(exactly = 0) { access.move(any(), any(), any()) }
    }

    @Test
    fun stagingDoesNotOverwriteAnExistingApk() = runTest {
        val target = temporary.newFile("sample-1.apk")
        val access = mockk<FileAccessProvider>()
        every { access.exists("/root/apk/sample.apk") } returns true
        every { access.exists("/root/apk/sample-1.apk") } returns false
        every { access.mkdirs("/root/apk") } just Runs
        every { access.copy("/root/uploads/sample.apk", "/root/apk/sample-1.apk", false) } just Runs
        every { access.copyToLocal("/root/apk/sample-1.apk") } returns target
        val staged = apk().stageNativeApk(access)
        assertEquals("sample-1.apk", staged.fileName)
        assertEquals("/root/apk/sample-1.apk", staged.containerPath)
        verify(exactly = 0) { access.copy(any(), "/root/apk/sample.apk", any()) }
    }

    @Test
    fun alreadyStagedAttachmentIsNotCopiedOntoItself() = runTest {
        val access = mockk<FileAccessProvider>()
        val staged = apk().copy(containerPath = "/root/apk/sample.apk").stageNativeApk(access)
        assertEquals("/root/apk/sample.apk", staged.containerPath)
        verify(exactly = 0) { access.copy(any(), any(), any()) }
    }

    @Test
    fun flutterAttachmentStillSendsFileAndRouteWithHiddenPreview() {
        val context = mockk<Context>()
        every { context.getString(R.string.chat_attachment_prefix) } returns "附件："
        val apk = apk().copy(
            apkKind = ApkTargetKind.FLUTTER,
            hideFromInputPreview = true,
            containerPath = "/root/uploads/FBox.apk"
        )
        val request = appendAttachmentsToRequest(context, "分析", listOf(apk))
        assertTrue(request.contains("/root/uploads/FBox.apk"))
        assertTrue(request.contains("为用户选定的 Flutter 应用"))
        assertTrue(request.contains("不重复启动解析"))
        assertTrue(request.startsWith("分析\n\n（随消息附带文件"))
    }

    @Test
    fun ordinaryFilesDoNotAcquireApkRouting() {
        val context = mockk<Context>()
        every { context.getString(R.string.chat_attachment_prefix) } returns "附件："
        val log = apk().copy(fileName = "log.txt", mimeType = "text/plain", apkKind = null)
        val request = appendAttachmentsToRequest(context, "读日志", listOf(log))
        assertFalse(request.contains("【系统提示】"))
        assertTrue(request.startsWith("读日志\n\n附件："))
    }
}
