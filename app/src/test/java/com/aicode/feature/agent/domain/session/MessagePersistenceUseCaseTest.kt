package com.aicode.feature.agent.domain.session

import androidx.room.InvalidationTracker
import com.aicode.feature.agent.data.local.dao.AgentMessageDao
import com.aicode.feature.agent.data.local.database.AgentDatabase
import com.aicode.feature.agent.data.local.entity.AgentMessageEntity
import com.aicode.feature.agent.domain.model.AgentMessage
import com.aicode.feature.agent.domain.reverse.ApkTargetKind
import com.aicode.feature.agent.domain.reverse.appendUserAttachmentContext
import com.aicode.feature.agent.presentation.AgentAttachment
import com.aicode.feature.agent.presentation.MessageRole
import io.mockk.coEvery
import io.mockk.coVerify
import io.mockk.every
import io.mockk.mockk
import kotlinx.coroutines.test.runTest
import kotlinx.serialization.decodeFromString
import kotlinx.serialization.encodeToString
import kotlinx.serialization.json.Json
import org.junit.Assert.assertEquals
import org.junit.Assert.assertFalse
import org.junit.Assert.assertNull
import org.junit.Assert.assertTrue
import org.junit.Test

/**
 * 验证落库前的内容净化与按字节限长：剥离内嵌 base64 图片 data URL、超长内容按 UTF-8 字节截断，
 * 防止超大字段撑爆单行触发 SQLite CursorWindow 崩溃。
 */
class MessagePersistenceUseCaseTest {

    @Test
    fun persistAndBuildHistoryPreserveApkRoutesWithoutChangingUserContent() = runTest {
        val dao = mockk<AgentMessageDao>()
        val database = mockk<AgentDatabase>()
        val tracker = mockk<InvalidationTracker>(relaxed = true)
        every { database.invalidationTracker } returns tracker
        val stored = mutableListOf<AgentMessageEntity>()
        coEvery { dao.insert(capture(stored)) } returns Unit
        coEvery { dao.getMessagesBySessionOnce("session") } answers { stored.toList() }
        val persistence = MessagePersistenceUseCase(dao, database)
        val attachments = listOf(ApkTargetKind.NATIVE, ApkTargetKind.FLUTTER, null).mapIndexed { index, kind ->
            AgentAttachment(
                fileName = "app$index.apk",
                containerPath = "~/workspace/attachments/app$index.apk",
                localPath = "",
                mimeType = "application/vnd.android.package-archive",
                sizeBytes = 128,
                isImage = false,
                apkKind = kind
            )
        }
        val request = "  查看这三个附件  \n"
        val modelRequest = appendUserAttachmentContext(request, attachments)
        val nextRequest = "  继续看第一个的入口\n"

        persistence.persist("session", MessageRole.USER, request, id = "with-apks", attachments = attachments)
        persistence.persist("session", MessageRole.USER, nextRequest, id = "next")
        val saved = stored.first()
        val restored = Json.decodeFromString<List<AgentAttachment>>(saved.attachmentsJson!!)
        assertEquals(request, saved.content)
        assertFalse(saved.content.contains("【系统提示】"))
        assertEquals(attachments, restored)
        assertEquals(request, saved.toUIMessage().content)
        assertEquals(attachments, saved.toUIMessage().attachments)
        assertEquals(modelRequest, appendUserAttachmentContext(saved.toUIMessage().content, saved.toUIMessage().attachments))
        assertNull(stored.last().attachmentsJson)

        val history = persistence.buildHistory("session", "pending")
        assertEquals(2, history.size)
        assertEquals(modelRequest, (history[0] as AgentMessage.UserMessage).content)
        assertEquals(nextRequest, (history[1] as AgentMessage.UserMessage).content)
        val reloaded = MessagePersistenceUseCase(dao, database).buildHistory("session", "pending")
        assertEquals(history, reloaded)
        assertEquals(request, stored.first().content)
        coVerify(exactly = 2) { dao.insert(any()) }
    }

    @Test
    fun buildHistoryHandlesLegacyJsonAndAlreadyExpandedModelRequests() = runTest {
        val dao = mockk<AgentMessageDao>()
        val database = mockk<AgentDatabase>()
        val tracker = mockk<InvalidationTracker>(relaxed = true)
        every { database.invalidationTracker } returns tracker
        val legacyJson = """[{"fileName":"legacy.apk","containerPath":"~/workspace/legacy.apk","localPath":"","mimeType":"application/vnd.android.package-archive","sizeBytes":128,"isImage":false}]"""
        val legacy = AgentMessageEntity(
            id = "legacy",
            sessionId = "session",
            role = "USER",
            content = "旧消息原文",
            timestamp = 1,
            attachmentsJson = legacyJson
        )
        val attachment = AgentAttachment(
            fileName = "native.apk",
            containerPath = "~/workspace/native.apk",
            localPath = "",
            mimeType = "application/vnd.android.package-archive",
            sizeBytes = 128,
            isImage = false,
            apkKind = ApkTargetKind.NATIVE
        )
        val expandedAttachments = listOf(
            attachment,
            attachment.copy(fileName = "notes.txt", containerPath = "~/workspace/notes.txt", mimeType = "text/plain", apkKind = null)
        )
        val expanded = appendUserAttachmentContext("模型请求", expandedAttachments, "Attachments:")
        val alreadyExpanded = legacy.copy(
            id = "expanded",
            content = expanded,
            timestamp = 2,
            attachmentsJson = Json.encodeToString(expandedAttachments)
        )
        coEvery { dao.getMessagesBySessionOnce("session") } returns listOf(legacy, alreadyExpanded)
        val history = MessagePersistenceUseCase(dao, database).buildHistory("session", "pending")

        assertNull(legacy.toUIMessage().attachments.single().apkKind)
        val legacyContent = (history[0] as AgentMessage.UserMessage).content
        assertTrue(legacyContent.startsWith("旧消息原文\n\n（随消息附带文件：~/workspace/legacy.apk）"))
        assertTrue(legacyContent.contains("未记录用户选择的类型"))
        assertFalse(legacyContent.contains("为用户选定的"))
        assertEquals(expanded, (history[1] as AgentMessage.UserMessage).content)
        assertEquals("旧消息原文", legacy.content)
        coVerify(exactly = 0) { dao.insert(any()) }
    }

    @Test
    fun historyPlacesSummaryBeforeRetainedMessagesWithoutChangingDisplayTimestamps() {
        val retained = AgentMessageEntity(id = "retained", sessionId = "session", role = "USER", content = "goal", timestamp = 100)
        val marker = AgentMessageEntity(id = "marker", sessionId = "session", role = "USER", content = "marker", timestamp = 200, isCompactionMarker = true)
        val summary = AgentMessageEntity(id = "summary", sessionId = "session", role = "ASSISTANT", content = "summary", timestamp = 201, isContextSummary = true)
        val latest = retained.copy(id = "latest", timestamp = 300)
        val display = listOf(retained, marker, summary, latest)
        val history = MessagePersistenceUseCase.orderHistoryEntities(display)
        assertEquals(listOf("marker", "summary", "retained", "latest"), history.map { it.id })
        assertEquals(listOf(200L, 201L, 100L, 300L), history.map { it.timestamp })
        assertEquals(listOf("retained", "marker", "summary", "latest"), display.map { it.id })
    }

    @Test
    fun sanitizeContent_stripsInlineBase64Image() {
        val input = "这是回复。看图：![截图](data:image/png;base64,iVBORw0KGgoAAAANSUhEUgAAAAEAAAABCAYAAAAfFcSJAAAADUlEQVR42mNk+M9QDwADhgGAWjR9awAAAABJRU5ErkJggg==) 结束。"

        val result = MessagePersistenceUseCase.sanitizeContent(input)

        assertTrue(result.contains("图片已省略"))
        assertFalse(result.contains("iVBORw0KGgo"))
        assertTrue(result.contains("这是回复"))
    }

    @Test
    fun sanitizeContent_stripsBareDataUrl() {
        val input = "data:image/jpeg;base64,/9j/4AAQSkZJRgABAQAAAQ=="

        val result = MessagePersistenceUseCase.sanitizeContent(input)

        assertTrue(result.contains("图片已省略"))
        assertFalse(result.contains("/9j/4AAQSk"))
    }

    @Test
    fun sanitizeContent_truncatesOversizedPlainText() {
        val oversized = "a".repeat(300_000)

        val result = MessagePersistenceUseCase.sanitizeContent(oversized)

        assertTrue(result.endsWith(MessagePersistenceUseCase.CONTENT_TRUNCATED_MARKER))
        val kept = result.removeSuffix(MessagePersistenceUseCase.CONTENT_TRUNCATED_MARKER)
        assertTrue(kept.toByteArray(Charsets.UTF_8).size <= MessagePersistenceUseCase.MAX_CONTENT_BYTES)
    }

    @Test
    fun sanitizeContent_boundsBytesForMultibyteText() {
        // 中文单字符 3 字节：字符数上限约束不住真实占用，必须按字节截断。
        val oversized = "汉".repeat(100_000)

        val result = MessagePersistenceUseCase.sanitizeContent(oversized)

        assertTrue(result.endsWith(MessagePersistenceUseCase.CONTENT_TRUNCATED_MARKER))
        val kept = result.removeSuffix(MessagePersistenceUseCase.CONTENT_TRUNCATED_MARKER)
        assertTrue(kept.toByteArray(Charsets.UTF_8).size <= MessagePersistenceUseCase.MAX_CONTENT_BYTES)
    }

    @Test
    fun sanitizeContent_keepsNormalTextUnchanged() {
        val normal = "普通消息，不需要处理。".repeat(10)

        assertEquals(normal, MessagePersistenceUseCase.sanitizeContent(normal))
    }

    @Test
    fun capBytes_truncatesOversizedJson() {
        val oversized = "[{\"id\":\"" + "a".repeat(300_000) + "\"}]"

        val result = MessagePersistenceUseCase.capBytes(
            oversized,
            MessagePersistenceUseCase.MAX_SNAPSHOT_BYTES
        )

        assertTrue(result.toByteArray(Charsets.UTF_8).size <= MessagePersistenceUseCase.MAX_SNAPSHOT_BYTES)
    }

    @Test
    fun capBytes_doesNotSplitSurrogatePair() {
        val oversized = "😀".repeat(50_000)

        val result = MessagePersistenceUseCase.capBytes(
            oversized,
            MessagePersistenceUseCase.MAX_SNAPSHOT_BYTES
        )

        assertTrue(result.toByteArray(Charsets.UTF_8).size <= MessagePersistenceUseCase.MAX_SNAPSHOT_BYTES)
        assertEquals(0, result.length % 2)
    }

    @Test
    fun capBytes_keepsNormalJsonUnchanged() {
        val normal = "[{\"id\":\"call_1\",\"name\":\"writeFile\"}]"

        assertEquals(
            normal,
            MessagePersistenceUseCase.capBytes(normal, MessagePersistenceUseCase.MAX_SNAPSHOT_BYTES)
        )
    }
}
