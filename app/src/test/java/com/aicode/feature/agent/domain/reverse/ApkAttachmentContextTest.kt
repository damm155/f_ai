package com.aicode.feature.agent.domain.reverse

import com.aicode.feature.agent.presentation.AgentAttachment
import kotlinx.serialization.decodeFromString
import kotlinx.serialization.encodeToString
import kotlinx.serialization.json.Json
import org.junit.Assert.assertEquals
import org.junit.Assert.assertFalse
import org.junit.Assert.assertNull
import org.junit.Assert.assertTrue
import org.junit.Test

class ApkAttachmentContextTest {
    private val json = Json { ignoreUnknownKeys = true }

    private fun attachment(
        fileName: String = "sample.apk",
        kind: ApkTargetKind? = null,
        containerPath: String = "~/workspace/uploads/$fileName"
    ) = AgentAttachment(
        fileName = fileName,
        containerPath = containerPath,
        localPath = "/data/local/tmp/$fileName",
        mimeType = if (fileName.endsWith(".apk", ignoreCase = true)) {
            "application/vnd.android.package-archive"
        } else {
            "application/octet-stream"
        },
        sizeBytes = 128,
        isImage = false,
        apkKind = kind
    )

    @Test
    fun nativeAttachmentUsesReadOnlyApkRouteUnlessModificationIsRequested() {
        val apk = attachment(kind = ApkTargetKind.NATIVE)
        val result = appendUserAttachmentContext("查看入口", listOf(apk))

        assertTrue(result.startsWith("查看入口\n\n（随消息附带文件：${apk.containerPath}）"))
        assertTrue(result.contains("【系统提示】${apk.containerPath} 为用户选定的普通（非 Flutter）应用：直接走原生 APK 工具链"))
        assertTrue(result.contains("loadSkill(\"apk-re\")"))
        assertTrue(result.contains("通过 Bash 使用 aicode-apk，按用户需求选择"))
        assertTrue(result.contains("dex-method"))
        assertTrue(result.contains("仅在用户需求要求时才修改、重打包或调用 apkSign 签名"))
        assertTrue(result.contains("禁止加载 flutter-re"))
        assertTrue(result.contains("禁止对该 APK 运行 aicode-blutter --scan 或 aicode-blutter 分析命令"))
        assertFalse(result.contains("loadSkill(\"flutter-re\")"))
        assertFalse(result.contains("dex-return"))
        assertFalse(result.contains("/root/apk"))
        assertFalse(result.contains(apk.localPath))
    }

    @Test
    fun flutterAttachmentChecksExistingAppAnalysisBeforeContainerAnalysis() {
        val apk = attachment(kind = ApkTargetKind.FLUTTER)
        val result = appendUserAttachmentContext("查看 Dart 逻辑", listOf(apk))

        assertTrue(result.contains("【系统提示】${apk.containerPath} 为用户选定的 Flutter 应用："))
        assertTrue(result.contains("loadSkill(\"flutter-re\")"))
        assertTrue(result.contains("先检查已有的 App 侧本地解析状态与对应结果"))
        assertTrue(result.contains("若正在解析则等待该任务"))
        assertTrue(result.contains("不重复启动解析"))
        assertTrue(result.contains("aicode-blutter 是独立的容器编译分析路线，不会调用 App 侧 Runner"))
        assertTrue(result.contains("按用户需求也可分析宿主 DEX"))
        assertFalse(result.contains("禁止读 apk-re"))
        assertFalse(result.contains("/root/apk"))
        assertFalse(result.contains("/root/out"))
    }

    @Test
    fun unselectedApkDoesNotPretendTheUserSelectedARoute() {
        val result = appendUserAttachmentContext("分析", listOf(attachment()))

        assertTrue(result.contains("未记录用户选择的类型"))
        assertTrue(result.contains("不得假装用户已选择原生或 Flutter"))
        assertTrue(result.contains("先确认类型"))
        assertFalse(result.contains("为用户选定的"))
        assertFalse(result.contains("loadSkill("))
        assertFalse(result.contains("aicode-blutter --scan"))
    }

    @Test
    fun ordinaryAttachmentsKeepTheExistingPrefixAndFileList() {
        val text = attachment("notes.txt")
        val image = attachment("screen.png").copy(mimeType = "image/png", isImage = true)
        val result = appendUserAttachmentContext("查看附件  \n", listOf(text, image))

        assertEquals(
            "查看附件\n\n附件：\n- notes.txt：${text.containerPath}\n- screen.png：${image.containerPath}",
            result
        )
        assertFalse(result.contains("【系统提示】"))
        assertFalse(result.contains("随消息附带文件"))
    }

    @Test
    fun ordinaryAttachmentsRespectACustomPrefix() {
        val text = attachment("notes.txt")

        assertEquals(
            "Attachments:\n- notes.txt：${text.containerPath}",
            appendUserAttachmentContext(" \n", listOf(text), "Attachments:")
        )
    }

    @Test
    fun mixedAttachmentsKeepOrdinaryFilesAndSeparateApkRoutes() {
        val text = attachment("notes.txt")
        val native = attachment("native.apk", ApkTargetKind.NATIVE)
        val flutter = attachment("flutter.apk", ApkTargetKind.FLUTTER)
        val result = appendUserAttachmentContext("对比", listOf(native, text, flutter))

        assertTrue(result.startsWith(
            "对比\n\n附件：\n- notes.txt：${text.containerPath}\n\n" +
                "（随消息附带文件：${native.containerPath}、${flutter.containerPath}）"
        ))
        val hints = result.split("【系统提示】").drop(1)
        assertEquals(2, hints.size)
        assertTrue(hints[0].startsWith("${native.containerPath} 为用户选定的普通"))
        assertTrue(hints[1].startsWith("${flutter.containerPath} 为用户选定的 Flutter"))
        assertFalse(hints.any { it.contains(text.containerPath) })
    }

    @Test
    fun duplicatePathsProduceOneFileEntryAndOneHintPerApk() {
        val native = attachment("native.apk", ApkTargetKind.NATIVE)
        val text = attachment("notes.txt")
        val attachments = listOf(native, text, native.copy(fileName = "renamed.apk"), text.copy(fileName = "copy.txt"))

        assertEquals(
            appendUserAttachmentContext("查看", listOf(native, text)),
            appendUserAttachmentContext("查看", attachments)
        )
    }

    @Test
    fun duplicateFileNamesAtDifferentPathsAreKept() {
        val native = attachment("same.apk", ApkTargetKind.NATIVE, "~/workspace/one/same.apk")
        val flutter = attachment("same.apk", ApkTargetKind.FLUTTER, "~/workspace/two/same.apk")
        val result = appendUserAttachmentContext("对比", listOf(native, flutter))

        assertTrue(result.contains("（随消息附带文件：${native.containerPath}、${flutter.containerPath}）"))
        assertEquals(2, result.split("【系统提示】").size - 1)
    }

    @Test
    fun attachmentJsonRoundTripPreservesAllRouteStates() {
        val attachments = listOf(
            attachment("native.apk", ApkTargetKind.NATIVE),
            attachment("flutter.apk", ApkTargetKind.FLUTTER),
            attachment("legacy.apk"),
            attachment("notes.txt")
        )
        val encoded = json.encodeToString(attachments)
        val decoded = json.decodeFromString<List<AgentAttachment>>(encoded)

        assertTrue(encoded.contains("\"apkKind\":\"NATIVE\""))
        assertTrue(encoded.contains("\"apkKind\":\"FLUTTER\""))
        assertEquals(attachments, decoded)
        assertNull(decoded[2].apkKind)
        assertEquals(
            appendUserAttachmentContext("分析", attachments),
            appendUserAttachmentContext("分析", decoded)
        )
    }

    @Test
    fun alreadyExpandedModelRequestDoesNotAppendTheSameSuffixAgain() {
        val attachments = listOf(
            attachment("notes.txt"),
            attachment("native.apk", ApkTargetKind.NATIVE),
            attachment("flutter.apk", ApkTargetKind.FLUTTER)
        )
        val modelRequest = appendUserAttachmentContext("分析", attachments)

        assertEquals(modelRequest, appendUserAttachmentContext(modelRequest, attachments))
        assertEquals(modelRequest + " \n", appendUserAttachmentContext(modelRequest + " \n", attachments))
    }

    @Test
    fun localizedPrefixDoesNotDuplicateAnAlreadyExpandedRequest() {
        val text = attachment("notes.txt")
        val apks = listOf(
            attachment("native.apk", ApkTargetKind.NATIVE),
            attachment("flutter.apk", ApkTargetKind.FLUTTER)
        )
        for (attachments in listOf(listOf(text), listOf(text) + apks)) {
            for (request in listOf("", "分析")) {
                val english = appendUserAttachmentContext(request, attachments, "Attachments:")
                val chinese = appendUserAttachmentContext(request, attachments)

                assertEquals(english, appendUserAttachmentContext(english, attachments))
                assertEquals(chinese, appendUserAttachmentContext(chinese, attachments, "Attachments:"))
            }
        }
    }

    @Test
    fun attachmentOnlyAndOrdinaryRequestsAreAlsoIdempotent() {
        for (attachments in listOf(listOf(attachment(kind = ApkTargetKind.NATIVE)), listOf(attachment("notes.txt")))) {
            val modelRequest = appendUserAttachmentContext(" \n", attachments)

            assertEquals(modelRequest, appendUserAttachmentContext(modelRequest, attachments))
        }
    }

    @Test
    fun mentioningAPathInTheOriginalRequestDoesNotSuppressAttachmentContext() {
        val apk = attachment(kind = ApkTargetKind.NATIVE)
        val request = "只分析 ${apk.containerPath} 的入口"
        val result = appendUserAttachmentContext(request, listOf(apk))

        assertTrue(result.startsWith("$request\n\n（随消息附带文件：${apk.containerPath}）"))
        assertTrue(result.contains("【系统提示】"))
    }

    @Test
    fun userTextIsPreservedExceptForTrailingWhitespaceBeforeTheSuffix() {
        val apk = attachment(kind = ApkTargetKind.NATIVE, containerPath = "~/workspace/a folder/真实附件.apk")
        val request = "  第一行\r\n    第二行\t\n\n"
        val result = appendUserAttachmentContext(request, listOf(apk))

        assertTrue(result.startsWith(request.trimEnd() + "\n\n"))
        assertTrue(result.contains("（随消息附带文件：${apk.containerPath}）"))
        assertFalse(result.contains(apk.localPath))
    }

    @Test
    fun aFollowingRequestWithoutAttachmentsRemainsUnchanged() {
        appendUserAttachmentContext("分析", listOf(attachment(kind = ApkTargetKind.NATIVE)))
        val nextRequest = "  继续上一条\n\n"

        assertEquals(nextRequest, appendUserAttachmentContext(nextRequest, emptyList()))
        assertEquals("", appendUserAttachmentContext("", emptyList()))
    }

    @Test
    fun apkRecognitionSupportsCaseInsensitiveNamesMimeTypesAndRecordedKinds() {
        val uppercase = attachment("APP.APK").copy(mimeType = "application/octet-stream")
        val mimeOnly = attachment("download.bin").copy(mimeType = "APPLICATION/VND.ANDROID.PACKAGE-ARCHIVE")
        val kindOnly = attachment("download.bin", ApkTargetKind.NATIVE)

        assertTrue(uppercase.isApkAttachment)
        assertTrue(mimeOnly.isApkAttachment)
        assertTrue(kindOnly.isApkAttachment)
        assertFalse(attachment("notes.txt").isApkAttachment)
        for (apk in listOf(uppercase, mimeOnly, kindOnly)) {
            assertTrue(appendUserAttachmentContext("分析", listOf(apk)).contains("【系统提示】"))
        }
    }
}
