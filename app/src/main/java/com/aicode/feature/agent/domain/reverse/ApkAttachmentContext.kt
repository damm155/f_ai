package com.aicode.feature.agent.domain.reverse

import com.aicode.feature.agent.presentation.AgentAttachment

internal val AgentAttachment.isApkAttachment: Boolean
    get() = apkKind != null || fileName.endsWith(".apk", ignoreCase = true) ||
        mimeType.equals("application/vnd.android.package-archive", ignoreCase = true)

internal fun appendUserAttachmentContext(
    request: String,
    attachments: List<AgentAttachment>,
    attachmentPrefix: String = "附件："
): String {
    if (attachments.isEmpty()) return request
    val (apks, files) = attachments.distinctBy { it.containerPath }.partition { it.isApkAttachment }
    val attachmentText = buildString {
        if (files.isNotEmpty()) {
            append(attachmentPrefix)
            files.forEach { attachment ->
                append('\n')
                append("- ")
                append(attachment.fileName)
                append("：")
                append(attachment.containerPath)
            }
        }
        if (apks.isNotEmpty()) {
            if (isNotEmpty()) append("\n\n")
            append("（随消息附带文件：")
            append(apks.joinToString("、") { it.containerPath })
            append("）")
            apks.forEach { attachment ->
                append("\n\n【系统提示】")
                append(attachment.containerPath)
                when (attachment.apkKind) {
                    ApkTargetKind.NATIVE -> append(
                        " 为用户选定的普通（非 Flutter）应用：直接走原生 APK 工具链，先调用 AiCode 的 loadSkill(\"apk-re\")，" +
                            "通过 Bash 使用 aicode-apk，按用户需求选择 info、dex-strings、dex-refs、" +
                            "dex-class、dex-method、dex-fields、dex-xref、resource-read 等查询命令。" +
                            "仅在用户需求要求时才修改、重打包或调用 apkSign 签名。" +
                            "禁止加载 flutter-re，禁止对该 APK 运行 aicode-blutter --scan 或 aicode-blutter 分析命令。"
                    )
                    ApkTargetKind.FLUTTER -> append(
                        " 为用户选定的 Flutter 应用：调用 AiCode 的 loadSkill(\"flutter-re\") 后，" +
                            "先检查已有的 App 侧本地解析状态与对应结果；若正在解析则等待该任务，" +
                            "若已有与该附件对应的有效结果则优先读取，不重复启动解析。" +
                            "aicode-blutter 是独立的容器编译分析路线，不会调用 App 侧 Runner，仅在确有需要时使用。" +
                            "按用户需求也可分析宿主 DEX；仅在用户需求要求时才修改、重打包或签名。"
                    )
                    null -> append(
                        " 是 APK 附件，但未记录用户选择的类型；不得假装用户已选择原生或 Flutter。" +
                            "分析前应先确认类型，再选择对应技能与工具链，不要默认启动 Flutter 分析。"
                    )
                }
            }
        }
    }
    val trimmedRequest = request.trimEnd()
    // 首发前缀随界面语言变化，回放按稳定的文件清单与 APK 提示判重。
    val attachmentSuffix = if (files.isNotEmpty()) attachmentText.removePrefix(attachmentPrefix) else "\n\n$attachmentText"
    if (trimmedRequest == attachmentText || trimmedRequest.endsWith(attachmentSuffix)) return request
    return if (trimmedRequest.isEmpty()) attachmentText else "$trimmedRequest\n\n$attachmentText"
}
