package com.aicode.feature.agent.domain.reverse

import android.content.Context
import com.aicode.core.util.FileLogger
import com.aicode.feature.agent.domain.container.ContainerInstaller
import dagger.hilt.android.qualifiers.ApplicationContext
import java.io.File
import javax.inject.Inject
import javax.inject.Singleton

/**
 * 逆向工作区清理：删除可再生的中间产物，保留工具链本体与用户产出。
 *
 * 清理范围（都是"删了能重建"，或"任务已结束就没用了"）：
 * - 工作区附件目录：`<工作区>/.aicode/attachments/`（用户上传的 APK / 图片 / 日志）
 * - 容器 `/root/apk/`：导入待分析的 APK 副本
 * - 容器 `/root/out/`：blutter 分析结果（pp.txt / asm/ / objs.txt，单个应用可达上百 MB）
 * - 容器 `/root/work/`：临时脚本与中间产物
 * - `flutter-re/blutter/build/`、`dartsdk/`、`packages/`：blutter 编译产物与拉取的 Dart SDK
 *
 * **不删**：`/root/apk-tool`、`/root/so-tool`（工具链本体）、`/root/flutter-re` 其余部分
 * （含已打过补丁的源码）、`/root/patches`（补丁柜）、`/root/knowledge`（知识库）、
 * `/root/ai-skills`（自定义技能）——这些删了要么需要重新解压资产，要么是用户的永久产出。
 */
@Singleton
class ReverseWorkspaceCleaner @Inject constructor(
    @param:ApplicationContext private val context: Context,
    private val containerInstaller: ContainerInstaller
) {

    private companion object {
        const val TAG = "ReverseCleaner"

        /** rootfs 内可直接删除的目录（相对 rootfs 根）。 */
        private val CONTAINER_TARGETS = listOf(
            "root/apk",
            "root/out",
            "root/work",
            "root/flutter-re/blutter/build",
            "root/flutter-re/blutter/dartsdk",
            "root/flutter-re/blutter/packages"
        )
    }

    /** 一次清理的统计。 */
    data class CleanupResult(
        val freedBytes: Long,
        val removedDirs: Int,
        val failedPaths: List<String>
    ) {
        val freedText: String get() = formatSize(freedBytes)
    }

    private fun rootfsDir(): File = containerInstaller.rootfsDir

    /** 待清理的绝对路径清单（供 UI 展示"将要删除什么"）。 */
    fun targets(): List<File> {
        val rootfs = rootfsDir()
        val list = CONTAINER_TARGETS.map { File(rootfs, it) }.toMutableList()
        // 工作区附件目录：当前工作区的 .aicode/attachments
        attachmentsDir()?.let { list += it }
        return list.filter { it.exists() }
    }

    /** 当前工作区附件目录（不存在时返回 null）。 */
    fun attachmentsDir(): File? {
        val projects = File(context.filesDir, "projects")
        // 工作区可能有多个；attachments 在每个工作区下各一份
        return projects.listFiles()
            ?.filter { it.isDirectory }
            ?.map { File(File(it, ".aicode"), "attachments") }
            ?.filter { it.isDirectory }
            ?.takeIf { it.isNotEmpty() }
            ?.let { dirs -> if (dirs.size == 1) dirs.first() else null }
    }

    /** 当前占用的总字节数（供 UI 显示"可清理 X MB"）。 */
    fun totalSize(): Long = targets().sumOf { sizeOf(it) }

    /**
     * 执行清理。删除目录**内容**而非目录本身——部分工具（如 aicode-blutter 的 /root/out）
     * 依赖父目录存在，整目录删掉后下次运行要多一次 mkdir 兜底；保留空壳更稳。
     */
    suspend fun clean(): CleanupResult {
        var freed = 0L
        var removed = 0
        val failed = mutableListOf<String>()
        targets().forEach { dir ->
            val before = sizeOf(dir)
            val ok = runCatching { clearDirectory(dir) }
                .onFailure {
                    FileLogger.w(TAG, "清理失败: ${dir.absolutePath}", it)
                    failed += dir.absolutePath
                }
                .isSuccess
            if (ok) {
                freed += before
                removed += 1
            }
        }
        FileLogger.i(
            TAG,
            "逆向工作区清理完成：释放 ${formatSize(freed)}，处理 $removed 个目录" +
                if (failed.isEmpty()) "" else "，失败 ${failed.size} 个"
        )
        return CleanupResult(freed, removed, failed)
    }

    /** 删掉目录下全部子项，保留目录本身。 */
    private fun clearDirectory(dir: File) {
        if (!dir.isDirectory) {
            dir.delete()
            return
        }
        dir.listFiles()?.forEach { child ->
            if (child.isDirectory) child.deleteRecursively() else child.delete()
        }
    }

    private fun sizeOf(file: File): Long {
        if (!file.exists()) return 0L
        if (file.isFile) return file.length()
        return file.walkTopDown()
            .filter { it.isFile }
            .sumOf { it.length() }
    }
}

/** 字节数转可读文本（与设置页 StorageUsage 的格式保持一致）。 */
internal fun formatSize(bytes: Long): String = when {
    bytes >= 1024L * 1024 * 1024 -> String.format(java.util.Locale.US, "%.2f GB", bytes / (1024.0 * 1024 * 1024))
    bytes >= 1024L * 1024 -> String.format(java.util.Locale.US, "%.1f MB", bytes / (1024.0 * 1024))
    bytes >= 1024L -> String.format(java.util.Locale.US, "%.1f KB", bytes / 1024.0)
    else -> "$bytes B"
}
