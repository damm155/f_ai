package com.aicode.feature.agent.domain.container

import android.content.Context
import com.aicode.core.util.FileLogger
import dagger.hilt.android.qualifiers.ApplicationContext
import java.io.File
import java.io.InputStream
import javax.inject.Inject
import javax.inject.Singleton

/**
 * 逆向能力资产（移植自 FBox）的按需投送。
 *
 * 设计对齐 FBox `LinuxManager.ensureFlutterRe()` 的两条原则：
 *
 * 1. **按需解压**：资产随 APK 打在 `assets/reverse/` 下，不预铺进 rootfs；
 *    第一次真正用到时才释放到容器内 `/root/`。
 * 2. **版本自愈**：不是"有就跳过"，而是逐项校验关键文件是否齐备、补丁是否在位，
 *    任一缺失就覆盖重解。因此 rootfs 被 [ContainerInstaller.installRootfsIfNeed] 整体删除重装后，
 *    首次使用会自动重建，无需额外持久化。
 *
 * 与之相对，**用户产出**（知识库 / 补丁柜 / 自定义技能）不可重建，走持久目录 + proot `-b` 绑定，
 * 见 [persistentBindings]。
 *
 * 资产落位表（`assets/reverse/` 下 → 容器 `/root/` 下）：
 * ```
 * apk_tool/apk_tool.py   → /root/apk-tool/apk_tool.py
 * apk_tool/reapk/ 树     → /root/apk-tool/reapk/          (apk_tool.py 的依赖包，必须同级)
 * so_tool/so_tool.py     → /root/so-tool/so_tool.py
 * flutter-re.tar         → /root/flutter-re/              (blutter 源码工具链，tar 解压)
 * skills/<id>/SKILL.md    → ~/.aicode/skills/<id>/SKILL.md  (AiCode 全局技能根，持久)
 * ```
 * 不落沙箱的资产（App 侧直接用）：`blutter/runners.json`、`blutter/frida.template.js`、
 * `keystore/patch.keystore`、`reflutter/` 树。
 *
 * 注意：技能**不放** rootfs 内的 `/root/ai-skills`（那是 FBox 的做法）——AiCode 的技能来自
 * `~/.aicode/skills` 目录式来源，且该目录经 proot `-b` 持久绑定、与 rootfs 重装无关。
 */
@Singleton
class ReverseAssets @Inject constructor(
    @ApplicationContext private val context: Context,
    private val containerInstaller: ContainerInstaller
) {

    companion object {
        private const val TAG = "ReverseAssets"

        /** assets 下的资产根目录。 */
        const val ASSET_DIR = "reverse"

        /**
         * 资产版本。**改动 assets/reverse 下任何内容后 +1**，会触发容器内一次性自愈重解。
         * 写入 `/root/apk-tool/.version`（在 rootfs 内部，随 rootfs 重装一起消失 —— 这正是我们要的）。
         */
        private const val ASSETS_VERSION = "rev-1"

        /** flutter-re 自愈校验点：任一缺失即整包覆盖重解（对齐 FBox 的 hasCompleteToolchain / 补丁检查）。 */
        private val FLUTTER_RE_REQUIRED = listOf(
            "setup.sh",                            // FBox 的 hasCompleteToolchain 也校验它（见其报错原文）
            "blutter/blutter.py",
            "blutter/dartvm_fetch_build.py",
            "blutter/extract_dart_info.py",
            "blutter/blutter/src/DartTypes.cpp",   // 承载 FBOX_UNKNOWN_ABSTRACT_TYPE 补丁
            "blutter/blutter/src/ElfHelper.cpp",   // 承载 BLUTTER_DART_SINGLE_SNAPSHOT 补丁
            "blutter/scripts/CMakeLists.txt"
        )

        /** 需要持久化的用户产出目录名（容器内 /root/<name>，宿主 filesDir/reverse/<name>）。 */
        private val PERSISTENT_DIRS = listOf("knowledge", "patches", "ai-skills")

        /** 内置技能 id（assets/reverse/skills/<id>.md）。 */
        private val BUILTIN_SKILLS = listOf("apk-re", "flutter-re")
    }

    // ---------------------------------------------------------------- 路径

    /** 容器内 root（= rootfs/root），随 profile 变化。 */
    private fun containerRoot(profile: ContainerProfile): File =
        File(containerInstaller.rootfsDirFor(profile), "root")

    fun apkToolDir(profile: ContainerProfile): File = File(containerRoot(profile), "apk-tool")
    fun soToolDir(profile: ContainerProfile): File = File(containerRoot(profile), "so-tool")
    fun flutterReDir(profile: ContainerProfile): File = File(containerRoot(profile), "flutter-re")

    /** App 侧 blutter 调度配置目录（runners.json / frida.template.js），由 BlutterRunnerService 使用。 */
    fun blutterConfigDir(): File = File(context.filesDir, "$ASSET_DIR/blutter").apply { mkdirs() }

    /** 持久目录宿主根（`filesDir/reverse`），承载用户产出。 */
    fun persistentRoot(): File = File(context.filesDir, ASSET_DIR).apply { mkdirs() }

    /**
     * 供 [LinuxContainerEngine.buildBaseProotArgv] 拼 `-b` 的持久挂载对（`宿主源:容器目标`）。
     *
     * 只含**用户产出**（知识库 / 补丁柜 / 自定义技能）：这些不可重建，rootfs 重装即丢。
     * 工具链（apk-tool / so-tool / flutter-re）不在此列 —— 走 [ensureInstalled] 自愈。
     *
     * 注意 proot 的 `-b` 要求**源路径已存在**，故此处顺带 mkdirs（对齐 FBox
     * `MountedFoldersStore.materializeMountTargets()` 与 AiCode 自身 aicodeDir 的做法）。
     */
    fun persistentBindings(): List<String> = PERSISTENT_DIRS.map { name ->
        val host = File(persistentRoot(), name).apply { mkdirs() }
        "${host.absolutePath}:/root/$name"
    }

    /** 容器内持久目录的宿主路径，供 `WorkspacePathMapper` 做反向映射。 */
    fun persistentHostDir(containerName: String): File = File(persistentRoot(), containerName)

    // ---------------------------------------------------------------- 安装

    /**
     * 按需释放全部资产到容器内 `/root/`；已就绪则快速返回。幂等，可在每次进容器前调用。
     *
     * [force] 为 true 时忽略版本标记强制重解（排障用）。
     */
    fun ensureInstalled(
        profile: ContainerProfile = ContainerProfile.BUILTIN_ALPINE,
        force: Boolean = false
    ) {
        val root = containerRoot(profile)
        if (!containerInstaller.rootfsDirFor(profile).isDirectory) {
            // rootfs 还没装好，跳过（安装流程结束后会再调一次）
            FileLogger.d(TAG, "rootfs 未就绪，跳过逆向资产释放：${containerInstaller.rootfsDirFor(profile)}")
            return
        }
        root.mkdirs()

        val apkTool = apkToolDir(profile)
        val marker = File(apkTool, ".version")
        // 就绪判断必须是**纯检查**（不能带安装副作用），否则会漏装后续资产。
        // 校验真实文件而非只信 marker：rootfs 若被重装，marker 随 rootfs 一起消失，自然触发重解。
        val flutterReReady = FLUTTER_RE_REQUIRED.all { File(flutterReDir(profile), it).isFile }
        val upToDate = !force &&
            marker.isFile && marker.readText().trim() == ASSETS_VERSION &&
            File(apkTool, "apk_tool.py").isFile &&
            File(apkTool, "reapk/api.py").isFile &&
            File(soToolDir(profile), "so_tool.py").isFile &&
            File(containerInstaller.aicodeDir, "skills/apk-re/SKILL.md").isFile &&
            flutterReReady

        if (upToDate) {
            FileLogger.d(TAG, "逆向资产已是当前版本（$ASSETS_VERSION），跳过")
            return
        }

        val startedAt = System.currentTimeMillis()
        try {
            installApkTool(profile)
            installSoTool(profile)
            installFlutterReHealing(profile)
            installSkills()
            installBlutterConfig()
            marker.parentFile?.mkdirs()
            marker.writeText(ASSETS_VERSION)
            FileLogger.i(
                TAG,
                "逆向资产释放完成（版本 $ASSETS_VERSION，耗时 ${System.currentTimeMillis() - startedAt}ms，" +
                    "目标=${root.absolutePath}）"
            )
        } catch (e: Exception) {
            FileLogger.e(TAG, "逆向资产释放失败（耗时 ${System.currentTimeMillis() - startedAt}ms）", e)
            throw e
        }
    }

    // ---------------------------------------------------------------- 各资产

    /** apk_tool.py + reapk 依赖包（两者必须同目录，apk_tool.py 里是 `from reapk import …`）。 */
    private fun installApkTool(profile: ContainerProfile) {
        val dest = apkToolDir(profile)
        copyAssetFile("$ASSET_DIR/apk_tool/apk_tool.py", File(dest, "apk_tool.py"))
        copyAssetTree("$ASSET_DIR/apk_tool/reapk", File(dest, "reapk"))
    }

    private fun installSoTool(profile: ContainerProfile) {
        val dest = soToolDir(profile)
        copyAssetFile("$ASSET_DIR/so_tool/so_tool.py", File(dest, "so_tool.py"))
    }

    /** flutter-re.tar → /root/flutter-re/。带逐项自愈：缺任一必需文件即整包覆盖重解。 */
    private fun installFlutterReHealing(profile: ContainerProfile) {
        val dest = flutterReDir(profile)
        if (FLUTTER_RE_REQUIRED.all { File(dest, it).isFile }) return
        dest.deleteRecursively()
        runCatching { installFlutterRe(profile) }.onFailure {
            FileLogger.e(
                TAG,
                "flutter-re 版本自愈失败：覆盖后容器 blutter 源码仍未包含所需兼容补丁" +
                    "（BLUTTER_DART_SINGLE_SNAPSHOT / FBOX_UNKNOWN_ABSTRACT_TYPE），" +
                    "请检查 assets/reverse/flutter-re.tar 是否已内置对应补丁",
                it
            )
        }
    }

    /**
     * 解压 flutter-re.tar 到 `/root/flutter-re/`。
     *
     * 资产虽名为 `.tar`，实为 **gzip 压缩**（魔数 `1f 8b`，与 FBox APK 内一致），故走 GZIP。
     * 复用 [ContainerInstaller.extractRootfsTo]：它已正确处理目录 / 符号链接 / 硬链接 / 权限位
     * （blutter 源码树里有 symlink 与可执行脚本，必须走这条而不是普通 copy）。
     */
    private fun installFlutterRe(profile: ContainerProfile) {
        val dest = flutterReDir(profile)
        dest.mkdirs()
        context.assets.open("$ASSET_DIR/flutter-re.tar").use { input: InputStream ->
            val n = containerInstaller.extractRootfsTo(
                destDir = dest,
                input = input,
                format = ContainerInstaller.CompressedFormat.GZIP,
                onProgress = {}
            )
            FileLogger.i(TAG, "flutter-re 解压完成：$n 个条目 → ${dest.absolutePath}")
        }
    }

    /**
     * 内置技能：`assets/reverse/skills/<id>/SKILL.md` → `~/.aicode/skills/<id>/SKILL.md`。
     *
     * 落在 AiCode 的**全局技能根**（`filesDir/aicode/skills`，容器内 `~/.aicode/skills`）：
     * 该目录经 proot `-b` 持久绑定，与 rootfs 重装无关，故不参与自愈重解。
     * 格式要求 `SKILL.md` + frontmatter（`name`/`description`），已在资产内准备好。
     */
    private fun installSkills() {
        val base = File(containerInstaller.aicodeDir, "skills")
        BUILTIN_SKILLS.forEach { id ->
            val src = "$ASSET_DIR/skills/$id/SKILL.md"
            if (!assetExists(src)) return@forEach
            copyAssetFile(src, File(File(base, id), "SKILL.md"))
        }
    }

    /** App 侧 blutter 调度配置（不落沙箱）。 */
    private fun installBlutterConfig() {
        val dir = blutterConfigDir()
        listOf("runners.json", "frida.template.js").forEach { name ->
            val src = "$ASSET_DIR/blutter/$name"
            if (assetExists(src)) copyAssetFile(src, File(dir, name))
        }
    }

    // ---------------------------------------------------------------- 工具

    /** 递归拷贝 assets 目录（走 assets.list，避免 AGP 打包后 File 路径不可用）。 */
    private fun copyAssetTree(assetPath: String, destDir: File) {
        val children = context.assets.list(assetPath).orEmpty()
        if (children.isEmpty()) {
            // 叶子节点：assets.list 对文件返回空数组，此时按文件处理
            if (assetExists(assetPath)) {
                copyAssetFile(assetPath, destDir)
                return
            }
        }
        destDir.mkdirs()
        children.forEach { child ->
            val childAsset = "$assetPath/$child"
            val childDest = File(destDir, child)
            val grandChildren = context.assets.list(childAsset).orEmpty()
            if (grandChildren.isEmpty()) copyAssetFile(childAsset, childDest)
            else copyAssetTree(childAsset, childDest)
        }
    }

    private fun copyAssetFile(assetPath: String, dest: File) {
        dest.parentFile?.mkdirs()
        context.assets.open(assetPath).use { input ->
            dest.outputStream().use { output -> input.copyTo(output) }
        }
    }

    private fun assetExists(path: String): Boolean {
        val dir = path.substringBeforeLast('/', "")
        val name = path.substringAfterLast('/')
        return runCatching { context.assets.list(dir).orEmpty().contains(name) }.getOrDefault(false)
    }
}
