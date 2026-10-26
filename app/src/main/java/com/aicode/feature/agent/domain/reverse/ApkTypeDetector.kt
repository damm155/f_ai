package com.aicode.feature.agent.domain.reverse

import java.io.File
import java.util.zip.ZipFile

/** APK 目标类型。 */
enum class ApkTargetKind {
    /** 含 Flutter 特征（`libapp.so` / `libflutter.so` / `assets/flutter_assets/`）。 */
    FLUTTER,

    /** 原生应用（Java/Kotlin DEX 层）。 */
    NATIVE
}

/**
 * 判定 APK 是 Flutter 应用还是原生应用（对齐 FBox `LinuxViewModel.checkApkIsFlutter`）。
 *
 * 只遍历 ZIP 中央目录的**条目名**——不解压、不读 AndroidManifest、不解析 so，毫秒级返回。
 * 这与 FBox 的做法一致：它在 `flReApkDir()` 下打开 `ZipFile`，对每个 entry 名记三条标志位，
 * 三者齐备才判定为 Flutter：
 *
 * 1. 以 `assets/flutter_assets/` 开头；
 * 2. 以 `/libflutter.so` 结尾（或整名等于 `libflutter.so`）；
 * 3. 以 `/libapp.so` 结尾（或整名等于 `libapp.so`）。
 *
 * 用「齐备」而非「任一命中」是有意的：`libflutter.so` 单独出现不足以说明是 Flutter 目标
 * （存在只打包了引擎片段、或资源里残留同名文件的包），而三者齐备是 Flutter 产物的稳定特征。
 *
 * 判定失败（文件不存在、长度为 0、不是合法 ZIP）一律按 [ApkTargetKind.NATIVE] 处理，
 * 与 FBox 相同——宁可走通用 DEX 链，也不要在证据不足时把人送去几分钟的 blutter 编译。
 */
object ApkTypeDetector {

    private const val FLUTTER_ASSETS_PREFIX = "assets/flutter_assets/"
    private const val LIBFLUTTER = "libflutter.so"
    private const val LIBFLUTTER_SUFFIX = "/libflutter.so"
    private const val LIBAPP = "libapp.so"
    private const val LIBAPP_SUFFIX = "/libapp.so"

    /** 判定宿主上的 APK 文件。 */
    fun detect(apk: File): ApkTargetKind {
        if (!apk.isFile || apk.length() == 0L) return ApkTargetKind.NATIVE
        return runCatching {
            ZipFile(apk).use { zip ->
                var hasFlutterAssets = false
                var hasLibflutter = false
                var hasLibapp = false
                val entries = zip.entries()
                while (entries.hasMoreElements()) {
                    val name = entries.nextElement().name
                    if (!hasFlutterAssets && name.startsWith(FLUTTER_ASSETS_PREFIX)) {
                        hasFlutterAssets = true
                    }
                    if (!hasLibflutter && (name.endsWith(LIBFLUTTER_SUFFIX) || name == LIBFLUTTER)) {
                        hasLibflutter = true
                    }
                    if (!hasLibapp && (name.endsWith(LIBAPP_SUFFIX) || name == LIBAPP)) {
                        hasLibapp = true
                    }
                    if (hasFlutterAssets && hasLibflutter && hasLibapp) return ApkTargetKind.FLUTTER
                }
                ApkTargetKind.NATIVE
            }
        }.getOrDefault(ApkTargetKind.NATIVE)
    }
}
