package com.zuimo.fbox.blutterrunner

/**
 * Blutter Runner JNI 桥（移植自 FBox，**包名与类名必须原样保留**）。
 *
 * 原因：18 个预编译 runner（libfbox_blutter_2_14_0.so … libfbox_blutter_3_12_0.so）以
 * **JNI 静态注册**方式导出符号，符号名在编译期就定死为
 * `Java_com_zuimo_fbox_blutterrunner_BlutterJni_nativeRun` 等——改包名/类名即
 * `UnsatisfiedLinkError`（MINIS-PORT.md 第 5 轮实录坑 ①）。
 *
 * 线程约定：[nativeRun] 是**阻塞**调用（整个 blutter 分析跑完才返回），必须在子线程调；
 * [nativeLastError] 在 nativeRun 返回非 0 后调，取 native 侧错误描述。
 */
object BlutterJni {
    /**
     * 加载指定 runner。入参是 **loadLibrary 名**（不带 lib 前缀 / .so 后缀），
     * 例如 `"fbox_blutter_3_5_0"`。so 必须在 `nativeLibraryDir`（由 jniLibs 打包自动满足）。
     * 同一进程内重复 load 不同 runner 会失败（JNI 静态注册符号冲突）——因此每个 runner
     * 跑在独立进程（:blutter）里，一个进程只 load 一次。
     */
    fun load(libraryName: String): Boolean =
        runCatching {
            System.loadLibrary(libraryName)
            true
        }.getOrDefault(false)

    /**
     * 阻塞执行 blutter 分析。
     *
     * @param libappDir **libapp.so 所在目录**（不是 APK、不是解压根目录！）——
     *   传错导致 mmap 快照失败、native 直接 SIGSEGV（MINIS-PORT 坑 ③）。
     * @param outDir 分析输出目录（pp.txt / asm/ / objs.txt 写这里）
     * @param libflutter libflutter.so 的绝对路径（Dart 版本信息来源）
     * @param logPath 进度日志文件（native 逐行追加，主进程 tail 它刷新浮窗）
     * @return 退出码：0=成功；非 0 时用 [nativeLastError] 取错误
     */
    private external fun nativeRun(
        libappDir: String,
        outDir: String,
        libflutter: String,
        logPath: String
    ): Int

    /** 取最近一次 nativeRun 的错误描述；无错误时为空串。 */
    private external fun nativeLastError(): String

    /** 供 Service 调用的封装：写结果 JSON 前的最后一步。 */
    fun run(libappDir: String, outDir: String, libflutter: String, logPath: String): Int =
        try {
            nativeRun(libappDir, outDir, libflutter, logPath)
        } catch (t: UnsatisfiedLinkError) {
            -99
        }

    fun lastError(): String =
        try { nativeLastError() } catch (_: Throwable) { "" }
}
