package com.aicode.feature.agent.domain.reverse

import android.content.Context
import android.content.Intent
import com.aicode.core.util.FileLogger
import com.zuimo.fbox.blutterrunner.BlutterRunnerService
import dagger.hilt.android.qualifiers.ApplicationContext
import java.io.File
import java.util.zip.ZipFile
import javax.inject.Inject
import javax.inject.Singleton
import kotlinx.coroutines.delay
import kotlinx.serialization.Serializable
import kotlinx.serialization.json.Json

/**
 * Blutter Runner 快通道：Dart 快照 hash 探测 → runners.json 匹配 → :blutter 进程执行。
 *
 * 全流程对齐 FBox（tryFastAnalyze / runRunnerIsolated / BlutterRunnerService）：
 * 1. 解 APK 取 libapp.so + libflutter.so（**libapp_dir 必须是 libapp.so 所在目录**，MINIS-PORT 坑 ③）；
 * 2. 从 libapp.so 提取 Dart snapshot hash（魔数 f5 f5 dc dc + 偏移 +20 处 32 字节 hex，
 *    块间重叠 64 字节防跨界漏检，对齐 FBox SnapshotHash.extract）；
 * 3. hash 与 assets/blutter/runners.json 的 snapshotHashes 求交集 → 命中即得 runner 库名；
 * 4. Intent 显式启动 :blutter 进程的 BlutterRunnerService（extras 同 FBox：runner/libapp_dir/
 *    out_dir/libflutter/log/result/hash），轮询结果 JSON（180s 超时、>8s 探活）；
 * 5. 崩溃/超时 → 拉黑该 hash（本会话不再重试，直接走容器编译路线）。
 */
@Singleton
class BlutterRunnerExecutor @Inject constructor(
    @param:ApplicationContext private val context: Context
) {
    private companion object {
        const val TAG = "BlutterRunner"
        const val MAGIC_0 = 0xF5.toByte()
        const val MAGIC_1 = 0xF5.toByte()
        const val MAGIC_2 = 0xDC.toByte()
        const val MAGIC_3 = 0xDC.toByte()
        /** 主进程等待 runner 的总超时。实测 17MB 的 APK 约 55s，大包留足余量。 */
        const val WAIT_TIMEOUT_MS = 300_000L
        const val POLL_INTERVAL_MS = 500L
        /** 每隔多久探一次 :blutter 进程是否还活着（死了就不必等满超时）。 */
        const val ALIVE_PROBE_MS = 8_000L
        /** hash 拉黑缓存（会话级；跨进程重启即清，FBox 同策略）。 */
    }

    /** runners.json 的一条 runner 记录。 */
    @Serializable
    data class Runner(
        val library: String,
        val dartVersion: String,
        val snapshotHashes: List<String> = emptyList(),
        val supported: Boolean = true
    )

    @Serializable
    data class RunResult(val code: Int, val error: String = "")

    private val blacklisted = mutableSetOf<String>()

    /** 快通道是否可用（runner 资产是否打进 APK）。 */
    fun isAvailable(): Boolean = runnerList().isNotEmpty()

    private fun runnerList(): List<Runner> = runCatching {
        val json = context.assets.open("blutter/runners.json").bufferedReader().use { it.readText() }
        val obj = Json { ignoreUnknownKeys = true }
            .decodeFromString(kotlinx.serialization.json.JsonObject.serializer(), json)
        Json { ignoreUnknownKeys = true }.decodeFromString<List<Runner>>(obj["runners"].toString())
    }.getOrElse {
        FileLogger.w(TAG, "解析 runners.json 失败", it)
        emptyList()
    }

    /**
     * 从 libapp.so 提取 Dart snapshot hash 集合。
     * 特征：4 字节魔数 f5 f5 dc dc；hash = 魔数起 +20 处连续 32 个 [0-9a-g] 字节。
     * 扫描前 8 MB（FBox 同值），块间重叠 64 字节防 hash 跨 64KB 块漏检。
     */
    fun extractSnapshotHashes(libapp: File): Set<String> {
        val out = LinkedHashSet<String>()
        runCatching {
            val scanLen = minOf(libapp.length(), 8L * 1024 * 1024).toInt()
            val buf = ByteArray(64 * 1024)
            var filePos = 0L
            java.io.RandomAccessFile(libapp, "r").use { raf ->
                while (filePos < scanLen) {
                    raf.seek(filePos)
                    val n = raf.read(buf)
                    if (n < 4) break
                    var i = 0
                    while (i <= n - 4) {
                        if (buf[i] == MAGIC_0 && buf[i + 1] == MAGIC_1 &&
                            buf[i + 2] == MAGIC_2 && buf[i + 3] == MAGIC_3
                        ) {
                            val abs = filePos + i
                            if (abs + 20 + 32 <= libapp.length()) {
                                raf.seek(abs + 20)
                                val h = ByteArray(32)
                                raf.readFully(h)
                                var ok = true
                                for (b in h) {
                                    val c = b.toInt().toChar()
                                    if (!((c in '0'..'9') || (c in 'a'..'f'))) { ok = false; break }
                                }
                                if (ok) out.add(String(h))
                            }
                        }
                        i++
                    }
                    filePos += n - 64 // 重叠 64 字节
                }
            }
        }.onFailure { FileLogger.w(TAG, "提取 snapshot hash 失败", it) }
        return out
    }

    /** hash → runner；未命中/null 返回 null。黑名单内的直接跳过。 */
    fun selectRunner(hashes: Set<String>): Runner? {
        if (hashes.isEmpty()) return null
        // 归一化比较（trim + 小写）：提取端与注册表任一侧的格式漂移都不应导致漏配
        val norm = hashes.map { it.trim().lowercase() }.toSet()
        return runnerList().firstOrNull { r ->
            r.supported && r.snapshotHashes.any { it.trim().lowercase() in norm } && r.library !in blacklisted
        }
    }

    /**
     * 执行快通道。返回 null=启动失败/超时/崩溃（调用方回退容器编译路线）；
     * 非 null=退出码（0 成功）。
     */
    suspend fun execute(
        apkName: String,
        libappDir: File,
        libappFile: File,
        libflutterFile: File?,
        outDir: File,
        onLog: (String) -> Unit
    ): Int? {
        val startedAt = System.currentTimeMillis()
        val hashes = extractSnapshotHashes(libappFile)
        if (hashes.isEmpty()) {
            onLog("⚠ 未在 libapp.so 提取到 Dart snapshot hash（可能已加固）")
            return null
        }
        onLog("✓ Dart snapshot hash: ${hashes.take(2).joinToString()}")
        val runner = selectRunner(hashes)
        if (runner == null) {
            val all = runnerList()
            val blackHit = all.firstOrNull { it.library in blacklisted && it.snapshotHashes.any { h -> h in hashes } }
            onLog("⚠ hash 未命中内置 Runner（提取=${hashes.joinToString()}，注册表=${all.size} 条，" +
                "黑名单=${blacklisted.joinToString().ifEmpty { "空" }}）")
            if (blackHit != null) {
                onLog("　→ 实际是被拉黑：${blackHit.library}（Dart ${blackHit.dartVersion}）；重进应用可清黑名单重试")
            } else {
                onLog("　→ Dart 版本不在内置覆盖范围（2.14.0–3.12.0），走容器编译路线")
            }
            return null
        }
        onLog("✓ 命中内置 Runner：${runner.library}（Dart ${runner.dartVersion}），启动 :blutter 进程…")

        val resultFile = File(context.cacheDir, "blutter_run_result_${System.currentTimeMillis()}.json")
        val heartbeatFile = File(context.cacheDir, "blutter_run_heartbeat.json")
        val logFile = File(outDir, "runner.log")
        resultFile.delete()
        heartbeatFile.delete()

        val intent = Intent(context, BlutterRunnerService::class.java).apply {
            putExtra("runner", runner.library)
            putExtra("libapp_dir", libappDir.absolutePath)
            putExtra("out_dir", outDir.absolutePath)
            putExtra("libflutter", libflutterFile?.absolutePath ?: "")
            putExtra("log", logFile.absolutePath)
            putExtra("result", resultFile.absolutePath)
            putExtra("heartbeat", heartbeatFile.absolutePath)
            putExtra("hash", hashes.first())
        }
        val started = runCatching { context.startService(intent) }.isSuccess
        if (!started) {
            FileLogger.e(TAG, "启动 :blutter 服务失败")
            onLog("✗ 无法启动 :blutter 进程")
            return null
        }

        // 轮询结果（结果文件 → 心跳 → 产物信号，三者任一可判定状态）
        val deadline = System.currentTimeMillis() + WAIT_TIMEOUT_MS
        while (System.currentTimeMillis() < deadline) {
            // ① 结果文件到 = 最终裁决（优先级最高）
            if (resultFile.isFile) {
                val r = runCatching {
                    Json { ignoreUnknownKeys = true }.decodeFromString<RunResult>(resultFile.readText())
                }.getOrNull()
                if (r != null) {
                    if (r.code == 0) {
                        blacklisted.remove(runner.library)
                        onLog("✓ Runner 执行完成（exit 0，耗时 ${(System.currentTimeMillis() - startedAt) / 1000}s）")
                    } else {
                        blacklisted.add(runner.library)
                        onLog("✗ Runner 退出码 ${r.code} ${r.error}")
                    }
                    resultFile.delete()
                    return r.code
                }
            }

            // ② 产物信号（runner 不写 .analyzed_meta，用产物文件当心跳）
            // ③ 判定死亡：无结果文件、无心跳、也无产物时才能拉黑放弃
            // 这里不再依赖 /proc（Android 12 上跨进程 cmdline 常读到空串，会把活着的 runner 误判为崩溃）。
            if (!resultFile.isFile && !heartbeatFresh(heartbeatFile) && !hasOutputSignal(outDir)) {
                onLog("✗ :blutter 进程已无心跳且无结果文件（native 崩溃，拉黑该 runner）")
                blacklisted.add(runner.library)
                return null
            }

            // 顺带把 runner 日志 tail 给浮窗
            tailRunnerLog(logFile, onLog)
            delay(POLL_INTERVAL_MS)
        }
        onLog("✗ Runner 执行超时（${WAIT_TIMEOUT_MS / 1000}s）")
        blacklisted.add(runner.library)
        return null
    }

    /** runner.log 增量 tail：读文件末尾几行喂给 onLog（去重由调用方的 lastLine 承担）。 */
    private var lastLogLen = 0L
    private fun tailRunnerLog(logFile: File, onLog: (String) -> Unit) {
        runCatching {
            if (!logFile.isFile) return
            val len = logFile.length()
            if (len > lastLogLen) {
                logFile.inputStream().use { ins ->
                    ins.skip(lastLogLen)
                    ins.readBytes().toString(Charsets.UTF_8).lineSequence()
                        .map { it.trim() }
                        .filter { it.isNotEmpty() }
                        .forEach(onLog)
                }
                lastLogLen = len
            }
        }.onFailure { lastLogLen = 0 }
    }

    /**
     * 心跳是否新鲜。Service 侧每 2s 改写一次心跳文件，故允许 ALIVE_PROBE_MS 的宽限；
     * 文件不存在（旧 Service/异常）视为「无法证明死亡」，也返回 true，宁可等超时。
     */
    private fun heartbeatFresh(heartbeatFile: File): Boolean {
        if (!heartbeatFile.isFile) return true
        val ts = runCatching { heartbeatFile.readText().trim().toLong() }.getOrNull() ?: return true
        return System.currentTimeMillis() - ts < ALIVE_PROBE_MS
    }

    /** 产物信号：outDir 里已出现任何 blutter 产物（pp.txt / asm/ / objs.txt）＝ runner 正常工作。 */
    private fun hasOutputSignal(outDir: File): Boolean =
        runCatching {
            File(outDir, "pp.txt").let { it.isFile && it.length() > 0 } ||
                (File(outDir, "asm").isDirectory && File(outDir, "asm").listFiles()?.isNotEmpty() == true) ||
                File(outDir, "objs.txt").let { it.isFile && it.length() > 0 }
        }.getOrDefault(false)

    /** 解 APK 抽 libapp.so / libflutter.so 到 [baseDir]/lib/arm64-v8a/。返回 (libappDir, libapp, libflutter)。 */
    fun extractFlutterLibs(apkFile: File, baseDir: File): Triple<File, File, File?>? {
        runCatching {
            val dest = File(baseDir, "lib/arm64-v8a")
            val want = listOf("lib/arm64-v8a/libapp.so", "lib/arm64-v8a/libflutter.so")
            ZipFile(apkFile).use { z ->
                for (name in want) {
                    val e = z.getEntry(name) ?: continue
                    val out = File(baseDir, name)
                    out.parentFile?.mkdirs()
                    if (!out.isFile || out.length() != e.size) {
                        z.getInputStream(e).use { ins -> out.outputStream().use { ins.copyTo(it) } }
                    }
                }
            }
            val libapp = File(dest, "libapp.so")
            if (!libapp.isFile) return null
            return Triple(dest, libapp, File(dest, "libflutter.so").takeIf { it.isFile })
        }.onFailure { FileLogger.w(TAG, "解压 Flutter libs 失败", it) }
        return null
    }
}
