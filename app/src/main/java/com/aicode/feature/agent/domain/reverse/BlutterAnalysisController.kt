package com.aicode.feature.agent.domain.reverse

import android.content.Context
import com.aicode.core.util.FileLogger
import com.aicode.feature.agent.domain.container.CommandEngine
import com.aicode.feature.agent.domain.container.CommandEvent
import com.aicode.feature.workspace.domain.WorkspacePathMapper
import dagger.hilt.android.qualifiers.ApplicationContext
import java.io.File
import javax.inject.Inject
import androidx.lifecycle.ViewModel
import androidx.lifecycle.viewModelScope
import kotlinx.coroutines.Job
import kotlinx.coroutines.delay
import kotlinx.coroutines.isActive
import kotlinx.coroutines.flow.MutableStateFlow
import kotlinx.coroutines.flow.StateFlow
import kotlinx.coroutines.flow.asStateFlow
import kotlinx.coroutines.launch

/**
 * Blutter 本地分析控制器（对齐 FBox 的「Blutter 解析 Dart AOT（本地执行，不消耗 AI 额度）」）。
 *
 * 职责：
 * 1. 持有分析进度状态（[state]），供输入框上方的进度浮窗订阅渲染；
 * 2. 选定「Flutter 应用」线路后由 UI 调 [start]：
 *    - 先试 **Runner So 快通道**（:blutter 独立进程，秒级，零联网零 token）；
 *    - 未命中/失败自动回退 **容器编译路线**（aicode-blutter，40 分钟上限）；
 * 3. 日志逐行回灌浮窗；完成后 UI 决定下一步（不自动发消息——用户主导，见 MINIS-PORT 第 5 轮）。
 */
@dagger.hilt.android.lifecycle.HiltViewModel
class BlutterAnalysisController @Inject constructor(
    private val commandEngine: CommandEngine,
    private val pathMapper: WorkspacePathMapper,
    private val runnerExecutor: BlutterRunnerExecutor,
    @ApplicationContext private val context: Context
) : ViewModel() {
    private companion object {
        const val TAG = "BlutterAnalysis"
        const val TIMEOUT_MS = 40L * 60 * 1000
    }

    private val scope = viewModelScope
    private var job: Job? = null
    @Volatile private var runGeneration = 0L

    private val _state = MutableStateFlow(BlutterUiState.idle())
    val state: StateFlow<BlutterUiState> = _state.asStateFlow()

    /** 宿主 rootfs 根（容器内 / 的实体；容器 /root 即其 root/ 子目录）。 */
    private fun hostRootfs(): File = File(context.filesDir, "rootfs")


    private suspend fun <T> withContextIO(block: () -> T): T =
        kotlinx.coroutines.withContext(kotlinx.coroutines.Dispatchers.IO) { block() }

    /**
     * 把容器内路径还原为**宿主真实路径**（App 侧 File 直接可读）。
     *
     * 附件的容器路径形如 `~/workspace/.aicode/attachments/x.apk`（`~` = /root），
     * 经 WorkspacePathMapper 的挂载表翻回宿主 `files/projects/<项目>/.aicode/attachments/x.apk`。
     * **不再用 shell cp**——附件源在 rootfs 之外，靠容器 cp 要处理 `~` 展开与引号转义，易错；
     * 宿主两侧（工作区文件 ↔ rootfs/root/apk/）App 直接读写，一条 File.copyTo 搞定。
     */
    private fun hostFileOf(containerPath: String): File? = runCatching {
        pathMapper.toHostFile(containerPath)
    }.getOrNull()

    /**
     * 启动一次 Blutter 分析（幂等保护：已在跑则忽略）。
     *
     * [apkContainerPath] 为**容器内路径**（如 ~/workspace/.aicode/attachments/x.apk）。
     */
    fun start(apkContainerPath: String, sessionId: String? = null): Boolean {
        if (_state.value.running || job?.isActive == true) {
            FileLogger.w(TAG, "已有分析在跑，忽略本次请求: $apkContainerPath")
            return false
        }
        val generation = ++runGeneration
        val name = apkContainerPath.substringAfterLast('/').replace(Regex("(?i)\\.apk$"), "")
        _state.value = BlutterUiState(
            apkName = name,
            outDir = "/root/out/$name",
            phase = BlutterPhase.PREPARING,
            route = BlutterRoute.CONTAINER_BUILD,
            running = true,
            sessionId = sessionId
        )
        job = scope.launch {
            val startedAt = System.nanoTime()
            val ticker = launch {
                while (isActive) {
                    delay(1_000L)
                    if (runGeneration == generation) {
                        _state.value = _state.value.copy(elapsedMs = (System.nanoTime() - startedAt) / 1_000_000)
                    }
                }
            }
            val lines = StringBuilder()
            var exitCode: Int? = null
            fun append(line: String) {
                if (line.isBlank() || runGeneration != generation) return
                lines.appendLine(line)
                _state.value = _state.value.copy(log = lines.toString(), lastLine = line, phase = phaseOf(line))
            }
            try {
                // ── 预置 APK：宿主侧直接复制（附件 ↔ rootfs/root/apk/ 之间），零 shell ──
                val hostApk = stageApk(apkContainerPath, name, ::append)
                if (hostApk == null) {
                    _state.value = _state.value.copy(
                        running = false,
                        phase = BlutterPhase.FAILED,
                        resultSummary = "APK 复制失败：附件路径无法映射到宿主（$apkContainerPath）。" +
                            "请确认已上传附件且容器就绪。"
                    )
                    return@launch
                }

                val matchingResult = withContextIO {
                    hasMatchingBlutterResult(hostApk, File(hostRootfs(), "root/out/$name"))
                }
                if (matchingResult) {
                    _state.value = _state.value.copy(
                        running = false,
                        phase = BlutterPhase.DONE,
                        reusedResult = true,
                        resultSummary = context.getString(com.aicode.R.string.blutter_existing_result, "/root/out/$name")
                    )
                    return@launch
                }

                withContextIO {
                    recordBlutterCompletion(File(hostRootfs(), "root/out/$name"), false)
                }

                // ===== 快通道：Runner So（对齐 FBox tryFastAnalyze；秒级，不联网）=====
                if (runnerExecutor.isAvailable()) {
                    _state.value = _state.value.copy(route = BlutterRoute.RUNNER_SO)
                    append("〔快通道〕解 APK 抽取 libapp.so / libflutter.so…")
                    val extracted = withContextIO {
                        runnerExecutor.extractFlutterLibs(hostApk, File(hostRootfs(), "root/out/$name"))
                    }
                    if (extracted == null) {
                        append("⚠ Flutter so 提取失败，转容器编译路线")
                    } else {
                        val (libappDir, libapp, libflutter) = extracted
                        append("✓ libapp.so ${"%.1f".format(libapp.length() / 1048576f)}MB 已就位")
                        val outDir = File(hostRootfs(), "root/out/$name")
                        outDir.mkdirs()
                        // 清掉上一次分析残留的产物：否则「重跑同一个应用」时，
                        // hasProducts 会拿旧 pp.txt 当本次结果，把失败误报成成功。
                        listOf("pp.txt", "objs.txt", "asm", "runner.log").forEach { n ->
                            runCatching { File(outDir, n).deleteRecursively() }
                        }
                        val code = runnerExecutor.execute(
                            apkName = name,
                            libappDir = libappDir,
                            libappFile = libapp,
                            libflutterFile = libflutter,
                            outDir = outDir,
                            onLog = ::append
                        )
                        if (code != null) {
                            // native 返回 0 不等于真的产出：:blutter 进程复用、目录已有产物时
                            // 会在毫秒级直接返回 0。必须用 pp.txt/asm/ 作为成功的硬证据。
                            val produced = hasBlutterProducts(outDir)
                            val ok = code == 0 && produced
                            if (ok) withContextIO { recordBlutterCompletion(outDir, true) }
                            if (code == 0 && !produced) {
                                append("⚠ Runner 返回 0 但未产出 pp.txt/asm（耗时过短，实际未完成）")
                            }
                            _state.value = _state.value.copy(
                                running = false,
                                phase = if (ok) BlutterPhase.DONE else BlutterPhase.FAILED,
                                exitCode = code,
                                resultSummary = when {
                                    ok -> "Runner 分析完成：/root/out/$name/（pp.txt / asm/ / objs.txt）"
                                    code == 0 -> "Runner 未产出结果（exit 0 但无 pp.txt/asm），可重试或走容器编译路线"
                                    else -> "Runner 退出码 $code（已记录黑名单，可回退容器编译路线）"
                                }
                            )
                            return@launch
                        }
                        // 慢通道前置刹车：runner 可能已产出部分/全部产物（如误判后放弃），有则直接认领
                        if (hasBlutterProducts(outDir)) {
                            _state.value = _state.value.copy(
                                running = false,
                                phase = BlutterPhase.DONE,
                                resultSummary = "Runner 已产出结果（进程放弃前完成）：/root/out/$name/（pp.txt / asm/ / objs.txt）"
                            )
                            return@launch
                        }
                        append("〔快通道未走通〕转容器编译路线（较慢，首次需联网拉 Dart SDK）")
                        _state.value = _state.value.copy(route = BlutterRoute.CONTAINER_BUILD)
                    }
                } else {
                    _state.value = _state.value.copy(route = BlutterRoute.CONTAINER_BUILD)
                }

                // ===== 慢通道：容器编译路线（aicode-blutter；APK 已在 /root/apk/）=====
                val quotedApk = "'/root/apk/${name.replace("'", "'\\''")}.apk'"
                val flow = commandEngine.runCommandStream(
                    "aicode-blutter $quotedApk",
                    projectPath = null,
                    timeoutMs = TIMEOUT_MS
                )
                flow.collect { ev ->
                    when (ev) {
                        is CommandEvent.Line -> {
                            val line = ev.text
                            lines.appendLine(line)
                            _state.value = _state.value.copy(
                                log = lines.toString(),
                                phase = phaseOf(line),
                                lastLine = line
                            )
                        }
                        is CommandEvent.Exit -> exitCode = ev.code
                    }
                }
                val ok = exitCode == 0 && withContextIO { hasBlutterProducts(File(hostRootfs(), "root/out/$name")) }
                if (ok) withContextIO { recordBlutterCompletion(File(hostRootfs(), "root/out/$name"), true) }
                _state.value = _state.value.copy(
                    running = false,
                    phase = if (ok) BlutterPhase.DONE else BlutterPhase.FAILED,
                    exitCode = exitCode,
                    resultSummary = if (ok)
                        "Blutter 分析完成：/root/out/$name/（pp.txt / asm/ / objs.txt）"
                    else
                        "Blutter 分析失败（exit=$exitCode）。常见原因：首次分析需联网拉 Dart SDK 失败；" +
                            "或该 Dart 版本未被 blutter 适配（走 aicode-so 兜底链）"
                )
            } catch (e: kotlinx.coroutines.CancellationException) {
                if (runGeneration == generation) _state.value = _state.value.copy(
                    running = false,
                    phase = BlutterPhase.FAILED,
                    resultSummary = "分析已取消"
                )
            } catch (e: Exception) {
                FileLogger.e(TAG, "Blutter 分析异常", e)
                if (runGeneration == generation) _state.value = _state.value.copy(
                    running = false,
                    phase = BlutterPhase.FAILED,
                    resultSummary = "分析异常：${e.message}"
                )
            } finally {
                ticker.cancel()
                if (runGeneration == generation) {
                    _state.value = _state.value.copy(elapsedMs = (System.nanoTime() - startedAt) / 1_000_000)
                }
            }
        }
        return true
    }

    /**
     * 把 APK 从附件目录复制到 /root/apk/<name>.apk（宿主两侧直拷）。
     *
     * 源路径解析顺序：
     * 1. [WorkspacePathMapper.toHostFile]（挂载表：workspace/.aicode → 宿主项目目录）；
     * 2. `~/` 前缀手工展开（mapper 不可用时的兜底，容错旧调用）；
     * 3. 已是宿主路径则直接用。
     * 成功后校验目标文件存在且非空，把失败暴露在 PREPARING 阶段而不是留给后续通道报「找不到」。
     */
    private suspend fun stageApk(
        apkContainerPath: String,
        name: String,
        onLog: (String) -> Unit
    ): File? = withContextIO {
        val dst = File(hostRootfs(), "root/apk/$name.apk").apply {
            parentFile?.mkdirs()
        }
        val src: File? = sequence {
            yield(runCatching { pathMapper.toHostFile(apkContainerPath) }.getOrNull())
            val expanded = apkContainerPath
                .replaceFirst("^~/?".toRegex(), hostRootfs().absolutePath + "/root/")
            yield(if (File(expanded).isFile) File(expanded) else null)
            val asHost = File(apkContainerPath)
            yield(if (asHost.isFile) asHost else null)
        }.filterNotNull().firstOrNull { it.isFile }

        if (src == null) {
            onLog("✗ 找不到源 APK：$apkContainerPath")
            return@withContextIO null
        }
        runCatching { if (src.canonicalFile != dst.canonicalFile) src.copyTo(dst, overwrite = true) }
            .onFailure {
                onLog("✗ APK 复制失败：${it.message}")
                return@withContextIO null
            }
        if (!dst.isFile || dst.length() == 0L) {
            onLog("✗ APK 复制后为空：${dst.absolutePath}")
            return@withContextIO null
        }
        onLog("✓ APK 已就位：/root/apk/$name.apk（${"%.1f".format(dst.length() / 1048576f)}MB）")
        dst
    }

    /** 取消当前分析（杀不掉 native，但能停掉轮询与流收集；浮窗显示已取消）。 */
    fun cancel() {
        runGeneration += 1
        job?.cancel()
        job = null
        _state.value = _state.value.copy(running = false, phase = BlutterPhase.FAILED, resultSummary = "已取消")
    }

    /** 关闭浮窗（重置回 IDLE）。 */
    fun dismiss() {
        runGeneration += 1
        job?.cancel()
        job = null
        _state.value = BlutterUiState.idle()
    }

    private fun phaseOf(line: String): BlutterPhase = when {
        line.contains("pip3 install", true) || line.contains("apt-get install", true) ||
            line.contains("Collecting", true) || line.contains("Downloading", true) -> BlutterPhase.PREPARE_ENV
        line.contains("cmake", true) || line.contains("ninja", true) ||
            line.contains("Configuring", true) || line.contains("Building", true) -> BlutterPhase.BUILDING
        line.contains("pp.txt", true) || line.contains("asm/", true) ||
            line.contains("objs.txt", true) || line.contains("分析完成", true) -> BlutterPhase.PRODUCING
        else -> BlutterPhase.ANALYZING
    }
}

/** 分析路线：内置 Runner So 快通道 / 容器编译慢通道。 */
enum class BlutterRoute { RUNNER_SO, CONTAINER_BUILD }

/** 分析阶段（浮窗标题/进度胶囊展示）。 */
enum class BlutterPhase(val label: String) {
    IDLE(""),
    PREPARING("准备中"),
    PREPARE_ENV("环境自愈（可能联网装依赖）"),
    ANALYZING("Blutter 解析中"),
    BUILDING("编译 Dart 快照解析器"),
    PRODUCING("产出分析结果"),
    DONE("分析完成"),
    FAILED("分析失败")
}

/** 浮窗状态。 */
data class BlutterUiState(
    val apkName: String = "",
    val outDir: String = "",
    val phase: BlutterPhase = BlutterPhase.IDLE,
    val route: BlutterRoute = BlutterRoute.CONTAINER_BUILD,
    val running: Boolean = false,
    val log: String = "",
    val lastLine: String = "",
    val exitCode: Int? = null,
    val resultSummary: String = "",
    val elapsedMs: Long = 0L,
    val reusedResult: Boolean = false,
    val sessionId: String? = null
) {
    val finished: Boolean get() = phase == BlutterPhase.DONE || phase == BlutterPhase.FAILED
    val isError: Boolean get() = phase == BlutterPhase.FAILED

    companion object {
        fun idle() = BlutterUiState()
    }
}
