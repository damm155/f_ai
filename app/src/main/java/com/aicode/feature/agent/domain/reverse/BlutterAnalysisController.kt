package com.aicode.feature.agent.domain.reverse

import com.aicode.core.util.FileLogger
import com.aicode.feature.agent.domain.container.CommandEngine
import com.aicode.feature.agent.domain.container.CommandEvent
import com.aicode.feature.agent.domain.container.LinuxContainerEngine
import android.content.Context
import androidx.lifecycle.ViewModel
import androidx.lifecycle.viewModelScope
import dagger.hilt.android.qualifiers.ApplicationContext
import java.io.File
import kotlinx.coroutines.Job
import kotlinx.coroutines.flow.MutableStateFlow
import kotlinx.coroutines.flow.StateFlow
import kotlinx.coroutines.flow.asStateFlow
import kotlinx.coroutines.launch

/**
 * Blutter 本地分析控制器（对齐 FBox 的「Blutter 解析 Dart AOT（本地执行，不消耗 AI 额度）」）。
 *
 * 双路线（对齐 FBox tryFastAnalyze 语义）：
 * 1. **快通道** [BlutterRunnerExecutor]：Dart snapshot hash → 命中内置 Runner So →
 *    :blutter 独立进程 JNI 执行（秒级，不联网）；
 * 2. **慢通道**：hash 未命中/失败 → 容器内 `aicode-blutter` 编译路线（首次需联网拉 Dart SDK）。
 *
 * 状态流 [state] 供输入框上方的进度浮窗订阅渲染（对齐 TodoDashboardBar 视觉）。
 */
@dagger.hilt.android.lifecycle.HiltViewModel
class BlutterAnalysisController @javax.inject.Inject constructor(
    private val commandEngine: CommandEngine,
    private val runnerExecutor: BlutterRunnerExecutor,
    @param:ApplicationContext private val context: Context
) : ViewModel() {
    /** App 侧直接可写的宿主 rootfs 根（容器内 / 的实体；容器内 /root 即其 root/ 子目录）。 */
    private fun hostRootfs(): File = File(context.filesDir, "rootfs")

    private companion object {
        const val TAG = "BlutterAnalysis"

        /** 慢通道首次分析某 Dart 版本要现场拉 SDK + 编译，放宽到 40 分钟。 */
        const val TIMEOUT_MS = 40L * 60 * 1000
    }

    private suspend fun <T> withContextIO(block: () -> T): T =
        kotlinx.coroutines.withContext(kotlinx.coroutines.Dispatchers.IO) { block() }


    private val scope = viewModelScope
    private var job: Job? = null

    private val _state = MutableStateFlow(BlutterUiState.idle())
    val state: StateFlow<BlutterUiState> = _state.asStateFlow()

    /** 是否有分析在跑（UI 显示浮窗/进度条的判据）。 */
    val isRunning: Boolean get() = _state.value.running

    /**
     * 启动一次 Blutter 分析（幂等保护：已在跑则忽略）。
     *
     * [apkContainerPath] 为**容器内路径**（如 /root/uploads/x.apk 或 /root/apk/x.apk）；
     * 控制器只管把命令送进容器，不关心宿主映射。
     */
    fun start(apkContainerPath: String) {
        if (_state.value.running) {
            FileLogger.w(TAG, "已有分析在跑，忽略本次请求: $apkContainerPath")
            return
        }
        val name = apkContainerPath.substringAfterLast('/').removeSuffix(".apk")
        _state.value = BlutterUiState(
            apkName = name,
            outDir = "/root/out/$name",
            phase = BlutterPhase.PREPARING,
            route = BlutterRoute.CONTAINER_BUILD,
            running = true
        )
        job = scope.launch {
            val lines = StringBuilder()
            var exitCode: Int? = null
            fun append(line: String) {
                if (line.isBlank()) return
                lines.appendLine(line)
                _state.value = _state.value.copy(log = lines.toString(), lastLine = line, phase = phaseOf(line))
            }
            try {
                // 工具链工作目录约定：待分析 APK 在 /root/apk/（aicode-blutter/aicode-apk 均在此找）。
                // 附件落在 /root/uploads/，先复制过去（幂等）。失败不中断——若源路径本就是 /root/apk/ 也无妨。
                runCatching {
                    commandEngine.runCommandSync(
                        "mkdir -p /root/apk /root/out && " +
                            "cp -f '${apkContainerPath.replace("'", "'\\''")}' /root/apk/ 2>/dev/null || true",
                        projectPath = null,
                        timeoutMs = 15_000
                    )
                }.onFailure { FileLogger.w(TAG, "预置 /root/apk 失败（继续）: ${it.message}") }

                // ===== 快通道：Runner So（对齐 FBox tryFastAnalyze；秒级，不联网）=====
                if (runnerExecutor.isAvailable()) {
                    _state.value = _state.value.copy(route = BlutterRoute.RUNNER_SO)
                    append("〔快通道〕解 APK 抽取 libapp.so / libflutter.so…")
                    // APK 落在宿主 rootfs 的 root/apk/（容器内 /root/apk/）——App 侧 File 直接可读
                    val hostApk = File(hostRootfs(), "root/apk/$name.apk")
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
                        val code = runnerExecutor.execute(
                            apkName = name,
                            libappDir = libappDir,
                            libappFile = libapp,
                            libflutterFile = libflutter,
                            outDir = outDir,
                            onLog = ::append
                        )
                        if (code != null) {
                            val ok = code == 0
                            _state.value = _state.value.copy(
                                running = false,
                                phase = if (ok) BlutterPhase.DONE else BlutterPhase.FAILED,
                                exitCode = code,
                                resultSummary = if (ok)
                                    "Runner 分析完成：/root/out/$name/（pp.txt / asm/ / objs.txt）"
                                else
                                    "Runner 退出码 $code（已记录，可回退容器编译路线）"
                            )
                            return@launch
                        }
                        append("〔快通道未走通〕转容器编译路线（较慢，首次需联网拉 Dart SDK）")
                        _state.value = _state.value.copy(route = BlutterRoute.CONTAINER_BUILD)
                    }
                } else {
                    _state.value = _state.value.copy(route = BlutterRoute.CONTAINER_BUILD)
                }

                // ===== 慢通道：容器编译路线（aicode-blutter）=====
                val flow = when (commandEngine) {
                    is LinuxContainerEngine ->
                        (commandEngine as LinuxContainerEngine).runCommandStream(
                            "aicode-blutter '/root/apk/$name.apk'",
                            projectPath = null,
                            timeoutMs = TIMEOUT_MS
                        )
                    else -> commandEngine.runCommandStream(
                        "aicode-blutter '${apkContainerPath.replace("'", "'\\''")}'",
                        projectPath = null,
                        timeoutMs = TIMEOUT_MS
                    )
                }
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
                val ok = exitCode == 0
                _state.value = _state.value.copy(
                    running = false,
                    phase = if (ok) BlutterPhase.DONE else BlutterPhase.FAILED,
                    exitCode = exitCode,
                    resultSummary = if (ok)
                        "Blutter 分析完成：$apkContainerPath → /root/out/$name/（pp.txt / asm/ / objs.txt）"
                    else
                        "Blutter 分析失败（exit=$exitCode）。常见原因：首次分析需联网拉 Dart SDK 失败；" +
                            "或该 Dart 版本未被 blutter 适配（走 aicode-so 兜底链）"
                )
                FileLogger.i(TAG, "blutter 结束 exit=$exitCode apk=$apkContainerPath")
            } catch (e: Exception) {
                _state.value = _state.value.copy(
                    running = false,
                    phase = BlutterPhase.FAILED,
                    exitCode = exitCode,
                    resultSummary = "Blutter 分析异常: ${e.message}"
                )
                FileLogger.e(TAG, "blutter 异常", e)
            }
        }
    }

    /** 取消当前分析（浮窗上的关闭按钮）。 */
    fun cancel() {
        job?.cancel()
        _state.value = _state.value.copy(
            running = false,
            phase = BlutterPhase.FAILED,
            resultSummary = "已手动取消"
        )
    }

    /** 清掉浮窗（结束后用户叉掉）。 */
    fun dismiss() {
        _state.value = BlutterUiState.idle()
    }

    /** 按日志行猜测阶段（浮窗展示用，非精确）。 */
    private fun phaseOf(line: String): BlutterPhase = when {
        line.contains("blutter 分析开始", true) -> BlutterPhase.RUNNING
        // 只在真正开始装包时报"环境自愈"（正常镜像依赖已齐，setup.sh 秒过不产生这些行）
        line.contains("pip3 install", true) || line.contains("apt-get install", true) ||
            line.contains("Collecting", true) || line.contains("Downloading", true) -> BlutterPhase.PREPARE_ENV
        line.contains("cmake", true) || line.contains("ninja", true) ||
            line.contains("Compiling", true) || line.contains("Building", true) -> BlutterPhase.BUILDING
        line.contains("pp.txt", true) || line.contains("objs.txt", true) ||
            line.contains("asm/", true) -> BlutterPhase.DUMPING
        else -> _state.value.phase
    }
}

/** 分析路线（预留 Runner 快通道）。 */
enum class BlutterRoute { RUNNER_SO, CONTAINER_BUILD }

/** 分析阶段（浮窗标题/进度展示）。 */
enum class BlutterPhase(val label: String) {
    IDLE(""),
    PREPARING("准备中"),
    PREPARE_ENV("环境自愈（可能联网装依赖）"),
    RUNNING("Blutter 解析中"),
    BUILDING("编译 Dart 快照解析器"),
    DUMPING("产出分析结果"),
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
    val resultSummary: String = ""
) {
    val finished: Boolean get() = phase == BlutterPhase.DONE || phase == BlutterPhase.FAILED
    val isError: Boolean get() = phase == BlutterPhase.FAILED

    companion object {
        fun idle() = BlutterUiState()
    }
}
