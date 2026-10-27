package com.zuimo.fbox.blutterrunner

import android.app.Service
import android.content.Intent
import android.os.IBinder
import com.aicode.core.util.FileLogger
import java.io.File

/**
 * Blutter Runner 执行服务（移植自 FBox，**类名与包路径必须原样保留**——
 * Intent 显式类名 + 独立进程声明 `android:process=":blutter"` 引用它）。
 *
 * 职责（对齐 FBox onStartCommand smali @0x71b944）：
 * 从 Intent 收 7 个 extra（runner / libapp_dir / out_dir / libflutter / log / result / hash），
 * 起子线程：BlutterJni.load(runner) → run(...) → 写结果 JSON（{"code":N}）→ stopSelf()。
 *
 * **必须运行在 :blutter 独立进程**（Manifest 声明），原因（MINIS-PORT 坑 ⑤）：
 * 1. 一个进程只能 load 一个 runner（JNI 静态注册符号唯一）；
 * 2. 隔离 native 崩溃（SIGSEGV 不拖垮主进程）。
 *
 * AiCode 适配：Application.onCreate 里若有抢占性初始化（如 bind socket），
 * 子进程也会执行——Android 默认用同一个 Application 类。当前 AiCode 的 AIEditorApp
 * 无 abstract socket bind（grep 无 offload/localabstract），无需按 MINIS 方式早退；
 * 若将来加了，记得在此按 `Application.getProcessName() == ":blutter"` 早退。
 */
class BlutterRunnerService : Service() {

    private companion object {
        const val TAG = "BlutterRunner"
        /** 心跳间隔：主进程据此判断 runner 是否活着（不依赖 /proc）。 */
        const val HEARTBEAT_MS = 2_000L
    }

    override fun onBind(intent: Intent?): IBinder? = null

    override fun onStartCommand(intent: Intent?, flags: Int, startId: Int): Int {
        val runner = intent?.getStringExtra("runner") ?: ""
        val libappDir = intent?.getStringExtra("libapp_dir") ?: ""
        val outDir = intent?.getStringExtra("out_dir") ?: ""
        val libflutter = intent?.getStringExtra("libflutter") ?: ""
        val logPath = intent?.getStringExtra("log") ?: ""
        val resultPath = intent?.getStringExtra("result") ?: ""
        val hash = intent?.getStringExtra("hash") ?: ""
        val heartbeatPath = intent?.getStringExtra("heartbeat") ?: ""

        if (runner.isBlank() || libappDir.isBlank()) {
            FileLogger.e(TAG, "runner/libapp_dir 为空，放弃执行")
            writeResult(resultPath, -1, "runner or libapp_dir blank")
            stopSelf()
            return START_NOT_STICKY
        }

        // 心跳：nativeRun 是阻塞调用，worker 线程无法兼任心跳，故单独起一个守护线程。
        // 主进程靠它判断 runner 是否还在跑——Android 12 上跨进程读 /proc/<pid>/cmdline 常被裁掉，
        // 只能读到空串，靠它探活会把活着的 runner 误判为崩溃。
        val workerAlive = java.util.concurrent.atomic.AtomicBoolean(true)
        if (heartbeatPath.isNotBlank()) {
            Thread {
                val hb = File(heartbeatPath)
                while (workerAlive.get()) {
                    runCatching {
                        hb.parentFile?.mkdirs()
                        hb.writeText(System.currentTimeMillis().toString())
                    }
                    runCatching { Thread.sleep(HEARTBEAT_MS) }
                }
            }.apply { isDaemon = true }.start()
        }

        Thread {
            val started = System.currentTimeMillis()
            FileLogger.i(TAG, "runner=$runner libappDir=$libappDir outDir=$outDir hash=$hash")
            var code = -1
            var err = ""
            try {
                if (!BlutterJni.load(runner)) {
                    code = -2
                    err = "loadLibrary 失败: $runner"
                    FileLogger.e(TAG, err)
                } else {
                    code = BlutterJni.run(libappDir, outDir, libflutter, logPath)
                    if (code != 0) err = BlutterJni.lastError()
                    FileLogger.i(TAG, "nativeRun 退出码=$code 耗时=${System.currentTimeMillis() - started}ms")
                }
            } catch (t: Throwable) {
                code = -3
                err = t.message ?: t.toString()
                FileLogger.e(TAG, "runner 执行异常", t)
            }
            workerAlive.set(false)
            writeResult(resultPath, code, err)
            runCatching { File(logPath).appendText("\n[exit code: $code]\n") }
            stopSelf()
            // 必须让 :blutter 进程真正退出：runner 以 JNI 静态注册导出符号，
            // 同名的 nativeRun 已绑在第一次 load 的 so 上，进程复用后再 loadLibrary
            // 另一个版本会失效，native 会毫秒级返回 0（假成功，无产物）。
            // 先等 500ms 让主进程读到结果文件，再退出进程。
            runCatching { Thread.sleep(500) }
            kotlin.system.exitProcess(0)
        }.start()

        return START_NOT_STICKY
    }

    /** 写握手结果：{"code":N,"error":"..."}；主进程轮询该文件判定结束。 */
    private fun writeResult(path: String, code: Int, error: String) {
        runCatching {
            File(path).parentFile?.mkdirs()
            val esc = error.replace("\\", "\\\\").replace("\"", "\\\"").replace("\n", " ")
            File(path).writeText("{\"code\":$code,\"error\":\"$esc\"}")
        }.onFailure { FileLogger.e(TAG, "写结果失败: $path", it) }
    }
}
