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

        if (runner.isBlank() || libappDir.isBlank()) {
            FileLogger.e(TAG, "runner/libapp_dir 为空，放弃执行")
            writeResult(resultPath, -1, "runner or libapp_dir blank")
            stopSelf()
            return START_NOT_STICKY
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
            writeResult(resultPath, code, err)
            runCatching { File(logPath).appendText("\n[exit code: $code]\n") }
            stopSelf()
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
