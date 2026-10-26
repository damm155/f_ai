package com.aicode.feature.agent.domain.tool.reverse

import android.content.Context
import com.aicode.core.util.FileLogger
import com.aicode.feature.agent.domain.tool.AgentTool
import com.aicode.feature.agent.domain.tool.ParameterType
import com.aicode.feature.agent.domain.tool.ToolCapability
import com.aicode.feature.agent.domain.tool.ToolParameter
import com.aicode.feature.agent.domain.tool.ToolResult
import com.aicode.feature.workspace.domain.WorkspacePathMapper
import com.android.apksig.ApkSigner
import com.android.apksig.ApkVerifier
import dagger.hilt.android.qualifiers.ApplicationContext
import kotlinx.coroutines.CancellationException
import kotlinx.coroutines.Dispatchers
import kotlinx.coroutines.withContext
import kotlinx.serialization.json.JsonElement
import kotlinx.serialization.json.JsonPrimitive
import kotlinx.serialization.json.buildJsonObject
import kotlinx.serialization.json.put
import java.io.File
import java.security.KeyStore
import java.security.PrivateKey
import java.security.cert.X509Certificate
import javax.inject.Inject

/**
 * APK 签名（对齐 FBox 的 `apk_sign` / `LinuxViewModel.signApkWithApksig`）。
 *
 * 用 APK 内置的 `assets/reverse/keystore/patch.keystore`（PKCS12，口令与别名均为 `linuxbox`，
 * 证书 `CN=LinuxBox Patch`）对 APK 做 v1 + v2 签名，产出可直接安装的包。
 *
 * ## 为什么是 App 侧工具而不是容器命令
 * `apksig` 是 Java 库，容器内没有 JDK（这也正是 FBox 的做法——它同样在 App 侧调 apksig，
 * 见其 smali `Lcom/zuimo/fbox/ui/LinuxViewModel;->signApkWithApksig`）。
 *
 * ## 典型链路
 * ```
 * Bash: aicode-apk rebuild <改过的.apk> <out.apk>   # reapk 已做 zipalign，产出【未签名】包
 * apkSign apk=<out.apk 容器路径>                     # 本工具：签名 + 自校验
 * sendFile paths=[签名产物]                          # 展示给用户，点开即安装
 * ```
 *
 * 注意：输入必须是**已 zipalign** 的包。[aicode-apk rebuild] 已对齐；若输入未对齐，
 * 签名仍会成功，但 `lib/` 下的 .so 可能因未页对齐而在部分设备上无法加载。
 */
class ApkSignTool @Inject constructor(
    @param:ApplicationContext private val context: Context,
    private val pathMapper: WorkspacePathMapper
) : AgentTool() {

    private companion object {
        const val TAG = "ApkSignTool"

        /** 与 FBox 完全一致：assets 根下的 keystore 路径。 */
        const val KEYSTORE_ASSET = "reverse/keystore/patch.keystore"

        /** 与 FBox 一致：PKCS12 口令，同时用作 key 口令。 */
        const val KEYSTORE_PASSWORD = "linuxbox"

        const val DEFAULT_SUFFIX = "-signed"
    }

    override val name = "apkSign"

    override val description get() =
        "用内置 keystore 给 APK 做 v1+v2 签名，产出可直接安装的包，并自校验签名。\n" +
            "输入必须是【未签名且已 zipalign】的 APK —— 用 `Bash` 跑 `aicode-apk rebuild <apk> <out.apk>` 即可得到" +
            "（reapk 重打包时已做对齐）。\n" +
            "典型用法：改完 dex/manifest 后 `aicode-apk rebuild` → 本工具签名 → `sendFile` 发给用户安装。\n" +
            "注意：签名会改变 APK 指纹，与商店版签名不同，只能覆盖安装同签名版本；" +
            "若设备上已装同名应用且签名不同，需先卸载。"

    override val capabilities: Set<ToolCapability> = setOf(ToolCapability.WRITE_WORKSPACE)

    override val parameters get() = mapOf(
        "apk" to ToolParameter(
            name = "apk",
            type = ParameterType.STRING,
            description = "待签名的 APK 路径（容器视角，如 `/root/work/app-unsigned.apk` 或 `~/workspace/app.apk`）。" +
                "必须是未签名且已对齐的包，通常由 `aicode-apk rebuild` 产出。",
            required = true
        ),
        "out" to ToolParameter(
            name = "out",
            type = ParameterType.STRING,
            description = "输出路径（容器视角）。缺省：与输入同目录、文件名加 `-signed` 后缀。",
            required = false
        )
    )

    override suspend fun execute(args: Map<String, JsonElement>): ToolResult = withContext(Dispatchers.IO) {
        val apkArg = args.str("apk")
        if (apkArg.isBlank()) {
            return@withContext ToolResult.Error(
                "缺少 apk 参数：请传入未签名 APK 的容器路径，例如 /root/work/app-unsigned.apk",
                "INVALID_ARGS"
            )
        }
        val outArg = args.str("out")

        // 容器路径 → 宿主真实文件（签名必须走宿主 File，apksig 读不到 proot 内部视角）
        val input = runCatching { pathMapper.toHostFile(apkArg) }.getOrElse {
            return@withContext ToolResult.Error("输入路径无法解析：$apkArg（${it.message}）", "BAD_PATH")
        }
        if (!input.isFile) {
            return@withContext ToolResult.Error(
                "APK 不存在：$apkArg（宿主解析为 ${input.absolutePath}）", "NOT_FOUND"
            )
        }

        val output = if (outArg.isNotBlank()) {
            runCatching { pathMapper.toHostFile(outArg) }.getOrElse {
                return@withContext ToolResult.Error("输出路径无法解析：$outArg（${it.message}）", "BAD_PATH")
            }
        } else {
            File(input.parentFile, input.nameWithoutExtension + DEFAULT_SUFFIX + ".apk")
        }

        if (output.absolutePath == input.absolutePath) {
            return@withContext ToolResult.Error(
                "输出路径与输入相同，apksig 不允许原地覆盖：请换一个 out（如 ${input.nameWithoutExtension}-signed.apk）",
                "SAME_PATH"
            )
        }
        output.parentFile?.mkdirs()
        if (output.exists()) output.delete()

        try {
            val (alias, signerConfig) = loadSignerConfig()

            ApkSigner.Builder(listOf(signerConfig))
                .setInputApk(input)
                .setOutputApk(output)
                .setV1SigningEnabled(true)
                .setV2SigningEnabled(true)
                .build()
                .sign()

            // 自查：签完立刻验一遍，避免把「装不上」的包交给用户
            val verified = ApkVerifier.Builder(output).build().verify()
            if (!verified.isVerified) {
                val errs = verified.errors.joinToString("; ") { it.toString() }.ifBlank { "未知原因" }
                FileLogger.w(TAG, "签名后校验未通过：$errs")
                return@withContext ToolResult.Error(
                    "签名已生成但自校验未通过：$errs（产物 ${output.absolutePath}）", "VERIFY_FAILED"
                )
            }

            val containerPath = runCatching { pathMapper.toContainerPath(output.absolutePath) }
                .getOrDefault(output.absolutePath)

            FileLogger.i(TAG, "签名完成：$containerPath（alias=$alias, ${output.length()} 字节）")
            ToolResult.Success(
                buildJsonObject {
                    put("apk", containerPath)
                    put("hostPath", output.absolutePath)
                    put("bytes", output.length())
                    put("signer", alias)
                    put("issuer", "CN=LinuxBox Patch")
                    // apksig 的验证器在 minSdk>=24 且 v2 通过时会跳过 v1 校验（v1 条目其实已写入），
                    // 因此 v1=false 时不必惊动用户，v2 为 true 即代表 Android 7+ 可装。
                    put("v2Verified", verified.isVerifiedUsingV2Scheme)
                    put("v3Verified", verified.isVerifiedUsingV3Scheme)
                    put("v1Verified", verified.isVerifiedUsingV1Scheme)
                    put(
                        "hint",
                        "已可安装。用 sendFile 把 $containerPath 发给用户；" +
                            "若设备已装同包名但签名不同的应用，需先卸载再装。"
                    )
                }
            )
        } catch (e: CancellationException) {
            throw e
        } catch (e: Throwable) {
            FileLogger.w(TAG, "签名失败：${e.message}", e)
            ToolResult.Error("签名失败：${e.javaClass.simpleName}: ${e.message}", "SIGN_FAILED")
        }
    }

    /** 读取字符串参数（缺省/非字符串值一律返回空串）。 */
    private fun Map<String, JsonElement>.str(key: String): String =
        (this[key] as? JsonPrimitive)?.content?.trim().orEmpty()

    /**
     * 从 assets 载入 PKCS12 keystore 并构造 apksig 的 signer 配置。
     *
     * 流程与 FBox `signApkWithApksig` 逐行对应：载入 keystore → 取第一个别名 → 取私钥与证书。
     */
    private fun loadSignerConfig(): Pair<String, ApkSigner.SignerConfig> {
        val password = KEYSTORE_PASSWORD.toCharArray()
        val keyStore = KeyStore.getInstance("PKCS12")
        context.assets.open(KEYSTORE_ASSET).use { input -> keyStore.load(input, password) }

        val alias = keyStore.aliases().nextElement()
        val privateKey = keyStore.getKey(alias, password) as? PrivateKey
            ?: error("keystore 中取不到私钥（alias=$alias）")
        val certificate = keyStore.getCertificate(alias) as? X509Certificate
            ?: error("keystore 中取不到证书（alias=$alias）")

        val signerConfig = ApkSigner.SignerConfig.Builder(alias, privateKey, listOf(certificate)).build()
        return alias to signerConfig
    }
}
