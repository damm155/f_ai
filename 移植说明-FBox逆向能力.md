# AiCode ← FBox 逆向能力移植：实施记录（第 1 批）

目标：把 FBox 的逆向能力（APK/DEX/SO/Flutter）装进 AiCode 1.12.0，容器已换 Debian。
路径兼容定案见同目录 `AiCode_FBox_路径兼容定案.md`。

---

## 一、资产落位（`app/src/main/assets/`）

| 落位路径 | 来源（FBox APK assets） | 大小 | 运行期去向 |
|---|---|---|---|
| `reverse/apk_tool/apk_tool.py` | `apk_tool/apk_tool.py` | 26 KB | `/root/apk-tool/` |
| `reverse/apk_tool/reapk/**`（14 文件） | `reapk_pkg/reapk/**` | 179 KB | `/root/apk-tool/reapk/` |
| `reverse/so_tool/so_tool.py` | `so_tool/so_tool.py` | 28 KB | `/root/so-tool/` |
| `reverse/flutter-re.tar`（gzip，64 条目） | 同名 | 136 KB | `/root/flutter-re/`（解压） |
| `reverse/skills/{apk-re,flutter-re}/SKILL.md` | `skills/*.md`（已加 frontmatter + 工具名映射前言） | 18 KB | `~/.aicode/skills/`（持久） |
| `reverse/blutter/{runners.json,frida.template.js}` | `blutter/*` | 20 KB | App 侧 `filesDir/reverse/blutter/` |
| `reverse/reflutter/reflutter/**` | `reflutter_pkg/reflutter/**` | 55 KB | 备用（尚未接线） |
| `reverse/keystore/patch.keystore` | `patch.keystore` | 7.5 KB | 备用（APK 签名用） |

镜像：

| 落位路径 | 来源 | 大小 |
|---|---|---|
| `_armAssets/container/arm/debian-rootfs.bin` | `rootfs/debian-arm64.tgz`（改名：AGP 会把 .tar.gz/.tgz 当归档自动解压） | 178 MB |
| `_armAssets/container/arm/debian-rootfs.version` | 同名（内容 `3`） | — |

> `alpine-rootfs.bin`（3.7 MB）**保留未删**，供 x86solo flavor 与回滚使用；
> ⚠ x86solo flavor 目前仍指向 Alpine，本批未处理（见「未完成」）。

---

## 二、代码改动

### 新增 1 个文件

**`feature/agent/domain/container/ReverseAssets.kt`（274 行）**

对齐 FBox `LinuxManager.ensureFlutterRe()` 的两条原则：

- **按需解压**：`ensureInstalled(profile)` 首次调用才把 `assets/reverse/**` 释放进容器 `/root/**`；
- **版本自愈**：就绪判断是**纯检查**（校验真实文件 + `.version` 标记），任一缺失即整包重解。
  标记写在 `/root/apk-tool/.version`（**在 rootfs 内部**）——rootfs 被整体删除重装时标记随之消失，
  自然触发重建。这正是 FBox 的做法。

自愈校验点（对齐 FBox 的 `hasCompleteToolchain` / 补丁检查）：

```
blutter/blutter.py、dartvm_fetch_build.py、extract_dart_info.py、
blutter/blutter/src/DartTypes.cpp（FBOX_UNKNOWN_ABSTRACT_TYPE 补丁载体）、
blutter/blutter/src/ElfHelper.cpp（BLUTTER_DART_SINGLE_SNAPSHOT 补丁载体）、
blutter/scripts/CMakeLists.txt
```

flutter-re 解压复用 `ContainerInstaller.extractRootfsTo()`（已正确处理 symlink / hardlink / 权限位）。
`REV_ASSETS_VERSION` 改动资产后 +1 即可强制重解。

关键 API：

```kotlin
reverseAssets.ensureInstalled(profile)          // 幂等，缺则自愈
reverseAssets.persistentBindings()              // 用户产出的 -b 列表
reverseAssets.persistentRoot()                  // filesDir/reverse
reverseAssets.blutterConfigDir()                // App 侧 blutter 配置
```

### 修改 4 个文件

| 文件 | 改动 |
|---|---|
| `ContainerInstaller.kt` | `INSTALL_VERSION`：`alpine-3.21.3-v6` → `debian-13-arm64-v1`；`ASSET_ROOTFS`：→ `debian-rootfs.bin` |
| `LinuxContainerEngine.kt`（5 处） | ① 构造注入 `ReverseAssets`；②③ `ensureInstalled()` 的快/慢两条路径都调 `ensureReverseAssets(profile)`（失败**不阻塞**容器使用）；④ 新增私有 `ensureReverseAssets()`；⑤ `buildBaseProotArgv()` 新增两组 `-b` |
| `WorkspacePathMapper.kt`（4 处） | ① 引入 `ReverseAssets`；② 构造注入；③ `extraMounts()` 合并 `builtinMounts()`；④ **`toContainerPath()` 让显式挂载先于工作区规则匹配** |
| `assets/prompts/` | 新增内置片段 `80-reverse-engineering.md`（自动被 `builtinFiles()` 扫描，启动时随 `prompts/` 全量同步到 `~/.aicode/prompts/`） |

### 新增 3 个沙箱 wrapper（无需 Kotlin 改动）

`assets/aicode/bin/` 下的文件由既有的 `ContainerInstaller.extractEnvTool()` 自动释放到
`~/.aicode/bin/`（已在容器 `PATH` 上）：

| 命令 | 作用 |
|---|---|
| `aicode-apk` | → `python3 /root/apk-tool/apk_tool.py "$@"`（info/manifest-edit/dex-*/resource-read/rebuild） |
| `aicode-so` | → `python3 /root/so-tool/so_tool.py "$@"`（info/symbols/jni/disasm/strings/cfg） |
| `aicode-blutter` | Flutter 分析（容器编译路线）：setup.sh → gcc13_fix（可选）→ **直接传 APK 路径**给 `blutter.py` |

---

## 三、新增的 proot 绑定（`buildBaseProotArgv`）

```
-r <rootfs>  -b /dev  -b /proc  -b /sys  -b /system  -0
-b <工作区>:/root/workspace              -w /root/workspace      （原有）
-b filesDir/aicode:/root/.aicode                                  （原有）
-b <工作区>/.aicode/attachments:/root/uploads                      ← 新增
-b filesDir/reverse/knowledge:/root/knowledge                      ← 新增
-b filesDir/reverse/patches:/root/patches                          ← 新增
-b filesDir/reverse/ai-skills:/root/ai-skills                      ← 新增
```

设计取舍（与定案文档一致）：

- **附件**绑到 `/root/uploads`：使 FBox 系统提示 / 技能 / 工具描述里写死的 `/root/uploads` 原样成立，**零文本改动**。
- **用户产出**（知识库/补丁柜/自定义技能）绑持久目录：不可重建，rootfs 重装即丢。
- **工具链**（apk-tool / so-tool / flutter-re）**不绑**，走 `ReverseAssets` 按需解压 + 自愈，与 FBox 一致。

`WorkspacePathMapper` 同步登记了这些挂载；`toContainerPath()` 调整为**显式挂载优先**——因为
`<工作区>/.aicode/attachments` 嵌套在工作区内部，会打破原「工作区/aicode/rootfs 三根互不重叠」的假设，
不先匹配挂载表的话，同一文件在 shell（走 bind）与文件工具（走工作区规则）下会呈现两个不同路径。

---

## 四、运行期行为（首次进容器）

1. `ContainerInstaller.installRootfsIfNeed()` 解压 178 MB Debian rootfs（首次，耗时较长），写 `.installed=debian-13-arm64-v1`
2. `LinuxContainerEngine.ensureInstalled()` → `extractDocs()` / `extractEnvTool()`（含 3 个新 wrapper）
   / `ensureReverseAssets()`
3. `ReverseAssets.ensureInstalled()` 释放：`/root/apk-tool/**`（+reapk）、`/root/so-tool/**`、
   `/root/flutter-re/**`（64 条目）、`~/.aicode/skills/{apk-re,flutter-re}/SKILL.md`、App 侧 blutter 配置
4. 会话系统提示里出现 `80-reverse-engineering.md` 片段；技能列表出现 `apk-re` / `flutter-re`

---

## 五、验证清单

编译安装后逐项确认：

- [ ] `cat /etc/os-release` → Debian；`python3 -c "import capstone;print(capstone.__version__)"` → 5.0.7
- [ ] `ls /root/apk-tool /root/so-tool /root/flutter-re` 有内容
- [ ] `aicode-apk --help`、`aicode-so --help` 输出子命令表
- [ ] `python3 -c "import sys;sys.path.insert(0,'/root/apk-tool');import reapk;print(reapk.__file__)"` 成功
- [ ] `cp /root/uploads/<某apk> /root/apk/ && aicode-apk info <名字>` 有输出
- [ ] 设置里能看到 `apk-re` / `flutter-re` 两个技能
- [ ] `rm -rf /root/flutter-re` 后重启进容器 → 自动重建（自愈生效）
- [ ] 换一次容器版本后 `~/.aicode/skills`、`filesDir/reverse/{knowledge,patches}` 仍在（持久化生效）
- [ ] 工作区放一张图 → `ls /root/uploads` 能看到同名文件（附件绑定生效）
- [ ] 文件工具读 `/root/uploads/<名>` 与 shell `ls /root/uploads` 一致（映射器已登记）

---

## 六、未完成 / 后续

| # | 项 | 说明 |
|---|---|---|
| 1 | **Blutter 快通道** | `BlutterRunnerService` + 18 个 runner `.so` + `libfbox_icu.so` + `runners.json` 尚未接线。资产里的 `reverse/blutter/*` 已就位。**注意 MINIS-PORT 记录的 6 个坑**（尤其：18 个 runner 全依赖 `libfbox_icu.so`(38 MB)、`libapp_dir` 必须传「libapp.so 所在目录」、runner 内硬编码 `/data/data/com.zuimo.fbox/files/w.js` 需二进制改写） |
| 2 | **APK 签名** | `aicode-apk rebuild` 产出未签名 APK。`reverse/keystore/patch.keystore` 已备，可在沙箱内装 `apksigner`（需 JRE）或 App 侧用 apksig 实现 `aicode-sign` |
| 3 | **x86solo flavor** | 仅有 Debian/arm64 镜像；x86 仍指 Alpine（`ASSET_ROOTFS` 是全局常量，切 flavor 会一起切）。建议 x86solo 单独用一个 flavor 级 asset 常量，或直接下掉该 flavor |
| 4 | **reflutter** | `reverse/reflutter/**` 已备资产，未接 `aicode-reflutter` wrapper |
| 5 | **dex-xref / 资源读取** | `apk_tool.py` 支持，但 wrapper 帮助文本里只做了概要说明 |
| 6 | **补丁存储柜** | FBox 的补丁记录功能（`patch_so` + 补丁柜）未移植；目前打补丁靠 `python3` 就地改字节 |

---

## 七、回滚

```sh
# 代码
git checkout -- app/src/main/java/com/aicode/feature/agent/domain/container/ContainerInstaller.kt \
                app/src/main/java/com/aicode/feature/agent/domain/container/LinuxContainerEngine.kt \
                app/src/main/java/com/aicode/feature/workspace/domain/WorkspacePathMapper.kt
rm app/src/main/java/com/aicode/feature/agent/domain/container/ReverseAssets.kt
# 资产
rm -rf app/src/main/assets/reverse app/src/main/assets/prompts/80-reverse-engineering.md
rm app/src/main/assets/aicode/bin/aicode-{apk,so,blutter}
rm app/src/_armAssets/container/arm/debian-rootfs.{bin,version}
```

（注：我在容器内无法执行 `git checkout` 之外的编译验证——环境无 JDK/Android SDK。**编译请在你的构建机上跑**：
`cd src/android && ./gradlew :app:assembleDebug`。）

---

## 八、镜像自动回退（后续补充，取代原「固定指向 Debian」）

原先 `ASSET_ROOTFS` 是固定常量 `debian-rootfs.bin`、`INSTALL_VERSION` 固定为 `debian-13-arm64-v1`。
这样**删掉 Debian 镜像就编不过运行期**（找不到 asset），不适合「先编小包、之后再放 Debian」的流程。

现改为**运行时自动回退**（`ContainerInstaller`）：

```kotlin
val ASSET_ROOTFS: String by lazy {           // 优先 Debian，缺失则 Alpine
    val dir = ASSET_DIR
    val debian = "$dir/${DEBIAN_ROOTFS_NAME}"
    if (assetExists(debian)) debian else "$dir/${ALPINE_ROOTFS_NAME}"
}
val INSTALL_VERSION: String by lazy {        // 必须与 ASSET_ROOTFS 绑定
    if (ASSET_ROOTFS.endsWith(DEBIAN_ROOTFS_NAME)) DEBIAN_INSTALL_VERSION else ALPINE_INSTALL_VERSION
}
const val ALPINE_INSTALL_VERSION = "alpine-3.21.3-v6"   // 与原版一致，存量设备不白重解压
const val DEBIAN_INSTALL_VERSION = "debian-13-arm64-v1"
```

**为什么 `INSTALL_VERSION` 必须绑定**：若它是固定常量，「先用 Alpine 编包、之后把 Debian 放回来」时
标记不变 → `isInstalled()` 误判为已安装 → **镜像换了却不解压**，容器还是旧镜像且毫无报错。
绑定后换镜像即换标记，自动触发重装。

两个值都 `by lazy` + 运行时探测 assets，因此：

- 删 `debian-rootfs.bin` → 自动回退 Alpine，**无需改代码**；
- 放回 `debian-rootfs.bin` → 自动切回 Debian 并触发重解压；
- **即使直接往已编译好的 APK 里替换 assets 里的 rootfs，也能识别**（因为是运行期探测，非编译期常量）
  ——但替换会破坏 APK 签名，必须重新签名；
- x86solo flavor 无 Debian 资产 → 自动落到 Alpine，不会再崩（原第 3 项遗留问题已顺带解决）。

### Alpine 版的能力边界（重要）

| 命令 | Alpine 下 | 说明 |
|---|---|---|
| `aicode-apk` | ⚠ 需 `apk add python3` | `apk_tool.py` + `reapk` 是纯标准库，有 python3 即可 |
| `aicode-so` | ✗ | 还需 `apk add py3-capstone` |
| `aicode-blutter` | ✗ | 需现场 cmake/ninja 编译，还要 `build-base cmake ninja` |
| 路径绑定 / 提示词 / 技能 / wrapper 落位 | ✅ | 这些与发行版无关，Alpine 版即可验证 |

**结论：Alpine 版适合验证「编译通过 + 接线正确」，真正做逆向必须 Debian。**
两个 wrapper 已加依赖自检，缺 python3 / capstone 时会打印明确的安装指引而不是 `not found`。

### 导出产物对应关系

| 文件 | 用途 |
|---|---|
| `AiCode-1.12.0-FBox逆向移植.zip`（23 MB） | **编译用**：最新代码，已移出 Debian 镜像，自动回退 Alpine |
| `debian-rootfs.zip`（178 MB） | 内含 `debian-rootfs.bin` + `debian-rootfs.version`；要用 Debian 时放进 `app/src/_armAssets/container/arm/` |

---

## 九、Debian 作为唯一内置镜像（最终形态）

**决定**：内置容器就是 Debian，**不再同时内置 Alpine**。

理由：`installRootfsIfNeed()` 在首次进入容器时就会解压内置镜像。若内置仍是 Alpine，
用户开箱第一件事就是白解压一遍 + 拿到一个跑不了逆向的容器，然后再去导入 Debian —— 多此一举。
之前提过的「Alpine 常驻 + Debian 走设置导入」方案已据此**撤回**。

### arm 的 Alpine 已删除

`app/src/_armAssets/container/arm/alpine-rootfs.bin` 已删。目的不只是省 3.7 MB，
更重要的是**让失败变响亮**：留着的话，一旦 `debian-rootfs.bin` 没放对，
`ASSET_ROOTFS` 会静默回退到 Alpine —— 用户以为在用 Debian，逆向却莫名失败，极难排查。

`_x86Assets/container/x86/alpine-rootfs.bin` **未动**（x86solo flavor 仍依赖它）——
是否保留该 flavor 见「待决」。

### 开发期用占位镜像加速

真 Debian 镜像 185 MB，不适合每次编译都打进去。做法：

| 文件 | 占位版（开发） | 真镜像（交付） |
|---|---|---|
| `debian-rootfs.bin` | arm64 Alpine 内容，3,850,365 字节 | 185,889,833 字节 |
| `debian-rootfs.version` | `placeholder` | `3` |
| 算出的 `INSTALL_VERSION` | `debian-13-arm64-v1-placeholder-3850365` | `debian-13-arm64-v1-3-185889833` |

换镜像后版本串必然变化 → `isInstalled()` 判为未安装 → **首次进容器自动重解压**，无需清数据。
`ContainerInstaller` 会主动打印版本串，供核对是否生效。

外置版就一个前提：`androidResources { noCompress += "bin" }`（已加）。
不加则资产被压缩 → `openFd()` 取不到长度 → 指纹退化成 `-1`，同名替换检测不到。

### 待决：x86solo flavor

`build.gradle.kts` 有三个 flavor：`universal` / `armsolo` / `x86solo`。
x86 侧没有 Debian 镜像，因此：

- 若**不发布 x86**：建议直接下掉 `x86solo`（连同 `_x86Assets` 的 Alpine、`_x86JniLibs`），
  工程只剩 arm64 一套镜像，语义最干净，也省 3.4 MB。
- 若要**保留 x86**：需自备 x86_64 的 Debian rootfs（FBox 只提供 arm64），否则该 flavor 只能用 Alpine，
  即「x86 上不具备逆向能力」——需在文档与提示词里说明。

### 已决：x86 整体移除

用户确认 x86 用不上，已删除：

| 位置 | 处理 |
|---|---|
| `app/build.gradle.kts` | 删 `x86solo` flavor；`universal` / `armsolo` 的 `abiFilters` 均只留 `arm64-v8a`；sourceSets 只保留 `_armAssets` / `_armJniLibs` |
| `app/src/_x86Assets`、`app/src/_x86JniLibs` | 整目录删除（省 3.4 MB） |
| `ContainerInstaller.ASSET_DIR` | 由「按设备 ABI 选 `container/arm` 或 `container/x86`」简化为常量 `"container/arm"` |
| `ContainerInstaller.ASSET_ROOTFS` | 由「Debian 优先、缺失回退 Alpine」简化为固定 Debian，**且不做任何 fallback**：资产缺失直接在 install 阶段报错。理由：静默回退到别的镜像会让「逆向莫名失败」变得极难排查 |
| `ContainerInstaller.assetExists()` | 已无使用，删除 |
| `ContainerImageCatalog.CURRENT_ABI` | 由按设备 ABI 判定简化为固定 `"arm64"`（连带移除 `android.os.Build` import） |

保留不动（与 flavor 无关，是**容器内发行版**的架构判断，不能删）：
`assets/aicode/lib/env-common.sh`、`lib/android-sdk.sh` 里的 `x86_64` 分支
（它们判断的是容器内 `$ARCH`，用于选镜像源 / 换 aapt2 二进制）。

`universal` 与 `armsolo` 现在完全等价（都是 arm64）。保留两个只是不改动既有构建命令习惯；
若要进一步精简，可下掉 `container` flavor 维度只留一个 flavor。

占位版包体积随之从 23 MB 降到 **19 MB**。

---

## 十、补齐缺口（本批新增，对应 FBox 的 App 侧工具层）

### 10.1 完整缺口核对结论

FBox 共 **38 个 AI 工具**，逐项对照 AiCode 后，容器工具链层**零缺失**（`aicode-apk` 13 子命令、
`aicode-so` 6 子命令 = FBox 全量子命令集，且用的是同一份 `apk_tool.py`/`so_tool.py`）。
缺的全在 **App 侧工具/UI 层**：

| # | FBox 有 | AiCode 原状 | 本批处理 |
|---|---|---|---|
| 1 | `apk_sign` / `repack_apk`（含签名导出） | ❌ 无签名能力 | ✅ **已补（10.2）** |
| 2 | 类型判定 + 弹窗推荐/框选 | ❌ 无 | ✅ **已补（10.3）** |
| 3 | `patch_so` | ❌ `aicode-so` 只读 | ⏳ 未做 |
| 4 | Blutter Runner 快通道（18 so + 服务） | ❌ 无 | ⏳ 未做 |
| 5 | 补丁柜 5 件套 | ❌ 无（`CheckpointManager` 是会话文件检查点，非补丁柜） | ⏳ 未做 |
| 6 | `fast_scan_apk` / `analysis_status` / `search_flutter` / `read_flutter_result` | ❌ 无 | ⏳ 建议并入 wrapper（`--scan`/`--status`）+ 提示词引导用 grep/readFile |
| 7 | `reflutter` 链 | ⚠️ 资产已放、未接线 | ⏳ 未做 |
| 8 | `query_experience` / `save_experience` | ⚠️ `/root/knowledge` 已持久绑定、未接线 | ⏳ 未做 |
| 9 | `ocr_image` | ⚠️ 仅 `viewImage`（给模型看图，非离线取字） | ⏳ 未做 |
| 10 | `create_task_plan`/`update`/`finish` | ✅ `todo` 等价 | — |
| 11 | `memory_write`/`get`、`file_*`、`run_terminal_command`、`list_skills`/`read_skill`、`so_*`、`apk_*` | ✅ 均已有等价 | — |

**AiCode 反而更强**：`websearch`/`webfetch`/`browser`（FBox 无联网）、`task` 子代理、`manageMcp`、`Shizuku`。

### 10.2 APK 签名（新增）

**做法与 FBox 完全同构**：FBox 自己就内嵌 Google 官方 apksig（`classes2.dex` 里
`com.android.apksig.ApkSigner` / `V1|V2|V3SchemeSigner` / `ApkVerifier` 齐全），签名在 **App 侧**做
（容器无 JDK）。核到其 smali `LinuxViewModel.signApkWithApksig(File, File)`，流程逐条为：

```
KeyStore.getInstance("PKCS12") → assets.open("patch.keystore") → ks.load(is, "linuxbox".toCharArray())
alias = ks.aliases().nextElement() → getKey(alias, pw) / getCertificate(alias)
ApkSigner.SignerConfig.Builder(alias, key, listOf(cert)).build()
ApkSigner.Builder(listOf(cfg)).setInputApk(in).setOutputApk(out)
    .setV1SigningEnabled(true).setV2SigningEnabled(true).build().sign()
```

据此在 AiCode 落地：

| 项 | 内容 |
|---|---|
| 依赖 | `com.android.tools.build:apksig:8.7.3`（腾讯 mirror 有；字节码 major=52/Java8，无需脱糖） |
| 混淆 | `proguard-rules.pro` 加 `-keep class com.android.apksig.** { *; }`（其 ASN.1 编解码用反射读字段注解，R8 后 v1 签名会失败） |
| 工具 | `feature/agent/domain/tool/reverse/ApkSignTool.kt`，名 `apkSign`，参数 `apk`（容器路径）/`out`（可选） |
| 注册 | `AgentModule.provideToolRegistry` 加参 + `register("apkSign", apkSignTool)` |
| 密钥 | 复用 FBox 的 `assets/reverse/keystore/patch.keystore`（**口令 `linuxbox`，别名 `linuxbox`，证书 CN=LinuxBox Patch，有效期至 2054**） |

**实测验证（容器内装 JDK 21 + apksig 8.7.3 真跑）**：
造最小真实 APK（Manifest + resources.arsc + classes.dex + lib/*.so）→ `aicode-apk rebuild` 出未签名包
→ 用与 Kotlin 逐行对应的 Java 程序签名 → `ApkVerifier` 结果：
`alias=linuxbox / subject=CN=LinuxBox Patch / v2=true / v3=true / 全部通过=true`。
产物含 `META-INF/MANIFEST.MF`、`LINUXBOX.SF`、`LINUXBOX.RSA`（v1 已写入；apksig 验证器在
minSdk≥24 且 v2 通过时会跳过 v1 校验，故 `isVerifiedUsingV1Scheme()=false` 属正常，与 FBox 一致）。

**顺带核实**：`reapk` 的 `write_aligned_zip` **保留原压缩方式**（`e["method"]` 原样写回），
STORED 的 `.so` 按 **4096** 对齐、其余 STORED 按 4 对齐 → 重打包不会破坏 `extractNativeLibs=false` 的包。

标准交付链路已写入系统提示片段 `80-reverse-engineering.md`：
`aicode-apk rebuild` → `apkSign` → `sendFile`。

### 10.3 类型判定 + 推荐/框选弹窗（新增）

**判定**：`feature/agent/domain/reverse/ApkTypeDetector.kt`，对齐 FBox `checkApkIsFlutter`
（`code_off=0x786db4`）：只遍历 ZIP 中央目录条目名，三特征**齐备**才判 Flutter ——
① `assets/flutter_assets/` 前缀 ② `/libflutter.so`（或裸名）③ `/libapp.so`（或裸名）。
不解压、不读 Manifest、毫秒级；文件缺失/长度为 0/非法 ZIP 一律按 NATIVE（与 FBox 相同）。

**弹窗**：`feature/agent/presentation/component/ApkRouteDialog.kt`，对齐 FBox `ApkRouteDialog`：
- 标题「选择分析线路」+ 文件名 + 判定结论文案（命中 Flutter 与未命中两套）
- 两张 `RouteOptionCard`（Flutter 应用 / 普通应用）
- **`selected = (卡片类型 == 判定结果)`** → 主色 2dp 描边 + `primaryContainer` 底 + **「推荐」徽标**
  （这就是 FBox 那圈"自动框选"的真身：不是焦点逻辑）
- 配色改用本工程主题令牌（`MaterialTheme.colorScheme` + `semanticColors` + `Spacing`/`Radius`），
  **未沿用 FBox 的 Cyan 硬编码**，遵守 `CLAUDE.md` 主题硬规则

**接线**：`AIChatPanel.handlePickedAttachments` 上传成功回调里，若文件名以 `.apk` 结尾 →
`withContext(Dispatchers.IO) { ApkTypeDetector.detect(...) }` → 置 `apkRoutePrompt` 状态 → 渲染弹窗。
选线后 `enqueueAgentRequest` 发一条**带路由指令**的请求（指令里写明「已检测为 Flutter/原生 +
应读取的技能名」），避免 AI 自己猜类型；同时把该附件从待发列表移除、`followBottom = true`。

文案入 `values/strings.xml`（中文，默认）与 `values-en/strings.xml`（英文）各 9 条 `apk_route_*`。

### 10.4 本批改动文件清单

| 类型 | 文件 |
|---|---|
| 新增 | `feature/agent/domain/reverse/ApkTypeDetector.kt` |
| 新增 | `feature/agent/domain/tool/reverse/ApkSignTool.kt` |
| 新增 | `feature/agent/presentation/component/ApkRouteDialog.kt` |
| 修改 | `di/AgentModule.kt`（注册 apkSign） |
| 修改 | `feature/agent/presentation/component/AIChatPanel.kt`（上传后判定 + 弹窗渲染 + 选线入队） |
| 修改 | `app/build.gradle.kts`（apksig 依赖） |
| 修改 | `app/proguard-rules.pro`（apksig keep） |
| 修改 | `res/values/strings.xml`、`res/values-en/strings.xml`（9 条文案 × 2） |
| 修改 | `assets/prompts/80-reverse-engineering.md`（签名链路 + apkSign 行） |

### 10.5 仍未做（按建议优先级）

1. `patch_so`（SO 字节补丁）——`aicode-so` 只读，Flutter 补丁链仍断在这一步
2. Blutter Runner 快通道（18 个 .so + 独立 Service，收益：几分钟 → 秒级）
3. 补丁柜（留档/回滚）、`reflutter` 接线、知识库经验接线、OCR

### 10.6 patch_so（已按用户思路收敛到最简实现）

**用户的定调**：不要复刻 FBox 的「Kotlin heredoc 运行期生成」——直接把两个脚本塞进
`flutter-re.tar`（本来解压目标就是 `/root/flutter-re/`），一起分发，**零额外代码**。

| 项 | 内容 |
|---|---|
| 来源 | 两个脚本从 FBox dex 里提取（`PATCH_SO_SCRIPT` / heredoc 内嵌，5649 / 4939 字符），**原封不动**使用 |
| 落位 | `assets/reverse/flutter-re.tar` 内（条目 64 → 67），解压即到 `/root/flutter-re/{patch_so,fbox_gcc13_fix}.py` |
| 自愈 | `FLUTTER_RE_REQUIRED` 加上两个脚本 → 缺失即整包重解，与 blutter 校验点同一机制 |
| 回退 | `installRuntimeScripts` / `RUNTIME_SCRIPTS` 机制已删除（不需要了） |

**patch_so.py 能力（FBox 原版，实测验证）**：
- `virt_to_offset`：64 位小端 ELF 的 PT_LOAD 换算（比 so_tool 的 SoCtx 更轻，不看节区）
- `assemble`：**内嵌汇编器**——不是 keystone，而是把 asm 写成 .s 文件调 GNU `as` + `objcopy` 取 `.text`，
  **零额外依赖**（rootfs 自带 binutils）；亮点是**分支指令 PC 重定位**：
  `b #0x1980` 会逐条跟踪当前地址、换算成 `. + 偏移` 再交给 as，编码正确
- `patch_file`：r+ 写入 + 读回校验 + 同路径写自动 `.bak` 备份；`--out` 可另存
- 指令长度校验：arm64 必须是 4 的倍数

**实测（容器内真实 so：libandroid-shmem.so）**：
```
hex:  0x1978 --bytes "1F 20 03 D5"  → FD 7B BA A9 → 1F 20 03 D5（nop）✓ 读回通过
asm:  0x1978 "mov w0, #1; ret"      → 20 00 80 52 C0 03 5F D6 ✓（与标准编码一致）
branch: 0x1978 "b #0x1980"          → 02 00 00 14，disasm 回读 `b #0x1980 ; → shmget+0x8` ✓
```

**与 aicode-so patch 的分工**（都保留，写进了 wrapper 与提示词）：
- 完整版 `python3 /root/flutter-re/patch_so.py <so> <addr> "asm…"`：asm 编译、分支重定位、.bak
- 轻量版 `aicode-so patch <so> <addr:hex>[:more] [--dry] / --restore`：纯 hex 多地址、--dry 预览、.orig 整文件回滚

至此 FBox 的 SO 补丁链在 AiCode 完整成立：
`aicode-so symbols/jni/disasm` 定位 → `patch_so.py` 打补丁 → `aicode-so disasm` 回读验证。

---

## 十一、本轮修复（r3）

### 11.1 选 Flutter 后自动触发 Blutter + 进度浮窗（核心缺口，已补）

| 组件 | 说明 |
|---|---|
| `BlutterAnalysisController`（@HiltViewModel） | 状态流 `BlutterUiState`（apkName/phase/route/running/log/lastLine/exitCode/resultSummary）；`start()` 先把附件 cp 到 `/root/apk/`，再流式跑 `aicode-blutter`（`runCommandStream`，40 分钟超时），逐行 `collect` 更新状态；`cancel()/dismiss()` |
| `BlutterProgressCard`（浮窗） | 输入框上方白底卡片：标题+路线标签（Runner So / 容器编译）、细进度条、最近一行、可展开的终端质感日志区（surfaceVariant、200dp 上限、自动滚动语义）、结束态结果与关闭。配色全走主题令牌 |
| AIChatPanel 接线 | 选 Flutter → `start(attachment.containerPath)`；同时入队的路由指令明确「本地解析已启动、结果在 /root/out/<名>/、勿重跑」 |
| 阶段猜测 | 按日志关键字切 phase（setup/Collecting→环境自愈；cmake/ninja→编译；pp.txt/asm→产出） |

route 枚举预留 `RUNNER_SO`，接 Runner 快通道时只需在 start() 里改执行器，UI 零改动。

### 11.2 对面 AI 实测报的 bug（全部修掉）

| bug | 修法 | 验证 |
|---|---|---|
| `aicode-blutter --read` 必挂（heredoc 字符串断行） | 合并为单行字面量 | 真跑 `--read` 输出正常 ✓ |
| `--status` 的 printf 同源断行 | 改 `\n` | sh -n ✓ |
| `so_tool cfg` 两处 tuple/对象混用（603/619 行） | `insns[-1][0]/[3].size`、`block_ranges` 索引修 | `cfg shmget` 19 块 20 边 ✓ |

### 11.3 容器不解压的根因排查（写给用户的指引）

- `.installed` 标记 = `INSTALL_VERSION` 指纹（`debian-13-arm64-v1-<version 内容>-<openFd 长度>`）。
- 换镜像后必须**指纹变化**才重解。占位→真镜像长度必变，理应触发；若没触发：
  1. logcat 看「内置镜像版本串」——长度若为 -1，说明 `noCompress` 未生效（openFd 取不到长度），
     此时指纹只取决于 version 文件内容——**覆盖镜像时 version 内容必须同步改**；
  2. 最快兜底：设置 → 容器 → 重置容器。
- 技能列表空与 rootfs 未就绪是同一条链（`ensureReverseAssets` 在 rootfs 就绪后才跑），
  容器修好后技能自然出来——与用户实测现象吻合。

### 11.4 弹窗白底

`ApkRouteDialog` 显式 `containerColor = surface` + `tonalElevation = 0`，与 AiCode 其它弹窗一致。

### 11.5 setup.sh 精简（用户决策：去掉 frida-tools / rizin）

用户用外部 MCP Frida，容器内装 frida-tools 纯属拖累（pip 联网 150s+，每个新容器都要装一遍）；
rizin 对 blutter 编译分析无用（ELF 分析已由 so_tool + binutils 覆盖）。

- `flutter-re.tar` 内的 `setup.sh` 已替换为精简版：[1/4] apt 编译链 + [2/4] pyelftools + [3/4] blutter 命令别名 + [4/4] 标记。frida/rizin 段整段删除。
- `aicode-blutter` 加快速探测：`python3 -c "import elftools" && cmake && ninja` 齐备时**整段跳过 setup.sh**——正常路径日志干净，浮窗不再闪「环境自愈」。
- 浮窗阶段猜测收紧：只在日志出现 `pip3 install` / `apt-get install` / `Collecting` / `Downloading` 时才报「环境自愈」（真正在装包），而不是看到 setup.sh 字样就报。

效果：真 Debian 镜像下，浮窗正常路径直接是「Blutter 解析中」；只有首次分析某 Dart 版本（要拉 SDK 编译）才会出现「编译 Dart 快照解析器」长阶段；环境真缺东西时才显示「环境自愈」。

---

## 十二、Blutter Runner 快通道接线（r6，对齐 MINIS-PORT 成功案例）

### 12.1 资产（19 个 so，121 MB，全进 `_armJniLibs/arm64-v8a/`）

| so | 作用 |
|---|---|
| `libfbox_blutter_2_14_0 … 3_12_0`（18 个） | 各 Dart 版本预编译 runner（JNI 静态注册） |
| `libfbox_icu.so`（38 MB） | **全部 runner 的 DT_NEEDED 依赖**，缺一个 = 全军覆没（MINIS 坑②） |

`keepDebugSymbols` 加了两组通配防 NDK strip 动符号。`runners.json`/`frida.template.js` 进 `assets/blutter/`。

### 12.2 代码（4 个新文件 + 2 处改）

| 文件 | 说明 |
|---|---|
| `com.zuimo.fbox.blutterrunner.BlutterJni`（Kotlin） | **包名类名原样保留**（JNI 静态注册符号 `Java_com_zuimo_fbox_blutterrunner_BlutterJni_*`）；`load(libraryName)` / `run(libappDir,outDir,libflutter,log)` / `lastError()` |
| `com.zuimo.fbox.blutterrunner.BlutterRunnerService` | Intent 收 7 extra（runner/libapp_dir/out_dir/libflutter/log/result/hash，与 FBox smali @0x71b944 逐字对应）→ 子线程 load+run → 写 `{"code":N,"error":...}` JSON → stopSelf。**Manifest 声明 `android:process=":blutter"`**（一进程一 runner + 崩溃隔离，AXML 实证 FBox 同款） |
| `BlutterRunnerExecutor` | ① `extractFlutterLibs`（ZipFile 抽 libapp/libflutter，**libapp_dir=所在目录** 坑③）② `extractSnapshotHashes`（魔数 f5f5dcdc + 偏移+20 取 32 字节 `[0-9a-g]`，8MB 扫描、64B 重叠，对齐 FBox）③ `selectRunner`（hash 交集 + supported + 会话级黑名单）④ `execute`（180s 轮询结果 JSON + 8s 进程探活 + tail runner.log 喂浮窗） |
| `BlutterAnalysisController.start()` | **先快通道**（isAvailable → 抽 so → hash → 命中 → :blutter 执行）；失败/未命中 → 日志明示转慢通道（aicode-blutter）——与 FBox tryFastAnalyze 语义一致；浮窗 route 徽章显示「Runner So」或「容器编译」 |

### 12.3 MINIS-PORT 六坑对照

| 坑 | 处理 |
|---|---|
| ① JNI 包名类名不可改 | ✅ `com.zuimo.fbox.blutterrunner` 原样 |
| ② icu 依赖 | ✅ 一起进 jniLibs |
| ③ libapp_dir 语义 | ✅ 传 libapp.so 所在目录（注释+实现双强调） |
| ④ w.js 硬编码路径 | ⚠ **待办**：runner 内嵌 `/data/data/com.zuimo.fbox/files/w.js`；AiCode 包名不是 fbox 时需**二进制等长替换**（NUL 补齐）。frida 动态插桩场景才用到 w.js——纯静态分析是否触发待真机验证；若触发，打包脚本里按包名 sed so |
| ⑤ :blutter 子进程早退 | ✅ Manifest 已声明独立进程；AiCode 的 Application 无 abstract socket bind，无需早退（注释说明触发条件） |
| ⑥ 环境失败≠不兼容 | ✅ 探活 + 结果 JSON 双通道区分；失败即拉黑，不烧全部 18 个 |

### 12.4 流程

```
选 Flutter → 快通道：cp APK → 解 libapp/libflutter → hash 探测 → runners.json 匹配
    ├─ 命中 → startService(:blutter) → JNI nativeRun → 轮询 result JSON → /root/out/<名>/
    └─ 未命中/崩 → 拉黑 → 慢通道 aicode-blutter（容器编译）
```
