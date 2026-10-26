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
