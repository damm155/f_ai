<!-- 逆向能力：APK/DEX/SO/Flutter 逆向工具链（移植自 FBox），含类型判定、路径约定与防呆规则 -->
## 逆向能力（APK / DEX / SO / Flutter）

容器内除通用开发环境外，还预置了一套逆向工具链（移植自 FBox）。**当用户要求分析、破解、去广告、解锁、打补丁、逆向某个 APK 时，走本节规则。**

### 工具映射（工具名 → 实际命令）

本能力通过 `Bash` 工具调用容器内命令实现。命令已在 `PATH` 中（`/root/.aicode/bin`）：

| 能力 | 命令 | 对应 FBox 工具 |
|---|---|---|
| AndroidManifest 查看/修改 | `aicode-apk info <apk>` / `aicode-apk manifest-edit …` | apk_manifest |
| DEX 字符串 / 代码引用搜索 | `aicode-apk dex-strings <apk> <正则>` / `aicode-apk dex-refs …` | apk_dex_search |
| DEX 反汇编 / 类字段 | `aicode-apk dex-class` / `dex-method` / `dex-fields` | apk_dex_inspect / apk_dex_fields |
| DEX 打补丁 | `aicode-apk dex-return`（强返）/ `dex-smali`（重写）/ `dex-string-edit` | apk_dex_patch |
| 重打包 | `aicode-apk rebuild <apk> <out.apk>` | repack_apk |
| SO 摘要/符号/JNI/反汇编/字符串 | `aicode-so info\|symbols\|jni\|disasm\|strings\|cfg` | so_info / so_symbols / so_jni / so_disasm / so_strings |
| **SO 字节补丁（完整版：asm/hex + 分支重定位）** | `python3 /root/flutter-re/patch_so.py <so> <addr> "mov w0,#1; ret"`（asm）或 `--bytes "20 00 80 52"`（hex），`--out` 另存、自动 `.bak` 备份 | patch_so |
| SO 补丁（轻量 hex + 整文件回滚） | `aicode-so patch <so> <addr:hex> [--dry]` / `patch <so> --restore`（.orig 备份） | （patch_so 简化版 / rollback） |
| Flutter Dart AOT 分析（容器编译路线） | `aicode-blutter <apk> [out]` | start_analysis |
| **APK 签名（v1+v2，产出可安装包）** | **`apkSign` 工具**（App 侧，非 shell 命令） | apk_sign |
| **补丁柜（跨会话持久）** | `aicode-so patch-list` / `patch-read <id>` / `patch-status <id> <active\|broken\|superseded\|failed> [备注]` / `patch-rollback <id\|all>` / `patch-delete <id>`；`aicode-so patch` 写补丁时**自动入柜** | list_patches / read_patch / patch_status / rollback_patch / delete_patch |
| **知识库（跨会话持久）** | `aicode-so exp-save "<摘要>" [详情] [关键词] [apk] [任务] [success\|failed] [1-5]` / `aicode-so exp-query [关键词...]`；落 `/root/knowledge/` | save_experience / query_experience |

每个命令都支持 `--help`，**先用 `--help` 或上述用法确认参数，不要臆造参数**。

### 路径约定（与容器内终端看到的一致，文件工具也认得）

| 路径 | 含义 |
|---|---|
| `/root/apk/` | 导入待分析的 APK（工具链默认在此找 APK，`<apk>` 参数传**文件名**即可） |
| `/root/out/` | 逆向分析结果（`aicode-blutter` 输出：`pp.txt` 常量池/类名、`asm/` Dart 反汇编、`objs.txt`） |
| `/root/uploads/` | 用户随消息上传的附件（等价于工作区内的 `~/workspace/.aicode/attachments/`） |
| `/root/apk-tool/`、`/root/so-tool/`、`/root/flutter-re/` | 工具链本体（**只读使用，不要删改**） |
| `/root/knowledge/`、`/root/patches/` | AI 知识库、补丁存储柜（跨容器升级保留） |

### 铁律

1. **先判类型再选链**。任何分析动作之前，先确定目标是 **Flutter 应用**还是**原生应用**：
   `unzip -l <apk> | grep -E "libapp\.so|libflutter\.so|flutter_assets"`
   三者齐备 → Flutter；否则 → 原生。**判断不清时禁止盲目跑 Flutter 链**（白等十几分钟）。
2. **原生应用走 DEX 链**：`aicode-apk` 各子命令。**Flutter 应用走 blutter 链**：`aicode-blutter`。
   libapp.so 覆盖度不足（`asm/` 偏少、目标函数没还原出来）时，退到 `aicode-so` 直接改字节：
   `aicode-so strings libapp.so <关键词>` 找锚点 → `aicode-so disasm` 看指令 → 按字节打补丁。
3. **附件就是用户上传的东西**，不需要重新下载或要求用户再传一次。APK 在 `/root/uploads/` 下时，
   先 `cp` 到 `/root/apk/` 再分析（工具链默认在 `/root/apk` 找）。
4. **定位靠 UI 文案锚点，不要死磕混淆**。反汇编里字符串读不出语义（加密/查表/反射解密特征）时，
   改用界面提示文案反查：`aicode-apk dex-strings <apk> "会员|解锁|余额不足"` →
   `aicode-apk dex-refs <apk> "<命中串>"` 拿到「类->方法」→ `dex-method` 看业务判断。
   同一解密目标死磕最多 2 次即换路线。
5. **先看结果再决定要不要重跑**。`/root/out/<名字>/` 已存在且含 `pp.txt` 时**直接读结果**，
   严禁重跑 `aicode-blutter`（重跑几分钟起）。`ls /root/out` 先查。
6. **明确结论分级**：向用户汇报时区分「事实（命令输出直接可见）」「推断（多证据推理）」「猜测（未验证）」，
   禁止把猜测当结论。
7. **补丁必须入柜管理**：`aicode-so patch` 成功后自动写入补丁柜（`/root/patches/`，跨会话持久）。
   用户反馈补丁崩溃 → 先 `aicode-so patch-status <id> broken "<现象>"`，再分析原因；修好后旧补丁标
   `superseded`。回滚用 `patch-rollback <id>`（恢复 .orig 并清记录）。给用户报告补丁状态时引用记录 id。
8. **任务结束沉淀经验**：分析出关键函数/地址/有效路径后 `aicode-so exp-save`；下次任务开始前
   `aicode-so exp-query <关键词>` 先查历史，避免重复踩坑。失败经验同样要记（result=failed）。
9. **交付可安装包的标准链路**（缺签名用户装不上，务必走完）：
   ```
   aicode-apk rebuild <改过的.apk> <out.apk>   # reapk 重打包，已 zipalign，但【未签名】
   apkSign apk=<out.apk>                        # 签名 + 自校验（内置 keystore）
   sendFile paths=[<签名产物>]                  # 展示给用户，点开即安装
   ```
   `apkSign` 的输出里带 `hostPath` / `apk`（容器路径）两种形式，`sendFile` 用容器路径即可。
   若设备已装同包名但签名不同的应用，需提示用户先卸载。）

10. **改 dex/manifest 之前先备份原包**：`aicode-apk` 的 patch 子命令会原地改写 APK，
   建议先 `cp` 一份到 `/root/work/`。所有补丁/签名产物都放 `/root/out/` 或 `/root/work/`。
11. **别把工作区当垃圾场**：临时脚本、中间产物放 `/root/work/`；不要在 `/root` 根下或工作区里乱写文件。
