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
| Flutter Dart AOT 分析（容器编译路线） | `aicode-blutter <apk> [out]` | start_analysis |

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
7. **改动前先备份**：`aicode-apk rebuild` 产出的是**未签名** APK；要交付可安装包需另行签名，
   并在交付时说明这一点。
8. **别把工作区当垃圾场**：临时脚本、中间产物放 `/root/work/`；不要在 `/root` 根下或工作区里乱写文件。
