---
name: flutter-re
description: Flutter 应用逆向全流程（Dart AOT 反汇编、libapp.so 打补丁）。含 runner 快通道与容器编译慢通道。
---

# 技能：Flutter 逆向全流程（Blutter + SO 补丁）

对 Flutter APK 做逆向分析并打补丁，最终输出可安装的 patched APK。

## 〇、铁律（最高优先级，违反即严重错误）

- **先读已有结果**：绑定目录或已完成分析存在时，先检查 `pp.txt`、`objs.txt`、`asm/` 和完成状态，确认与目标 APK 对应，不重复解析。
- **App 与 Shell 是不同入口**：选择 Flutter 类型后，App 尝试内置 Runner；`aicode-blutter <apk>` 只走容器编译，不调用 App Runner。
- **只有结果缺失时才启动分析**：先确认实际 APK 路径；已有 App 分析任务时等待，不并行启动第二条解析链。容器分析使用 `terminal` 且 `notify=true`。
- **禁止手搓 blutter 工具链**：不要手动 `cmake`/`ninja` 编译 `/root/flutter-re/blutter`，不要改其 `src/*.cpp` 去「适配 SDK」。慢通道由 `aicode-blutter` 内部驱动，它已经带了必要的兼容补丁（`fbox_gcc13_fix.py` 等）。
- **先查缓存再跑**：`/root/out/<名字>/pp.txt` 已存在就直接读结果，**严禁重跑**（重跑几分钟到十几分钟）。
- **多步骤任务先建清单**：3 步以上先用 `todo` 工具列步骤，逐步更新，完成后清空。

## 一、命令映射（FBox 工具名 → AiCode 实际命令）

| 用途 | 命令 |
|---|---|
| 关键词侦察 | `aicode-apk fast-scan <apk> [关键词,逗号分隔]`（UTF-8/UTF-16LE + DEX；仅提供文件偏移，不是函数地址） |
| 类型检查（仅未知类型时） | `aicode-blutter --scan <apk>` |
| 跑分析与反汇编 | `aicode-blutter <apk> [输出目录]` |
| 查分析状态 / 缓存 | `aicode-blutter --status <名字或out目录>` |
| 全文搜特征串/函数名 | `aicode-blutter --search <out目录> <正则> [limit=30] [offset=0] [per_file=3]` |
| 精读结果 | `readFile` 或 `aicode-blutter --read <文件> [limit=4000] [start_line=1] [start_char=0]`；截断后沿用输出的 `next_line`/`next_char` |
| SO 摘要/符号/JNI/反汇编/字符串 | `aicode-so info\|symbols\|jni\|disasm\|strings\|cfg <so>` |
| SO 打补丁（asm/hex + 分支重定位） | `python3 /root/flutter-re/patch_so.py <so> <addr> "<已核实的arm64汇编>"` 或 `--bytes "20 00 80 52"`；首次原件留 `.orig`、上一版留 `.bak`，并自动入补丁柜 |
| SO 轻量补丁 / 回滚 | `aicode-so patch <so> <addr:hex> [--dry]` / `patch <so> --restore` |
| 重打包（**未签名**） | `aicode-apk rebuild <apk> <out.apk> [--replace <ZIP条目>=<文件>]...` |
| 签名（App 侧工具） | `apkSign apk=<容器路径>` |
| 补丁柜 | `aicode-so patch-list\|patch-read\|patch-status\|patch-rollback\|patch-delete` |
| 知识库 | `aicode-so exp-save …` / `aicode-so exp-query …` |

路径约定：APK 放 `/root/apk/`；分析结果在 `/root/out/<名字>/`（`pp.txt` 常量池/类名、`asm/` Dart 反汇编、`objs.txt` 对象结构）；工具链本体 `/root/flutter-re/`、`/root/so-tool/` **只读使用，不要删改**。

## 二、标准流程（按顺序执行，不要跳步）

1. **侦察环境**：`ls /root/apk` 与 `ls /root/out`，确认有哪些 APK、哪些已完成分析。
2. **判类型**：已由用户选择 Flutter 时不重复检查；仅未知类型时用 `aicode-blutter --scan <实际APK路径>`。非 Flutter 使用 `loadSkill("apk-re")`。
3. **结果优先**：已有有效且匹配的结果就直接读取；结果缺失才经 `terminal` 运行 `aicode-blutter <实际APK路径> [输出目录]`，按结束通知继续。
4. **读总览**：`ls /root/out/<名字>/` 看结构，再读 `pp.txt` 头部，了解类/函数规模。
5. **检查覆盖度（必做）**：运行 `aicode-blutter --status <结果目录>`，分别报告递归汇编文件数与带地址函数数。一个 Dart 文件可含多个函数，`pp.txt` 是对象池，不能将文件数与对象池条目数相除计算恢复率。没有可靠的函数总数时说明“函数覆盖率未验证”；搜索未命中不得断言逻辑不存在。
6. **定位目标**：`aicode-blutter --search /root/out/<名字> "<关键词>"` 全文搜索，逐行计数并跨文件轮转取样。按输出 `next_offset` 翻页；`truncated=true` 不代表其余文件无命中。每次最多 200 条、16000 UTF-8 字节；命中长路径或行被截短时，缩小到目标子目录再搜索。随后 `readFile` 精读函数及真实地址。
7. **确认地址**：地址必须来自 asm 真实标注，**禁止凭空猜**。找不到就如实告诉用户。
8. **搜索止损**：同一目标最多 3 种搜索方式（换关键词 / 搜 `addNames.py` 函数名 / 搜 `objs.txt` 结构），不中就换策略（动态 hook），禁止无限循环。
9. **构造补丁**（arm64）：先从原函数和调用点确认返回类型与 Dart ABI。Dart 的 `true`、`false`、`null` 是对象，不能直接套用 C/JNI 的 `mov w0,#1`、`mov w0,#0` 返回模板；整数也需要按 Smi 编码。引用实际反汇编中的 NULL/布尔对象寄存器与偏移，不猜常量。`nop`、分支和返回均须保持指令边界及调用约定。
10. **打补丁**：`python3 /root/flutter-re/patch_so.py <so> <addr> "<汇编>"`。
    - so 路径以实际文件为准，App Runner 提取库位于 `/root/out/<名字>/lib/arm64-v8a/libapp.so`。只改用户授权目标，非必要不动 `libflutter.so`。
    - 工具会打印「原字节 / 新字节」，**核对原字节是否为预期的函数开头**（如 `STP X29, X30`），防止打错位置。
    - 分支指令注意范围：`b/bl` ±128MB，`b.cond`/`cbz`/`cbnz` ±1MB，`tbz/tbnz` ±32KB，超出会报错。
11. **重打包 + 签名**：
    ```
    aicode-apk rebuild <apk> /root/work/out.apk --replace lib/arm64-v8a/libapp.so=<已修改SO实际路径>
    apkSign apk=/root/work/out.apk
    sendFile paths=[<签名产物容器路径>]
    ```
12. **收尾**：告知产物路径；提醒签名与原版不同需先卸载原版。`sendFile` 报文件超限时，告知用户在「偏好设置 → 工具」调高单文件上限后重试，不伪造导出成功。

## 三、防呆规则（违反=犯错）

- **不臆造路径**：引用任何文件前先 `ls` 确认存在。
- **不猜地址**：虚拟地址必须来自 asm 结果；补丁后必须核对原字节。
- **不动错误目标**：只改用户明确要求的函数；`libflutter.so` / `libdart.so` 非必要不动。
- **不要手动 zip**：重打包必须用 `aicode-apk rebuild`；修改外部 SO 后必须显式 `--replace` 注回，随后对比包内库与已修改库的哈希，不能仅重写原 APK。
- **「没找到」≠「不存在」**：覆盖度不足时，asm 搜不到**不能**作为「逻辑在服务端」的证据，必须标低置信度。
- **结论分级**：区分「事实」「推断」「猜测」，猜测必须明说未验证。
- **如实报告失败**：找不到函数、分析失败、补丁失败都要说明原因与建议，不许编造成功。

## 四、常见坑

- **清理工作区只允许删 `/root/apk` 与 `/root/out` 下的内容**。严禁删 `/root/flutter-re`（工具链）、`/root/ai-skills`、`/root/patches`、`/root/knowledge`，也不得删 `/root` 本身。删前先列出内容让用户确认。
- 输出结构（版本差异大，先 `ls` 确认）：新版 `asm/` 是大量 `.dart` 文件（内含汇编文本与地址标注），旧版是 `.S` 文件。读取方式相同。
- 同一函数可能有多个变体（`xxx_0`、`xxx_1`），注意选对变体。
- arm64 指令固定 4 字节，补丁长度必须是 4 的倍数（hex 模式同样）。
- `libapp.so` 可能超过 100MB，补丁耗时长属正常。
- `patch_so.py` 与轻量补丁共用 `.orig`/`.bak` 和补丁柜；失败时工具恢复上一版，仍应保留原 APK 作为最终基线。
- 若用户要「破解付费/绕过服务器校验」等违规需求，礼貌拒绝并说明只能用于学习与合法逆向。

## 五、自定义技能说明

自定义技能使用 `~/.aicode/skills/<名称>/SKILL.md` 或 `<工作区>/.aicode/skills/<名称>/SKILL.md`，同名项目级优先。
