---
name: flutter-re
description: Flutter 应用逆向全流程（Dart AOT 反汇编、libapp.so 打补丁）。含 runner 快通道与容器编译慢通道。
---

# 技能：Flutter 逆向全流程（Blutter + SO 补丁）

对 Flutter APK 做逆向分析并打补丁，最终输出可安装的 patched APK。

## 〇、铁律（最高优先级，违反即严重错误）

- **先读已绑定或已完成的分析结果**。当前系统上下文若已绑定 `/root/out/<目录>`，先查看其中的 `pp.txt`、`asm/`、`objs.txt`，围绕这些结果完成用户需求；存在目录不等于分析完整，需要检查文件内容与覆盖度，不要重复解析。
- **App 与 shell 是不同入口**：用户在类型选择框选择 Flutter 后，App 先尝试内置 Runner；未命中时才使用容器编译路线。shell 的 `aicode-blutter <apk>` 只执行容器编译，不会调用 App 侧 Runner。
- **结果不存在时才启动分析**：先确认对应原 APK 确实存在；App 正在解析时等待其完成，不并行启动第二条链。需要在容器中解析时通过 `terminal` 运行 `aicode-blutter <实际APK路径> [输出目录]`，按后台任务通知继续，不能假装已有结果。
- **禁止手搓 blutter 工具链**：不要手动 `cmake`/`ninja` 编译 `/root/flutter-re/blutter`，不要改其 `src/*.cpp` 去「适配 SDK」。慢通道由 `aicode-blutter` 内部驱动，它已经带了必要的兼容补丁（`fbox_gcc13_fix.py` 等）。
- **先查缓存再跑**：`/root/out/<名字>/pp.txt` 已存在就直接读结果，**严禁重跑**（重跑几分钟到十几分钟）。
- **多步骤任务先建清单**：3 步以上先用 `todo` 工具列步骤，逐步更新，完成后清空。

## 一、命令映射（FBox 工具名 → AiCode 实际命令）

| 用途 | 命令 |
|---|---|
| 秒级侦察（分析前必做） | `aicode-blutter --scan <apk>` |
| 跑分析与反汇编 | `aicode-blutter <apk> [输出目录]` |
| 查分析状态 / 缓存 | `aicode-blutter --status <名字或out目录>` |
| 全文搜特征串/函数名 | `aicode-blutter --search <out目录> <正则>` |
| 精读结果 | `readFile` / `search` 工具直接读 `/root/out/<名字>/` 下文件 |
| SO 摘要/符号/JNI/反汇编/字符串 | `aicode-so info\|symbols\|jni\|disasm\|strings\|cfg <so>` |
| SO 打补丁（asm/hex + 分支重定位） | `python3 /root/flutter-re/patch_so.py <so> <addr> "mov w0,#1; ret"` 或 `--bytes "20 00 80 52"`，`--out` 另存、自动 `.bak` |
| SO 轻量补丁 / 回滚 | `aicode-so patch <so> <addr:hex> [--dry]` / `patch <so> --restore` |
| 重打包（**未签名**） | `aicode-apk rebuild <apk> <out.apk>` |
| 签名（App 侧工具） | `apkSign apk=<容器路径>` |
| 补丁柜 | `aicode-so patch-list\|patch-read\|patch-status\|patch-rollback\|patch-delete` |
| 知识库 | `aicode-so exp-save …` / `aicode-so exp-query …` |

路径约定：APK 放 `/root/apk/`；分析结果在 `/root/out/<名字>/`（`pp.txt` 常量池/类名、`asm/` Dart 反汇编、`objs.txt` 对象结构）；工具链本体 `/root/flutter-re/`、`/root/so-tool/` **只读使用，不要删改**。

## 二、标准流程（按顺序执行，不要跳步）

1. **侦察环境**：`ls /root/apk` 与 `ls /root/out`，确认有哪些 APK、哪些已完成分析。
2. **判类型**：已由用户选择 Flutter 或已明确绑定其分析结果时，不重复扫描。未确定类型时用 `aicode-blutter --scan <实际APK路径>` 查看 Flutter 特征；非 Flutter 请改用 `loadSkill("apk-re")`。
3. **结果优先**：已绑定目录或已有对应结果时直接进入第 4 步；只有结果缺失且 APK 路径已核实时才运行 `aicode-blutter <实际APK路径> [输出目录]`。该命令走容器编译路线，首次可能耗时十几分钟。
4. **读总览**：`ls /root/out/<名字>/` 看结构，再读 `pp.txt` 头部，了解类/函数规模。
5. **检查覆盖度（必做）**：
   ```
   find /root/out/<名字>/asm -type f -name '*.dart' | wc -l
   ```
   与 `pp.txt` 里的函数总数对比。未反汇编占比 > 20% 时，**后续「asm 中未找到」的结论都要标低置信度**，优先考虑动态验证而非断言不存在。
6. **定位目标**：`aicode-blutter --search /root/out/<名字> "<关键词>"` 全文搜（`pp.txt` + `asm/`）。命中后 `readFile` 精读，找函数入口虚拟地址（asm 文件内以 `0x...` 标注）。
7. **确认地址**：地址必须来自 asm 真实标注，**禁止凭空猜**。找不到就如实告诉用户。
8. **搜索止损**：同一目标最多 3 种搜索方式（换关键词 / 搜 `addNames.py` 函数名 / 搜 `objs.txt` 结构），不中就换策略（动态 hook），禁止无限循环。
9. **构造补丁**（arm64）：
   - 返回 false/0：`mov w0, #0; ret`
   - 返回 true/1：`mov w0, #1; ret`
   - 返回 null：`mov x0, #0; ret`
   - 跳过一段逻辑：若干 `nop`
   - 直接跳转：`b #0x目标地址`（PC 相对由工具换算）
10. **打补丁**：`python3 /root/flutter-re/patch_so.py <so> <addr> "<汇编>"`。
    - so 用 `/root/apk/<应用>/lib/arm64-v8a/libapp.so`（Dart 代码所在；只有改引擎才动 `libflutter.so`）。
    - 工具会打印「原字节 / 新字节」，**核对原字节是否为预期的函数开头**（如 `STP X29, X30`），防止打错位置。
    - 分支指令注意范围：`b/bl` ±128MB，`b.cond`/`cbz`/`cbnz` ±1MB，`tbz/tbnz` ±32KB，超出会报错。
11. **重打包 + 签名**：
    ```
    aicode-apk rebuild <apk> /root/work/out.apk
    apkSign apk=/root/work/out.apk
    sendFile paths=[<签名产物容器路径>]
    ```
12. **收尾**：告知产物路径；提醒签名与原版不同需先卸载原版；若有签名校验可能闪退，需配合 hook 绕过。

## 三、防呆规则（违反=犯错）

- **不臆造路径**：引用任何文件前先 `ls` 确认存在。
- **不猜地址**：虚拟地址必须来自 asm 结果；补丁后必须核对原字节。
- **不动错误目标**：只改用户明确要求的函数；`libflutter.so` / `libdart.so` 非必要不动。
- **不要手动 zip**：重打包必须用 `aicode-apk rebuild`，禁止用 `zip/unzip` 改 APK 后假装完成。
- **「没找到」≠「不存在」**：覆盖度不足时，asm 搜不到**不能**作为「逻辑在服务端」的证据，必须标低置信度。
- **结论分级**：区分「事实」「推断」「猜测」，猜测必须明说未验证。
- **如实报告失败**：找不到函数、分析失败、补丁失败都要说明原因与建议，不许编造成功。

## 四、常见坑

- **清理工作区只允许删 `/root/apk` 与 `/root/out` 下的内容**。严禁删 `/root/flutter-re`（工具链）、`/root/ai-skills`、`/root/patches`、`/root/knowledge`，也不得删 `/root` 本身。删前先列出内容让用户确认。
- 输出结构（版本差异大，先 `ls` 确认）：新版 `asm/` 是大量 `.dart` 文件（内含汇编文本与地址标注），旧版是 `.S` 文件。读取方式相同。
- 同一函数可能有多个变体（`xxx_0`、`xxx_1`），注意选对变体。
- arm64 指令固定 4 字节，补丁长度必须是 4 的倍数（hex 模式同样）。
- `libapp.so` 可能超过 100MB，补丁耗时长属正常。
- 补丁只改文件，`patch_so.py` 会自动留 `.bak`；失败重来从原 APK 重新解压即可。
- 若用户要「破解付费/绕过服务器校验」等违规需求，礼貌拒绝并说明只能用于学习与合法逆向。

## 五、自定义技能说明

用户可在容器 `/root/ai-skills/` 放置同名 `.md` 自定义技能（覆盖本默认技能）。
