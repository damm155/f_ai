---
name: flutter-re
description: Flutter 应用逆向全流程（Dart AOT 反汇编、libapp.so 打补丁）。含 runner 快通道与容器编译慢通道。
---

# 技能：Flutter 逆向全流程（Blutter + SO 补丁）

对 Flutter APK 做逆向分析并打补丁，最终输出可安装的 patched APK。

## 〇、铁律（最高优先级，违反即严重错误）

- **Dart 反汇编一律用 `aicode-blutter`**，它会自动选路：
  - **快通道**：命中内置预编译 runner（App 侧 `:blutter` 进程，秒级、离线、零 token）；
  - **慢通道**：未命中时在容器内现场编译 blutter（首次需联网拉 Dart SDK，十几分钟，属正常）。
- **不要自己选路、不要自己判断该走哪条**。直接 `aicode-blutter <apk>`，快慢由工具决定。
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
2. **判类型**：`aicode-blutter --scan <apk>` 秒级确认是 Flutter（有 `libapp.so` / `libflutter.so` / `flutter_assets`）。非 Flutter 请改用 `loadSkill("apk-re")`。
3. **启动分析**：结果目录不存在时跑 `aicode-blutter /root/apk/<apk>`。快通道秒级返回；慢通道会打印编译进度，可耗时十几分钟，**耐心等，不要中断重试**。
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
