---
name: flutter-re
description: Flutter 应用逆向全流程（Dart AOT 反汇编、libapp.so 打补丁）。含 blutter 链与 SO 兜底链。
---

> **移植说明**：本文档原属 FBox，工具名已映射到 AiCode 的 wrapper 命令 ——
> - `start_analysis` / `fast_scan_apk` / `search_flutter` / `read_flutter_result` → **`aicode-blutter <apk>`** 产出 `/root/out/<名字>/`
>   （`pp.txt` 常量池/类名、`asm/` Dart 反汇编、`objs.txt`），随后用 `grep` / `readFile` 自行读取；
> - `so_info` / `so_symbols` / `so_jni` / `so_disasm` / `so_strings` → **`aicode-so <子命令>`**；
> - `patch_so` → 按 `aicode-so disasm` 得到的偏移，用 `python3` 就地改字节（或后续补丁工具）。
> 路径约定不变：APK 放 `/root/apk/`，结果在 `/root/out/`。
> **先查缓存**：`/root/out/<名字>/pp.txt` 已存在就直接读结果，**严禁重跑 `aicode-blutter`**（重跑几分钟起）。

# 技能：Flutter 逆向全流程（Blutter + SO 补丁）

对 Flutter APK 做逆向分析并打补丁，最终输出可安装的 patched APK。涉及工具：Blutter（Dart AOT 反汇编）、patch_so（补丁）、repack_apk（重打包签名）。

## 〇、铁律（最高优先级，违反即严重错误）

- **Dart 代码反汇编一律调用 `start_analysis` 工具**，它会用内置的、已适配各 Dart 版本（含 3.10.0 等最新版）的预编译 blutter 二进制，自动按 APK 的 Dart 版本选 runner，秒级离线分析并自动缓存。
- **绝对禁止**手动执行 `python3 blutter.py`、`python3 extract_dart_info.py`、`dartvm_fetch_build.py`，禁止手动 `cmake`/`ninja` 编译 blutter 工具链，禁止手改 `/root/flutter-re/blutter/src/*.cpp` 去"适配 SDK"。
- **为什么禁止**：容器内 `/root/flutter-re/blutter` 是一套过期的独立源码工具链，与新版 Dart（3.4+ 单快照模型）的 ABI 不兼容（`_kDartVmSnapshotData` 旧双快照符号已废弃、Closure 布局变更、stub 重构），用它必然陷入无休止编译报错。APK 的 Dart 版本再新（3.10/3.13 等），`start_analysis` 也能正确处理，无需、也禁止自己去编译工具链。
- 一旦发现自己在调试 `/root/flutter-re/blutter` 这套工具链的编译/符号问题，**立即停止**，改用 `start_analysis`。

## 一、标准流程（按顺序执行，不要跳步）

1. **先侦察环境**：用 `run_terminal_command` 执行 `ls -R /root/apk` 和 `ls -R /root/out`，确认有哪些 APK、哪些已完成分析。
2. **判断分析状态**：
   - APK 存在但 `/root/out` 没有对应子目录 → 调用 `start_analysis`（参数 apk_name）后台启动分析，告知用户「分析已在后台运行，完成后我会自动继续」，然后**停下等待系统通知**，不要继续往下做。
   - APK 不存在 → 告知用户先在「Flutter 逆向」页导入并选择 APK。
   - 分析结果已存在 → 直接进入第 3 步。
   - 分析缓存说明：同一 APK（文件内容未变）重复调用 start_analysis 会自动命中缓存，秒级返回并复用 `/root/out/<应用>` 旧结果（系统通知会标注「命中缓存」），**不需要重新分析**；只有换用新版本 APK 才需要重新分析。同 Dart 版本的多个 APK 也会复用已编译的 Blutter 二进制与 Dart VM，不会重复下载编译。
3. **读总览**：先 `read_dir` 查看 `/root/out/<应用>/` 结构（不同 Blutter 版本输出差异较大），再读取 `README.md`（若存在），了解库结构、符号数量、关键函数。若没有 README.md，直接看目录结构即可，不要卡住。
4. **检查覆盖度（重要，必须做）**：新版 Blutter 反汇编是 `asm/` 下大量 `.dart` 文件（内含汇编），旧版是 `.S` 文件。用 `run_terminal_command` 执行：
   ```
   find /root/out/<应用>/asm -type f \( -name '*.S' -o -name '*.dart' \) | wc -l; grep -c 'size: -0x1' /root/out/<应用>/addNames.py 2>/dev/null
   ```
   比较已反汇编函数数与未反汇编（size: -0x1）函数数。若未反汇编占比 > 20%，**后续所有"asm 中未找到引用"的结论都要标注低置信度**，并优先考虑动态验证（frida）而非纯静态判断。
5. **定位目标**：先用 `search_flutter`（参数：app=应用目录名、query=关键字符串）在结果目录全文搜索目标函数名/字符串，一步拿到所有命中文件+行号；再用 `read_flutter_result` 精读命中文件，找到函数入口虚拟地址（文件内以 `0x...` 标注）。若无命中，再考虑 `pp.txt`（常量池）反查函数名。
6. **确认地址**：地址必须来自 asm 文件真实标注，**禁止凭空猜测地址**。若找不到目标，如实告诉用户，不要硬编。
7. **搜索止损**：同一目标最多尝试 3 种不同搜索方式（pp 偏移搜索 / 二进制指令模式 / 函数名关联），3 次不中就切换策略（frida 动态 hook、搜 addNames.py 函数名、搜 objs.txt 对象结构），**禁止无限重复同类搜索**。
8. **动态验证（推荐在静态瓶颈时使用）**：当静态分析无法定位或覆盖度低时，用 `run_terminal_command` 尝试 frida：
   - `frida -U -f <包名> -l /root/out/<应用>/blutter_frida.js --no-pause 2>&1`
   - 或编写短 hook 脚本 hook JSON 解析 / 目标函数返回值
   - 动态结果能直接验证"改某值是否生效"，比纯静态猜测可靠
9. **构造补丁**：根据用户需求写 arm64 汇编（推荐）或 hex 字节：
   - 返回 false / 0：`mov w0, #0; ret`
   - 返回 true / 1：`mov w0, #1; ret`
   - 返回 null：`mov x0, #0; ret`
   - 跳过一段逻辑：若干 `nop`
   - 直接跳转：`b #0x目标地址`（arm64 分支为 PC 相对，工具会自动换算偏移；也可写 `b 0x目标地址`）
10. **打补丁**：调用 `patch_so`，参数：
   - so_path：`root/apk/<应用>/lib/arm64-v8a/libapp.so`（libapp.so 是 Dart 代码所在；只有改 Flutter 引擎才动 libflutter.so）
   - address：第 5 步确认的虚拟地址（0x 开头）
   - patch：汇编指令或 hex 字节
   - format：`asm` 或 `hex`
   - 链式补丁：连续打多个补丁时，`patch_so` 会自动基于上一次的 `.patched` 文件继续打（所有补丁累积生效），不需要重新解压 APK；打完所有补丁后只需 `repack_apk` 一次。若需重置，删除 `/root/apk/<应用>/lib/arm64-v8a/libapp.so.patched` 或重新解压 APK 即可。
11. **核对输出**：patch_so 会返回「原字节 / 新字节 / 写入结果」，检查原字节是否为预期的函数开头（例如 `STP X29, X30` 等），防止打错位置。
12. **重打包**：调用 `repack_apk`（参数 apk_name 必填，so_path 可省略）自动重打包 + 签名 + 导出。
13. **收尾**：告知用户导出路径（`下载/FBox/<应用>-patched.apk`），并提醒：若目标 App 有签名校验，安装后可能闪退，需要配合 frida 绕过（容器已内置 frida）。

## 二、防呆规则（必须遵守，违反=犯错）

- **不臆造路径**：所有文件路径先用 `ls` 确认存在，再引用。
- **不猜地址**：虚拟地址必须来自 asm 分析结果；补丁后必须核对「原字节」是否符合预期。
- **不动错误目标**：只改用户明确要求的函数；`libflutter.so` / `libdart.so` 非必要不动。
- **不要手动 zip**：重打包必须用 `repack_apk`，禁止用 shell 的 zip/unzip 改 APK 后假装完成。
- **分析完成前不补丁**：`start_analysis` 返回不代表分析完成，必须等「系统通知」。
- **如实报告失败**：找不到函数、分析失败、补丁失败都要如实说明原因和建议，不许编造成功。
- **"没找到"≠"不存在"**：反汇编覆盖度不足（未反汇编函数占比 > 20%）时，asm 中搜不到字符串引用**不能**作为"该逻辑在服务端/代码中不存在"的证据，必须标注低置信度，且优先用 frida 动态验证。禁止仅凭静态搜索失败就断言"patch 无效"或"服务端驱动"。
- **结论分级**：输出结论时区分「事实（asm/命令输出直接可见）」「推断（多证据推理）」「猜测（未验证的推测）」，猜测必须明说"这是猜测，未验证"。
- **搜索止损**：同一目标最多 3 种搜索方式，不中就换策略（动态 hook / addNames.py / objs.txt），禁止无限循环同类搜索。

## 三、常见坑

- 清理工作区时只允许删除 `/root/apk`（导入的 APK）与 `/root/out`（分析结果）下的内容，例如 `rm -rf /root/apk/*`、`rm -rf /root/out/*`。**严禁删除 `/root/flutter-re`（工具链）、`/root/ai-skills`（自定义技能）、`/root/patches`（补丁存储柜）**，也不得删除 /root 根目录本身。删除前先列出内容让用户确认。
- Blutter 输出结构（版本差异大，先 `read_dir` 确认）：`/root/out/<应用>/` 通常含 `pp.txt`（常量池）、`asm/`（反汇编，新版为 `.dart` 文件内含汇编、旧版为 `.S` 文件）、`addNames.py`/`objs.txt`（符号与对象）、`frida.js`（Hook 脚本）。README.md 不一定存在。
- asm 文件命名含函数名；同一函数可能有多个变体（如 `xxx_0`、`xxx_1`），确认选择目标变体。新版 `.dart` 文件通常同时含汇编文本与地址标注，读取方式与 `.S` 相同。
- **patch_so 的 asm 格式支持绝对地址分支**：写 `b #0x目标地址`、`bl #0x目标地址`、`b.eq #0x目标地址`、`tbz w0, #4, #0x目标地址` 等时，工具会自动按补丁地址计算相对偏移并正确编码（arm64 分支是 PC 相对，不要自己换算偏移）。但注意分支范围限制：`b/bl` 只能跳 ±128MB，`b.cond`/`cbz`/`cbnz` 只能 ±1MB，`tbz`/`tbnz` 只能 ±32KB，超出会报「conditional branch out of range」。
- asm 文件命名含函数名；同一函数可能有多个变体（如 `xxx_0`、`xxx_1`），确认选择目标变体。
- arm64 指令固定 4 字节，patch 内容长度必须是 4 的倍数（hex 模式同样）。
- libapp.so 可能超过 100MB，补丁脚本最多等待 5 分钟，属于正常。
- 补丁只改文件，不产生 `.bak` 之外的可逆备份，失败重来用 `run_terminal_command` 从原 APK 重新解压即可。
- 若用户要「破解付费/绕过服务器校验」等违规需求，礼貌拒绝并说明只能用于学习与合法逆向。

## 四、自定义技能说明

用户可在容器 `/root/ai-skills/` 放置同名 `.md` 自定义技能（会覆盖本默认技能）；其他 `.md` 会被 `list_skills` 列出、`read_skill` 读取。
