---
name: apk-re
description: 原生 APK 逆向（AndroidManifest / DEX 查改与重打包）。非 Flutter 目标时用本技能。
---

> **移植说明**：本文档原属 FBox，工具名已映射到 AiCode 的 wrapper 命令 ——
> `apk_manifest` / `apk_dex_search` / `apk_dex_inspect` / `apk_dex_fields` / `apk_dex_patch` / `apk_sign` / `repack_apk`
> 一律改用 `aicode-apk <子命令>`（先跑 `aicode-apk --help` 看全部子命令与参数）。
> 路径约定不变：APK 放 `/root/apk/`，工具默认在那里找；临时产物放 `/root/work/`。
> 注意：`aicode-apk rebuild` 产出的 APK **未签名**，交付时要说明。

# 技能：原生 APK 逆向（Manifest + DEX，非 Flutter 目标）

对任意 Android APK（Kotlin/Java 原生应用，非 Flutter）做 Manifest 查询修改、DEX 字符串搜索、smali 反汇编、方法补丁，最终签名导出可安装 APK。涉及工具：apk_manifest、apk_dex_search、apk_dex_inspect、apk_dex_fields、apk_dex_patch、apk_sign。全部为内置工具链（容器 /root/apk-tool，纯 Python 直读二进制，无需反编译整个 APK，秒级）。

## 〇、铁律（最高优先级，违反即严重错误）

- **工具链自动部署**：首次调用任一 apk_* 工具会自动把内置工具链部署到容器（/root/apk-tool/），无需手动安装。若提示「容器内没有 python3」，指引用户到「Flutter 逆向 · Blutter」页一键安装 Python 环境。
- **判断目标类型再选链**：目标是 Flutter 应用（有 libapp.so/libflutter.so）→ 走 read_skill(flutter-re) 的 Blutter 链；目标是普通原生应用 → 走本技能的 DEX 链。不要用错。
- **禁止反编译整个 APK**：本工具链直读二进制 DEX/AXML，禁止安装 apktool/jadx 到容器再全量反编译（慢且没必要），禁止手动 python3 调 reapk 内部 API（一律走 5 个工具）。
- **改完必须签名导出**：任何修改（manifest/dex/string）完成后，必须调用 apk_sign 导出，禁止把未签名 APK 留在容器里让用户自己取。

## 一、标准流程（按顺序执行，不要跳步）

1. **侦察环境**：`run_terminal_command` 执行 `ls /root/apk` 确认可用 APK（工具参数 apk 传文件名即可，也可传 /root/apk 下绝对路径）。
2. **看 Manifest**：调用 `apk_manifest`（action=get, apk=app.apk）拿包名/版本/权限/导出组件/debuggable 状态，了解攻击面。顺带确认目标不是 Flutter（无 libapp.so）。
3. **定位目标**：调用 `apk_dex_search`（mode=strings, query=正则）搜特征字符串（会员/解锁/接口地址/UI 文案）。命中后再 mode=refs 拿到「哪个类->哪个方法」加载了该字符串——这直接就是逻辑代码位置。**禁止用 shell 的 strings|grep|sort 组合拳替代本工具。**
4. **读代码**：调用 `apk_dex_inspect`：
   - mode=class 列出类的全部方法（含签名与 native 标记），核对方法名；
   - mode=method 反汇编方法体为带地址 smali（自动给出寄存器数），读懂逻辑。
5. **看字段**：调用 `apk_dex_fields`（class=类描述符）一次列出该类全部字段（static/instance 分组、Java 类型、访问标志）。确认实体类成员布局（如用户实体里金币/会员字段是哪个）、找状态开关字段时必用——**绝对禁止为看类字段手写 Python 解析 DEX**。
6. **打补丁**：调用 `apk_dex_patch`，按场景选模式：
   - **return 模式（最常用）**：布尔开关类逻辑（isVip/isAd/premium/isValid）直接强制返回 true/false/null/void，秒级，原地 nop 填充。例：mode=return, class=Lcom/x/pay/VipManager;, method=isVip, value=true。
   - **smali 模式（改逻辑）**：先用 `file_write` 写新方法体 smali 文件（每行一条指令，寄存器数沿用原方法），再 mode=smali 传文件路径。支持扩容/新增字符串与引用。常用片段：
     - 返回 true：`const/4 v0, #1` + `return v0`
     - 返回 false：`const/4 v0, #0` + `return v0`
     - 跳过调用：把对应 invoke 行删掉或改为 nop
   - **string 模式（改文案/URL）**：old_string 精确匹配，new_string 不得比旧串长（MUTF-8 编码后），产出新 APK（需 out_apk 参数）。
7. **签名导出**：调用 `apk_sign`（apk=修改后的 APK 文件名）完成重对齐 + v1+v2 签名 + 导出到「下载/FBox/」。
8. **收尾**：告知用户导出路径，提醒：签名与原版不同，需先卸载原版再安装；若目标有签名校验（SignatureCheck）可能闪退，可用 apk_dex_search 搜 "signature" 相关类再补丁其校验方法。

## 一b、字符串加密混淆应对（np/protect 等加固）

发现字符串被加密混淆（反汇编里是 sparse-switch 查表 + 反射调用 `Lnp/protect/...;` 解密方法，直接读不出语义）时：

- **立即放弃**死磕解密类 <init> 和解密算法——那是无底洞。
- **改走 UI 文案锚点路线**：apk_dex_search(strings) 搜界面提示文案（「车票数不够」「会员到期」「余额不足」这类用户可见提示）→ mode=refs 定位加载它的 类->方法 → apk_dex_inspect 反汇编该方法，直接看业务判断逻辑（比较哪个字段、跳转条件是什么）。文案锚点不受字符串加密影响（运行时明文加载）。
- 实体字段语义不明时用 apk_dex_fields 拿字段布局（类型/顺序），再结合业务方法里 iget/iput 的字段索引对照推断。
- 同一解密目标死磕最多 2 次即换路线。

## 二、防呆规则（必须遵守，违反=犯错）

- **类描述符格式**：必须是 `Lcom/example/Class;`（L 开头分号结尾，包名用斜线）。混淆后类名是 `La/b/c;` 这类短名，先 strings/refs 搜到再复制，禁止凭空拼类名。
- **方法名不带签名**：method 参数只传方法名（如 isVip），不传括号签名；同名重载取第一个有 code 的。
- **不猜偏移**：smali 补丁前必须先用 apk_dex_inspect mode=method 看过原方法体，确认寄存器数够用（新指令的寄存器号不得超原方法 registers 数）。
- **string 模式长度限制**：新串不能比旧串长是硬限制，长了就换思路（改加载它的方法逻辑），不要反复尝试。
- **原地修改不可逆**：return/smali 模式直接改写目标 APK 的 dex（无备份）。改坏了用 `run_terminal_command` 从原始 APK 重新导入（或让用户重新导入原 APK）。
- **搜索止损**：同一目标最多 3 种搜索方式（换关键词/换正则/搜类名），不中就换策略（refs 反查、动态验证），禁止无限循环同类搜索。
- **如实报告**：类未找到、方法未找到、补丁失败都要如实说明，不许编造成功。

## 三、常见坑

- 加固应用（360/腾讯乐固/梆梆）的 classes.dex 只是壳，真实 dex 运行时才解密——strings 搜不到目标特征串时先想到加固，如实告知用户本工具链不支持脱壳。
- 多 dex 应用：工具自动遍历全部 classesN.dex，无需关心目标在哪个 dex。
- native 方法（JNI）在 DEX 里没有代码体，dex-class 会标 [native]；要改 native 逻辑得动 so，超出本工具链范围。
- dex-smali 重写后整 DEX 重排（池扩容），文件会变大属正常；SHA-1/Adler32 自动重算。
- manifest-edit 与 dex 补丁是两类修改：manifest-edit 产出新 APK 文件；dex return/smali 是原地改。两者可在同一 APK 上叠加（先 manifest-edit 出新文件，再在新文件上打 dex 补丁）。
- Android 9 及以下设备不认 v2-only 签名——本工具 v1+v2 都签，无需关心。
- 若用户要「破解付费/绕过服务器校验」等违规需求，礼貌拒绝并说明只能用于学习与合法逆向。

## 四、自定义技能说明

用户可在容器 `/root/ai-skills/` 放置同名 `.md` 自定义技能（会覆盖本默认技能）；其他 `.md` 会被 `list_skills` 列出、`read_skill` 读取。
