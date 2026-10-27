---
name: apk-re
description: 原生 APK 逆向（AndroidManifest / DEX 查改与重打包）。非 Flutter 目标时用本技能。
---

# 技能：原生 APK 逆向（Manifest + DEX，非 Flutter 目标）

对任意 Android APK（Kotlin/Java 原生应用，非 Flutter）做 Manifest 查询修改、DEX 字符串搜索、smali 反汇编、方法补丁，最终签名导出可安装 APK。

工具全部是容器内 `aicode-apk` 的子命令（纯 Python 直读二进制，无需反编译整个 APK，秒级）。**先跑 `aicode-apk --help` 确认参数，禁止臆造参数。**

## 〇、铁律（最高优先级，违反即严重错误）

- **先判类型再选链**。目标是 Flutter 应用（`libapp.so` / `libflutter.so` / `assets/flutter_assets`）→ 改用 `loadSkill("flutter-re")` 走 blutter 链；目标是普通原生应用 → 继续本技能。判定用 `unzip -l <apk> | grep -E "libapp\.so|libflutter\.so|flutter_assets"` 或 `aicode-apk info <apk>`。
- **禁止反编译整个 APK**：本工具链直读二进制 DEX/AXML。禁止往容器装 apktool/jadx 再全量反编译（慢且没必要），禁止手写 Python 解析 DEX（见下条）。
- **禁止手写 DEX/AXML 解析器**：要看类、方法、字段，一律用 `aicode-apk dex-class` / `dex-method` / `dex-fields`。自己写解析器必然出错且浪费轮次。
- **禁止用 shell 的 `strings | grep` 组合拳替代 dex-strings**：shell 只能匹配到原始字节，拿不到「哪个类→哪个方法」的引用关系；`dex-strings` 之后必须接 `dex-refs`。
- **改完必须签名导出**：任何修改（manifest / dex / string）完成后都要走 `apkSign` 交付，禁止把未签名 APK 留在容器里让用户自己取。
- **多步骤任务先建清单**：3 步以上的逆向任务先用 `todo` 工具列出步骤，每完成一步更新状态，全部完成后清空。

## 一、命令映射（FBox 工具名 → AiCode 实际命令）

| 用途 | 命令 |
|---|---|
| Manifest 查询 | `aicode-apk info <apk>` |
| Manifest 修改 | `aicode-apk manifest-edit <apk> debuggable=1,cleartext=1,perm=android.permission.X --out <out.apk>` |
| DEX 搜字符串 | `aicode-apk dex-strings <apk> <正则>` |
| DEX 查引用（类→方法） | `aicode-apk dex-refs <apk> <正则>` |
| 列类的方法 | `aicode-apk dex-class <apk> <类描述符>` |
| 反汇编方法（smali） | `aicode-apk dex-method <apk> <类描述符> <方法名>` |
| 列类字段 | `aicode-apk dex-fields <apk> <类描述符>` |
| 强制返回 | `aicode-apk dex-return <apk> <类> <方法> true\|false\|null\|void` |
| smali 重写 | `aicode-apk dex-smali <apk> <类> <方法> <smali文件>` |
| 改字符串 | `aicode-apk dex-string-edit <apk> <旧串> <新串> --out <out.apk>` |
| 交叉引用 | `aicode-apk dex-xref <apk> <method\|field\|type> <目标>` |
| 重打包（**未签名**） | `aicode-apk rebuild <apk> <out.apk>` |
| 签名（App 侧工具） | `apkSign apk=<容器路径>` — 不是 shell 命令 |

路径约定：APK 放 `/root/apk/`（参数传文件名即可）；临时产物放 `/root/work/`；用户上传的附件在 `/root/uploads/`。

## 二、标准流程（按顺序执行，不要跳步）

1. **侦察环境**：`ls /root/apk` 确认可用 APK。
2. **看 Manifest**：`aicode-apk info <apk>` 拿包名/版本/权限/导出组件/debuggable 状态，顺带确认不是 Flutter。
3. **定位目标**：`aicode-apk dex-strings <apk> "<正则>"` 搜特征串（会员/解锁/接口地址/UI 文案）；命中后用 `aicode-apk dex-refs <apk> "<命中串>"` 拿到「类→方法」，这就是逻辑代码位置。
4. **读代码**：`aicode-apk dex-class` 列方法（含签名与 `[native]` 标记）→ `aicode-apk dex-method` 反汇编方法体（带地址与寄存器数）。
5. **看字段**：`aicode-apk dex-fields <类描述符>` 一次列出全部字段（static/instance、类型、访问标志）。找状态开关字段时必用。
6. **打补丁**（三种模式）：
   - **强制返回（最常用）**：布尔开关（isVip/isAd/premium/isValid）直接 `dex-return ... true`，原地 nop 填充。
   - **smali 重写（改逻辑）**：先用 `writeFile` 写新方法体 smali（每行一条指令，寄存器数沿用原方法），再 `dex-smali` 传文件路径。常用片段：
     - 返回 true：`const/4 v0, #1` + `return v0`
     - 返回 false：`const/4 v0, #0` + `return v0`
     - 跳过调用：把 invoke 行改为 `nop` 或删掉
   - **改字符串（文案/URL）**：`dex-string-edit`，新旧串精确匹配，新串**不得比旧串长**（MUTF-8 编码后），需 `--out`。
7. **重打包 + 签名**：
   ```
   aicode-apk rebuild <改过的.apk> /root/work/out.apk   # 已 zipalign，但【未签名】
   apkSign apk=/root/work/out.apk                        # 签名 + 自校验
   sendFile paths=[<签名产物容器路径>]
   ```
8. **收尾**：告知产物路径，提醒签名与原版不同需先卸载原版；若有 SignatureCheck 可能闪退，用 `dex-strings "signature"` 定位校验方法再补丁。

## 三、字符串加密混淆应对（np/protect 等加固）

反汇编里是 sparse-switch 查表 + 反射调用 `Lnp/protect/...;` 解密方法、直接读不出语义时：

- **立即放弃**死磕解密类 `<init>` 与解密算法——无底洞。
- **改走 UI 文案锚点**：`dex-strings` 搜界面提示文案（「车票数不够」「会员到期」「余额不足」）→ `dex-refs` 定位加载它的类→方法 → `dex-method` 看业务判断（比较哪个字段、跳转条件）。
- 实体字段语义不明时用 `dex-fields` 拿字段布局，再结合 `iget`/`iput` 的字段索引对照推断。
- 同一解密目标死磕最多 2 次即换路线。

## 四、防呆规则（违反=犯错）

- **类描述符格式**：必须 `Lcom/example/Class;`（L 开头、分号结尾、包名用斜线）。混淆后是 `La/b/c;` 这类短名，先搜到再复制，禁止凭空拼。
- **方法名不带签名**：只传方法名（如 `isVip`），不传括号签名；同名重载取第一个有 code 的。
- **不猜偏移**：smali 补丁前必须先用 `dex-method` 看过原方法体，确认新指令的寄存器号不超原方法 `registers` 数。
- **字符串长度硬限制**：新串不能比旧串长，长了就改加载它的方法逻辑，不要反复试。
- **原地修改不可逆**：return/smali 模式直接改写目标 APK 的 dex（无备份）。改坏了从原始 APK 重新导入。
- **搜索止损**：同一目标最多 3 种搜索方式（换关键词/换正则/搜类名），不中就换策略，禁止无限循环。
- **结论分级**：区分「事实（命令输出直接可见）」「推断（多证据推理）」「猜测（未验证）」，猜测必须明说未验证。
- **如实报告**：类/方法未找到、补丁失败都要如实说明，不许编造成功。

## 五、常见坑

- 加固应用（360/腾讯乐固/梆梆）的 classes.dex 只是壳，真实 dex 运行时才解密——`dex-strings` 搜不到特征串时先想到加固，如实告知本工具链不支持脱壳。
- 多 dex 应用：工具自动遍历全部 `classesN.dex`。
- native 方法在 DEX 里没有代码体，`dex-class` 会标 `[native]`；要改 native 逻辑得动 so，用 `aicode-so` 或 `patch_so.py`。
- `dex-smali` 重写后整 DEX 重排（池扩容），文件变大属正常；SHA-1/Adler32 自动重算。
- `manifest-edit` 产出新 APK 文件；`dex-return`/`dex-smali` 原地改。两者可叠加（先 manifest-edit 出文件，再在新文件上打 dex 补丁）。
- Android 9 及以下不认 v2-only 签名——`apkSign` 是 v1+v2 都签，无需关心。
- 若用户要「破解付费/绕过服务器校验」等违规需求，礼貌拒绝并说明只能用于学习与合法逆向。

## 六、自定义技能说明

用户可在容器 `/root/ai-skills/` 放置同名 `.md` 自定义技能（覆盖本默认技能）。
