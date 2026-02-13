# iPic v1.8.4 逆向分析

- **Bundle ID:** `net.toolinbox.ipic`
- **二进制格式:** Universal (x86_64 + arm64)
- **目标:** 绕过图床升级锁，解锁所有图床

## 1. 背景

iPic 是 macOS 上的图床上传工具。免费版只支持微博图床，其他图床（七牛、又拍云、阿里 OSS、腾讯 COS、Imgur、Flickr、S3、B2、R2）需要 Pro 订阅才能使用。

## 2. 分析过程

### 第一步：字符串搜索

从用户可见的提示文字入手。升级锁弹窗显示 **"Upgrade to unlock all image hosts."**

```bash
strings iPic | grep -iE "upgrade|unlock|license|trial"
```

找到的关键字符串：
- `Upgrade to unlock all image hosts.` — 锁定提示
- `All image hosts unlocked.` — 解锁提示
- `licenseKey`, `trialStartDateKey` — 偏好设置的 key
- `net.toolinbox.ipic.NotificationToUpgrade` — 通知名
- `https://api.toolinbox.net/license` — 许可证 API

### 第二步：在 IDA 中定位字符串地址（IDA MCP: find_regex）

```
find_regex("Upgrade to unlock all image hosts")
→ addr: 0x1000bfab0
```

### 第三步：交叉引用（IDA MCP: xrefs_to）

```
xrefs_to(0x1000bfab0)
→ sub_10007FB4C (Free AccountType 初始化器)
→ sub_10008012C (升级弹窗)
```

### 第四步：反编译 & 追踪（IDA MCP: decompile）

反编译 `sub_10008012C` 发现：

```c
if ( !(unsigned __int8)sub_100081B10() ) {
    // 在升级弹窗中显示试用信息
}
```

这指向了**核心检查函数**：`sub_100081B10`。

### 第五步：分析核心检查函数

```
sub_100081B10() @ 0x100081B10
```

反编译后的逻辑：

```c
__int64 sub_100081B10() {
    // 获取 PreferenceManager 单例
    swift_once(&token, PreferenceManager_init);

    // 从偏好设置读取 trialStartDate
    sub_10000D880();  // → privateTrialStartDate

    // 检查日期是否为 nil (Optional<Date> == .none)
    if (trialStartDate == nil)
        return 0;     // 无试用记录 → 免费用户

    // 计算剩余试用天数
    if (sub_100081940() > 0)
        return 1;     // 还有剩余天数 → Pro/试用激活
    else
        return 2;     // 天数用完 → 已过期
}
```

**怎么看出是在操作日期？** 关键线索：
- `type metadata accessor for Date` — Swift Date 类型的元数据访问
- 常量 `86400.0` — 一天的秒数 (60×60×24)
- `Date.init()` 获取当前时间
- `Date.timeIntervalSince(_:)` 计算时间差
- `7 - daysPassed` — 7 天试用期减去已过天数

### 第六步：分析试用天数计算器

```
sub_100081940() @ 0x100081940
```

```c
__int64 sub_100081940() {
    Date? startDate = PreferenceManager.trialStartDate;

    if (startDate == nil)
        return 7;  // 默认 7 天

    double elapsed = Date().timeIntervalSince(startDate);
    int daysPassed = (int)(elapsed / 86400.0);  // 秒 → 天

    if (elapsed < 0) return 0;

    int remaining = 7 - daysPassed;
    return remaining > 0 ? remaining : 0;
}
```

### 第七步：通过所有调用者验证返回值含义

**单独看 `sub_100081B10` 的返回值 0、1、2 无法确定含义，必须看调用者如何使用返回值。**

```
xrefs_to(0x100081B10) → 5 个调用点
```

| 地址 | 功能 | 如何使用返回值 |
|------|------|---------------|
| `0x100034E28` | 上传服务 | `== 1` → 允许上传；否则 → 显示升级弹窗 |
| `0x10003DA60` | 菜单项启用 | `== 1` → `setState(true)`；否则 → `setState(false)` |
| `0x10003F65C` | 添加/选择图床 | `== 1` → 允许；否则 → 阻止 |
| `0x100069238` | 状态栏菜单切换 | `!= 1` → 显示升级弹窗 |
| `0x10008012C` | 升级弹窗 | `== 0` → 显示试用信息 |

**所有调用者都只检查 `== 1`（允许）vs `!= 1`（阻止）。**

## 3. 架构总览

```
用户点击非微博图床
        │
        ▼
是 WeiboImageHost？ ──是──→ 允许（微博始终免费）
        │ 否
        ▼
比较 AccountType.productIdentifier
与 Free AccountType.productIdentifier
        │
    ┌───┴───┐
    │匹配   │不匹配
    │(免费)  │(已购买)
    ▼       ▼
sub_100081B10()   允许
    │
    ├─ return 0 → 阻止（无试用记录）
    ├─ return 1 → 允许（试用/Pro 激活中）
    └─ return 2 → 阻止（已过期）
```

## 4. 关键类

| 类名 | 作用 |
|------|------|
| `PreferenceManager` | 单例，在 NSUserDefaults + iCloud 中存储 license/accountType/trialDate |
| `AccountType` | NSCoding 对象，包含 productIdentifier、expiresDate |
| `AccountHelper` | 账户检查的静态辅助类 |
| `License` | 通过 `https://api.toolinbox.net/license` 验证许可证密钥 |
| `Trial` (Toolinbox.framework) | 试用状态追踪（7 天试用） |
| `IAPHelper` (Toolinbox.framework) | 应用内购买和收据验证 |

## 5. 关键地址 (arm64)

| 虚拟地址 | 描述 |
|----------|------|
| `0x100081B10` | **核心 Pro 检查** — 返回 0/1/2 |
| `0x100081940` | 试用剩余天数计算器 |
| `0x10000D4B4` | 从偏好设置获取 AccountType |
| `0x10000D880` | 读取试用开始日期 |
| `0x10007FB4C` | Free AccountType 单例初始化 |
| `0x10008012C` | 升级弹窗 |
| `0x100034E28` | 上传服务 Pro 检查 |
| `0x10003DA60` | 图床菜单启用/禁用 |
| `0x10003F65C` | 图床选择检查 |
| `0x100069238` | 状态栏菜单图床切换检查 |

## 6. Patch 方案

**目标：** `sub_100081B10` @ `0x100081B10`

**补丁：** 将函数序言替换为：
```asm
MOV W0, #1    ; return 1（Pro 激活）
RET
```

**字节码：** `20 00 80 52 C0 03 5F D6`（8 字节）

**原始字节：** `F6 57 BD A9 F4 4F 01 A9`

Patch 后，所有 5 个调用点都会收到 `1` → 所有图床解锁。

**需要重签名：** `codesign --force --deep --sign - iPic.app`

## 7. Patch 实现方式

### dylib 注入（运行时 Hook）

通过向 Mach-O 注入 `LC_LOAD_DYLIB` 加载命令，使应用启动时自动加载我们的 dylib。dylib 在 `__attribute__((constructor))` 中执行，在 `main()` 之前运行，计算 ASLR slide 后直接在内存中 patch 目标函数。

**优点：**
- 不修改原始代码段，原始二进制的 `__TEXT` 段保持不变
- 使用 COW (Copy-on-Write) 页面，只在内存中修改
- 可以随时移除 dylib 恢复原状

**工作原理：**
1. dylib 通过注入的 `LC_LOAD_DYLIB` 在应用启动时加载
2. `__attribute__((constructor))` 在 `main()` 之前执行
3. 通过 `_dyld_get_image_vmaddr_slide()` 获取 ASLR 偏移
4. 运行时地址 = 静态虚拟地址 + ASLR slide
5. `vm_protect()` + `VM_PROT_COPY` 创建 COW 页面，使代码页可写
6. `memcpy()` 写入 `MOV W0,#1; RET`
7. `sys_icache_invalidate()` 刷新指令缓存（ARM64 必须）
8. 恢复页面为只读+可执行

详见 `dylib_hook/` 目录下的完整实现。
