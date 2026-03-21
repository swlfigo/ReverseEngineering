# 绕过代码完整性检查的 Hook 方案

## 问题

代码保护 SDK（如 JMCodeProtect）会定时检查受保护函数的代码字节和 ObjC IMP 指针。
`Interceptor.attach` 会修改函数入口指令，被检测后触发闪退。

## 方案 1: 闪电 Hook（Hook → 捕获 → 恢复）

**原理**: 检查器是定时的（~15秒一次），在两次检查之间完成 hook 和恢复。

```javascript
function flashHook(target, callback) {
    var listener = Interceptor.attach(target, {
        onEnter: function(args) {
            callback(args, this.context);
            // 捕获到数据后立即移除 hook，恢复原始字节
            listener.detach();
        }
    });
    // 安全超时: 如果没触发就主动移除
    setTimeout(function() { listener.detach(); }, 10000);
}

// 用法: 每次只 hook 一次调用
flashHook(target.implementation, function(args, ctx) {
    console.log('key:', args[3]);
    // 只捕获一次，hook 就移除了
});
```

**优点**: 简单，利用时间窗口
**缺点**: 只能捕获一次调用；如果检查频率高可能来不及

## 方案 2: 内存镜像 Hook

**原理**: 把受保护函数复制到新的内存页，hook 副本而非原始代码。检查器只扫描原始地址。

```javascript
function mirrorHook(originalAddr, funcSize) {
    // 1. 分配新内存页
    var mirror = Memory.alloc(funcSize);
    Memory.protect(mirror, funcSize, 'rwx');

    // 2. 复制原始函数代码
    Memory.copy(mirror, originalAddr, funcSize);

    // 3. 修复副本中的 PC-relative 指令 (ADRP/B/BL 等)
    // ... 需要根据具体函数修复相对地址 ...

    // 4. hook 副本 (原始代码不变，检查器看不到)
    Interceptor.attach(mirror, {
        onEnter: function(args) {
            console.log('hooked on mirror!', args[0]);
        }
    });

    // 5. 重定向调用: 让调用者跳到副本
    // 方式A: 修改调用处的 BL 目标 (如果调用处不受保护)
    // 方式B: hook 调用者 (如 prepare()) 在内部替换参数
    return mirror;
}
```

**优点**: 原始代码完全不变，检查器无法发现
**缺点**: 需要修复 PC-relative 指令；需要一种方式让调用重定向到副本

## 方案 3: 找到并杀死检查器

**原理**: 检查器本身是一个 timer/thread，找到它并禁用。

```javascript
// Step 1: Hook timer 创建，找到检查器
var timers = [];
Interceptor.attach(Module.findExportByName('libdispatch.dylib', 'dispatch_source_set_timer'), {
    onEnter: function(args) {
        var interval = args[2].toInt32() / 1000000;  // ns → ms
        var lr = this.context.lr;
        // 记录来自目标模块的 timer
        if (isFromMainModule(lr) && interval > 5000 && interval < 30000) {
            timers.push({source: args[0], interval: interval, lr: lr});
            console.log('Suspect timer: ' + interval + 'ms from ' + DebugSymbol.fromAddress(lr));
        }
    }
});

// Step 2: 等 App 初始化完成后，取消可疑 timer
setTimeout(function() {
    var dispatch_source_cancel = new NativeFunction(
        Module.findExportByName('libdispatch.dylib', 'dispatch_source_cancel'),
        'void', ['pointer']
    );
    timers.forEach(function(t) {
        console.log('Cancelling timer: ' + t.interval + 'ms');
        dispatch_source_cancel(t.source);
    });
    // 现在可以安全 hook 了
    Interceptor.attach(protectedFunction, { ... });
}, 5000);
```

**也可能是 pthread**:
```javascript
// 如果检查器是独立线程
Interceptor.attach(Module.findExportByName(null, 'pthread_create'), {
    onEnter: function(args) {
        var startRoutine = args[2];
        if (isFromProtectionSDK(startRoutine)) {
            // 替换线程函数为空操作
            args[2] = emptyFunction;
        }
    }
});
```

**优点**: 一劳永逸，之后可以自由 hook
**缺点**: 需要准确识别检查器 timer/thread；误杀可能导致 App 功能异常

## 方案 4: Hook 检查函数本身

**原理**: 检查器的逻辑一般是：读取代码字节 → 比较 → 不一致则退出。Hook 比较或退出的部分。

```javascript
// 检查器通常调用 memcmp 比较代码字节
Interceptor.attach(Module.findExportByName(null, 'memcmp'), {
    onEnter: function(args) {
        var addr = args[0];
        // 如果比较的地址在受保护函数范围内
        if (isProtectedAddress(addr)) {
            this.fakeResult = true;
        }
    },
    onLeave: function(retval) {
        if (this.fakeResult) {
            retval.replace(0);  // 返回 0 = 相等，骗过检查
        }
    }
});
```

**或者 hook 哈希函数** (如果检查器用 hash 而非直接比较):
```javascript
// 如果检查器计算代码段的 hash
Interceptor.attach(CC_SHA256, {
    onEnter: function(args) {
        var dataAddr = args[0];
        if (isProtectedCodeRegion(dataAddr)) {
            // 替换为原始未修改的代码来计算 hash
            Memory.copy(tempBuf, originalCodeBackup, args[1].toInt32());
            args[0] = tempBuf;
        }
    }
});
```

**优点**: 直接对抗检查逻辑
**缺点**: 需要知道检查器用的是 memcmp/hash/自定义比较

## 方案 5: Stalker 指令级追踪

**原理**: Frida Stalker 在 CPU 级别追踪执行，不修改原始代码。用于不需要持续 hook 的场景。

```javascript
// 在目标函数被调用时启用 Stalker
Interceptor.attach(callerFunction, {  // hook 调用者 (不受保护)
    onEnter: function(args) {
        Stalker.follow(this.threadId, {
            events: { call: true },
            onCallSummary: function(summary) {
                // summary 包含所有被调用的函数及次数
                send({type: 'calls', data: summary});
            }
        });
    },
    onLeave: function(retval) {
        Stalker.unfollow(this.threadId);
        Stalker.flush();
    }
});
```

**优点**: 完全不修改代码，无法被代码完整性检查检测
**缺点**: 性能开销大，可能卡顿；只能观察不能修改参数

## 方案 6: ObjC Runtime 层面替换

**原理**: 不替换 IMP，而是替换整个 Method 结构或 Class 的方法列表。

```javascript
// 方式A: 添加新方法，然后 method_exchangeImplementations
var newImp = new NativeCallback(function(self, sel, arg1, arg2) {
    console.log('intercepted!', arg1, arg2);
    return originalFn(self, sel, arg1, arg2);
}, 'pointer', ['pointer', 'pointer', 'pointer', 'long']);

// 先给另一个类添加同签名方法
var helperSel = ObjC.selector('helperMethod:arg2:');
var method_setImplementation = new NativeFunction(
    Module.findExportByName(null, 'method_setImplementation'),
    'pointer', ['pointer', 'pointer']
);

// 方式B: 替换 class_replaceMethod (可能绕过 IMP 指针检查)
var class_replaceMethod = new NativeFunction(
    Module.findExportByName(null, 'class_replaceMethod'),
    'pointer', ['pointer', 'pointer', 'pointer', 'pointer']
);
```

**注意**: 如果保护 SDK 同时检查 method_list 结构，此方案也会失败。

## 方案 7: 保存/恢复原始字节

**原理**: hook 前备份原始字节，每次检查器运行前恢复，检查后再重新 hook。

```javascript
var targetAddr = protectedFunction;
var originalBytes = Memory.readByteArray(targetAddr, 16);  // 备份

// hook 检查器的入口，在检查前恢复原始代码
Interceptor.attach(integrityCheckFunction, {
    onEnter: function() {
        // 恢复原始字节
        Memory.patchCode(targetAddr, 16, function(code) {
            code.writeByteArray(originalBytes);
        });
    },
    onLeave: function() {
        // 检查完毕，重新 hook
        Interceptor.attach(targetAddr, hookCallbacks);
    }
});
```

**优点**: 检查器每次看到的都是原始代码
**缺点**: 需要知道检查器函数的地址；检查期间 hook 失效可能丢失调用

## 推荐策略

```
场景                              推荐方案
─────────────────────────────────────────────
只需捕获一次数据                    方案 1 (闪电 hook)
需要持续 hook                      方案 3 (杀检查器) 或方案 4 (hook 检查函数)
不确定检查机制                      方案 5 (Stalker) 先观察
调用者不受保护                      直接 hook 调用者 + NativeFunction 调用目标
完全无法 hook                      方案 2 (内存镜像)
```

## 识别检查器的方法

1. **计时法**: hook 受保护函数后计时，看多久闪退 → 推断检查间隔
2. **Hook exit/abort**: 在 exit/abort 中打 backtrace → 找到检查器调用链
3. **Hook memcmp/hash**: 看谁在比较代码段内存
4. **Hook dispatch_source**: 找 10-30 秒间隔的定时器
5. **搜索特征**: 在保护 SDK 模块中搜索受保护函数地址的引用 (ADRP/LDR)

---

## 实测验证结论

### 测试环境

集换社 v3.36.1, JMCodeProtect SDK, 目标: hook `+[JMBox125 JMBox167:JMBox501:]`

### 测试结果

| bypass 配置 | 结果 | 分析 |
|------------|------|------|
| SVC NOP 单独 | App 卡住 | dyld 检测未绕过，App 无法初始化 |
| SVC + dyld + 基础 | App 初始化但 hook 没触发 | 缺 strstr/open 等 hook 导致异常 |
| **完整 bypass** (SVC + dyld + 全套) | **✓ 60s 稳定, 7 次 hook 成功** | 所有自杀路径被阻断 |
| 完整 bypass 去掉 exit/kill | ✓ 25s 存活 | SVC NOP 已阻断内核级自杀 |

### 核心发现

**之前以为需要额外方案绕过完整性检查，实际不需要。**

完整性检查的自杀路径走的是 SVC 系统调用（内核级 exit/kill）。SVC NOP 已经把这些调用全部无效化了。检查器检测到代码被修改，但杀不死进程。

**真正导致闪退的不是完整性检查，而是 bypass 不完整** — 早期脚本缺少某些 Frida 检测的 hook（如 strstr/open/connect），App 在初始化阶段就被 Frida 检测杀掉了，时间上恰好和完整性检查的 15 秒周期吻合，造成了误判。

### 通用结论

```
场景                                     最佳方案
──────────────────────────────────────────────────────
自杀路径用 SVC 系统调用 (大部分 iOS SDK)    SVC NOP (一招解决所有)
自杀路径用纯用户态 exit/kill               hook exit/kill/abort/syscall
自杀路径用异常触发 (非法指令/空指针)        全局异常处理器
不确定自杀路径                             全套 bypass (SVC + hook + 异常处理器)
```

**经验教训**: 遇到 hook 后闪退时，先确保 bypass 脚本完整覆盖所有检测层。不要急着寻找"更高级"的绕过方案，问题可能就是 bypass 少了一两个 hook。
