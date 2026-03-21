# iOS 逆向实战手册

从两个真实项目（WebSocket 加密通信 + API 参数加密）中提炼的通用方法论。
遇到新的 iOS 逆向任务时，按此手册检索思路。

---

## 一、Frida 反检测绕过

### 检测方式速查

| 检测层 | 原理 | 特征 | 绕过 |
|--------|------|------|------|
| SVC 系统调用 | 二进制中嵌入 `svc #0x80`，直接调内核检测调试器 | 注入后**毫秒级**闪退，hook 任何函数都来不及 | 扫描可执行内存，把 `01 10 00 D4` 全替换为 NOP `D503201F` |
| dyld 库枚举 | `_dyld_image_count/name` 遍历加载的库查找 "frida" | 能进入 App 但几秒后闪退 | 替换 dyld API 过滤掉 frida 相关库 |
| 符号/文件探测 | `dlsym` 找 frida 符号，`open/access` 查 frida 文件，`strstr` 搜关键字 | 同上 | 逐个 hook，关键字黑名单拦截 |
| 网络端口检测 | `connect()` 连接 27042-27044 端口 | 同上 | hook connect，frida 端口重定向 |
| 反调试 | `ptrace(PT_DENY_ATTACH)`、`sysctl` 查 P_TRACED、`getppid` 检查父进程 | 同上 | hook 各函数返回安全值 |
| 异常端口 | `task_get_exception_ports` 检测 Frida 注册的异常处理器 | 同上 | 清空返回的端口列表 |
| 线程名检测 | `pthread_getname_np` 查找 frida/gmain/gum-js-loop 线程 | 同上 | 替换函数，清空匹配的线程名 |
| 自杀机制 | `exit/_exit/kill/syscall/__pthread_kill/abort` | 前面检测触发后的动作 | 全部 hook，阻止退出 |

### 绕过顺序

**必须按顺序执行**，否则后面的 hook 还没设置好 App 就崩了:

```
1. SVC NOP (最先! 阻止内核级检测)
2. dyld 隐藏 (阻止库枚举)
3. 系统函数 hook (dlsym/open/strstr/connect/ptrace/sysctl/...)
4. 自杀拦截 (exit/kill/syscall/...)
5. 全局异常处理器 (兜底)
6. ---- bypass 完成, 开始业务 hook ----
```

### 关键要点

- **必须用 spawn 模式** (`device.spawn`)，不能 attach 到已运行的进程
- bypass 代码必须**同步执行**完毕后再 `setTimeout` 设置业务 hook
- 对非系统 dylib 也要扫描 SVC（有些 SDK 在自己的框架里也有）

### 判断缺了哪层

如果加了 bypass 仍然闪退:
1. 闪退时间 <1秒 → 可能还有未 NOP 的 SVC 或遗漏的 dylib
2. 闪退时间 ~5秒 → 可能是 dyld/符号/文件检测遗漏
3. 闪退时间 ~15秒 → 可能是**定时器检测**（代码完整性检查，见下文）

---

## 二、定位加密入口

### 通用思路: 从已知到未知

```
已知: 抓包看到加密数据 (密文参数、加密 body、WebSocket 加密帧)
未知: 加密在哪里发生，用了什么算法

路径: 密文出现的位置 → hook 设置点 → backtrace → 加密函数
```

### 策略 1: Hook 网络出口 (最常用)

根据加密数据出现的位置选择 hook 点:

| 场景 | Hook 目标 | 获取方式 |
|------|-----------|---------|
| HTTPS 请求参数 | `NSMutableURLRequest.setURL:` | URL 中的加密参数 |
| HTTPS 请求 body | `NSMutableURLRequest.setHTTPBody:` | POST body |
| WebSocket 发送 | `SRWebSocket.send:` 或底层 | WS 帧内容 |
| 通用 socket | `SSL_write` / `send` | 原始数据 |

**然后看 backtrace 找到加密函数**:

```javascript
Interceptor.attach(target, {
    onEnter: function(args) {
        var data = /* 读取参数 */;
        if (data.indexOf('加密特征') !== -1) {
            console.log(Thread.backtrace(this.context, Backtracer.ACCURATE)
                .map(DebugSymbol.fromAddress).join('\n'));
        }
    }
});
```

### 策略 2: Hook 标准 Crypto API (快速排除)

先 hook 所有标准加密 API，看加密是否经过它们:

```javascript
// CommonCrypto
CCCrypt               // AES/DES/3DES 一次性加解密
CCCryptorCreate       // 流式加密初始化
CCCryptorUpdate       // 流式加密数据

// Security.framework
SecKeyCreateEncryptedData    // RSA/EC 加密
SecKeyCreateDecryptedData    // RSA/EC 解密
SecKeyCreateWithData         // 导入密钥

// CryptoSwift (Swift)
AES.encrypt / decrypt

// SwiftyRSA
ClearMessage.encrypted / EncryptedMessage.decrypted
```

**如果 hook 到了**: 直接从参数读取 key/iv/明文，**几分钟搞定**。

**如果 hook 不到**: 目标使用了自定义加密实现（如代码保护 SDK 自带的加密），需要深入分析。

### 策略 3: 搜索字符串/符号 (辅助定位)

```javascript
// 搜索加密相关的 ObjC 方法
var resolver = new ApiResolver('objc');
resolver.enumerateMatches('-[* *encrypt*]');
resolver.enumerateMatches('+[* *AES*]');

// 搜索二进制中的关键字符串
Memory.scanSync(base, size, '61 65 73 4b 65 79');  // "aesKey"
```

---

## 三、AES 加密逆向

### 快速路径: 标准实现

如果 hook `CCCrypt` 能捕获到:

```javascript
Interceptor.attach(CCCrypt, {
    onEnter: function(args) {
        this.op      = args[0].toInt32();    // 0=加密, 1=解密
        this.alg     = args[1].toInt32();    // 0=AES
        this.key     = args[3];              // 密钥指针
        this.keyLen  = args[4].toInt32();    // 16=AES128, 32=AES256
        this.iv      = args[5];              // IV 指针 (CBC模式)
        this.dataIn  = args[6];              // 输入数据
        this.dataLen = args[7].toInt32();    // 输入长度
    }
});
```

直接读 key 和 iv，用 Python 复现:
```python
from Crypto.Cipher import AES
cipher = AES.new(key, AES.MODE_CBC, iv)
plaintext = cipher.decrypt(ciphertext)
```

### 困难路径: 自定义实现

当标准 API 没被调用时:

#### Step 1: 确认是否是 AES

搜索 AES S-box 特征 (`63 7c 77 7b f2 6b 6f c5`):

```javascript
Memory.scanSync(module.base, module.size, '63 7c 77 7b f2 6b 6f c5');
```

- 找到 → 有软件 AES 实现
- 没找到 → 可能用 ARM 硬件指令 (AESE/AESD) 或非 AES 算法

搜索 ARM 硬件 AES 指令:
```javascript
Memory.scanSync(base, size, '?? 48 28 4E');  // AESE
Memory.scanSync(base, size, '?? 58 28 4E');  // AESD
```

#### Step 2: 追踪加密函数内部

反汇编加密函数，重点关注:
- `ADRP + LDR`: 加载数据/常量/查找表的地址
- `EOR` (XOR): key 混合操作
- `BL`: 子函数调用 (可能是 AES 轮函数)
- 循环结构: AES-128 有 10 轮

```javascript
var addr = functionEntry;
for (var i = 0; i < 500; i++) {
    var ins = Instruction.parse(addr);
    console.log(ins.mnemonic + ' ' + ins.opStr);
    if (ins.mnemonic === 'ret') break;
    addr = ins.next;
}
```

#### Step 3: 已知明文-密文分析

同时 hook 输入和输出，获取多组 (明文, 密文) 对:

```javascript
Interceptor.attach(encryptFunc, {
    onEnter: function(args) { this.input = readBytes(args[0], 16); },
    onLeave: function(ret)  { this.output = readBytes(ret, 16); }
});
```

然后用 Python 穷举验证:
```python
for mode in [AES.MODE_CBC, AES.MODE_ECB, AES.MODE_CFB]:
    for key_candidate in candidates:
        try:
            dec = AES.new(key_candidate, mode, iv).decrypt(ct)
            if dec == expected_plaintext:
                print(f"FOUND! mode={mode}, key={key_candidate.hex()}")
        except: pass
```

#### Step 4: 注意非标准用法

AES 算法是标准的，但用法可能特殊:

| 常见变体 | 特征 | 如何发现 |
|---------|------|---------|
| key/IV 角色互换 | 固定值当 IV 用，随机值当 key | 标准 CBC 解密失败时试试交换 |
| key 前后处理 | XOR/hash/截取后才是真正的 key | hook 加密函数内部看 key 怎么变的 |
| 多层包装 | AES 输出后还有 XOR/base64/字节打乱 | 对比 AES 输出和最终密文 |
| 分段 key | key 不是连续 16 字节，从多处 XOR 组合 | 分析 key 加载的反汇编 |

---

## 四、RSA 加密逆向

### 快速路径: Security.framework

```javascript
// 捕获 RSA 密钥创建
Interceptor.attach(SecKeyCreateWithData, {
    onEnter: function(args) {
        var keyData = ObjC.Object(args[0]);
        // DER 格式的公钥/私钥
    }
});

// 导出已有的密钥
var SecKeyCopyExternalRepresentation = new NativeFunction(...);
var derData = SecKeyCopyExternalRepresentation(keyRef, errPtr);
```

### 常见模式

| 模式 | 说明 | 特征 |
|------|------|------|
| 标准 PKCS1 | `SecKeyCreateEncryptedData` | 256 字节输出 (RSA-2048) |
| Textbook RSA | `m = c^e mod n`，无 padding | 自定义实现，直接大数运算 |
| RSA + AES 混合 | RSA 加密 AES key，AES 加密数据 | 常见于通信协议 |
| per-account key | 每个用户不同的 RSA 公钥 | 需要登录后从网络/本地存储提取 |

### 提取密钥的 Hook 点

```javascript
// 从 ObjC 字典中提取
Interceptor.attach(NSDictionary['- objectForKey:'], {
    onEnter: function(args) {
        var key = ObjC.Object(args[2]).toString();
        if (key === 'publicKey' || key === 'privateKey') {
            var val = ObjC.Object(args[0]).objectForKey_(args[2]);
            console.log(key + ': ' + val.toString());
        }
    }
});

// 从 Security.framework 导出 DER
Interceptor.attach(SecKeyCreateWithData, {
    onLeave: function(retval) {
        var exported = SecKeyCopyExternalRepresentation(retval, errPtr);
        // exported = DER 格式的密钥
    }
});
```

---

## 五、代码保护 SDK 对抗

### 识别保护类型

| 特征 | 保护类型 | 应对策略 |
|------|---------|---------|
| 混淆的类名 (JMBox125, GDTfuncXXX) | 名称混淆 | 通过功能分析还原真实含义 |
| 跳转表 + 间接 BR | 控制流平坦化 (OLLVM) | Frida 运行时反汇编，解析跳转表 |
| 磁盘上是 `brk` 指令，运行时正常 | 代码加密 | dump 运行时内存再分析 |
| hook 后定时闪退 (~15秒) | 代码完整性检查 | 不 hook，用 NativeFunction 直接调用 |
| method swizzle 后闪退 | IMP 指针检查 | 同上 |

### 控制流平坦化分析

特征代码:
```arm64
adrp    x23, #jump_table_page
add     x23, x23, #offset
ldr     x8, [x23, w8, uxtw #3]   ; 从跳转表加载
mov     x24, #constant             ; 解码常量
add     x8, x8, x24                ; 计算真实地址
br      x8                         ; 间接跳转
```

应对: IDA 无法静态分析 `br x8`，但 Frida 在运行时可以:
1. `Instruction.parse` 逐条反汇编
2. 读取跳转表内存 + 解码常量 → 计算所有可能的跳转目标
3. 通过 IDA MCP 的 `patch` 工具将运行时代码写入 IDA 数据库

### 代码完整性保护绕过

```
❌ Interceptor.attach    → 修改函数入口字节 → 被检测
❌ ObjC IMP swizzle      → 修改方法指针 → 被检测
✅ NativeFunction 调用   → 不修改任何东西 → 安全

// 安全的调用方式
var imp = ObjC.classes.Target['+ method:'].implementation;
var fn = new NativeFunction(imp, 'pointer', ['pointer', 'pointer', 'pointer', 'long']);
var result = fn(classPtr, selector, arg1, arg2);
```

### 运行时代码 dump

代码在磁盘上加密时，需要从运行时内存 dump:

```javascript
// dump 指定偏移范围的运行时代码
var data = Memory.readByteArray(base.add(offset), size);
send({type: 'dump', data: data});

// Python 端保存为文件，可导入 IDA 分析
```

---

## 六、密钥查找方法论

### 从易到难排序

```
1. Hook 标准 API 参数          → 最快，几分钟
2. 搜索字符串/配置文件          → 硬编码的 key
3. NSUserDefaults / Keychain   → 本地存储的 key
4. 网络响应                     → 服务器下发的 key
5. 函数参数/寄存器              → hook 加密函数入口读参数
6. 栈帧读取                     → 从调用链的上层帧读保存的寄存器
7. 反汇编分析                   → 从查找表/常量计算 key
8. 穷举内存搜索                 → dump 内存 + 已知明文验证
```

### 已知明文验证

有了 (明文, 密文) 对后，可以验证任何 key 候选值:

```python
from Crypto.Cipher import AES
def test_key(key, iv, ct, expected_pt):
    try:
        dec = AES.new(key, AES.MODE_CBC, iv).decrypt(ct)
        return dec == expected_pt
    except:
        return False
```

### 常见的 key 来源

| 来源 | 特征 | 提取方式 |
|------|------|---------|
| 硬编码字符串 | 固定 16/32 字节 ASCII | 搜索二进制字符串 |
| 配置文件 | plist/json 中的 key 字段 | 读取 App Bundle |
| 服务器下发 | 登录/初始化时返回 | hook 网络响应 |
| 密钥派生 | PBKDF2/HKDF 从密码生成 | hook 派生函数 |
| 查找表 XOR | 多个表通过 XOR 组合 | 反汇编找到表地址和组合逻辑 |
| Bundle ID/设备 ID 派生 | MD5/SHA256(bundleId) 等 | 尝试常见派生 |

### key 不在常规位置时的排查

1. **每次启动都变?** → 两次启动对比相同内存区域
2. **运行时计算?** → hook 加密函数，读寄存器/栈上的 key 值
3. **分散存储?** → 反汇编看 key 是怎么被加载到寄存器的
4. **白盒加密?** → key 嵌入 S-box 表，无法提取为独立值
5. **标准 API 被绕过?** → 确认不是自实现的加密 (搜索 S-box 特征)

---

## 七、验证与调试技巧

### 逐步验证法

每破解一层就立刻验证，不要等全部做完:

```
✓ AES 核心: 已知明文 + key + IV → 解密匹配?
✓ 数据结构: header + IV + CT 的拆分正确?
✓ 多 block: 2+ block 的数据解密也匹配?
✓ 最终格式: base64/hex/mask 处理后与原始密文一致?
✓ API 调用: 用自己的加密结果调 API 能拿到正确响应?
```

### 对比法

让 App 和自己的代码加密相同数据，逐字节对比:

```javascript
// 在 Frida 中同时捕获每一步的中间值
Interceptor.attach(aesFunc, {
    onEnter: function(args) { /* 读入参 */ },
    onLeave: function(ret)  { /* 读出参 */ }
});
```

```python
# 用 Python 复现相同步骤，对比每步输出
my_step1 = xor(plaintext, key)
assert my_step1 == app_step1  # 逐步确认
```

### IDA + Frida 配合

| IDA 做什么 | Frida 做什么 |
|-----------|-------------|
| 静态分析函数结构 | 运行时验证数据 |
| 反编译伪代码 (需要 patch 运行时代码) | 反汇编 + 读取内存 |
| 交叉引用分析 | hook 捕获调用关系 |
| 类型/结构体标注 | 读取 ObjC 对象属性 |

通过 IDA MCP Server 可以让 Frida/Python 直接操作 IDA:
```python
# Python → IDA MCP → patch 运行时代码到 IDA 数据库
requests.post('http://127.0.0.1:13337/mcp', json={
    "method": "tools/call",
    "params": {"name": "patch", "arguments": {"patches": {"addr": "0x...", "data": "..."}}}
})
```

---

## 八、WebSocket 加密通信逆向

### 分层剥离法

WS 加密通常是多层嵌套，从外到内剥离:

```
1. 抓包: 看 WS 帧的整体结构 (JSON? 二进制?)
2. 外层: 找字段含义 (code/type/msg/sign 等)
3. 识别加密字段: 哪些 value 是 base64/hex 编码的密文
4. Hook 收发函数: 找到加密/解密的代码入口
5. 提取密钥: hook 加密函数参数
6. 独立解密器: Python 复现
```

### 常见 WS 加密模式

| 模式 | 特征 | 破解要点 |
|------|------|---------|
| AES 加密 message | message 字段是 base64 密文 | 找 key/iv 来源 (固定? 动态? 每次不同?) |
| RSA 加密补充数据 | 256 字节的 base64 块 | 找 RSA 公钥 (hook SecKeyCreateWithData) |
| ECIES 签名/信封 | 固定格式头 + EC 公钥 + 加密 payload | 通常无法解密 (需服务端私钥)，但不影响接收 |
| 混合加密 | AES 加密数据 + RSA 加密 AES key | 先解 RSA 拿到 AES key，再解数据 |

### 密钥来源判断

```
固定 key:     每次加密结果不同但 key 不变 → 服务器下发后存本地
动态 key:     每次请求都不同 → 从 timestamp/nonce 派生
per-account:  不同账号不同 key → 登录/激活时服务器下发
```

**提取固定 key**: Hook CCCrypt 或加密函数，读参数中的 key 值。

**提取动态 key**: 需要找到派生算法。常见模式:
```python
# 从 timestamp 派生 (MD5)
key = md5(str(timestamp) + salt).digest()

# 从服务器下发的 aes_key 变换
key = reverse(aes_key)  # 翻转
iv = aes_key             # 原值做 IV
```

### 独立客户端构建

一旦提取到密钥和算法:

```python
import websocket
ws = websocket.create_connection("ws://server:port")

# 注册 (发送设备ID/用户ID)
ws.send(json.dumps({"type": "reg", "uid_from": "USER_ID"}))

# 接收加密消息 → 解密
msg = json.loads(ws.recv())
plaintext = aes_decrypt(base64.b64decode(msg['message']), key, iv)
```

---

## 九、常见坑

| 坑 | 现象 | 解决 |
|----|------|------|
| Hook 太多方法 | App 极卡或崩溃 | 只 hook 必要的，避免 objc_msgSend 全局 hook |
| setTimeout 不触发 | Hook 设置了但回调不执行 | spawn 模式下 ObjC runtime 未就绪，加延迟 |
| Stalker 卡主线程 | App 界面冻结 | Stalker 开销太大，改用针对性 hook |
| base64 hook 太宽 | 系统框架也用 base64，导致崩溃 | 用 backtrace 过滤，只关注目标模块的调用 |
| 反汇编偏移不对 | 运行时 ASLR 随机基地址 | 用 `ptr.sub(module.base)` 转为模块内偏移 |
| IDA 分析不完整 | 控制流平坦化导致 JUMPOUT | dump 运行时代码 patch 进 IDA，手动建函数 |
| 磁盘二进制代码加密 | IDA 看到 `brk` trap | 从运行时 dump 解密后的代码 |
| 单 block 成功多 block 失败 | ECB vs CBC | 确认多 block 间是否有链式操作 |
