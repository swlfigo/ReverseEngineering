# 逆向工程笔记

macOS/iOS 应用逆向分析、Patch 脚本与 Claude Code Skill。

## Claude Code Skill

本仓库包含一个 [Claude Code](https://docs.anthropic.com/en/docs/claude-code) Skill，可让 Claude 在逆向工程任务中自动加载实战方法论。

### 安装

```bash
# 克隆仓库
git clone https://github.com/swlfigo/ReverseEngineering.git

# 复制 skill 到 Claude Code 的 skills 目录
cp -r ReverseEngineering/skills/reverse-engineering ~/.claude/skills/
```

安装后，Claude Code 在遇到逆向相关任务时会自动加载此 skill。

### Skill 内容

| 章节 | 覆盖内容 |
|------|---------|
| Frida 反检测绕过 | 9 种检测方式识别 + 绕过方案 (SVC/dyld/反调试/完整性保护等) |
| 加密定位流程 | 从抓包到定位加密函数的决策树 |
| AES 逆向 | 标准 API hook → 自定义实现分析 → 密钥查找 8 级路径 |
| RSA 密钥提取 | Security.framework hook 点 + ObjC 字典提取 |
| 代码保护 SDK 对抗 | 控制流平坦化、代码加密、完整性检查的应对 |
| WebSocket 加密通信 | 分层剥离法 + 密钥来源判断 |
| 验证技巧 | 逐步验证法 + IDA/Frida 配合 |

## 实战文档

| 文档 | 内容 |
|------|------|
| [ios-reverse-playbook.md](./ios-reverse-playbook.md) | iOS 逆向通用方法论 (详细版，含代码示例) |
| [skills/reverse-engineering/SKILL.md](./skills/reverse-engineering/SKILL.md) | Claude Code Skill 版本 (精简版，自动加载) |

## 目录结构

```
.
├── skills/                           # Claude Code Skills
│   └── reverse-engineering/
│       └── SKILL.md                  # 逆向工程 skill
├── ios-reverse-playbook.md           # iOS 逆向实战手册 (详细版)
├── tools/                            # 通用工具
│   └── insert_dylib                  # Mach-O dylib 注入工具
├── iPic/                             # iPic 逆向
│   ├── analysis.md
│   ├── patch.sh
│   └── dylib_hook/
└── ...
```

## 通用工具

### `tools/insert_dylib`

向 Mach-O 二进制注入 `LC_LOAD_DYLIB` 加载命令。预编译的 Universal Binary (x86_64 + arm64)，来源于 [tyilo/insert_dylib](https://github.com/tyilo/insert_dylib)。

```bash
tools/insert_dylib <dylib_path> <binary> --inplace --all-yes
```

## 应用列表

| 应用 | 版本 | 描述 | Patch 方式 |
|------|------|------|-----------|
| [iPic](./iPic/) | 1.8.4 | 图床上传工具 — 解锁所有图床 | 二进制 Patch / dylib 注入 |
