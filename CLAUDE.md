# 项目规范

## 语言

- 所有文档（analysis.md、README.md）使用**中文**撰写
- 代码注释使用**中文**
- 技术术语、函数名、地址等保留英文原文

## 目录结构

每个逆向目标应用一个独立文件夹，包含：

```
<AppName>/
├── analysis.md          # 逆向分析文档
├── patch.sh             # 二进制 Patch 脚本
└── dylib_hook/          # dylib 注入方案
    ├── hook.c           # Hook 源码
    └── patch_dylib.sh   # 一键注入脚本
```

通用工具放在 `tools/` 目录，供所有应用复用（如 `insert_dylib`）。

## 分析文档 (analysis.md)

每篇分析文档应包含：

1. **背景** — 应用功能、目标（绕过什么限制）
2. **分析过程** — 逐步记录，从字符串搜索到最终定位关键函数的完整链路
3. **架构总览** — 调用关系图（ASCII 流程图）
4. **关键类/函数** — 表格列出类名、作用
5. **关键地址** — 表格列出虚拟地址、描述
6. **Patch 方案** — 目标地址、原始字节、补丁字节、汇编含义

## 脚本规范

### 通用要求

- 脚本头部使用 `#!/usr/bin/env bash`
- 启用严格模式：`set -euo pipefail`
- 带颜色的日志输出（info/ok/warn/error）
- 自动查找应用路径（/Applications、~/Applications、~/Desktop）
- 版本校验：检查目标应用版本是否匹配，不匹配时警告并确认

### patch.sh（二进制 Patch）

- 必须支持三种模式：`patch`（默认）、`--restore`、`--verify`
- Patch 前自动创建 `.bak` 备份
- 校验原始字节，不匹配则中止（防止重复 patch 或版本错误）
- Patch 后自动重签名：`codesign --force --deep --sign -`
- 使用 `lipo` + `otool` 自动计算 Fat Binary 中的文件偏移
- git 仓库中不提交编译产物（.dylib、.o 等）

### patch_dylib.sh（dylib 注入）

- 必须支持三种模式：`patch`（默认）、`--restore`、`--verify`
- 自动编译 hook.c 为 dylib（`clang -arch arm64 -dynamiclib`）
- 使用 `tools/insert_dylib` 注入 `LC_LOAD_DYLIB`
- dylib 安装路径统一使用 `@executable_path/../Frameworks/<name>.dylib`
- 签名 dylib + 重签名整个 App
- 恢复时同时删除 dylib 文件和还原二进制

### hook.c（运行时 Hook）

- 使用 `__attribute__((constructor))` 作为入口
- 通过 `_dyld_get_image_vmaddr_slide()` 获取 ASLR slide
- Patch 前必须校验原始字节，不匹配则中止
- 使用 `vm_protect()` + `VM_PROT_COPY` 实现 COW 写入
- 写入后调用 `sys_icache_invalidate()` 刷新指令缓存
