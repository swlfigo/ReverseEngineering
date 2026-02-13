# 逆向工程笔记

macOS 应用逆向分析与 Patch 脚本。

## 目录结构

```
.
├── tools/                    # 通用工具
│   └── insert_dylib          # Mach-O LC_LOAD_DYLIB 注入工具 (Universal Binary)
├── iPic/                     # 各应用逆向文件夹
│   ├── analysis.md           # 逆向分析过程
│   ├── patch.sh              # 一键 Patch（直接修改二进制）
│   └── dylib_hook/           # dylib 注入方案
│       ├── hook.c            # Hook 源码
│       └── patch_dylib.sh    # 一键编译 + 注入 + 签名
└── ...
```

## 通用工具

### `tools/insert_dylib`

向 Mach-O 二进制注入 `LC_LOAD_DYLIB` 加载命令。预编译的 Universal Binary (x86_64 + arm64)，来源于 [tyilo/insert_dylib](https://github.com/tyilo/insert_dylib)。

```bash
# 注入（原地修改）
tools/insert_dylib <dylib_path> <binary> --inplace --all-yes

# 注入（输出到新文件）
tools/insert_dylib <dylib_path> <binary> <output_binary>
```

## 应用列表

| 应用 | 版本 | 描述 | Patch 方式 |
|------|------|------|-----------|
| [iPic](./iPic/) | 1.8.4 | 图床上传工具 — 解锁所有图床 | 二进制 Patch / dylib 注入 |
