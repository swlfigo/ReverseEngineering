/**
 * iPic v1.8.4 - 运行时 Hook (dylib 注入)
 *
 * 不修改磁盘上的二进制代码段，而是在加载时在内存中 patch 目标函数。
 *
 * 目标: sub_100081B10 (Pro 状态检查)
 *   - 原始: 读取试用日期，计算剩余天数
 *   - Hook:  始终返回 1 (Pro 激活)
 *
 * 工作原理:
 *   1. dylib 通过注入到 Mach-O 的 LC_LOAD_DYLIB 加载
 *   2. __attribute__((constructor)) 在 main() 之前运行
 *   3. 计算运行时地址 = 静态虚拟地址 + ASLR slide
 *   4. vm_protect() 使代码页可写 (COW)
 *   5. 写入 ARM64 指令: MOV W0,#1; RET
 *
 * 编译:
 *   clang -arch arm64 -dynamiclib -o libipic_hook.dylib hook.c
 */

#include <stdio.h>
#include <stdint.h>
#include <string.h>
#include <mach-o/dyld.h>
#include <mach/mach.h>
#include <sys/mman.h>
#include <libkern/OSCacheControl.h>

// ─── 配置 ────────────────────────────────────────────────────────
// sub_100081B10 的虚拟地址（不含 ASLR）
#define TARGET_VA       0x100081B10

// 函数起始处的原始字节（用于校验）
static const uint8_t ORIGINAL_BYTES[] = { 0xF6, 0x57, 0xBD, 0xA9, 0xF4, 0x4F, 0x01, 0xA9 };

// 补丁: MOV W0, #1; RET
static const uint8_t PATCH_BYTES[] = { 0x20, 0x00, 0x80, 0x52, 0xC0, 0x03, 0x5F, 0xD6 };

#define PATCH_SIZE sizeof(PATCH_BYTES)

// ─── 日志 ────────────────────────────────────────────────────────
#define LOG_PREFIX "[iPicHook] "
#define LOG(fmt, ...) printf(LOG_PREFIX fmt "\n", ##__VA_ARGS__)

// ─── 核心逻辑 ────────────────────────────────────────────────────

/**
 * 获取主可执行文件的 ASLR slide。
 * 每次启动进程时基地址都会随机化；
 * slide = 实际基地址 - 首选基地址
 */
static intptr_t get_main_image_slide(void) {
    uint32_t count = _dyld_image_count();
    for (uint32_t i = 0; i < count; i++) {
        const struct mach_header *header = _dyld_get_image_header(i);
        // MH_EXECUTE = 主二进制（不是 dylib/framework）
        if (header->filetype == MH_EXECUTE) {
            return _dyld_get_image_vmaddr_slide(i);
        }
    }
    return 0;
}

/**
 * 使内存页可写，写入补丁，恢复保护。
 *
 * 使用 vm_protect 而非 mprotect，因为：
 * - mprotect 可能在 code-signed 页上失败
 * - vm_protect 配合 VM_PROT_COPY 会创建 COW (写时复制) 页面
 */
static int patch_memory(void *addr, const uint8_t *patch, size_t size) {
    // 获取页对齐地址
    vm_address_t page = (vm_address_t)addr & ~(vm_page_size - 1);
    vm_size_t page_size = vm_page_size;

    // 使页面可写（VM_PROT_COPY 触发 COW）
    kern_return_t kr = vm_protect(
        mach_task_self(),
        page,
        page_size,
        0,  // 非 set_maximum
        VM_PROT_READ | VM_PROT_WRITE | VM_PROT_COPY
    );
    if (kr != KERN_SUCCESS) {
        LOG("vm_protect(RW) 失败: %d", kr);
        return -1;
    }

    // 写入补丁
    memcpy(addr, patch, size);

    // 刷新指令缓存（ARM64 上必须！）
    sys_icache_invalidate(addr, size);

    // 恢复为 只读+可执行
    kr = vm_protect(
        mach_task_self(),
        page,
        page_size,
        0,
        VM_PROT_READ | VM_PROT_EXECUTE
    );
    if (kr != KERN_SUCCESS) {
        LOG("vm_protect(RX) 失败: %d (非致命)", kr);
        // 非致命：代码仍然可以工作，只是保护不理想
    }

    return 0;
}

// ─── 入口点 ──────────────────────────────────────────────────────
__attribute__((constructor))
static void hook_init(void) {
    LOG("=== iPic Hook 加载中 ===");

    // 1. 获取 ASLR slide
    intptr_t slide = get_main_image_slide();
    LOG("ASLR slide: 0x%lx", (unsigned long)slide);

    // 2. 计算运行时地址
    uint8_t *target = (uint8_t *)((intptr_t)TARGET_VA + slide);
    LOG("目标函数: %p (VA 0x%llx + slide)", target, (uint64_t)TARGET_VA);

    // 3. 校验原始字节（安全检查）
    if (memcmp(target, ORIGINAL_BYTES, sizeof(ORIGINAL_BYTES)) != 0) {
        LOG("警告: 原始字节不匹配！");
        LOG("  期望: %02x %02x %02x %02x %02x %02x %02x %02x",
            ORIGINAL_BYTES[0], ORIGINAL_BYTES[1], ORIGINAL_BYTES[2], ORIGINAL_BYTES[3],
            ORIGINAL_BYTES[4], ORIGINAL_BYTES[5], ORIGINAL_BYTES[6], ORIGINAL_BYTES[7]);
        LOG("  实际: %02x %02x %02x %02x %02x %02x %02x %02x",
            target[0], target[1], target[2], target[3],
            target[4], target[5], target[6], target[7]);
        LOG("中止 hook 以防止崩溃。");
        return;
    }

    // 4. 执行 Patch！
    if (patch_memory(target, PATCH_BYTES, PATCH_SIZE) == 0) {
        LOG("已 patch sub_100081B10 → MOV W0,#1; RET");
        LOG("所有图床已解锁！");
    } else {
        LOG("Patch 失败！");
    }

    LOG("=== iPic Hook 完成 ===");
}
