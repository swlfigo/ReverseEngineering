#!/usr/bin/env bash
#
# iPic v1.8.4 Dylib Hook Patch Script
# 通过注入 dylib 在运行时 hook sub_100081B10，使其始终返回 1 (Pro active)
# 解锁所有图床 (七牛、又拍云、阿里OSS、腾讯COS、Imgur、Flickr、S3、B2、R2)
#
# 用法：
#   ./patch_dylib.sh [path_to_iPic.app]            # 编译 + 注入 + 签名
#   ./patch_dylib.sh --restore [path_to_iPic.app]   # 恢复原始二进制
#   ./patch_dylib.sh --verify [path_to_iPic.app]    # 检查注入状态
#

set -euo pipefail

# ─── 配置 ──────────────────────────────────────────────────────────
APP_NAME="iPic"
TARGET_VERSION="1.8.4"
DYLIB_NAME="libipic_hook.dylib"
DYLIB_INSTALL_PATH="@executable_path/../Frameworks/${DYLIB_NAME}"

# 脚本所在目录
SCRIPT_DIR="$(cd "$(dirname "$0")" && pwd)"
REPO_ROOT="$(cd "${SCRIPT_DIR}/../.." && pwd)"
HOOK_SOURCE="${SCRIPT_DIR}/hook.c"
INSERT_DYLIB="${REPO_ROOT}/tools/insert_dylib"

# ─── 颜色 ──────────────────────────────────────────────────────────
RED='\033[0;31m'
GREEN='\033[0;32m'
YELLOW='\033[0;33m'
CYAN='\033[0;36m'
NC='\033[0m'

info()  { echo -e "${CYAN}[*]${NC} $*"; }
ok()    { echo -e "${GREEN}[✓]${NC} $*"; }
warn()  { echo -e "${YELLOW}[!]${NC} $*"; }
error() { echo -e "${RED}[✗]${NC} $*"; exit 1; }

# ─── 辅助函数 ─────────────────────────────────────────────────────
find_app() {
    local search_path="${1:-}"
    if [[ -n "$search_path" && -d "$search_path" ]]; then
        echo "$search_path"
        return 0
    fi

    local candidates=(
        "/Applications/${APP_NAME}.app"
        "$HOME/Applications/${APP_NAME}.app"
        "$HOME/Desktop/${APP_NAME}.app"
    )
    for c in "${candidates[@]}"; do
        if [[ -d "$c" ]]; then
            echo "$c"
            return 0
        fi
    done
    return 1
}

get_binary() {
    echo "$1/Contents/MacOS/${APP_NAME}"
}

get_frameworks_dir() {
    echo "$1/Contents/Frameworks"
}

check_version() {
    local app_path="$1"
    local plist="$app_path/Contents/Info.plist"
    if [[ ! -f "$plist" ]]; then
        error "Info.plist not found at $plist"
    fi
    /usr/libexec/PlistBuddy -c "Print CFBundleShortVersionString" "$plist" 2>/dev/null || echo "unknown"
}

kill_app() {
    if pgrep -x "$APP_NAME" > /dev/null 2>&1; then
        warn "${APP_NAME} 正在运行，正在终止..."
        killall "$APP_NAME" 2>/dev/null || true
        sleep 1
    fi
}

check_dependencies() {
    if ! command -v clang &> /dev/null; then
        error "需要 clang。请安装 Xcode Command Line Tools: xcode-select --install"
    fi
    if ! command -v codesign &> /dev/null; then
        error "需要 codesign"
    fi
    if [[ ! -f "$HOOK_SOURCE" ]]; then
        error "找不到 hook 源文件: $HOOK_SOURCE"
    fi
    if [[ ! -x "$INSERT_DYLIB" ]]; then
        error "找不到 insert_dylib 工具: $INSERT_DYLIB"
    fi
}

is_dylib_injected() {
    local binary="$1"
    local dylib_path="$2"
    # 检查 LC_LOAD_DYLIB 中是否包含目标 dylib
    otool -l "$binary" 2>/dev/null | grep -A2 "LC_LOAD_DYLIB" | grep -q "$dylib_path"
}

# ─── 操作 ─────────────────────────────────────────────────────────
do_verify() {
    local app_path="$1"
    local binary
    binary=$(get_binary "$app_path")
    local frameworks_dir
    frameworks_dir=$(get_frameworks_dir "$app_path")

    info "Binary: $binary"

    local version
    version=$(check_version "$app_path")
    info "版本: $version"

    # 检查 LC_LOAD_DYLIB 是否已注入
    local injected=false
    if is_dylib_injected "$binary" "$DYLIB_INSTALL_PATH"; then
        injected=true
    fi

    # 检查 dylib 文件是否存在
    local dylib_exists=false
    if [[ -f "$frameworks_dir/$DYLIB_NAME" ]]; then
        dylib_exists=true
    fi

    if $injected && $dylib_exists; then
        ok "状态: 已注入 (PATCHED)"
        info "  LC_LOAD_DYLIB: $DYLIB_INSTALL_PATH"
        info "  Dylib 文件: $frameworks_dir/$DYLIB_NAME"
        return 0
    elif $injected && ! $dylib_exists; then
        warn "状态: 异常 — LC_LOAD_DYLIB 已注入但 dylib 文件缺失"
        return 2
    else
        info "状态: 未注入 (ORIGINAL)"
        return 1
    fi
}

do_patch() {
    local app_path="$1"
    local binary
    binary=$(get_binary "$app_path")
    local frameworks_dir
    frameworks_dir=$(get_frameworks_dir "$app_path")

    if [[ ! -f "$binary" ]]; then
        error "找不到二进制文件: $binary"
    fi

    # 版本检查
    local version
    version=$(check_version "$app_path")
    info "应用版本: $version"
    if [[ "$version" != "$TARGET_VERSION" ]]; then
        warn "版本不匹配！期望 $TARGET_VERSION，实际 $version"
        warn "Patch 可能无法正常工作。继续？(y/N)"
        read -r confirm
        [[ "$confirm" == "y" || "$confirm" == "Y" ]] || exit 0
    fi

    # 检查是否已注入
    if is_dylib_injected "$binary" "$DYLIB_INSTALL_PATH"; then
        if [[ -f "$frameworks_dir/$DYLIB_NAME" ]]; then
            ok "已经注入过了，无需重复操作。"
            return 0
        else
            info "LC_LOAD_DYLIB 已存在但 dylib 缺失，重新编译..."
        fi
    fi

    check_dependencies

    # 终止运行中的应用
    kill_app

    # 1. 编译 dylib
    info "编译 ${DYLIB_NAME}..."
    local tmp_dylib="/tmp/${DYLIB_NAME}"
    clang -arch arm64 \
        -dynamiclib \
        -install_name "$DYLIB_INSTALL_PATH" \
        -o "$tmp_dylib" \
        "$HOOK_SOURCE" \
        -framework Foundation
    ok "编译完成: $tmp_dylib"

    # 2. 创建 Frameworks 目录并复制 dylib
    mkdir -p "$frameworks_dir"
    cp "$tmp_dylib" "$frameworks_dir/$DYLIB_NAME"
    ok "Dylib 已复制到: $frameworks_dir/$DYLIB_NAME"
    rm -f "$tmp_dylib"

    # 3. 创建备份
    local backup="${binary}.bak"
    if [[ ! -f "$backup" ]]; then
        info "创建备份: $backup"
        cp "$binary" "$backup"
    else
        info "备份已存在: $backup"
    fi

    # 4. 注入 LC_LOAD_DYLIB (使用 insert_dylib)
    info "注入 LC_LOAD_DYLIB..."
    if ! "$INSERT_DYLIB" "$DYLIB_INSTALL_PATH" "$binary" --inplace --all-yes; then
        error "注入失败！"
    fi
    ok "注入完成"

    # 5. 签名 dylib
    info "签名 dylib..."
    codesign --force --sign - "$frameworks_dir/$DYLIB_NAME" 2>/dev/null
    ok "Dylib 已签名"

    # 6. 重签名整个 App
    info "重签名应用..."
    codesign --force --deep --sign - "$app_path" 2>/dev/null
    ok "应用已重签名（ad-hoc）"

    # 7. 验证
    if is_dylib_injected "$binary" "$DYLIB_INSTALL_PATH"; then
        ok "验证通过"
    else
        error "验证失败！"
    fi

    echo ""
    ok "Patch 完成！所有图床已解锁。"
    info "运行 '${0} --restore ${app_path}' 可恢复原始状态。"
}

do_restore() {
    local app_path="$1"
    local binary
    binary=$(get_binary "$app_path")
    local backup="${binary}.bak"
    local frameworks_dir
    frameworks_dir=$(get_frameworks_dir "$app_path")

    if [[ ! -f "$backup" ]]; then
        error "找不到备份文件: $backup"
    fi

    # 终止运行中的应用
    kill_app

    # 1. 恢复二进制
    info "从备份恢复二进制..."
    cp "$backup" "$binary"
    ok "二进制已恢复"

    # 2. 移除 dylib
    if [[ -f "$frameworks_dir/$DYLIB_NAME" ]]; then
        rm -f "$frameworks_dir/$DYLIB_NAME"
        ok "已移除 dylib: $frameworks_dir/$DYLIB_NAME"
    fi

    # 3. 重签名
    info "重签名应用..."
    codesign --force --deep --sign - "$app_path" 2>/dev/null
    ok "已重签名"

    # 4. 验证
    if ! is_dylib_injected "$binary" "$DYLIB_INSTALL_PATH"; then
        ok "恢复完成！二进制已恢复原始状态。"
    else
        warn "恢复完成，但 LC_LOAD_DYLIB 仍然存在（可能备份已被修改）。"
    fi
}

# ─── 主入口 ──────────────────────────────────────────────────────
main() {
    echo ""
    echo -e "${CYAN}╔══════════════════════════════════════╗${NC}"
    echo -e "${CYAN}║  iPic v${TARGET_VERSION} Dylib Hook Patcher       ║${NC}"
    echo -e "${CYAN}║  解锁所有图床（运行时注入）         ║${NC}"
    echo -e "${CYAN}╚══════════════════════════════════════╝${NC}"
    echo ""

    local action="patch"
    local app_arg=""

    while [[ $# -gt 0 ]]; do
        case "$1" in
            --restore|-r)  action="restore"; shift ;;
            --verify|-v)   action="verify";  shift ;;
            --help|-h)
                echo "用法: $0 [--restore|--verify] [path_to_iPic.app]"
                echo ""
                echo "操作:"
                echo "  (默认)     编译 dylib + 注入 + 签名"
                echo "  --restore  恢复原始二进制"
                echo "  --verify   检查注入状态"
                exit 0
                ;;
            *)  app_arg="$1"; shift ;;
        esac
    done

    local app_path
    if ! app_path=$(find_app "$app_arg"); then
        error "找不到 ${APP_NAME}.app。请提供路径作为参数。"
    fi
    info "App 路径: $app_path"

    case "$action" in
        patch)   do_patch "$app_path" ;;
        restore) do_restore "$app_path" ;;
        verify)  do_verify "$app_path" ;;
    esac
}

main "$@"
