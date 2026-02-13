#!/usr/bin/env bash
#
# iPic v1.8.4 Patch Script
# Patches sub_100081B10 to always return 1 (Pro active)
# Unlocks all image hosts (Qiniu, UpYun, AliOSS, TencentCOS, Imgur, Flickr, S3, B2, R2)
#
# Usage:
#   ./patch.sh [path_to_iPic.app]           # Patch the app
#   ./patch.sh --restore [path_to_iPic.app] # Restore original binary
#   ./patch.sh --verify [path_to_iPic.app]  # Check patch status
#

set -euo pipefail

# ─── Config ──────────────────────────────────────────────────────────
APP_NAME="iPic"
TARGET_VERSION="1.8.4"

# Patch target: sub_100081B10 (core Pro check function)
# ARM64 virtual address: 0x100081B10
# Original: STP X22,X21,[SP,...]; STP X20,X19,[SP,...]  (function prologue)
# Patched:  MOV W0,#1; RET                               (always return 1)
ORIGINAL_BYTES="f657bda9f44f01a9"
PATCH_BYTES="20008052c0035fd6"

# ─── Colors ──────────────────────────────────────────────────────────
RED='\033[0;31m'
GREEN='\033[0;32m'
YELLOW='\033[0;33m'
CYAN='\033[0;36m'
NC='\033[0m'

info()  { echo -e "${CYAN}[*]${NC} $*"; }
ok()    { echo -e "${GREEN}[✓]${NC} $*"; }
warn()  { echo -e "${YELLOW}[!]${NC} $*"; }
error() { echo -e "${RED}[✗]${NC} $*"; exit 1; }

# ─── Helpers ─────────────────────────────────────────────────────────
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

check_version() {
    local app_path="$1"
    local plist="$app_path/Contents/Info.plist"
    if [[ ! -f "$plist" ]]; then
        error "Info.plist not found at $plist"
    fi
    local version
    version=$(/usr/libexec/PlistBuddy -c "Print CFBundleShortVersionString" "$plist" 2>/dev/null || echo "unknown")
    echo "$version"
}

calculate_offset() {
    local binary="$1"

    # Get arm64 fat offset
    local fat_offset
    fat_offset=$(lipo -detailed_info "$binary" 2>/dev/null | awk '/architecture arm64/{found=1} found && /offset/{print $2; exit}')
    if [[ -z "$fat_offset" ]]; then
        # Not a fat binary, try as thin arm64
        local arch
        arch=$(file "$binary" | grep -o "arm64" | head -1)
        if [[ "$arch" == "arm64" ]]; then
            fat_offset=0
        else
            error "Cannot find arm64 architecture in binary"
        fi
    fi

    # Get __TEXT segment vmaddr
    local vmaddr
    vmaddr=$(otool -arch arm64 -l "$binary" 2>/dev/null | awk '/segname __TEXT/{getline; print $2; exit}')
    if [[ -z "$vmaddr" ]]; then
        error "Cannot find __TEXT segment vmaddr"
    fi

    # Calculate: file_offset = fat_offset + (VA - vmaddr)
    python3 -c "
fat = $fat_offset
vmaddr = $vmaddr
va = 0x100081B10
offset = fat + (va - vmaddr)
print(offset)
"
}

read_bytes() {
    local binary="$1"
    local offset="$2"
    local count="$3"
    xxd -s "$offset" -l "$count" -p "$binary" | tr -d ' \n'
}

kill_app() {
    if pgrep -x "$APP_NAME" > /dev/null 2>&1; then
        warn "${APP_NAME} is running, killing it..."
        killall "$APP_NAME" 2>/dev/null || true
        sleep 1
    fi
}

# ─── Actions ─────────────────────────────────────────────────────────
do_verify() {
    local app_path="$1"
    local binary
    binary=$(get_binary "$app_path")

    info "Binary: $binary"

    local version
    version=$(check_version "$app_path")
    info "Version: $version"

    local offset
    offset=$(calculate_offset "$binary")
    info "Patch offset: $offset (0x$(printf '%X' "$offset"))"

    local current
    current=$(read_bytes "$binary" "$offset" 8)

    if [[ "$current" == "$PATCH_BYTES" ]]; then
        ok "Status: PATCHED"
        return 0
    elif [[ "$current" == "$ORIGINAL_BYTES" ]]; then
        info "Status: ORIGINAL (not patched)"
        return 1
    else
        warn "Status: UNKNOWN (bytes: $current)"
        warn "Expected original: $ORIGINAL_BYTES"
        warn "Expected patched:  $PATCH_BYTES"
        return 2
    fi
}

do_patch() {
    local app_path="$1"
    local binary
    binary=$(get_binary "$app_path")

    if [[ ! -f "$binary" ]]; then
        error "Binary not found: $binary"
    fi

    local version
    version=$(check_version "$app_path")
    info "App version: $version"
    if [[ "$version" != "$TARGET_VERSION" ]]; then
        warn "Version mismatch! Expected $TARGET_VERSION, got $version"
        warn "Patch may not work correctly. Continue anyway? (y/N)"
        read -r confirm
        [[ "$confirm" == "y" || "$confirm" == "Y" ]] || exit 0
    fi

    local offset
    offset=$(calculate_offset "$binary")
    info "Patch offset: $offset (0x$(printf '%X' "$offset"))"

    # Check current state
    local current
    current=$(read_bytes "$binary" "$offset" 8)

    if [[ "$current" == "$PATCH_BYTES" ]]; then
        ok "Already patched, nothing to do."
        return 0
    fi

    if [[ "$current" != "$ORIGINAL_BYTES" ]]; then
        error "Unexpected bytes at offset: $current (expected $ORIGINAL_BYTES). Aborting."
    fi

    # Kill running instance
    kill_app

    # Create backup
    local backup="${binary}.bak"
    if [[ ! -f "$backup" ]]; then
        info "Creating backup: $backup"
        cp "$binary" "$backup"
    else
        info "Backup already exists: $backup"
    fi

    # Apply patch
    info "Patching..."
    python3 -c "
import sys
with open('$binary', 'rb') as f:
    data = bytearray(f.read())

offset = $offset
original = bytes.fromhex('$ORIGINAL_BYTES')
patch = bytes.fromhex('$PATCH_BYTES')

if data[offset:offset+8] != original:
    print('ERROR: bytes mismatch at offset', file=sys.stderr)
    sys.exit(1)

data[offset:offset+8] = patch

with open('$binary', 'wb') as f:
    f.write(data)
"
    ok "Binary patched"

    # Verify patch
    current=$(read_bytes "$binary" "$offset" 8)
    if [[ "$current" != "$PATCH_BYTES" ]]; then
        error "Patch verification failed!"
    fi

    # Re-sign
    info "Re-signing..."
    codesign --force --deep --sign - "$app_path" 2>/dev/null
    ok "Re-signed with ad-hoc signature"

    echo ""
    ok "Patch complete! All image hosts unlocked."
    info "Run '${0} --restore ${app_path}' to restore original."
}

do_restore() {
    local app_path="$1"
    local binary
    binary=$(get_binary "$app_path")
    local backup="${binary}.bak"

    if [[ ! -f "$backup" ]]; then
        error "Backup not found: $backup"
    fi

    # Kill running instance
    kill_app

    info "Restoring from backup..."
    cp "$backup" "$binary"
    ok "Binary restored"

    # Re-sign
    info "Re-signing..."
    codesign --force --deep --sign - "$app_path" 2>/dev/null
    ok "Re-signed"

    # Verify
    local offset
    offset=$(calculate_offset "$binary")
    local current
    current=$(read_bytes "$binary" "$offset" 8)
    if [[ "$current" == "$ORIGINAL_BYTES" ]]; then
        ok "Restore complete! Binary is back to original."
    else
        warn "Restore done, but bytes don't match expected original."
    fi
}

# ─── Main ────────────────────────────────────────────────────────────
main() {
    echo ""
    echo -e "${CYAN}╔══════════════════════════════════════╗${NC}"
    echo -e "${CYAN}║  iPic v${TARGET_VERSION} Patcher                 ║${NC}"
    echo -e "${CYAN}║  Unlock all image hosts              ║${NC}"
    echo -e "${CYAN}╚══════════════════════════════════════╝${NC}"
    echo ""

    local action="patch"
    local app_arg=""

    while [[ $# -gt 0 ]]; do
        case "$1" in
            --restore|-r)  action="restore"; shift ;;
            --verify|-v)   action="verify";  shift ;;
            --help|-h)
                echo "Usage: $0 [--restore|--verify] [path_to_iPic.app]"
                exit 0
                ;;
            *)  app_arg="$1"; shift ;;
        esac
    done

    local app_path
    if ! app_path=$(find_app "$app_arg"); then
        error "Cannot find ${APP_NAME}.app. Please provide the path as argument."
    fi
    info "App path: $app_path"

    case "$action" in
        patch)   do_patch "$app_path" ;;
        restore) do_restore "$app_path" ;;
        verify)  do_verify "$app_path" ;;
    esac
}

main "$@"
