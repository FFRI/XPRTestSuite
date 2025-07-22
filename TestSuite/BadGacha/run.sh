#!/bin/bash
#
# (c) FFRI Security, Inc., 2025 / Author: FFRI Security, Inc.
#

source "$(dirname "$0")/../../common/run_template.sh"

readonly DEFAULT_TEST_CASES=("dmg" "backing")

create_dmg() {
    local dmg_path="$1"
    local src_image="$2" 
    local dst_path="$3"

    if [ -e "$dmg_path" ]; then
        rm "$dmg_path"
    fi

    hdiutil create -size 100m -fs APFS "$dmg_path"
    mkdir -p /tmp/mnt
    hdiutil attach -mountpoint /tmp/mnt "$dmg_path"

    log_info "Copying $src_image to $dst_path"
    mkdir -p "$(dirname "$dst_path")"
    cp "$src_image" "$dst_path"

    hdiutil detach /tmp/mnt

    log_info "Converting readonly dmg"
    hdiutil convert "$dmg_path" -format UDRO -o /tmp/test_tmp.dmg
    mv /tmp/test_tmp.dmg "$dmg_path"
}

show_detection_log() {
    log_info "Please run /Library/Apple/System/Library/CoreServices/XProtect.app/Contents/MacOS/XProtectRemediatorBadGacha or /Library/Apple/System/Library/CoreServices/XProtect.app/Contents/MacOS/XProtect"
    log stream --level debug --process XProtectRemediatorBadGacha --predicate 'subsystem == "com.apple.XProtectFramework.PluginAPI"'
}

cleanup() {
    log_info "Unmounting mounted volumes"
    if [ -d "/Volumes/untitled" ]; then
        hdiutil detach /Volumes/untitled
    fi
    if [ -d "/Volumes/untitled 1" ]; then
        hdiutil detach /Volumes/untitled\ 1
    fi

    log_info "Cleaning up all temporary files (files under /tmp/test1.dmg, /tmp/test2.dmg, and /tmp/test.c)"
    rm -f /tmp/test1.dmg
    rm -f /tmp/test2.dmg
    rm -f /tmp/test.c
    log_info "Killing processes that do not have their backing files"
    killall a.out
}

run_test_case() {
    local case_name=$1
    log_info "Running test case: $case_name"

    case $case_name in
        "dmg")
            # Create and mount DMG files
            create_dmg "/tmp/test1.dmg" "right-click.png" "/tmp/mnt/.background/hoge.png"
            create_dmg "/tmp/test2.dmg" "option-click.png" "/tmp/mnt/.background.png"
            # create_dmg "/tmp/test1.dmg" "choose-open.png" "/tmp/mnt/.background/hoge.png"
            # create_dmg "/tmp/test2.dmg" "unidentified-developer.png" "/tmp/mnt/.background.png"
            open /tmp/test1.dmg
            open /tmp/test2.dmg
            show_detection_log
            ;;
        "backing")
            # Run self-deleting process
            log_info "Running a process that self-deletes itself"
            log_info "This detection logic works for XPR version 133 or below"
            cat << EOF > /tmp/test.c
int main() { while(1){} }
EOF
            clang /tmp/test.c -o /tmp/a.out
            /tmp/a.out &
            rm /tmp/a.out
            show_detection_log
            ;;
        *)
            log_error "Unknown test case: $case_name"
            exit 1
            ;;
    esac
}

if [[ "${BASH_SOURCE[0]}" == "${0}" ]]; then
    main "$@"
fi
