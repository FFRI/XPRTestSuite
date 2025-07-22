#!/bin/bash
#
# (c) FFRI Security, Inc., 2025 / Author: FFRI Security, Inc.
#

source "$(dirname "$0")/../../common/run_template.sh"

readonly DEFAULT_TEST_CASES=("basic")

create_test_binary() {
    local target_path="$1"
    log_debug "Creating test binary at $target_path"
    cat <<EOF > /tmp/test.c
#include <stdio.h>

int main() {
    puts("sendLogEvent");
    puts("hexToData");
    puts("encryptDataa");
    puts("decryptDataa");
    puts("generateIV");
    puts("HostRotator");
}
EOF

    mkdir -p $(dirname "$target_path")
    clang /tmp/test.c -o "$target_path"
    truncate -s 80000 "$target_path"
}

setup_launch_agent() {
    local target_path="$1"
    log_debug "Setting up launch agent for $target_path"
    local plist_path="$HOME/Library/LaunchAgents/test.plist"
    mkdir -p $(dirname "$plist_path")
    cat <<EOF > "$plist_path"
<?xml version="1.0" encoding="UTF-8"?>
<!DOCTYPE plist PUBLIC "-//Apple//DTD PLIST 1.0//EN" "http://www.apple.com/DTDs/PropertyList-1.0.dtd">
<plist version="1.0">
<dict>
<key>Label</key>
<string>com.fuga.hoga</string>
<key>ProgramArguments</key>
<array>
    <string>$target_path</string>
</array>
</dict>
</plist>
EOF
}

show_detection_log() {
    log_info "Showing XProtect detection log"
    log_info "Please run /Library/Apple/System/Library/CoreServices/XProtect.app/Contents/MacOS/XProtectRemediatorDolittle or /Library/Apple/System/Library/CoreServices/XProtect.app/Contents/MacOS/XProtect"
    log stream --level debug --process XProtectRemediatorDolittle --predicate 'subsystem == "com.apple.XProtectFramework.PluginAPI"'
}

cleanup() {
    log_info "Cleaning up test environment"
    rm -f /tmp/test.c /tmp/test
    rm -f "$HOME/Library/LaunchAgents/test.plist"
}

run_test_case() {
    local case_name=$1
    log_info "Running test case: $case_name"

    case $case_name in
        "basic")
            local target_path="/tmp/test"
            create_test_binary "$target_path"
            setup_launch_agent "$target_path"
            ;;
        *)
            log_error "Unknown test case: $case_name"
            exit 1
            ;;
    esac

    show_detection_log
}

if [[ "${BASH_SOURCE[0]}" == "${0}" ]]; then
    main "$@"
fi

