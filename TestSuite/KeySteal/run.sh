#!/bin/bash
#
# (c) FFRI Security, Inc., 2025 / Author: FFRI Security, Inc.
#

source "$(dirname "$0")/../../common/run_template.sh"

readonly DEFAULT_TEST_CASES=("normal" "reportOnly")

if [ "$(id -u)" -eq 0 ]; then
    readonly LAUNCHAGENT_DIR="/Library/LaunchDaemons"
else
    readonly LAUNCHAGENT_DIR="$HOME/Library/LaunchAgents"
    mkdir -p $LAUNCHAGENT_DIR
fi

create_keysteal_sample() {
    log_debug "Creating KeySteal sample"
    cat <<EOF > /private/tmp/keysteal.c
#include <stdio.h>

int main() {
    puts("data:application/x-apple-aspen-mobileprovision;base64,%@");
    puts("\x00" "newdev" "\x00" "newid" "\x00" "gogogo");
    puts("{\"data\":\"%@\"}");
}
EOF

    local sample=XProtect_MACOS_KEYSTEAL_A
    local plist_path=$LAUNCHAGENT_DIR/test.plist
    local sample_path=$HOME/Library/$sample

    clang /private/tmp/keysteal.c -o $sample_path

    cat <<EOF > $plist_path
<?xml version="1.0" encoding="UTF-8"?>
<!DOCTYPE plist PUBLIC "-//Apple//DTD PLIST 1.0//EN" "http://www.apple.com/DTDs/PropertyList-1.0.dtd">
<plist version="1.0">
<dict>
	<key>Label</key>
	<string>com.fuga.hoga</string>
	<key>ProgramArguments</key>
	<array>
		<string>$sample_path</string>
	</array>
</dict>
</plist>
EOF
}

create_com_apple_server() {
    local report_only=$1
    local size=32
    
    if [ "$report_only" = "true" ]; then
        size=33
    fi
    
    log_debug "Creating com.apple.server file with size $size"
    truncate -s $size /Library/Caches/com.apple.server
}

show_detection_log() {
    log_info "Showing XProtect detection log"
    log_info "Please run /Library/Apple/System/Library/CoreServices/XProtect.app/Contents/MacOS/XProtectRemediatorKeySteal or /Library/Apple/System/Library/CoreServices/XProtect.app/Contents/MacOS/XProtect"
    log stream --level debug --process XProtectRemediatorKeySteal --predicate 'subsystem == "com.apple.XProtectFramework.PluginAPI"'
}

cleanup() {
    log_info "Cleaning up test environment"
    log_info "The following files will be deleted:"
    log_info "1. /private/tmp/keysteal.c"
    log_info "2. $HOME/Library/XProtect_MACOS_KEYSTEAL_A"
    log_info "3. $LAUNCHAGENT_DIR/test.plist"
    log_info "4. /Library/Caches/com.apple.server"
    
    rm -f /private/tmp/keysteal.c
    rm -f "$HOME/Library/XProtect_MACOS_KEYSTEAL_A"
    rm -f "$LAUNCHAGENT_DIR/test.plist"
    rm -f /Library/Caches/com.apple.server
    
    log_info "Cleanup completed"
}

run_test_case() {
    local case_name=$1
    log_info "Running test case: $case_name"

    case $case_name in
        "normal")
            create_com_apple_server "false"
            create_keysteal_sample
            ;;
        "reportOnly")
            create_com_apple_server "true"
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
