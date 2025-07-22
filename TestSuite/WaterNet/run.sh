#!/bin/bash
#
# (c) FFRI Security, Inc., 2025 / Author: FFRI Security, Inc.
#

source "$(dirname "$0")/../../common/run_template.sh"

readonly DEFAULT_TEST_CASES=("normal" "reportOnly")

if [ "$(id -u)" -eq 0 ]; then
    readonly HOME_DIR="/private/var/root"
else
    readonly HOME_DIR="$HOME"
fi

create_waternet_executable() {
    local output_file="$1"
    local temp_source="/tmp/waternet_source.c"
    
    # Create a C source file that includes multiple strings from the YARA rule
    cat > "$temp_source" << 'EOF'
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

// Strings that match the YARA rule
const char* connectToProxyManager = "connectToProxyManager";
const char* connectToDestination = "connectToDestination";
const char* heartbeatSender = "heartbeatSender";
const char* connectToCnc = "connectToCnc";
const char* proxit_peer = "proxit.com/peer";
const char* client_hostinfo = "_client.com/utils/hostinfo.";
const char* proxit_traffic = "proxit_traffic";
const char* config_build_address = "config.BuildAddress";

int main(int argc, char* argv[]) {
    // Just a dummy main function to make it a valid executable
    printf("WaterNet test executable\n");
    return 0;
}
EOF

    # Compile the source file to create a Mach-O executable
    clang -o "$output_file" "$temp_source"
    rm "$temp_source"
    
    if [ ! -f "$output_file" ]; then
        log_error "Failed to create waternet executable"
        exit 1
    fi
    
    log_debug "Created waternet executable at $output_file"
}

setup_waternet_test() {
    local report_only="$1"
    local target_paths=()
    local waternet_executable

    if [ "$report_only" = "false" ]; then
        # ~/Library/Application Support/(([a-zA-Z0-9]{19,40})|([a-zA-Z0-9]{39}/[a-zA-Z0-9]{39}))/(helper|main|m|h)$
        target_paths=(
            "$HOME_DIR/Library/Application Support/wfpvtrubs4gpq4jmwkftbndkc0" # depth 1
            "$HOME_DIR/Library/Application Support/aaaa/wfpvtrubs4gpq4jmwkftbndkc0" # depth 2
            "$HOME_DIR/Library/Application Support/aaaa/bbbbbb/wfpvtrubs4gpq4jmwkftbndkc0" # depth 3
            "$HOME_DIR/Library/Application Support/aaaa/bbbbbb/ccc/wfpvtrubs4gpq4jmwkftbndkc0" # depth 4 (not remediated)
        )
        # Create waternet executable in the current directory
        waternet_executable="$(dirname "$0")/waternet"
        create_waternet_executable "$waternet_executable"
    else
        # reportOnly
        # ~/Library/Application Support/(([a-zA-Z0-9]{7,18})|([a-zA-Z0-9]{41,})|([a-zA-Z0-9]{40,}/[a-zA-Z0-9]{40,}))/(helper|main|m|h)$
        target_paths=("$HOME_DIR/Library/Application Support/aaaaaaaa")
        touch empty
        waternet_executable="empty"
    fi

    # Create target directories and copy executables
    local target_path="${target_paths[0]}"
    # local target_path="${target_paths[1]}" # to test other cases
    
    mkdir -p "$target_path"
    local waternet_path="$target_path/main"
    
    log_debug "Creating $waternet_path"
    cp "$waternet_executable" "$waternet_path"
}

show_detection_log() {
    log_info "Showing XProtect detection log"
    log_info "Please run /Library/Apple/System/Library/CoreServices/XProtect.app/Contents/MacOS/XProtectRemediatorWaterNet or /Library/Apple/System/Library/CoreServices/XProtect.app/Contents/MacOS/XProtect"
    log stream --level debug --process XProtectRemediatorWaterNet --predicate 'subsystem == "com.apple.XProtectFramework.PluginAPI"'
}

cleanup() {
    log_info "Cleaning up test environment"
    log_info "The following files will be deleted:"
    log_info "$HOME_DIR/Library/Application Support/wfpvtrubs4gpq4jmwkftbndkc0"
    log_info "$HOME_DIR/Library/Application Support/aaaa"
    log_info "$HOME_DIR/Library/Application Support/aaaaaaaa"
    log_info "$(dirname "$0")/waternet"
    
    rm -rf "$HOME_DIR/Library/Application Support/wfpvtrubs4gpq4jmwkftbndkc0"
    rm -rf "$HOME_DIR/Library/Application Support/aaaa"
    rm -rf "$HOME_DIR/Library/Application Support/aaaaaaaa"
    rm -f "$(dirname "$0")/waternet"
    
    log_info "Cleanup completed"
}

run_test_case() {
    local case_name=$1
    log_info "Running test case: $case_name"

    case $case_name in
        "normal")
            setup_waternet_test "false"
            show_detection_log
            ;;
        "reportOnly")
            setup_waternet_test "true"
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
