#!/bin/bash
#
# (c) FFRI Security, Inc., 2025 / Author: FFRI Security, Inc.
#

source "$(dirname "$0")/../../common/run_template.sh"

readonly DEFAULT_TEST_CASES=("redpine")

check_root() {
    if [ "$(id -u)" -ne 0 ]; then
        log_error "Must be running as root"
        exit 1
    fi
}

cleanup() {
    log_info "Killing loader process"
    killall loader 2>/dev/null || true
    log_info "Killing in_memory_scan process"
    killall in_memory_scan 2>/dev/null || true
    log_info "Cleaning up built files"
    make clean
    log_info "Cleanup complete"
}

show_detection_log() {
    log_info "Please run /Library/Apple/System/Library/CoreServices/XProtect.app/Contents/MacOS/XProtectRemediatorRedPine or /Library/Apple/System/Library/CoreServices/XProtect.app/Contents/MacOS/XProtect"
    log_info "Note that XProtectRemediatorRedPine is removed in XProtectRemediator version 145 or later."
    log stream --level debug --process XProtectRemediatorRedPine --predicate 'subsystem == "com.apple.XProtectFramework.PluginAPI"'
}

run_test_case() {
    local test_case="$1"
    log_info "Running test case: $test_case"

    case "$test_case" in
        "redpine")
            check_root
            log_info "Building and running RedPine test..."
            make run &
            sleep 5
            log_info "RedPine test environment setup complete"
            show_detection_log
            ;;
        *)
            log_error "Unknown test case: $test_case"
            exit 1
            ;;
    esac
}

if [[ "${BASH_SOURCE[0]}" == "${0}" ]]; then
    main "$@"
fi
