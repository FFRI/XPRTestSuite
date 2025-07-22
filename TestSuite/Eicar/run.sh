#!/bin/bash
#
# (c) FFRI Security, Inc., 2025 / Author: FFRI Security, Inc.
#

source "$(dirname "$0")/../../common/run_template.sh"

readonly DEFAULT_TEST_CASES=("create_eicar")

cleanup() {
    log_info "Removing Eicar test file"
    rm -f /tmp/eicar
}

run_test_case() {
    local case_name=$1
    log_info "Running test case: $case_name"

    case $case_name in
        "create_eicar")
            log_info "Creating /tmp/eicar"
            echo 'X5O!P%@AP[4\PZX54(P^)7CC)7}$EICAR-STANDARD-ANTIVIRUS-TEST-FILE!$H+H*' > /tmp/eicar
            log_info "Please run /Library/Apple/System/Library/CoreServices/XProtect.app/Contents/MacOS/XProtectRemediatorEicar or /Library/Apple/System/Library/CoreServices/XProtect.app/Contents/MacOS/XProtect"
            log stream --level debug --process XProtectRemediatorEicar --predicate 'subsystem == "com.apple.XProtectFramework.PluginAPI" AND eventMessage CONTAINS "tmp" AND eventMessage CONTAINS "eicar"'
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
