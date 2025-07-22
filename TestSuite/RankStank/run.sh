#!/bin/bash
#
# (c) FFRI Security, Inc., 2025 / Author: FFRI Security, Inc.
#

source "$(dirname "$0")/../../common/run_template.sh"

readonly DEFAULT_TEST_CASES=("libffmpeg_app" "libffmpeg_any" "main_storage" "update_agent")

create_yara_matching_file() {
    local output_file="$1"
    local temp_file
    temp_file=$(mktemp)

    # Create a text file containing strings that match the YARA rule
    cat > "$temp_file" << 'EOF'
# This is a fake libffmpeg.dylib that matches the YARA rule
# It contains the following strings that match the rule:
# - _run_avcodec
# - %s/.main_storage
# - .session-lock
# - %s/UpdateAgent

# Function that will be detected by the YARA rule
void _run_avcodec() {
    // This is a fake function that contains the required string
    char* path = "%s/.main_storage";
    char* lock = ".session-lock";
    char* agent = "%s/UpdateAgent";
    
    // This is a fake binary pattern that matches the YARA rule
    // 80 b4 04 ?? ?? 00 00 7a
    unsigned char pattern[] = {
        0x80, 0xb4, 0x04, 0x00, 0x00, 0x00, 0x00, 0x7a
    };
}
EOF

    # Convert the text file to a binary file
    # Note: This is a simple way to create a binary file that matches the YARA rule
    # In a real malware sample, these strings would be part of the actual binary
    cp "$temp_file" "$output_file"
    rm "$temp_file"
}

cleanup() {
    log_info "Removing the following files and directories:"
    log_info "/Applications/3CX Desktop App.app"
    log_info "$HOME/Library/Application Support/3CX Desktop App/"
    log_info "/tmp/libffmpeg.dylib"
    rm -rf "/Applications/3CX Desktop App.app"
    rm -rf "$HOME/Library/Application Support/3CX Desktop App/"
    rm -f "/tmp/libffmpeg.dylib"
    log_info "Cleanup complete."
}

run_test_case() {
    local test_case="$1"
    log_info "Running test case: $test_case"

    case "$test_case" in
        "libffmpeg_app")
            # Check if 3CX Desktop App is already installed
            if [ -d "/Applications/3CX Desktop App.app" ]; then
                log_error "3CX Desktop App (possibly a legitimate version?) is already installed."
                log_error "Please uninstall the application before running this test."
                exit 1
            fi

            log_info "Setting up RankStank test environment for libffmpeg.dylib in 3CX Desktop App..."
            mkdir -p "/Applications/3CX Desktop App.app/Contents/Frameworks/Electron Framework.framework/Versions/A/Libraries/"
            log_info "Creating a fake libffmpeg.dylib that matches the YARA rule..."
            create_yara_matching_file "/Applications/3CX Desktop App.app/Contents/Frameworks/Electron Framework.framework/Versions/A/Libraries/libffmpeg.dylib"
            log_info "Test environment setup complete."
            show_detection_log
            ;;

        "libffmpeg_any")
            log_info "Setting up RankStank test environment for libffmpeg.dylib in /tmp..."
            log_info "Creating a fake libffmpeg.dylib that matches the YARA rule..."
            log_info "This test case does not work as expected because File(predicate: NSPredicate, @FileRemediationBuilder fileRemediationBuilder: @escaping () -> [AnyFileCondition]) seems broken."
            create_yara_matching_file "/tmp/libffmpeg.dylib"
            log_info "Test environment setup complete."
            show_detection_log
            ;;

        "main_storage")
            log_info "Setting up RankStank test environment for .main_storage..."
            mkdir -p "$HOME/Library/Application Support/3CX Desktop App/"
            touch "$HOME/Library/Application Support/3CX Desktop App/.main_storage"
            log_info "Test environment setup complete."
            show_detection_log
            ;;

        "update_agent")
            log_info "Setting up RankStank test environment for UpdateAgent..."
            mkdir -p "$HOME/Library/Application Support/3CX Desktop App/"
            touch "$HOME/Library/Application Support/3CX Desktop App/UpdateAgent"
            log_info "Test environment setup complete."
            show_detection_log
            ;;

        *)
            log_error "Unknown test case: $test_case"
            exit 1
            ;;
    esac
}

show_detection_log() {
    log_info "Please run /Library/Apple/System/Library/CoreServices/XProtect.app/Contents/MacOS/XProtectRemediatorRankStank or /Library/Apple/System/Library/CoreServices/XProtect.app/Contents/MacOS/XProtect"
    log stream --level debug --process XProtectRemediatorRankStank --predicate 'subsystem == "com.apple.XProtectFramework.PluginAPI"'
}

if [[ "${BASH_SOURCE[0]}" == "${0}" ]]; then
    main "$@"
fi