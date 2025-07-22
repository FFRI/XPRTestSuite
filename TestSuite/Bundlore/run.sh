#!/bin/bash
#
# (c) FFRI Security, Inc., 2025 / Author: FFRI Security, Inc.
#

source "$(dirname "$0")/../../common/run_template.sh"

readonly DEFAULT_TEST_CASES=("yara_service" "path_service" "yara_file" "unnotarized_file")

if [ "$(id -u)" -eq 0 ]; then
    readonly PLIST_DIR="/Library/LaunchDaemons"
else
    readonly PLIST_DIR="$HOME/Library/LaunchAgents"
fi

setup_test_case_yara_service() {
    log_info "Setting up test case: YARA Service Detection"
    log_debug "Creating yara_service.plist and /tmp/bundlore_yara_service"
    
    # Create executable that matches YARA rule
    cat << EOF > /tmp/bundlore_yara_service.c
#include <stdio.h>

int main(int argc, char *argv[]) {
    puts("Browser settings will be changed to allow the software to operate");
    puts("virtualbox");
    puts("vmware");
    puts("parallels");
}
EOF
    clang -o /tmp/bundlore_yara_service /tmp/bundlore_yara_service.c

    # Create LaunchAgent
    cat << EOF > "$PLIST_DIR/yara_service.plist"
<?xml version="1.0" encoding="UTF-8"?>
<!DOCTYPE plist PUBLIC "-//Apple//DTD PLIST 1.0//EN" "http://www.apple.com/DTDs/PropertyList-1.0.dtd">
<plist version="1.0">
<dict>
    <key>Label</key>
    <string>com.example.yara_service</string>
    <key>ProgramArguments</key>
    <array>
        <string>/tmp/bundlore_yara_service</string>
    </array>
</dict>
</plist>
EOF
}

setup_test_case_path_service() {
    log_info "Setting up test case: Path Service Detection"
    log_debug "Creating path_service.plist and /tmp/confup/bundlore_path_service.app"
    
    # Create app bundle in confup directory
    mkdir -p /tmp/confup/bundlore_path_service.app/Contents/MacOS
    cat << EOF > /tmp/bundlore_path_service.c
#include <stdio.h>

int main(int argc, char *argv[]) {
    puts("This is a test executable in confup directory");
}
EOF
    clang -o /tmp/confup/bundlore_path_service.app/Contents/MacOS/bundlore_path_service /tmp/bundlore_path_service.c
    
    cat << EOF > /tmp/confup/bundlore_path_service.app/Contents/Info.plist
<?xml version="1.0" encoding="UTF-8"?>
<!DOCTYPE plist PUBLIC "-//Apple//DTD PLIST 1.0//EN" "http://www.apple.com/DTDs/PropertyList-1.0.dtd">
<plist version="1.0">
<dict>
    <key>CFBundleIdentifier</key>
    <string>com.example.bundlore_path_service</string>
    <key>CFBundleExecutable</key>
    <string>bundlore_path_service</string>
    <key>CFBundleVersion</key>
    <string>1</string>
</dict>
</plist>
EOF
    codesign -s - -f /tmp/confup/bundlore_path_service.app

    # Create LaunchAgent
    cat << EOF > "$PLIST_DIR/path_service.plist"
<?xml version="1.0" encoding="UTF-8"?>
<!DOCTYPE plist PUBLIC "-//Apple//DTD PLIST 1.0//EN" "http://www.apple.com/DTDs/PropertyList-1.0.dtd">
<plist version="1.0">
<dict>
    <key>Label</key>
    <string>com.example.path_service</string>
    <key>ProgramArguments</key>
    <array>
        <string>/tmp/confup/bundlore_path_service.app/Contents/MacOS/bundlore_path_service</string>
    </array>
</dict>
</plist>
EOF
}

setup_test_case_yara_file() {
    log_info "Setting up test case: YARA File Detection"
    log_debug "Creating macOSOTA directory with YARA matching file"
    
    # Create directory and executable that matches YARA rule
    mkdir -p ~/Applications/macOSOTA
    cat << EOF > /tmp/bundlore_yara_file.c
#include <stdio.h>

int main(int argc, char *argv[]) {
    puts("Browser settings will be changed to allow the software to operate");
    puts("virtualbox");
    puts("vmware");
    puts("parallels");
}
EOF
    clang -o /tmp/bundlore_yara_file /tmp/bundlore_yara_file.c
    cp /tmp/bundlore_yara_file ~/Applications/macOSOTA/bundlore_yara_file
    truncate -s 103000 ~/Applications/macOSOTA/bundlore_yara_file
}

setup_test_case_unnotarized_file() {
    log_info "Setting up test case: Unnotarized File Detection"
    log_debug "Creating SofTruster directory with unnotarized Macho file"
    
    # Create directory and unnotarized executable
    mkdir -p ~/Applications/SofTruster
    cat << EOF > /tmp/bundlore_unnotarized.c
#include <stdio.h>

int main(int argc, char *argv[]) {
    puts("This is an unnotarized test executable");
}
EOF
    clang -o /tmp/bundlore_unnotarized /tmp/bundlore_unnotarized.c
    cp /tmp/bundlore_unnotarized ~/Applications/SofTruster/bundlore_unnotarized
    truncate -s 103000 ~/Applications/SofTruster/bundlore_unnotarized
}

show_detection_log() {
    log_info "Showing XProtect detection log"
    log_info "Please run /Library/Apple/System/Library/CoreServices/XProtect.app/Contents/MacOS/XProtectRemediatorBundlore or /Library/Apple/System/Library/CoreServices/XProtect.app/Contents/MacOS/XProtect"
    log stream --level debug --process XProtectRemediatorBundlore --predicate 'subsystem == "com.apple.XProtectFramework.PluginAPI"'
}

cleanup() {
    log_info "Cleaning up all test cases"

    # YARA Service Detection
    rm -f /tmp/bundlore_yara_service.c /tmp/bundlore_yara_service "$PLIST_DIR/yara_service.plist"

    # Path Service Detection
    rm -rf /tmp/confup/bundlore_path_service.app /tmp/bundlore_path_service.c "$PLIST_DIR/path_service.plist"

    # YARA File Detection
    rm -f /tmp/bundlore_yara_file.c /tmp/bundlore_yara_file ~/Applications/macOSOTA/bundlore_yara_file
    rmdir ~/Applications/macOSOTA

    # Unnotarized File Detection
    rm -f /tmp/bundlore_unnotarized.c /tmp/bundlore_unnotarized ~/Applications/SofTruster/bundlore_unnotarized
    rmdir ~/Applications/SofTruster
}

run_test_case() {
    local case_name=$1
    log_info "Running test case: $case_name"

    case $case_name in
        "yara_service")
            setup_test_case_yara_service
            ;;
        "path_service")
            setup_test_case_path_service
            ;;
        "yara_file")
            setup_test_case_yara_file
            ;;
        "unnotarized_file")
            setup_test_case_unnotarized_file
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
