#!/bin/bash
#
# (c) FFRI Security, Inc., 2025 / Author: FFRI Security, Inc.
#

source "$(dirname "$0")/../../common/run_template.sh"

# Constants
readonly APP_NAME=test.app
readonly APP_DIR=$APP_NAME/Contents
readonly EXT_APP_DIR=$APP_DIR/PlugIns/testex.appex

# Default test cases
readonly DEFAULT_TEST_CASES=("sheepswap_variant_1" "hunt_sheepswap_extension_obfuscation" "hunt_macos_sheepswap_strings" "extension_obfuscation")

# Function to create basic app structure
create_app_structure() {
    log_info "Removing previous application bundle"
    rm -rf "$APP_NAME"
    rm -rf "/Applications/$APP_NAME"

    mkdir -p "$APP_DIR/MacOS"
    mkdir -p "$EXT_APP_DIR/Contents/MacOS"
    mkdir -p "$EXT_APP_DIR/Contents/Resources"
}

# Function to create main app Info.plist
create_main_info_plist() {
    cat <<EOF > "$APP_DIR/Info.plist"
<?xml version="1.0" encoding="UTF-8"?>
<!DOCTYPE plist PUBLIC "-//Apple//DTD PLIST 1.0//EN" "http://www.apple.com/DTDs/PropertyList-1.0.dtd">
<plist version="1.0">
<dict>
    <key>CFBundleDisplayName</key>
    <string>test</string>
    <key>CFBundleExecutable</key>
    <string>test</string>
    <key>CFBundleIdentifier</key>
    <string>net.hoge.test</string>
    <key>CFBundleName</key>
    <string>test</string>
    <key>CFBundleSupportedPlatforms</key>
    <array>
        <string>MacOSX</string>
    </array>
    <key>NSPrincipalClass</key>
    <string>NSApplication</string>
</dict>
</plist>
EOF
}

# Function to create extension Info.plist
create_extension_info_plist() {
    cat <<EOF > "$EXT_APP_DIR/Contents/Info.plist"
<?xml version="1.0" encoding="UTF-8"?>
<!DOCTYPE plist PUBLIC "-//Apple//DTD PLIST 1.0//EN" "http://www.apple.com/DTDs/PropertyList-1.0.dtd">
<plist version="1.0">
<dict>
    <key>CFBundleDisplayName</key>
    <string>testex</string>
    <key>CFBundleExecutable</key>
    <string>testex</string>
    <key>CFBundleIdentifier</key>
    <string>net.hoge.testex.Extension</string>
    <key>CFBundleName</key>
    <string>testex</string>
    <key>CFBundlePackageType</key>
    <string>XPC!</string>
    <key>CFBundleSupportedPlatforms</key>
    <array>
        <string>MacOSX</string>
    </array>
    <key>NSExtension</key>
    <dict>
        <key>NSExtensionPointIdentifier</key>
        <string>com.apple.Safari.web-extension</string>
        <key>NSExtensionPrincipalClass</key>
        <string>TestWebExtension_Extension.SafariWebExtensionHandler</string>
    </dict>
</dict>
</plist>
EOF
}

# Function to create main app executable
create_main_executable() {
    cat <<EOF > "$APP_DIR/MacOS/test"
#!/bin/sh
open -a Calculator
EOF
    chmod +x "$APP_DIR/MacOS/test"
}

# Function to create temporary test files
create_temp_test_files() {
    log_info "Creating temporary test files..."
    # Create extension obfuscation test file
    cat <<EOF > /tmp/hunt_sheepswap_extension_obfuscation.c
#include <stdio.h>
int main() {
    puts("_\$sSS5index6beforeSS5IndexVAD_tF");
    puts("_\$sSS5index5afterSS5IndexVAD_tF");
    puts("_\$sSS5countSivg");
    puts("\x49\xaa\xaa\xaa\xaa\xaa\x28\x29\x00\xee\x49");
    puts("extension22SafariExtensionHandler");
    puts("messageReceivedWithName:fromPage:userInfo:");
}
EOF
    clang /tmp/hunt_sheepswap_extension_obfuscation.c -o /tmp/hunt_sheepswap_extension_obfuscation

    # Create variant 1 test file
    cat <<EOF > /tmp/sheepswap_variant_1.c
#include <stdio.h>

int main() {
    puts("lastHeartbeat");
    puts("sessionGuid");
    puts("extensionId");
    puts("userGuid");
}
EOF
    clang /tmp/sheepswap_variant_1.c -o /tmp/sheepswap_variant_1

    # Create strings test file
    cat <<EOF > /tmp/hunt_macos_sheepswap_strings.js
srchProxyURL
srchMatchData
navHist
matchDataTimer
EOF
    log_info "Temporary test files created"
}

# Function to cleanup temporary test files
cleanup() {
    log_info "Cleaning up temporary test files..."
    rm -f /tmp/hunt_sheepswap_extension_obfuscation.c
    rm -f /tmp/hunt_sheepswap_extension_obfuscation
    rm -f /tmp/sheepswap_variant_1.c
    rm -f /tmp/sheepswap_variant_1
    rm -f /tmp/hunt_macos_sheepswap_strings.js
    rm -rf "$APP_NAME"
    rm -rf "/Applications/$APP_NAME"
    log_info "Cleanup complete"
}

# Test case functions
create_app_ext_sheepswap_variant_1() {
    log_info "Creating sheepswap_variant_1 test case..."
    cp /tmp/sheepswap_variant_1 "$EXT_APP_DIR/Contents/MacOS/testex"
}

create_app_ext_hunt_sheepswap_extension_obfuscation() {
    log_info "Creating hunt_sheepswap_extension_obfuscation test case..."
    cp /tmp/hunt_sheepswap_extension_obfuscation "$EXT_APP_DIR/Contents/MacOS/testex"
    cp /tmp/hunt_macos_sheepswap_strings.js "$EXT_APP_DIR/Contents/Resources"
}

create_app_ext_hunt_macos_sheepswap_strings() {
    log_info "Creating hunt_macos_sheepswap_strings test case..."
    cp /tmp/hunt_macos_sheepswap_strings.js "$EXT_APP_DIR/Contents/Resources"
}

create_app_ext_extension_obfuscation() {
    log_info "Creating extension_obfuscation test case..."
    cp /tmp/hunt_sheepswap_extension_obfuscation "$EXT_APP_DIR/Contents/MacOS/testex"
}

# Show detection log
show_detection_log() {
    log_info "Please run /Library/Apple/System/Library/CoreServices/XProtect.app/Contents/MacOS/XProtectRemediatorSheepSwap or /Library/Apple/System/Library/CoreServices/XProtect.app/Contents/MacOS/XProtect"
    log stream --level debug --process XProtectRemediatorSheepSwap --predicate 'subsystem == "com.apple.XProtectFramework.PluginAPI"'
}

# Run test case
run_test_case() {
    local test_case="$1"
    log_info "Running test case: $test_case"

    log_info "Creating application..."
    create_app_structure
    create_main_info_plist
    create_extension_info_plist
    create_main_executable
    create_temp_test_files

    case "$test_case" in
        "sheepswap_variant_1")
            create_app_ext_sheepswap_variant_1
            ;;
        "hunt_sheepswap_extension_obfuscation")
            create_app_ext_hunt_sheepswap_extension_obfuscation
            ;;
        "hunt_macos_sheepswap_strings")
            create_app_ext_hunt_macos_sheepswap_strings
            ;;
        "extension_obfuscation")
            create_app_ext_extension_obfuscation
            ;;
        *)
            log_error "Unknown test case: $test_case"
            exit 1
            ;;
    esac

    # Run application to register the extension
    mv "$APP_NAME" /Applications/
    open "/Applications/$APP_NAME"
    sleep 1
    killall Calculator

    show_detection_log
}

# Entry point
if [[ "${BASH_SOURCE[0]}" == "${0}" ]]; then
    main "$@"
fi