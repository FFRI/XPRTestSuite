#!/bin/bash
#
# (c) FFRI Security, Inc., 2025 / Author: FFRI Security, Inc.
#

source "$(dirname "$0")/../../common/run_template.sh"

readonly DEFAULT_TEST_CASES=("snowdrift" "target_files" "webcontent_dylib" "itunes_info_plist" "windowserver_files" "launch_agent" "syncservices" "imis_log")

readonly LOGIN_USER_NAME=$(stat -f "%Su" /dev/console)
readonly CACHE_DIR=$(getconf DARWIN_USER_CACHE_DIR)

is_root() {
    [ "$(id -u)" -eq 0 ]
}

create_empty_file() {
    local file_path="$1"
    local owner="$2"
    log_debug "Creating empty file: $file_path"
    touch "$file_path"
    if [ "$owner" = "user" ]; then
        sudo -u "$LOGIN_USER_NAME" chown "$LOGIN_USER_NAME" "$file_path"
    fi
}

create_snowdrift_binary() {
    local target_path="$1"
    log_debug "Creating SnowDrift binary at $target_path"
    cat <<EOF > /tmp/snowdrift.c
#include <stdio.h>

int main() {
    puts("https://api.pcloud.com/getfilelink?path=%@&forcedownload=1");
    puts("-[Management initCloud:access_token:]");
    puts("*.doc;*.docx;*.xls;*.xlsx;*.ppt;*.pptx;*.hwp;*.hwpx;*.csv;*.pdf;*.rtf;*.amr;*.3gp;*.m4a;*.txt;*.mp3;*.jpg;*.eml;*.emlx");
}
EOF
    clang -o "$target_path" /tmp/snowdrift.c
}

register_service() {
    local binary_path="$1"
    local owner="$2"
    local plist_name="$3"
    log_debug "Registering service: $plist_name"
    
    if [ "$owner" = "user" ]; then
        local plist_path="$HOME/Library/LaunchAgents/$plist_name.plist"
    else
        local plist_path="/Library/LaunchDaemons/$plist_name.plist"
    fi
    
    cat <<EOF > "$plist_path"
<?xml version="1.0" encoding="UTF-8"?>
<!DOCTYPE plist PUBLIC "-//Apple//DTD PLIST 1.0//EN" "http://www.apple.com/DTDs/PropertyList-1.0.dtd">
<plist version="1.0">
<dict>
    <key>Label</key>
    <string>com.example.$plist_name</string>
    <key>ProgramArguments</key>
    <array>
        <string>$binary_path</string>
    </array>
    <key>RunAtLoad</key>
    <true/>
</dict>
</plist>
EOF
}

show_detection_log() {
    log_info "Showing XProtect detection log"
    log_info "Please run /Library/Apple/System/Library/CoreServices/XProtect.app/Contents/MacOS/XProtectRemediatorSnowDrift or /Library/Apple/System/Library/CoreServices/XProtect.app/Contents/MacOS/XProtect"
    log stream --level debug --process XProtectRemediatorSnowDrift --predicate 'subsystem == "com.apple.XProtectFramework.PluginAPI"'
}

cleanup() {
    log_info "Cleaning up test environment"
    
    # Files to clean up
    local files=(
        # SnowDrift malware files
        "/private/tmp/snowdrift"
        "/private/tmp/snowdrift.c"

        # Target files (unconditional deletion)
        "/Library/Logs/DiagnosticReports/.Analytics-Journal.core_analytics"
        "/Library/Application Support/Apple/Fonts/iWork/.Standard.ttc"
        "/Library/WebServer/share/httpd/manual/WindowServer"
        "/Library/Preferences/com.apple.iTunesInfo29.plist"
        "/Library/Preferences/com.apple.iTunesInfo.plist"
        "/Library/Preferences/com.apple.iTunesInfo27.plist"

        # webcontent.dylib
        "$CACHE_DIR/com.apple.WebKit.WebContent+com.apple.Safari/com.apple.speech.speechsynthesisd/webcontent.dylib"

        "/private/tmp/empty"
        "/private/tmp/empty.c"

        # WindowServer files
        "$HOME/windowserver"
        "$HOME/loginwindow"

        # Launch agent
        "$HOME/Library/LaunchAgents/.com.apple.softwareupdate.plist"
        "$HOME/Library/LaunchAgents/snowdrift.plist"

        # SyncServices
        "$HOME/Library/ApplicationSupport/SyncServices/softwareupdate"

        # imis.log
        "$HOME/Library/Logs/imis.log"
    )

    # Remove all files
    for file in "${files[@]}"; do
        if [[ -e "$file" ]]; then
            log_debug "Removing file: $file"
            rm -f "$file"
        fi
    done

    # Clean up directories if they are empty
    local dirs=(
        "$HOME/Library/Containers/com.apple.FaceTime/Data/Library"
        "$HOME/Library/Containers/com.apple.languageassetd"
        "$HOME/Library/ApplicationSupport/SyncServices"
        "/Library/Application Support/Apple/Fonts/iWork"
    )

    for dir in "${dirs[@]}"; do
        if [[ -d "$dir" ]]; then
            log_debug "Removing directory: $dir"
            rmdir "$dir" 2>/dev/null || true
        fi
    done

    log_info "Cleanup completed"
}

run_test_case() {
    local case_name=$1
    log_info "Running test case: $case_name"

    case $case_name in
        "snowdrift")
            if is_root; then
                log_error "This test case is only available as user"
                exit 1
            fi
            local snowdrift_binary_path="/private/tmp/snowdrift"
            create_snowdrift_binary "$snowdrift_binary_path"
            register_service "$snowdrift_binary_path" "user" "snowdrift"
            ;;
        "target_files")
            log_info "Testing target files (unconditional deletion)"
            if is_root; then
                create_empty_file "/Library/Logs/DiagnosticReports/.Analytics-Journal.core_analytics" "root"
                mkdir -p "/Library/Application Support/Apple/Fonts/iWork"
                create_empty_file "/Library/Application Support/Apple/Fonts/iWork/.Standard.ttc" "root"
                create_empty_file "/Library/WebServer/share/httpd/manual/WindowServer" "root"
                create_empty_file "/Library/Preferences/com.apple.iTunesInfo29.plist" "root"
                create_empty_file "/Library/Preferences/com.apple.iTunesInfo.plist" "root"
                create_empty_file "/Library/Preferences/com.apple.iTunesInfo27.plist" "root" # This file should be deleted, but is not deleted by XProtectRemediatorSnowDrift
            else
                log_error "This test case is only available as root"
                exit 1
            fi
            ;;
        "webcontent_dylib")
            log_info "Testing webcontent.dylib file"
            if is_root; then
                log_error "This test case is only available as user"
                exit 1
            fi
            mkdir -p "$CACHE_DIR/com.apple.WebKit.WebContent+com.apple.Safari/com.apple.speech.speechsynthesisd"
            create_empty_file "$CACHE_DIR/com.apple.WebKit.WebContent+com.apple.Safari/com.apple.speech.speechsynthesisd/webcontent.dylib" "user"
            ;;
        "windowserver_files")
            log_info "Testing WindowServer files (non-Apple signed)"
            if is_root; then
                log_error "This test case is only available as user"
                exit 1
            fi
            create_empty_file "$HOME/windowserver" "user"
            create_empty_file "$HOME/loginwindow" "user"
            ;;
        "launch_agent")
            log_info "Testing launch agent file"
            if is_root; then
                log_error "This test case is only available as user"
                exit 1
            fi
            create_empty_file "/private/tmp/empty" "user"
            register_service "/private/tmp/empty" "user" ".com.apple.softwareupdate"
            ;;
        "syncservices")
            log_info "Testing SyncServices/softwareupdate with YaraMatcher"
            if is_root; then
                log_error "This test case is only available as user"
                exit 1
            fi
            local snowdrift_binary_path="/private/tmp/snowdrift"
            create_snowdrift_binary "$snowdrift_binary_path"
            mkdir -p "$HOME/Library/ApplicationSupport/SyncServices"
            cp "$snowdrift_binary_path" "$HOME/Library/ApplicationSupport/SyncServices/softwareupdate"
            ;;
        "imis_log")
            log_info "Testing imis.log (report only)"
            if is_root; then
                log_error "This test case is only available as user"
                exit 1
            fi
            create_empty_file "$HOME/Library/Logs/imis.log" "user"
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
