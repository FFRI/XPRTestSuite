#!/bin/bash
#
# (c) FFRI Security, Inc., 2025 / Author: FFRI Security, Inc.
#

source "$(dirname "$0")/../../common/run_template.sh"

readonly DEFAULT_TEST_CASES=("process" "config" "files" "reportOnly")

readonly APP_NAME="Quartz"
# readonly APP_NAME="UpdateAgent"
readonly TEMP_DIR=$(mktemp -d)
readonly CONFIG_DIR="$HOME/Library/WebKit"
readonly TRIAL_DIR="$HOME/Library/Trial"
readonly TRANSLATION_DIR="$HOME/Library/Translation"
readonly SHARED_DIR="/Users/Shared"

# Function to create test executable with ColdSnap strings
create_test_executable() {
    cat <<EOF > $TEMP_DIR/$APP_NAME.cpp
#include <stdio.h>
#include <string.h>
#include <unistd.h>

// ColdSnap detection strings
const char* user_agent = "Mozilla/5.0 (Windows NT 6.1; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/81.0.4044.122 Safari/537.36";
const char* config_path = "%s/Library/WebKit/xpdf.conf";
const char* system_version = "/System/Library/CoreServices/SystemVersion.plist";
const char* encryption = "8A5Stream";

// ColdSnap detection symbols
void msg_system(void* msg) {}
void get_os_info(void* info) {}
void custom_sleep(unsigned int time) {}
void get_com_info(void* info) {}
void msg_keep_con(void* msg) {}
void msg_set_path(void* msg) {}
void get_file_time(char* path, char* time) {}
void msg_hibernate(void* msg, char flag) {}
void msg_secure_del(void* msg) {}
void get_internal_ip(void* info) {}
void msg_read_config(void* msg) {}
void reset_msg_stack(void) {}
void connect_to_proxy(void* msg) {}
void msg_write_config(void* msg) {}
void generate_random_string(size_t len) {}
void msg_up(void* msg) {}
void msg_cmd(void* msg) {}
void msg_dir(void* msg) {}
void msg_run(void* msg) {}
void pop_msg(void* msg) {}
void msg_down(void* msg) {}
void msg_exit(void* msg) {}
void msg_test(void* msg) {}
void push_msg(void* msg) {}
void msg_sleep(void* msg, char flag) {}

int main() {
    printf("ColdSnap test executable\n");
    while(1) { sleep(1); }  // Keep process running
    return 0;
}
EOF

    clang++ -o $TEMP_DIR/$APP_NAME $TEMP_DIR/$APP_NAME.cpp
    codesign --force --sign - $TEMP_DIR/$APP_NAME
}

create_config_file() {
    mkdir -p "$CONFIG_DIR"
    cat <<EOF > "$CONFIG_DIR/xpdf.conf"
http://example.com/beacon
EOF
    # Set file size to match detection criteria (1000-2000 bytes)
    truncate -s 1500 "$CONFIG_DIR/xpdf.conf"
}

create_files_in_target_directories() {
    mkdir -p "$TRIAL_DIR"
    mkdir -p "$TRANSLATION_DIR"
    mkdir -p "$SHARED_DIR"

    # Copy test executable to plugin directories with different names
    cp $TEMP_DIR/$APP_NAME "$TRIAL_DIR/plugin"
    cp $TEMP_DIR/$APP_NAME "$TRANSLATION_DIR/helper"
    cp $TEMP_DIR/$APP_NAME "$SHARED_DIR/update"
    chmod +x "$TRIAL_DIR/plugin" "$TRANSLATION_DIR/helper" "$SHARED_DIR/update"
}

create_reportonly_executable() {
    cat <<EOF > "$TEMP_DIR/${APP_NAME}_reportonly.cpp"
#include <unistd.h>
int main() {
    while (1) { sleep(1); }
    return 0;
}
EOF
    clang++ -o "$TEMP_DIR/$APP_NAME" "$TEMP_DIR/${APP_NAME}_reportonly.cpp"
    codesign --force --sign - "$TEMP_DIR/$APP_NAME"
}

show_detection_log() {
    log_info "Please run /Library/Apple/System/Library/CoreServices/XProtect.app/Contents/MacOS/XProtectRemediatorColdSnap or /Library/Apple/System/Library/CoreServices/XProtect.app/Contents/MacOS/XProtect"
    log stream --level debug --process XProtectRemediatorColdSnap --predicate 'subsystem == "com.apple.XProtectFramework.PluginAPI"'
}

cleanup() {
    log_info "Cleaning up test files..."
    rm -f "$TEMP_DIR/$APP_NAME" "$TEMP_DIR/$APP_NAME.cpp"
    rm -f "$CONFIG_DIR/xpdf.conf"
    rm -f "$TRIAL_DIR/plugin"
    rm -f "$TRANSLATION_DIR/helper"
    rm -f "$SHARED_DIR/update"
    killall $APP_NAME 2>/dev/null
}

run_test_case() {
    local case_name=$1
    log_info "Running test case: $case_name"

    case $case_name in
        "process")
            create_test_executable
            cp $TEMP_DIR/$APP_NAME ./
            chmod +x ./$APP_NAME
            log_info "Running ./$APP_NAME"
            ./$APP_NAME &
            ;;
        "reportOnly")
            create_reportonly_executable
            cp $TEMP_DIR/$APP_NAME ./
            chmod +x ./$APP_NAME
            log_info "Running reportOnly ./$APP_NAME"
            ./$APP_NAME &
            ;;
        "config")
            create_config_file
            ;;
        "files")
            create_test_executable
            create_files_in_target_directories
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
