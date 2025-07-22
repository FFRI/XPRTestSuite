#!/bin/bash
#
# (c) FFRI Security, Inc., 2025 / Author: FFRI Security, Inc.
#

source "$(dirname "$0")/../../common/run_template.sh"

readonly DEFAULT_TEST_CASES=("service" "process" "file")

SERVICE_MODE=false
PROCESS_MODE=false
FILE_MODE=false

if [ "$(id -u)" -eq 0 ]; then
    readonly LAUNCHAGENT_DIR="/Library/LaunchDaemons"
else
    readonly LAUNCHAGENT_DIR="$HOME/Library/LaunchAgents"
    mkdir -p $LAUNCHAGENT_DIR
fi
readonly SAMPLE_PATH_ROOT=/private/tmp
readonly PLIST_PATH=$LAUNCHAGENT_DIR/adload_test.plist
readonly ADLOAD_TEST_SAMPLE="AdLoad_A"

readonly LAUNCH_AGENT_REGISTERED_EXECUTABLE=$SAMPLE_PATH_ROOT/$ADLOAD_TEST_SAMPLE
readonly ADLOAD_LIKE_BINARY_NAME="$(pwd)/Install.command"
readonly CRONTAB_REGISTERED_EXECUTABLE=/tmp/hoge
readonly CRONTAB_PATH=$HOME/.crontab

setup_proxy() {
    if [ "$(id -u)" -eq 0 ]; then
        log_info "Adding proxy"
        networksetup -setsocksfirewallproxy Wi-Fi localhost 8080
    else
        log_error "Proxy remediation test is not supported for non-root user"
    fi
}

show_detection_log() {
    log_info "Please run /Library/Apple/System/Library/CoreServices/XProtect.app/Contents/MacOS/XProtectRemediatorAdload or /Library/Apple/System/Library/CoreServices/XProtect.app/Contents/MacOS/XProtect"
    log stream --level debug --process XProtectRemediatorAdload --predicate 'subsystem == "com.apple.XProtectFramework.PluginAPI"'
}

compile_fake_adload_binary() {
    log_info "Compiling fake adload binary"
    make
    if [[ -f $ADLOAD_TEST_SAMPLE ]]; then
        log_info "Compiled $ADLOAD_TEST_SAMPLE"
    else
        log_error "Failed to compile $ADLOAD_TEST_SAMPLE"
        exit 1
    fi
}

register_launch_agent() {
    log_info "Registering launch agent/daemon"
    log_debug "Creating $PLIST_PATH"
    cat <<EOF > $PLIST_PATH
<?xml version="1.0" encoding="UTF-8"?>
<!DOCTYPE plist PUBLIC "-//Apple//DTD PLIST 1.0//EN" "http://www.apple.com/DTDs/PropertyList-1.0.dtd">
<plist version="1.0">
<dict>
<key>Label</key>
<string>com.fuga.hoga</string>
<key>ProgramArguments</key>
<array>
    <string>$LAUNCH_AGENT_REGISTERED_EXECUTABLE</string>
</array>
<key>RunAtLoad</key>
<true/>
</dict>
</plist>
EOF
    log_info "Copying $ADLOAD_TEST_SAMPLE to $LAUNCH_AGENT_REGISTERED_EXECUTABLE"
    cp $ADLOAD_TEST_SAMPLE $LAUNCH_AGENT_REGISTERED_EXECUTABLE
}

create_crontab_and_register_executable() {
    log_info "Creating $CRONTAB_PATH and registering $CRONTAB_REGISTERED_EXECUTABLE executable"
    cat <<EOF > $CRONTAB_PATH
*/2 * * * * $CRONTAB_REGISTERED_EXECUTABLE
EOF
    cp $ADLOAD_TEST_SAMPLE $CRONTAB_REGISTERED_EXECUTABLE
}

run_fake_adload_process() {
    if [[ ! -d /Library/ApplicationSupport ]]; then
        log_info "Creating /Library/ApplicationSupport"
        mkdir -p /Library/ApplicationSupport
    fi

    log_info "Copying $ADLOAD_TEST_SAMPLE to $ADLOAD_LIKE_BINARY_NAME"
    cp $ADLOAD_TEST_SAMPLE $ADLOAD_LIKE_BINARY_NAME
    log_info "Running $ADLOAD_LIKE_BINARY_NAME"
    $ADLOAD_LIKE_BINARY_NAME &
}

cleanup() {
    log_info "Removing launch agent/daemon"
    rm -f $LAUNCH_AGENT_REGISTERED_EXECUTABLE
    rm -f $PLIST_PATH
    rm -f $CRONTAB_PATH
    rm -f $CRONTAB_REGISTERED_EXECUTABLE
    rm -f $ADLOAD_LIKE_BINARY_NAME
    rm -rf /Library/ApplicationSupport
    make clean
    log_info "Killing created processes"
    killall Install.command
    killall .mitmproxy
    killall $ADLOAD_TEST_SAMPLE
}

run_test_case() {
    local case_name=$1
    log_info "Running test case: $case_name"

    case $case_name in
        "service")
            SERVICE_MODE=true
            ;;
        "process")
            PROCESS_MODE=true
            ;;
        "file")
            FILE_MODE=true
            ;;
        *)
            log_error "Unknown test case: $case_name"
            exit 1
            ;;
    esac

    compile_fake_adload_binary

    if [ "$SERVICE_MODE" = true ]; then
        register_launch_agent
        setup_proxy
    fi

    if [ "$FILE_MODE" = true ]; then
        create_crontab_and_register_executable
    fi

    if [ "$PROCESS_MODE" = true ]; then
        run_fake_adload_process
    fi

    show_detection_log
}

if [[ "${BASH_SOURCE[0]}" == "${0}" ]]; then
    main "$@"
fi