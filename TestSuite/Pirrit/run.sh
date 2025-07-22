#!/bin/bash
#
# (c) FFRI Security, Inc., 2025 / Author: FFRI Security, Inc.
#

source "$(dirname "$0")/../../common/run_template.sh"

readonly DEFAULT_TEST_CASES=("pirrit_shell_script" "pirrit_variant" "pirrit_variant_ptrace" "pirrit_common_assembly" "pirrit_path_pattern")

is_root() {
    [ "$(id -u)" -eq 0 ]
}

# Create a launchd plist for a given executable
create_launchd_plist() {
    local executable_path="$1"

    if is_root; then
        local local_dir="/Library/LaunchDaemons"
    else
        local local_dir="$HOME/Library/LaunchAgents"
        mkdir -p "$local_dir"
    fi

    local plist_name="$(basename "$executable_path").plist"
    local plist_path="$local_dir/$plist_name"
    cat > "$plist_path" <<EOF
<?xml version="1.0" encoding="UTF-8"?>
<!DOCTYPE plist PUBLIC "-//Apple//DTD PLIST 1.0//EN" "http://www.apple.com/DTDs/PropertyList-1.0.dtd">
<plist version="1.0">
<dict>
    <key>Label</key>
    <string>$(basename "$executable_path").app</string>
    <key>ProgramArguments</key>
    <array>
        <string>$executable_path</string>
    </array>
    <key>RunAtLoad</key>
    <true/>
    <key>KeepAlive</key>
    <true/>
    <key>WatchPaths</key>
    <array>
        <string>/tmp</string>
    </array>
    <key>StartInterval</key>
    <integer>60</integer>
</dict>
</plist>
EOF
    log_info "Created plist: $plist_path"
}

# Create a Mach-O binary with Pirrit-like YARA hits
create_pirrit_binary() {
    local out_path="$1"
    local c_path="${out_path}.c"
    cat > "$c_path" <<EOF
#include <stdio.h>
int main() {
    const char* a = "_dlopen";
    const char* b = "_dlsym";
    const char* c = "RBSCSCSCSCSCRBRBSCRBRBRBRBRBp";
    const char* d = "\x31\xff\xbe\x0a\x00\x00\x00\xe8\x3b\x2e\x23\x00\x48\x8d\x35\xdd\xa6\x26\x00\x48\x89\xc7\xe8\x32\x2e\x23\x00\x48\x89\xc7";
    printf("%s %s %s\n", a, b, c);
    return 0;
}
EOF
    clang "$c_path" -o "$out_path"
    log_info "Created Pirrit-like binary: $out_path"
}

# Create a Pirrit variant binary (hunt_pirrit_variants)
create_pirrit_variant_binary() {
    local out_path="$1"
    local c_path="${out_path}.c"
    cat > "$c_path" <<EOF
#include <stdio.h>
int main() {
    const char* a = "@_IORegistryEntryCreateCFProperty";
    const char* b = "LicenseInstaller.build";
    const char* c = "RBSCSCSCSCSCRBRBSCRBRBRBRBRBp";
    printf("%s %s %s\n", a, b, c);
    return 0;
}
EOF
    clang "$c_path" -o "$out_path"
    log_info "Created Pirrit variant binary: $out_path"
}

# Create a Pirrit variant binary with ptrace deny (hunt_macos_ptrace_deny)
create_pirrit_ptrace_binary() {
    local out_path="$1"
    local c_path="${out_path}.c"
    cat > "$c_path" <<EOF
#include <stdio.h>
int main() {
    const char* a = "@_IORegistryEntryCreateCFProperty";
    const char* b = "LicenseInstaller.build";
    const char* c = "RBSCSCSCSCSCRBRBSCRBRBRBRBRBp";
    const char* d = "\x48\xc7\xc7\x1f\x00\x00\x00\x48\xc7\xc0\x1a\x00\x00\x02\x0f\x05";
    printf("%s %s %s\n", a, b, c);
    return 0;
}
EOF
    clang "$c_path" -o "$out_path"
    log_info "Created Pirrit ptrace binary: $out_path"
}

# Create a Pirrit shell script in /private/var/tmp (matches macos_pirrit_shell_script)
create_pirrit_shell_script() {
    local sh_path="/private/var/tmp/a.sh"
    echo -e '#!\x50\x4b\x03\x04 funzipaaa>' > "$sh_path"
    truncate -s 0x186b0 "$sh_path"
    log_info "Created Pirrit shell script: $sh_path"
}

# Create Application Support Pirrit binary (matches ExecutablePath constraint)
create_appsupport_pirrit() {
    local app_name="Hoge"
    local app_dir="$HOME/Library/Application Support/com.${app_name}/${app_name}.app/Contents/MacOS"
    mkdir -p "$app_dir"
    create_pirrit_binary "$app_dir/$app_name"
    create_launchd_plist "$app_dir/$app_name"
}

show_detection_log() {
    log_info "Please run /Library/Apple/System/Library/CoreServices/XProtect.app/Contents/MacOS/XProtectRemediatorPirrit or /Library/Apple/System/Library/CoreServices/XProtect.app/Contents/MacOS/XProtect"
    log stream --level debug --process XProtectRemediatorPirrit --predicate 'subsystem == "com.apple.XProtectFramework.PluginAPI"'
}

cleanup() {
    log_info "Cleaning up Pirrit infection simulation files..."
    # Pirrit shell script
    rm -f /private/var/tmp/a.sh
    # Pirrit variant binaries and sources
    rm -f /private/tmp/pirrit_variants /private/tmp/pirrit_variants.c
    rm -f /private/tmp/pirrit_variants_ptrace /private/tmp/pirrit_variants_ptrace.c
    # Application Support Pirrit binary and source
    rm -f "$HOME/Library/Application Support/com.Hoge/Hoge.app/Contents/MacOS/Hoge"
    rm -f /private/tmp/pirrit_common_assembly.c
    # Plists
    rm -f "$HOME/Library/LaunchAgents/aaa.plist"
    rm -f "$HOME/Library/LaunchAgents/tmp.aaaaaa.plist"
    rm -f "$HOME/Library/LaunchAgents/pirrit_variants.plist"
    rm -f "$HOME/Library/LaunchAgents/pirrit_variants_ptrace.plist"
    rm -f "/Library/LaunchDaemons/pirrit_variants.plist"
    rm -f "/Library/LaunchDaemons/pirrit_variants_ptrace.plist"
    # ExecutablePath pattern binaries
    rm -f /Library/aaa/aaa /var/root/Library/aaa/aaa "$HOME/Library/aaa/aaa"
    rm -f "$TMPDIR/tmp.aaaaaa"
    # Remove empty directories if possible
    rmdir "$HOME/Library/Application Support/com.Hoge/Hoge.app/Contents/MacOS" 2>/dev/null || true
    rmdir "$HOME/Library/Application Support/com.Hoge/Hoge.app/Contents" 2>/dev/null || true
    rmdir "$HOME/Library/Application Support/com.Hoge/Hoge.app" 2>/dev/null || true
    rmdir "$HOME/Library/Application Support/com.Hoge" 2>/dev/null || true
    rmdir "$HOME/Library/Application Support" 2>/dev/null || true
    rmdir "$HOME/Library/aaa" 2>/dev/null || true
    rmdir /Library/aaa 2>/dev/null || true
    rmdir /var/root/Library/aaa 2>/dev/null || true
    log_info "Cleanup complete."
}

run_test_case() {
    local case_name=$1
    log_info "Running test case: $case_name"

    case $case_name in
        "pirrit_shell_script")
            create_pirrit_shell_script
            ;;
        "pirrit_variant")
            local pirrit_variants="/private/tmp/pirrit_variants"
            create_pirrit_variant_binary "$pirrit_variants"
            create_launchd_plist "$pirrit_variants"
            ;;
        "pirrit_variant_ptrace")
            local pirrit_ptrace="/private/tmp/pirrit_variants_ptrace"
            create_pirrit_ptrace_binary "$pirrit_ptrace"
            create_launchd_plist "$pirrit_ptrace"
            ;;
        "pirrit_common_assembly")
            create_appsupport_pirrit
            ;;
        "pirrit_path_pattern")
            if is_root; then
                for path in "/Library/aaa/aaa" "/var/root/Library/aaa/aaa"; do
                    mkdir -p "$(dirname "$path")"
                    create_pirrit_binary "$path"
                    create_launchd_plist "$path"
                done
            else
                local user_aaa="$HOME/Library/aaa/aaa"
                mkdir -p "$(dirname "$user_aaa")"
                create_pirrit_binary "$user_aaa"
                create_launchd_plist "$user_aaa"
            fi
            local tmp_aaa="$TMPDIR/tmp.aaaaaa"
            mkdir -p "$(dirname "$tmp_aaa")"
            create_pirrit_binary "$tmp_aaa"
            create_launchd_plist "$tmp_aaa"
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