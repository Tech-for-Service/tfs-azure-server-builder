#!/bin/bash
#
# TFS Server Hardening - Verification Script
# ==========================================
#
# This script verifies hardening compliance and generates reports.
# Designed to run on a schedule (weekly) or manually.
#
# Location: /etc/tfs/hardening/verify.sh
# Usage: sudo /etc/tfs/hardening/verify.sh
#
# Version: 1.2.1
# Last Updated: May 2026
#

set -euo pipefail

# =============================================================================
# CONFIGURATION
# =============================================================================

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
CONFIG_FILE="${SCRIPT_DIR}/config.env"

# Report settings
REPORT_DIR="/var/log/hardening-reports"
TIMESTAMP=$(date +%Y%m%d-%H%M%S)
HOSTNAME_SHORT=$(hostname -s)
REPORT_FILE="${REPORT_DIR}/compliance-${HOSTNAME_SHORT}-${TIMESTAMP}.md"

# Azure IMDS API version
AZURE_IMDS_API_VERSION="2025-04-07"
AZURE_IMDS_URL="http://169.254.169.254/metadata/instance?api-version=${AZURE_IMDS_API_VERSION}"

# Colors
RED='\033[0;31m'
GREEN='\033[0;32m'
YELLOW='\033[1;33m'
BLUE='\033[0;34m'
CYAN='\033[0;36m'
BOLD='\033[1m'
NC='\033[0m'

# Counters
PASS_COUNT=0
FAIL_COUNT=0
WARN_COUNT=0

# =============================================================================
# HELPER FUNCTIONS
# =============================================================================

log() {
    local msg="$1"
    echo -e "$msg"
    echo -e "$msg" | sed 's/\x1b\[[0-9;]*m//g' >> "$REPORT_FILE" 2>/dev/null || true
}

check_pass() {
    ((PASS_COUNT++)) || true
    log "${GREEN}✅ PASS:${NC} $1"
}

check_fail() {
    ((FAIL_COUNT++)) || true
    log "${RED}❌ FAIL:${NC} $1"
}

check_warn() {
    ((WARN_COUNT++)) || true
    log "${YELLOW}⚠️ WARN:${NC} $1"
}

check_info() {
    log "${BLUE}ℹ️ INFO:${NC} $1"
}

section_header() {
    log ""
    log "## $1"
    log ""
}

setup_reporting() {
    mkdir -p "$REPORT_DIR" 2>/dev/null || true
    touch "$REPORT_FILE" 2>/dev/null || true
}

contains_space_list_item() {
    local needle="$1"
    local haystack="$2"
    local item

    for item in $haystack; do
        if [[ "$item" == "$needle" ]]; then
            return 0
        fi
    done

    return 1
}

normalize_fail2ban_ignoreip() {
    local ip="$1"

    # Fail2ban normalizes 127.0.0.1/8 to the actual loopback network.
    if [[ "$ip" == "127.0.0.1/8" ]]; then
        echo "127.0.0.0/8"
    else
        echo "$ip"
    fi
}

normalize_ssh_value() {
    local setting="$1"
    local value="$2"

    # OpenSSH may report PermitRootLogin prohibit-password as without-password.
    # They are equivalent for our purposes: root login is key-only, not password-based.
    if [[ "${setting,,}" == "permitrootlogin" && "$value" == "without-password" ]]; then
        echo "prohibit-password"
    else
        echo "$value"
    fi
}

sudo_nopasswd_line_is_expected() {
    local line="$1"

    # Azure cloud-init commonly grants the initial VM admin user passwordless sudo.
    if [[ "$line" =~ (^|:)${SSH_ADMIN_USER}[[:space:]]+ALL= ]]; then
        return 0
    fi

    # Laravel Forge installs scoped NOPASSWD rules for its managed service actions.
    if [[ "$ENABLE_FORGE_INTEGRATION" == "true" && "$line" =~ (^|:)forge[[:space:]]+ALL ]]; then
        return 0
    fi

    return 1
}

# =============================================================================
# LOAD CONFIGURATION
# =============================================================================

load_config() {
    if [[ -f "$CONFIG_FILE" ]]; then
        source "$CONFIG_FILE"
    fi

    # Storage/reporting config from config.env, with legacy fallback
    TFS_STORAGE_ACCOUNT="${TFS_STORAGE_ACCOUNT:-${AZURE_STORAGE_ACCOUNT:-}}"
    TFS_HARDENING_CONTAINER="${TFS_HARDENING_CONTAINER:-tfs-hardening-reports}"
    TFS_COMPLIANCE_CONTAINER="${TFS_COMPLIANCE_CONTAINER:-tfs-compliance-reports}"
    TFS_SERVER_NAME="${TFS_SERVER_NAME:-$(hostname -s)}"

    # SSH / Forge defaults should match setup.sh
    # SSH_ADMIN_USER is written by azure-server-builder. Falls back to svcops for legacy servers.
    SSH_ADMIN_USER="${SSH_ADMIN_USER:-svcops}"

    # Forge integration is optional. Set ENABLE_FORGE_INTEGRATION=true in config.env for Laravel Forge servers.
    ENABLE_FORGE_INTEGRATION="${ENABLE_FORGE_INTEGRATION:-false}"
    FORGE_IPS="${FORGE_IPS:-159.203.150.232 165.227.248.218 159.203.150.216 45.55.124.124}"

    if [[ "${ENABLE_FORGE_INTEGRATION}" == "true" ]]; then
        SSH_PERMIT_ROOT_LOGIN="${SSH_PERMIT_ROOT_LOGIN:-prohibit-password}"
    else
        SSH_PERMIT_ROOT_LOGIN="${SSH_PERMIT_ROOT_LOGIN:-no}"
    fi

    # Do not use SSH AllowUsers. Forge creates per-site Linux users dynamically,
    # and key-only authentication is the SSH access control policy.
    SSH_USE_ALLOW_USERS="${SSH_USE_ALLOW_USERS:-false}"

    ENABLE_FORGE_ROOT_MATCH="${ENABLE_FORGE_ROOT_MATCH:-false}"
    FORGE_ROOT_PERMIT_LOGIN="${FORGE_ROOT_PERMIT_LOGIN:-prohibit-password}"

    # Fail2ban defaults should match setup.sh
    FAIL2BAN_MAXRETRY="${FAIL2BAN_MAXRETRY:-6}"
    FAIL2BAN_FINDTIME="${FAIL2BAN_FINDTIME:-600}"
    FAIL2BAN_BANTIME="${FAIL2BAN_BANTIME:-86400}"
    if [[ "${ENABLE_FORGE_INTEGRATION}" == "true" ]]; then
        FAIL2BAN_IGNOREIP="${FAIL2BAN_IGNOREIP:-127.0.0.1/8 ::1 ${FORGE_IPS}}"
    else
        FAIL2BAN_IGNOREIP="${FAIL2BAN_IGNOREIP:-127.0.0.1/8 ::1}"
    fi
}

# =============================================================================
# SECTION 1: SYSTEM INFORMATION
# =============================================================================

check_system_info() {
    section_header "SECTION 1: SYSTEM INFORMATION"

    check_info "Hostname: $(hostname)"
    check_info "OS: $(lsb_release -ds 2>/dev/null || cat /etc/os-release | grep PRETTY_NAME | cut -d'"' -f2)"
    check_info "Kernel: $(uname -r)"
    check_info "Uptime: $(uptime -p)"
    check_info "CPU: $(nproc) cores"
    check_info "Memory: $(free -h | awk '/^Mem:/ {print $2}')"
    check_info "Disk: $(df -h / | awk 'NR==2 {print $2 " total, " $4 " available"}')"

    # Check if running on Azure using IMDS
    local imds_response
    imds_response=$(curl -s -H "Metadata:true" --connect-timeout 2 "$AZURE_IMDS_URL" 2>/dev/null)

    if [[ -n "$imds_response" && "$imds_response" != *"error"* ]]; then
        check_info "Cloud: Azure"

        local vm_size
        local location
        local vm_name
        local resource_group

        vm_size=$(echo "$imds_response" | grep -o '"vmSize":"[^"]*"' | cut -d'"' -f4)
        location=$(echo "$imds_response" | grep -o '"location":"[^"]*"' | cut -d'"' -f4)
        vm_name=$(echo "$imds_response" | grep -o '"name":"[^"]*"' | head -1 | cut -d'"' -f4)
        resource_group=$(echo "$imds_response" | grep -o '"resourceGroupName":"[^"]*"' | cut -d'"' -f4)

        [[ -n "$vm_name" ]] && check_info "VM Name: $vm_name"
        [[ -n "$vm_size" ]] && check_info "VM Size: $vm_size"
        [[ -n "$location" ]] && check_info "Location: $location"
        [[ -n "$resource_group" ]] && check_info "Resource Group: $resource_group"
    fi
}

# =============================================================================
# SECTION 2: ENCRYPTION AT REST
# =============================================================================

check_encryption() {
    section_header "SECTION 2: ENCRYPTION AT REST"

    local imds_response
    imds_response=$(curl -s -H "Metadata:true" --connect-timeout 2 "$AZURE_IMDS_URL" 2>/dev/null)

    if [[ -n "$imds_response" && "$imds_response" != *"error"* ]]; then
        check_pass "Running on Azure"

        set +e
        local encryption_at_host
        local secure_boot
        local vtpm
        local security_type

        encryption_at_host=$(echo "$imds_response" | grep -o '"encryptionAtHost":"[^"]*"' 2>/dev/null | cut -d'"' -f4)
        secure_boot=$(echo "$imds_response" | grep -o '"secureBootEnabled":"[^"]*"' 2>/dev/null | cut -d'"' -f4)
        vtpm=$(echo "$imds_response" | grep -o '"virtualTpmEnabled":"[^"]*"' 2>/dev/null | cut -d'"' -f4)
        security_type=$(echo "$imds_response" | grep -o '"securityType":"[^"]*"' 2>/dev/null | cut -d'"' -f4)
        set -e

        if [[ "$encryption_at_host" == "true" ]]; then
            check_pass "Encryption at Host: Enabled"
        else
            check_warn "Encryption at Host: Not enabled"
        fi

        check_pass "Server-Side Encryption (SSE): Enabled by default on Azure managed disks"

        log ""
        check_info "Security Profile:"

        if [[ -n "$security_type" ]]; then
            check_info "  Security Type: $security_type"
        fi

        if [[ "$secure_boot" == "true" ]]; then
            check_pass "  Secure Boot: Enabled"
        else
            check_warn "  Secure Boot: Not enabled"
        fi

        if [[ "$vtpm" == "true" ]]; then
            check_pass "  Virtual TPM: Enabled"
        else
            check_warn "  Virtual TPM: Not enabled"
        fi
    else
        check_info "Not running on Azure or IMDS unavailable - verify encryption at cloud provider level"
    fi
}

# =============================================================================
# SECTION 3: SSH HARDENING
# =============================================================================

check_ssh() {
    section_header "SECTION 3: SSH HARDENING"

    check_ssh_setting() {
        local setting="$1"
        local expected="$2"
        local desc="$3"

        local current
        local normalized_current
        local normalized_expected

        current=$(sshd -T 2>/dev/null | grep -i "^${setting} " | awk '{print $2}')
        normalized_current=$(normalize_ssh_value "$setting" "${current,,}")
        normalized_expected=$(normalize_ssh_value "$setting" "${expected,,}")

        if [[ "$normalized_current" == "$normalized_expected" ]]; then
            if [[ "${current,,}" != "$normalized_current" ]]; then
                check_pass "$desc: $current (equivalent to $normalized_current)"
            else
                check_pass "$desc: $current"
            fi
        else
            check_fail "$desc: Expected '$expected', found '${current:-not set}'"
        fi
    }

    check_info "Verifying SSH configuration..."
    check_info "SSH admin user expected: ${SSH_ADMIN_USER}"
    check_info "Forge integration expected: ${ENABLE_FORGE_INTEGRATION}"

    if systemctl is-active --quiet ssh; then
        check_pass "SSH service running"
    else
        check_fail "SSH service not running"
    fi

    check_ssh_setting "permitrootlogin" "${SSH_PERMIT_ROOT_LOGIN}" "Global root login setting"
    check_ssh_setting "passwordauthentication" "no" "Password auth disabled"
    check_ssh_setting "pubkeyauthentication" "yes" "Public key auth enabled"
    check_ssh_setting "permitemptypasswords" "no" "Empty passwords disabled"
    check_ssh_setting "x11forwarding" "no" "X11 forwarding disabled"
    check_ssh_setting "maxauthtries" "3" "Max auth tries"

    # The current policy intentionally does not use AllowUsers.
    # Forge creates per-site Linux users dynamically, so AllowUsers breaks site SSH access.
    local allowusers
    allowusers=$(sshd -T 2>/dev/null | grep -i "^allowusers " | cut -d' ' -f2- || true)

    if [[ -n "$allowusers" ]]; then
        check_fail "SSH AllowUsers is configured but policy allows any key-authenticated SSH user: $allowusers"
    else
        check_pass "SSH AllowUsers is not configured; any valid key-authenticated Linux user may SSH"
    fi

    if [[ -f "/etc/ssh/sshd_config.d/99-hardening.conf" ]]; then
        check_pass "Hardening config file exists"

        if [[ "$ENABLE_FORGE_INTEGRATION" == "true" && "$ENABLE_FORGE_ROOT_MATCH" == "true" ]]; then
            if grep -q "^Match Address" /etc/ssh/sshd_config.d/99-hardening.conf; then
                check_pass "Forge SSH Match Address block exists"
            else
                check_fail "Forge integration enabled but SSH Match Address block is missing"
            fi

            if grep -q "PermitRootLogin ${FORGE_ROOT_PERMIT_LOGIN}" /etc/ssh/sshd_config.d/99-hardening.conf; then
                check_pass "Forge Match block permits root as configured: ${FORGE_ROOT_PERMIT_LOGIN}"
            else
                check_warn "Could not confirm Forge Match block PermitRootLogin setting"
            fi
        else
            if grep -q "^Match Address" /etc/ssh/sshd_config.d/99-hardening.conf; then
                check_warn "SSH Match Address block exists while Forge integration/root match is disabled"
            else
                check_pass "No Forge SSH Match Address block required"
            fi
        fi
    else
        check_warn "Hardening config file missing"
    fi
}
# =============================================================================
# SECTION 4: FIREWALL (UFW)
# =============================================================================

check_firewall() {
    section_header "SECTION 4: FIREWALL (UFW)"

    check_info "UFW provides defense-in-depth alongside Azure NSG"

    if ! command -v ufw &>/dev/null; then
        check_fail "UFW not installed"
        return
    fi

    check_pass "UFW installed"

    local ufw_status
    ufw_status=$(ufw status | head -1)

    if [[ "$ufw_status" == *"active"* ]]; then
        check_pass "UFW is active"
    else
        check_fail "UFW is not active"
    fi

    log ""
    check_info "Current UFW rules:"
    ufw status numbered | while read -r line; do
        check_info "  $line"
    done || true

    ufw status | grep -q "22/tcp" && check_pass "SSH (22) allowed" || check_fail "SSH (22) not in rules"
    ufw status | grep -q "80/tcp" && check_pass "HTTP (80) allowed" || check_warn "HTTP (80) not in rules"
    ufw status | grep -q "443/tcp" && check_pass "HTTPS (443) allowed" || check_warn "HTTPS (443) not in rules"
}

# =============================================================================
# SECTION 5: FAIL2BAN
# =============================================================================

check_fail2ban() {
    section_header "SECTION 5: FAIL2BAN"

    if ! command -v fail2ban-client &>/dev/null; then
        check_fail "Fail2ban not installed"
        return
    fi

    check_pass "Fail2ban installed"

    if systemctl is-active --quiet fail2ban; then
        check_pass "Fail2ban service running"
    else
        check_fail "Fail2ban service not running"
        return
    fi

    log ""
    check_info "Active jails:"
    fail2ban-client status 2>/dev/null | grep "Jail list" | while read -r line; do
        check_info "  $line"
    done || true

    if fail2ban-client status sshd &>/dev/null; then
        local banned
        local total
        local banned_ips

        banned=$(fail2ban-client status sshd | grep "Currently banned" | awk '{print $NF}')
        total=$(fail2ban-client status sshd | grep "Total banned" | awk '{print $NF}')
        banned_ips=$(fail2ban-client status sshd | grep "Banned IP list" | cut -d: -f2- | xargs || true)

        check_info "SSH jail: $banned currently banned, $total total bans"

        if [[ -n "$banned_ips" ]]; then
            check_warn "Currently banned SSH IPs: $banned_ips"
        else
            check_pass "No IPs currently banned in SSH jail"
        fi

        # Verify fail2ban maxretry for sshd
        local configured_maxretry
        configured_maxretry=$(fail2ban-client get sshd maxretry 2>/dev/null || true)

        if [[ -n "$configured_maxretry" ]]; then
            if [[ "$configured_maxretry" == "$FAIL2BAN_MAXRETRY" ]]; then
                check_pass "SSH jail maxretry matches expected value: $configured_maxretry"
            else
                check_warn "SSH jail maxretry is $configured_maxretry; expected $FAIL2BAN_MAXRETRY"
            fi
        else
            check_warn "Could not read fail2ban sshd maxretry"
        fi

        # Verify fail2ban ignoreip contains configured trusted IPs
        local configured_ignoreip
        configured_ignoreip=$(fail2ban-client get sshd ignoreip 2>/dev/null || true)

        if [[ -n "$configured_ignoreip" ]]; then
            check_info "SSH jail ignoreip: $configured_ignoreip"

            for ip in $FAIL2BAN_IGNOREIP; do
                normalized_ip="$(normalize_fail2ban_ignoreip "$ip")"
                if contains_space_list_item "$normalized_ip" "$configured_ignoreip"; then
                    check_pass "Fail2ban ignoreip includes $ip"
                else
                    check_fail "Fail2ban ignoreip missing expected IP/range: $ip"
                fi
            done
        else
            check_warn "Could not read fail2ban sshd ignoreip"
        fi
    else
        check_fail "Fail2ban sshd jail is not active"
    fi
}

# =============================================================================
# SECTION 6: USER CONFIGURATION
# =============================================================================

check_users() {
    section_header "SECTION 6: USER CONFIGURATION"

    if id "$SSH_ADMIN_USER" &>/dev/null; then
        check_pass "SSH admin user '$SSH_ADMIN_USER' exists"

        set +e
        groups "$SSH_ADMIN_USER" | grep -q "sudo" 2>/dev/null
        local has_sudo=$?
        set -e

        if [[ $has_sudo -eq 0 ]]; then
            check_pass "SSH admin user '$SSH_ADMIN_USER' has sudo access"
        else
            check_warn "SSH admin user '$SSH_ADMIN_USER' does not have sudo access"
        fi
    else
        check_fail "SSH admin user '$SSH_ADMIN_USER' does not exist"
    fi

    if [[ "$ENABLE_FORGE_INTEGRATION" == "true" ]]; then
        if id "forge" &>/dev/null; then
            check_pass "User 'forge' exists"
        else
            check_fail "Forge integration enabled but user 'forge' does not exist"
        fi
    else
        check_info "Forge integration disabled; not requiring user 'forge'"
    fi

    log ""
    check_info "Users with sudo group membership:"
    local sudo_users
    sudo_users=$(getent group sudo | cut -d: -f4)

    if [[ -n "$sudo_users" ]]; then
        IFS=',' read -ra USERS <<< "$sudo_users"
        for user in "${USERS[@]}"; do
            check_info "  $user"
        done
    else
        check_info "  (none)"
    fi

    log ""
    check_info "Users with NOPASSWD sudo:"
    local expected_count=0
    local unexpected_found=false
    local nopasswd_found=false

    while IFS= read -r line; do
        if [[ -n "$line" && ! "$line" =~ ^# ]]; then
            nopasswd_found=true

            if sudo_nopasswd_line_is_expected "$line"; then
                ((expected_count++)) || true
                check_info "  Expected: $line"
            else
                check_warn "  Unexpected: $line"
                unexpected_found=true
            fi
        fi
    done < <(grep -r "NOPASSWD" /etc/sudoers /etc/sudoers.d/ 2>/dev/null | grep -v "^#" || true)

    if [[ "$nopasswd_found" == "false" ]]; then
        check_pass "  No NOPASSWD sudo entries found"
    elif [[ "$unexpected_found" == "false" ]]; then
        check_pass "  NOPASSWD sudo entries are expected for this server configuration ($expected_count found)"
    fi

    log ""
    check_info "Checking for users with empty passwords..."
    local empty_pass
    empty_pass=$(awk -F: '($2 == "" ) {print $1}' /etc/shadow 2>/dev/null)

    if [[ -z "$empty_pass" ]]; then
        check_pass "No users with empty passwords"
    else
        check_fail "Users with empty passwords: $empty_pass"
    fi

    log ""
    check_info "Checking for UID 0 accounts..."
    local uid0_users
    uid0_users=$(awk -F: '($3 == 0) {print $1}' /etc/passwd)

    if [[ "$uid0_users" == "root" ]]; then
        check_pass "Only 'root' has UID 0"
    else
        check_fail "Multiple UID 0 accounts: $uid0_users"
    fi

    log ""
    check_info "Users with login shells:"
    while IFS=: read -r username _ uid _ _ _ shell; do
        if [[ "$shell" == */bash || "$shell" == */sh || "$shell" == */zsh ]]; then
            if [[ $uid -ge 1000 ]] || [[ "$username" == "root" ]]; then
                check_info "  $username: $shell"
            fi
        fi
    done < /etc/passwd

    log ""
    check_info "SSH authorized_keys audit:"
    for user_home in /root /home/*; do
        local username
        username=$(basename "$user_home")
        [[ "$user_home" == "/root" ]] && username="root"

        local auth_keys="$user_home/.ssh/authorized_keys"
        if [[ -f "$auth_keys" ]]; then
            local key_count
            key_count=$(grep -c "^ssh-" "$auth_keys" 2>/dev/null || echo "0")
            check_info "  $username: $key_count key(s)"
        fi
    done

    log ""
    check_info "Last login per managed user:"
    local managed_users=("root" "$SSH_ADMIN_USER")
    if [[ "$ENABLE_FORGE_INTEGRATION" == "true" ]]; then
        managed_users+=("forge")
    fi

    for user in "${managed_users[@]}"; do
        if id "$user" &>/dev/null; then
            local last_login
            last_login=$(lastlog -u "$user" 2>/dev/null | tail -1)

            set +e
            echo "$last_login" | grep -q "Never logged in" 2>/dev/null
            local never_logged_in=$?
            set -e

            if [[ $never_logged_in -eq 0 ]]; then
                check_info "  $user: Never logged in"
            else
                local login_info
                login_info=$(last -1 "$user" 2>/dev/null | head -1)

                if [[ -n "$login_info" && ! "$login_info" =~ ^$ && ! "$login_info" =~ "wtmp begins" ]]; then
                    check_info "  $user: $login_info"
                else
                    check_info "  $user: No recent logins"
                fi
            fi
        fi
    done

    log ""
    check_info "Recent logins:"
    last -10 2>/dev/null | head -10 | while read -r line; do
        [[ -n "$line" && ! "$line" =~ "wtmp begins" ]] && check_info "  $line"
    done || true
}
# =============================================================================
# SECTION 7: KERNEL HARDENING
# =============================================================================

check_kernel() {
    section_header "SECTION 7: KERNEL HARDENING"

    check_sysctl() {
        local param="$1"
        local expected="$2"
        local desc="$3"

        local current
        current=$(sysctl -n "$param" 2>/dev/null)

        if [[ "$current" == "$expected" ]]; then
            check_pass "$desc ($param=$current)"
        else
            check_fail "$desc: Expected $expected, got ${current:-not set}"
        fi
    }

    check_info "Verifying kernel parameters..."

    check_sysctl "net.ipv4.ip_forward" "0" "IP forwarding disabled"
    check_sysctl "net.ipv4.tcp_syncookies" "1" "SYN cookies enabled"
    check_sysctl "kernel.randomize_va_space" "2" "ASLR enabled"
    check_sysctl "net.ipv4.conf.all.accept_redirects" "0" "ICMP redirects disabled"
    check_sysctl "net.ipv4.conf.all.send_redirects" "0" "ICMP send redirects disabled"
    check_sysctl "fs.suid_dumpable" "0" "SUID core dumps disabled"
    check_sysctl "kernel.dmesg_restrict" "1" "dmesg restricted"

    if [[ -f "/etc/sysctl.d/99-hardening.conf" ]]; then
        check_pass "Hardening sysctl config file exists"
    else
        check_warn "Hardening sysctl config file missing"
    fi
}

# =============================================================================
# SECTION 8: AUDIT LOGGING
# =============================================================================

check_auditd() {
    section_header "SECTION 8: AUDIT LOGGING (auditd)"

    if ! command -v auditctl &>/dev/null; then
        check_warn "Auditd not installed"
        return
    fi

    check_pass "Auditd installed"

    if systemctl is-active --quiet auditd; then
        check_pass "Auditd service running"

        local rule_count
        rule_count=$(auditctl -l 2>/dev/null | wc -l)
        check_info "Active audit rules: $rule_count"

        if [[ -f "/etc/audit/auditd.conf" ]]; then
            local num_logs
            local max_log_file

            num_logs=$(grep "^num_logs" /etc/audit/auditd.conf | awk '{print $3}')
            max_log_file=$(grep "^max_log_file " /etc/audit/auditd.conf | awk '{print $3}')

            if [[ -n "$num_logs" && -n "$max_log_file" ]]; then
                check_info "Retention: $num_logs logs x ${max_log_file}MB = ~$(( num_logs * max_log_file ))MB max"
            else
                check_warn "Could not determine auditd retention settings"
            fi
        fi
    else
        check_fail "Auditd service not running"
    fi
}

# =============================================================================
# SECTION 9: SERVICE VERIFICATION
# =============================================================================

check_php_fpm_services() {
    local found=false
    local active=false
    local service

    while IFS= read -r service; do
        [[ -z "$service" ]] && continue
        service="${service%.service}"
        found=true

        if systemctl is-active --quiet "$service"; then
            check_pass "PHP-FPM ($service): Running"
            active=true
        else
            check_warn "PHP-FPM ($service): Installed but not running"
        fi
    done < <(systemctl list-unit-files 'php*-fpm.service' --no-legend 2>/dev/null | awk '{print $1}')

    if [[ "$found" == "false" ]]; then
        check_info "PHP-FPM: Not installed"
    elif [[ "$active" == "false" ]]; then
        check_warn "PHP-FPM installed but no php*-fpm service is active"
    fi
}

check_services() {
    section_header "SECTION 9: SERVICE VERIFICATION"

    local -A services=(
        ["nginx"]="Web server"
        ["mysql"]="MySQL Database"
        ["redis-server"]="Redis Cache"
        ["supervisor"]="Process Supervisor"
    )

    for service in "${!services[@]}"; do
        local desc="${services[$service]}"

        set +e
        systemctl cat "$service" &>/dev/null
        local service_exists=$?
        set -e

        if [[ $service_exists -eq 0 ]]; then
            if systemctl is-active --quiet "$service"; then
                check_pass "$desc ($service): Running"
            else
                check_warn "$desc ($service): Installed but not running"
            fi
        else
            check_info "$desc ($service): Not installed"
        fi
    done

    check_php_fpm_services
}

# =============================================================================
# SECTION 10: SUMMARY
# =============================================================================

print_summary() {
    section_header "SUMMARY"

    local total=$((PASS_COUNT + FAIL_COUNT))
    local score=0

    if [[ $total -gt 0 ]]; then
        score=$(( (PASS_COUNT * 100) / total ))
    fi

    log "| Metric | Count |"
    log "|--------|-------|"
    log "| ${GREEN}✅ Passed${NC} | $PASS_COUNT |"
    log "| ${RED}❌ Failed${NC} | $FAIL_COUNT |"
    log "| ${YELLOW}⚠️ Warnings${NC} | $WARN_COUNT |"
    log ""
    log "**Compliance Score:** ${BOLD}$score%${NC} (based on $PASS_COUNT passed / $total checks)"
    log ""

    if [[ $score -ge 90 ]]; then
        log "**Status:** ${GREEN}✅ COMPLIANT${NC}"
    elif [[ $score -ge 70 ]]; then
        log "**Status:** ${YELLOW}⚠️ PARTIALLY COMPLIANT${NC}"
    else
        log "**Status:** ${RED}❌ NON-COMPLIANT${NC}"
    fi

    log ""
    log "---"
    log ""
    log "*Full report saved to: $REPORT_FILE*"
    log ""
}

# =============================================================================
# REMOTE UPLOAD
# =============================================================================

upload_to_azure() {
    if [[ -z "${TFS_STORAGE_ACCOUNT:-}" ]]; then
        check_info "No TFS_STORAGE_ACCOUNT configured - skipping upload"
        return 0
    fi

    section_header "REMOTE UPLOAD"

    if ! command -v az &>/dev/null; then
        check_warn "Azure CLI not installed - skipping remote upload"
        check_info "Install with: curl -sL https://aka.ms/InstallAzureCLIDeb | sudo bash"
        return 1
    fi

    check_info "Authenticating with Managed Identity..."
    if ! az login --identity --allow-no-subscriptions &>/dev/null; then
        check_warn "Managed Identity authentication failed"
        check_info "Ensure VM has Managed Identity enabled and Storage Blob Data Contributor role"
        return 1
    fi

    local blob_name="${TFS_SERVER_NAME}/compliance-${HOSTNAME_SHORT}-${TIMESTAMP}.md"

    check_info "Uploading to $TFS_COMPLIANCE_CONTAINER..."

    if az storage blob upload \
        --account-name "$TFS_STORAGE_ACCOUNT" \
        --container-name "$TFS_COMPLIANCE_CONTAINER" \
        --file "$REPORT_FILE" \
        --name "$blob_name" \
        --auth-mode login \
        --overwrite &>/dev/null; then
        check_pass "Report uploaded: $blob_name"
    else
        check_fail "Failed to upload report"
        return 1
    fi

    check_info "Upload complete: https://${TFS_STORAGE_ACCOUNT}.blob.core.windows.net/${TFS_COMPLIANCE_CONTAINER}/${TFS_SERVER_NAME}/"
}

# =============================================================================
# CLEANUP OLD LOCAL REPORTS
# =============================================================================

cleanup_old_reports() {
    section_header "LOCAL CLEANUP"

    local days_to_keep=30
    local deleted_count=0

    check_info "Removing local reports older than $days_to_keep days..."

    while IFS= read -r -d '' file; do
        rm -f "$file"
        ((deleted_count++)) || true
    done < <(find "$REPORT_DIR" -type f -name "*.md" -mtime +$days_to_keep -print0 2>/dev/null)

    if [[ $deleted_count -gt 0 ]]; then
        check_pass "Deleted $deleted_count old report(s)"
    else
        check_info "No old reports to delete"
    fi
}

# =============================================================================
# MAIN
# =============================================================================

main() {
    if [[ $EUID -ne 0 ]]; then
        echo -e "${RED}This script must be run as root (sudo)${NC}"
        exit 1
    fi

    setup_reporting
    load_config

    log "# TFS Server Hardening - Compliance Report"
    log ""
    log "**Version:** 1.2.1"
    log "**Started:** $(date -u +"%Y-%m-%d %H:%M:%S UTC")"
    log "**Server:** ${TFS_SERVER_NAME}"
    log ""
    log "---"
    log ""

    check_system_info
    check_encryption
    check_ssh
    check_firewall
    check_fail2ban
    check_users
    check_kernel
    check_auditd
    check_services

    print_summary
    upload_to_azure
    cleanup_old_reports
}

main "$@"