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
# Version: 1.0
# Last Updated: December 2025
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

# Azure IMDS API version (latest as of Dec 2025)
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
    ((PASS_COUNT++))
    log "${GREEN}✅ PASS:${NC} $1"
}

check_fail() {
    ((FAIL_COUNT++))
    log "${RED}❌ FAIL:${NC} $1"
}

check_warn() {
    ((WARN_COUNT++))
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

# =============================================================================
# LOAD CONFIGURATION
# =============================================================================

load_config() {
    if [[ -f "$CONFIG_FILE" ]]; then
        source "$CONFIG_FILE"
    fi

    # Set defaults from config.env (new format) or legacy format
    TFS_STORAGE_ACCOUNT="${TFS_STORAGE_ACCOUNT:-${AZURE_STORAGE_ACCOUNT:-}}"
    TFS_HARDENING_CONTAINER="${TFS_HARDENING_CONTAINER:-tfs-hardening-reports}"
    TFS_COMPLIANCE_CONTAINER="${TFS_COMPLIANCE_CONTAINER:-tfs-compliance-reports}"
    TFS_SERVER_NAME="${TFS_SERVER_NAME:-$(hostname -s)}"
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
        local vm_size=$(echo "$imds_response" | grep -o '"vmSize":"[^"]*"' | cut -d'"' -f4)
        local location=$(echo "$imds_response" | grep -o '"location":"[^"]*"' | cut -d'"' -f4)
        local vm_name=$(echo "$imds_response" | grep -o '"name":"[^"]*"' | head -1 | cut -d'"' -f4)
        local resource_group=$(echo "$imds_response" | grep -o '"resourceGroupName":"[^"]*"' | cut -d'"' -f4)
        
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
    
    # Check if on Azure by querying IMDS
    local imds_response
    imds_response=$(curl -s -H "Metadata:true" --connect-timeout 2 "$AZURE_IMDS_URL" 2>/dev/null)
    
    if [[ -n "$imds_response" && "$imds_response" != *"error"* ]]; then
        check_pass "Running on Azure"
        
        # Parse security profile from IMDS
        local encryption_at_host=$(echo "$imds_response" | grep -o '"encryptionAtHost":"[^"]*"' | cut -d'"' -f4)
        local secure_boot=$(echo "$imds_response" | grep -o '"secureBootEnabled":"[^"]*"' | cut -d'"' -f4)
        local vtpm=$(echo "$imds_response" | grep -o '"virtualTpmEnabled":"[^"]*"' | cut -d'"' -f4)
        local security_type=$(echo "$imds_response" | grep -o '"securityType":"[^"]*"' | cut -d'"' -f4)
        
        # Encryption at Host
        if [[ "$encryption_at_host" == "true" ]]; then
            check_pass "Encryption at Host: Enabled"
        else
            check_warn "Encryption at Host: Not enabled (data in transit to storage is unencrypted)"
        fi
        
        # Server-Side Encryption (always on for Azure managed disks)
        check_pass "Server-Side Encryption (SSE): Enabled by default on all managed disks"
        
        # Check for Azure Disk Encryption (ADE) - additional OS-level encryption
        set +e  # Temporarily allow grep to fail without exiting
        lsblk | grep -q "crypt" 2>/dev/null
        local crypt_found=$?
        set -e
        if [[ $crypt_found -eq 0 ]]; then
            check_pass "Azure Disk Encryption (ADE): Enabled (dm-crypt layer active)"
        else
            check_info "Azure Disk Encryption (ADE): Not enabled (optional additional layer)"
        fi
        
        # Trusted Launch / Security Profile
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
        check_info "Not running on Azure (or IMDS unavailable)"
        set +e  # Temporarily allow grep to fail without exiting
        lsblk | grep -q "crypt" 2>/dev/null
        local crypt_found=$?
        set -e
        if [[ $crypt_found -eq 0 ]]; then
            check_pass "Disk encryption (LUKS/dm-crypt) detected"
        else
            check_warn "No disk encryption detected - verify at cloud provider level"
        fi
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
        
        local current=$(sshd -T 2>/dev/null | grep -i "^${setting} " | awk '{print $2}')
        
        if [[ "${current,,}" == "${expected,,}" ]]; then
            check_pass "$desc: $current"
            return 0
        else
            check_fail "$desc: Expected '$expected', found '${current:-not set}'"
            return 1
        fi
    }
    
    check_info "Verifying SSH configuration..."

    # Check if SSH service is running
    if systemctl is-active --quiet ssh; then
        check_pass "SSH service running"
    else
        check_fail "SSH service not running"
    fi
    
    # Check settings
    check_ssh_setting "permitrootlogin" "no" "Root login disabled"
    check_ssh_setting "passwordauthentication" "no" "Password auth disabled"
    check_ssh_setting "pubkeyauthentication" "yes" "Public key auth enabled"
    check_ssh_setting "permitemptypasswords" "no" "Empty passwords disabled"
    check_ssh_setting "x11forwarding" "no" "X11 forwarding disabled"
    check_ssh_setting "maxauthtries" "3" "Max auth tries"
    
    # Check hardening config file exists
    if [[ -f "/etc/ssh/sshd_config.d/99-hardening.conf" ]]; then
        check_pass "Hardening config file exists"
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
    
    local ufw_status=$(ufw status | head -1)
    
    if [[ "$ufw_status" == *"active"* ]]; then
        check_pass "UFW is active"
    else
        check_fail "UFW is not active"
    fi
    
    # Verify rules
    log ""
    check_info "Current UFW rules:"
    ufw status numbered | while read -r line; do
        check_info "  $line"
    done
    
    # Check for expected rules
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
        
        # List active jails
        log ""
        check_info "Active jails:"
        fail2ban-client status 2>/dev/null | grep "Jail list" | while read -r line; do
            check_info "  $line"
        done
        
        # SSH jail status
        if fail2ban-client status sshd &>/dev/null; then
            local banned=$(fail2ban-client status sshd | grep "Currently banned" | awk '{print $NF}')
            local total=$(fail2ban-client status sshd | grep "Total banned" | awk '{print $NF}')
            check_info "SSH jail: $banned currently banned, $total total bans"
        fi
    else
        check_fail "Fail2ban service not running"
    fi
}

# =============================================================================
# SECTION 6: USER CONFIGURATION
# =============================================================================

check_users() {
    section_header "SECTION 6: USER CONFIGURATION"
    
    # Check for required users
    if id "svcops" &>/dev/null; then
        check_pass "User 'svcops' exists"

        set +e  # Temporarily allow grep to fail without exiting
        groups svcops | grep -q "sudo" 2>/dev/null
        local has_sudo=$?
        set -e
        if [[ $has_sudo -eq 0 ]]; then
            check_pass "User 'svcops' has sudo access"
        else
            check_warn "User 'svcops' does not have sudo access"
        fi
    else
        check_fail "User 'svcops' does not exist"
    fi
    
    if id "forge" &>/dev/null; then
        check_pass "User 'forge' exists (created by Forge)"
    else
        check_warn "User 'forge' does not exist (Forge may not have provisioned yet)"
    fi
    
    # Users with sudo group membership
    log ""
    check_info "Users with sudo group membership:"
    local sudo_users=$(getent group sudo | cut -d: -f4)
    if [[ -n "$sudo_users" ]]; then
        IFS=',' read -ra USERS <<< "$sudo_users"
        for user in "${USERS[@]}"; do
            check_info "  $user"
        done
    else
        check_info "  (none)"
    fi
    
    # Users with NOPASSWD sudo
    log ""
    check_info "Users with NOPASSWD sudo:"
    local nopasswd_found=false
    while IFS= read -r line; do
        if [[ -n "$line" && ! "$line" =~ ^# ]]; then
            check_warn "  $line"
            nopasswd_found=true
        fi
    done < <(grep -r "NOPASSWD" /etc/sudoers /etc/sudoers.d/ 2>/dev/null | grep -v "^#")
    if [[ "$nopasswd_found" == "false" ]]; then
        check_pass "  No NOPASSWD sudo entries found"
    fi
    
    # Check for empty passwords
    log ""
    check_info "Checking for users with empty passwords..."
    local empty_pass=$(awk -F: '($2 == "" ) {print $1}' /etc/shadow 2>/dev/null)
    if [[ -z "$empty_pass" ]]; then
        check_pass "No users with empty passwords"
    else
        check_fail "Users with empty passwords: $empty_pass"
    fi
    
    # Check for unauthorized root accounts (UID 0)
    log ""
    check_info "Checking for UID 0 accounts..."
    local uid0_users=$(awk -F: '($3 == 0) {print $1}' /etc/passwd)
    if [[ "$uid0_users" == "root" ]]; then
        check_pass "Only 'root' has UID 0"
    else
        check_fail "Multiple UID 0 accounts: $uid0_users"
    fi
    
    # Users with login shells
    log ""
    check_info "Users with login shells (can log in):"
    while IFS=: read -r username _ uid _ _ _ shell; do
        if [[ "$shell" == */bash || "$shell" == */sh || "$shell" == */zsh ]]; then
            if [[ $uid -ge 1000 ]] || [[ "$username" == "root" ]]; then
                check_info "  $username: $shell"
            fi
        fi
    done < /etc/passwd
    
    # SSH authorized_keys audit
    log ""
    check_info "SSH authorized_keys audit:"
    for user_home in /root /home/*; do
        local username=$(basename "$user_home")
        [[ "$user_home" == "/root" ]] && username="root"
        
        local auth_keys="$user_home/.ssh/authorized_keys"
        if [[ -f "$auth_keys" ]]; then
            local key_count=$(grep -c "^ssh-" "$auth_keys" 2>/dev/null || echo "0")
            check_info "  $username: $key_count key(s)"
        fi
    done
    
    # Last login per user
    log ""
    check_info "Last login per user:"
    for user in root svcops forge; do
        if id "$user" &>/dev/null; then
            local last_login=$(lastlog -u "$user" 2>/dev/null | tail -1)
            set +e  # Temporarily allow grep to fail without exiting
            echo "$last_login" | grep -q "Never logged in" 2>/dev/null
            local never_logged_in=$?
            set -e
            if [[ $never_logged_in -eq 0 ]]; then
                check_info "  $user: Never logged in"
            else
                local login_info=$(last -1 "$user" 2>/dev/null | head -1)
                if [[ -n "$login_info" && ! "$login_info" =~ ^$ && ! "$login_info" =~ "wtmp begins" ]]; then
                    check_info "  $user: $login_info"
                else
                    check_info "  $user: No recent logins"
                fi
            fi
        fi
    done
    
    # Recent logins (last 10)
    log ""
    check_info "Recent logins (last 10):"
    last -10 | head -10 | while read -r line; do
        [[ -n "$line" && ! "$line" =~ "wtmp begins" ]] && check_info "  $line"
    done
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
        local current=$(sysctl -n "$param" 2>/dev/null)
        
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
    
    # Check hardening config file exists
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
        
        local rule_count=$(auditctl -l 2>/dev/null | wc -l)
        check_info "Active audit rules: $rule_count"
        
        # Check retention config
        if [[ -f "/etc/audit/auditd.conf" ]]; then
            local num_logs=$(grep "^num_logs" /etc/audit/auditd.conf | awk '{print $3}')
            local max_log_file=$(grep "^max_log_file " /etc/audit/auditd.conf | awk '{print $3}')
            check_info "Retention: $num_logs logs x ${max_log_file}MB = ~$(( num_logs * max_log_file ))MB max"
        fi
    else
        check_fail "Auditd service not running"
    fi
}

# =============================================================================
# SECTION 9: SERVICE VERIFICATION
# =============================================================================

check_services() {
    section_header "SECTION 9: SERVICE VERIFICATION"
    
    # Services to check (Forge installs these)
    local -A services=(
        ["nginx"]="Web server"
        ["php8.3-fpm"]="PHP-FPM"
        ["mysql"]="MySQL Database"
        ["redis-server"]="Redis Cache"
        ["supervisor"]="Process Supervisor"
    )
    
    for service in "${!services[@]}"; do
        local desc="${services[$service]}"

        set +e  # Temporarily allow grep to fail without exiting
        systemctl list-unit-files | grep -q "^${service}" 2>/dev/null
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
}

# =============================================================================
# SECTION 10: SUMMARY
# =============================================================================

print_summary() {
    section_header "SUMMARY"

    local total=$((PASS_COUNT + FAIL_COUNT + WARN_COUNT))
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
    log "**Compliance Score:** ${BOLD}$score%${NC}"
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
# REMOTE UPLOAD (Azure Blob via Managed Identity)
# =============================================================================

upload_to_azure() {
    # Check if we have storage configuration
    if [[ -z "${TFS_STORAGE_ACCOUNT:-}" ]]; then
        check_info "No TFS_STORAGE_ACCOUNT configured - skipping upload"
        return 0
    fi

    section_header "REMOTE UPLOAD"

    # Check if Azure CLI is available
    if ! command -v az &>/dev/null; then
        check_warn "Azure CLI not installed - skipping remote upload"
        check_info "Install with: curl -sL https://aka.ms/InstallAzureCLIDeb | sudo bash"
        return 1
    fi

    # Login with Managed Identity (silent)
    check_info "Authenticating with Managed Identity..."
    if ! az login --identity --allow-no-subscriptions &>/dev/null; then
        check_warn "Managed Identity authentication failed"
        check_info "Ensure VM has Managed Identity enabled and Storage Blob Data Contributor role"
        return 1
    fi

    # Create blob name matching local file naming
    local blob_name="${TFS_SERVER_NAME}/compliance-${HOSTNAME_SHORT}-${TIMESTAMP}.md"

    check_info "Uploading to $TFS_COMPLIANCE_CONTAINER..."

    # Upload compliance report
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
# CLEANUP OLD LOCAL REPORTS (30 days)
# =============================================================================

cleanup_old_reports() {
    section_header "LOCAL CLEANUP"

    local days_to_keep=30
    local deleted_count=0

    check_info "Removing local reports older than $days_to_keep days..."

    # Find and delete old report files
    while IFS= read -r -d '' file; do
        rm -f "$file"
        ((deleted_count++))
    done < <(find "$REPORT_DIR" -type f -name "*.txt" -mtime +$days_to_keep -print0 2>/dev/null)

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
    # Check if running as root
    if [[ $EUID -ne 0 ]]; then
        echo -e "${RED}This script must be run as root (sudo)${NC}"
        exit 1
    fi

    # Setup
    setup_reporting
    load_config

    # Markdown Header
    log "# TFS Server Hardening - Compliance Report"
    log ""
    log "**Version:** 1.0"
    log "**Started:** $(date -u +"%Y-%m-%d %H:%M:%S UTC")"
    log "**Server:** ${TFS_SERVER_NAME}"
    log ""
    log "---"
    log ""

    # Run all checks
    check_system_info
    check_encryption
    check_ssh
    check_firewall
    check_fail2ban
    check_users
    check_kernel
    check_auditd
    check_services

    # Summary
    print_summary

    # Upload to compliance container
    upload_to_azure

    # Cleanup old local reports
    cleanup_old_reports
}

main "$@"
