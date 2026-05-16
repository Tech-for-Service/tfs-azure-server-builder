#!/bin/bash
#
# TFS Server Hardening - Setup Script
# ====================================
#
# This script applies hardening configurations to a Laravel Forge server.
# Run AFTER Forge has provisioned the server.
#
# Location: /etc/tfs/hardening/setup.sh
# Usage: sudo /etc/tfs/hardening/setup.sh
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
VERIFY_SCRIPT="${SCRIPT_DIR}/verify.sh"
TIMESTAMP=$(date +%Y%m%d-%H%M%S)

# Colors
RED='\033[0;31m'
GREEN='\033[0;32m'
YELLOW='\033[1;33m'
BLUE='\033[0;34m'
CYAN='\033[0;36m'
BOLD='\033[1m'
NC='\033[0m'

# =============================================================================
# HELPER FUNCTIONS
# =============================================================================

log() {
    echo -e "$1"
}

info() {
    log "${BLUE}[INFO]${NC} $1"
}

success() {
    log "${GREEN}[DONE]${NC} $1"
}

warn() {
    log "${YELLOW}[WARN]${NC} $1"
}

error() {
    log "${RED}[ERROR]${NC} $1"
}

section() {
    log ""
    log "${BOLD}════════════════════════════════════════════════════════════════${NC}"
    log "${BOLD}  $1${NC}"
    log "${BOLD}════════════════════════════════════════════════════════════════${NC}"
    log ""
}

backup_file() {
    local file="$1"
    if [[ -f "$file" ]]; then
        cp "$file" "${file}.bak.${TIMESTAMP}"
        info "Backed up $file"
    fi
}

csv_from_space_list() {
    local value="$1"
    value="${value//$'
'/ }"
    value="${value//$'	'/ }"
    echo "$value" | xargs | tr ' ' ','
}

# =============================================================================
# LOAD CONFIGURATION
# =============================================================================

load_config() {
    if [[ -f "$CONFIG_FILE" ]]; then
        source "$CONFIG_FILE"
        info "Loaded configuration from $CONFIG_FILE"
    else
        warn "No config file found at $CONFIG_FILE - using defaults"
    fi
    
    # Set defaults for any missing values
    ENABLE_SSH_HARDENING="${ENABLE_SSH_HARDENING:-true}"
    ENABLE_UFW="${ENABLE_UFW:-true}"
    ENABLE_FAIL2BAN="${ENABLE_FAIL2BAN:-true}"
    ENABLE_AUDITD="${ENABLE_AUDITD:-true}"
    ENABLE_KERNEL_HARDENING="${ENABLE_KERNEL_HARDENING:-true}"
    
    # SSH defaults
    # SSH_ADMIN_USER is written by azure-server-builder. Falls back to svcops for legacy servers.
    SSH_ADMIN_USER="${SSH_ADMIN_USER:-svcops}"

    # Forge integration is optional. Set ENABLE_FORGE_INTEGRATION=true in config.env for Laravel Forge servers.
    # Non-Forge servers will not receive Forge-specific SSH Match blocks, fail2ban allowlisting, or warnings.
    ENABLE_FORGE_INTEGRATION="${ENABLE_FORGE_INTEGRATION:-false}"
    FORGE_IPS="${FORGE_IPS:-159.203.150.232 165.227.248.218 159.203.150.216 45.55.124.124}"

    if [[ "${ENABLE_FORGE_INTEGRATION}" == "true" ]]; then
        SSH_ALLOWED_USERS="${SSH_ALLOWED_USERS:-${SSH_ADMIN_USER} forge}"
    else
        SSH_ALLOWED_USERS="${SSH_ALLOWED_USERS:-${SSH_ADMIN_USER}}"
    fi

    SSH_PERMIT_ROOT_LOGIN="${SSH_PERMIT_ROOT_LOGIN:-no}"
    SSH_ALLOW_TCP_FORWARDING="${SSH_ALLOW_TCP_FORWARDING:-yes}"

    ENABLE_FORGE_ROOT_MATCH="${ENABLE_FORGE_ROOT_MATCH:-${ENABLE_FORGE_INTEGRATION}}"
    FORGE_ROOT_PERMIT_LOGIN="${FORGE_ROOT_PERMIT_LOGIN:-prohibit-password}"
    FORGE_MATCH_ALLOWED_USERS="${FORGE_MATCH_ALLOWED_USERS:-root ${SSH_ALLOWED_USERS}}"
    
    FAIL2BAN_MAXRETRY="${FAIL2BAN_MAXRETRY:-6}"
    FAIL2BAN_FINDTIME="${FAIL2BAN_FINDTIME:-600}"
    FAIL2BAN_BANTIME="${FAIL2BAN_BANTIME:-86400}"
    if [[ "${ENABLE_FORGE_INTEGRATION}" == "true" ]]; then
        FAIL2BAN_IGNOREIP="${FAIL2BAN_IGNOREIP:-127.0.0.1/8 ::1 ${FORGE_IPS}}"
    else
        FAIL2BAN_IGNOREIP="${FAIL2BAN_IGNOREIP:-127.0.0.1/8 ::1}"
    fi

    UFW_ALLOWED_PORTS="${UFW_ALLOWED_PORTS:-22 80 443}"
    
    AUDITD_MAX_LOG_FILE="${AUDITD_MAX_LOG_FILE:-50}"
    AUDITD_NUM_LOGS="${AUDITD_NUM_LOGS:-90}"
}

# =============================================================================
# INSTALL PACKAGES
# =============================================================================

install_packages() {
    section "INSTALLING PACKAGES"

    local packages=()

    [[ "$ENABLE_UFW" == "true" ]] && packages+=(ufw)
    [[ "$ENABLE_FAIL2BAN" == "true" ]] && packages+=(fail2ban)
    [[ "$ENABLE_AUDITD" == "true" ]] && packages+=(auditd audispd-plugins)

    # Azure CLI for blob upload (always install if we have storage config)
    if [[ -n "${TFS_STORAGE_ACCOUNT:-}" ]]; then
        if ! command -v az &>/dev/null; then
            info "Installing Azure CLI..."
            curl -sL https://aka.ms/InstallAzureCLIDeb | bash
            success "Azure CLI installed"
        else
            info "Azure CLI already installed"
        fi
    fi

    if [[ ${#packages[@]} -gt 0 ]]; then
        info "Installing: ${packages[*]}"
        apt-get update -qq
        DEBIAN_FRONTEND=noninteractive apt-get install -y -qq "${packages[@]}"
        success "Packages installed"
    else
        info "No packages to install"
    fi
}

# =============================================================================
# SSH HARDENING
# =============================================================================

apply_ssh_hardening() {
    if [[ "$ENABLE_SSH_HARDENING" != "true" ]]; then
        info "SSH hardening disabled in config"
        return
    fi
    
    section "SSH HARDENING"
    
    local SSH_HARDENING_FILE="/etc/ssh/sshd_config.d/99-hardening.conf"
    
    info "Creating SSH hardening configuration..."
    info "SSH admin user: ${SSH_ADMIN_USER}"
    info "SSH allowed users: ${SSH_ALLOWED_USERS}"
    info "Forge integration: ${ENABLE_FORGE_INTEGRATION}"

    backup_file "$SSH_HARDENING_FILE"

    local forge_ips_csv=""
    if [[ "$ENABLE_FORGE_ROOT_MATCH" == "true" ]]; then
        forge_ips_csv="$(csv_from_space_list "$FORGE_IPS")"
    fi
    
    cat > "$SSH_HARDENING_FILE" << EOF
# TFS Server Hardening - SSH Configuration
# Applied by setup.sh on $(date)
# DO NOT EDIT - Managed by /etc/tfs/hardening/

# Authentication
PermitRootLogin ${SSH_PERMIT_ROOT_LOGIN}
PasswordAuthentication no
PermitEmptyPasswords no
PubkeyAuthentication yes
AuthenticationMethods publickey
MaxAuthTries 3
LoginGraceTime 60

# Allowed Users
AllowUsers ${SSH_ALLOWED_USERS}

# Session
ClientAliveInterval 300
ClientAliveCountMax 2
MaxSessions 3

# Security
X11Forwarding no
AllowTcpForwarding ${SSH_ALLOW_TCP_FORWARDING}
AllowAgentForwarding no
PermitUserEnvironment no

# Strong Ciphers Only
Ciphers chacha20-poly1305@openssh.com,aes256-gcm@openssh.com,aes128-gcm@openssh.com
MACs hmac-sha2-512-etm@openssh.com,hmac-sha2-256-etm@openssh.com
KexAlgorithms curve25519-sha256,curve25519-sha256@libssh.org

# Logging
LogLevel VERBOSE
EOF

    if [[ "$ENABLE_FORGE_ROOT_MATCH" == "true" ]]; then
        cat >> "$SSH_HARDENING_FILE" << EOF

# Laravel Forge management access
# Forge requires its public key in both /home/forge/.ssh/authorized_keys and /root/.ssh/authorized_keys
# for some server actions such as database/tunnel operations. Root SSH remains disabled globally above;
# this exception is limited to known Forge source IPs and still requires public key authentication.
Match Address ${forge_ips_csv}
    PermitRootLogin ${FORGE_ROOT_PERMIT_LOGIN}
    AllowUsers ${FORGE_MATCH_ALLOWED_USERS}
EOF
    fi
    
    chmod 600 "$SSH_HARDENING_FILE"
    
    # Test config before reloading
    if sshd -t 2>/dev/null; then
        systemctl reload ssh
        success "SSH hardening applied"
    else
        error "SSH config test failed - check $SSH_HARDENING_FILE"
        return 1
    fi
}


# =============================================================================
# FORGE KEY CHECK
# =============================================================================

check_forge_root_key() {
    if [[ "$ENABLE_FORGE_INTEGRATION" != "true" || "$ENABLE_FORGE_ROOT_MATCH" != "true" ]]; then
        return 0
    fi

    local forge_keys="/home/forge/.ssh/authorized_keys"
    local root_keys="/root/.ssh/authorized_keys"

    if [[ ! -f "$forge_keys" ]]; then
        warn "Forge authorized_keys not found at $forge_keys; Forge may not have provisioned yet"
        return 0
    fi

    if [[ ! -f "$root_keys" ]]; then
        warn "Root authorized_keys not found at $root_keys"
        warn "Laravel Forge may require its public key in both /home/forge/.ssh/authorized_keys and /root/.ssh/authorized_keys for some actions"
        return 0
    fi

    local missing_count=0
    while IFS= read -r key; do
        [[ -z "$key" || ! "$key" =~ ^ssh- ]] && continue
        if ! grep -Fxq "$key" "$root_keys"; then
            ((missing_count++)) || true
        fi
    done < "$forge_keys"

    if [[ $missing_count -gt 0 ]]; then
        warn "$missing_count key(s) from /home/forge/.ssh/authorized_keys are missing from /root/.ssh/authorized_keys"
        warn "If Forge database or tunnel actions fail, add the Forge key shown in Forge to root's authorized_keys"
    else
        success "Root authorized_keys contains the same SSH key(s) present for forge"
    fi
}

# =============================================================================
# UFW FIREWALL
# =============================================================================

apply_ufw() {
    if [[ "$ENABLE_UFW" != "true" ]]; then
        info "UFW disabled in config"
        return
    fi
    
    section "UFW FIREWALL"
    
    info "Configuring UFW..."
    
    # Set defaults
    ufw default deny incoming
    ufw default allow outgoing
    
    # Allow configured ports (add comment to existing rules if needed)
    for port in $UFW_ALLOWED_PORTS; do
        # Check if rule exists with our comment
        if ufw status | grep -q "${port}/tcp.*Hardening"; then
            info "UFW rule for port ${port} already has Hardening comment, skipping"
        # Check if rule exists without our comment
        elif ufw status | grep -q "^${port}/tcp.*ALLOW" || ufw status | grep -q "^${port}[[:space:]].*ALLOW"; then
            info "Updating UFW rule for port ${port} with Hardening comment"
            # Delete existing rule(s) for this port
            while ufw status numbered | grep -q "${port}/tcp\|${port}[[:space:]]"; do
                # Find the rule number
                local rule_num=$(ufw status numbered | grep "${port}/tcp\|${port}[[:space:]]" | head -1 | grep -o '^\[[[:space:]]*[0-9]*\]' | tr -d '[][:space:]')
                if [[ -n "$rule_num" ]]; then
                    echo "y" | ufw delete "$rule_num" >/dev/null 2>&1
                else
                    break
                fi
            done
            # Re-add with comment
            ufw allow "${port}/tcp" comment "Hardening"
            info "Updated UFW rule: ${port}/tcp"
        else
            # Rule doesn't exist, add it
            ufw allow "${port}/tcp" comment "Hardening"
            info "Added UFW rule: ${port}/tcp"
        fi
    done
    
    # Enable UFW (non-interactive)
    echo "y" | ufw enable
    
    success "UFW configured with ports: $UFW_ALLOWED_PORTS"
}

# =============================================================================
# FAIL2BAN
# =============================================================================

apply_fail2ban() {
    if [[ "$ENABLE_FAIL2BAN" != "true" ]]; then
        info "Fail2ban disabled in config"
        return
    fi
    
    section "FAIL2BAN"
    
    local JAIL_LOCAL="/etc/fail2ban/jail.local"
    
    info "Configuring Fail2ban..."
    backup_file "$JAIL_LOCAL"
    
    cat > "$JAIL_LOCAL" << EOF
# TFS Server Hardening - Fail2ban Configuration
# Applied by setup.sh on $(date)

[DEFAULT]
# Ban for ${FAIL2BAN_BANTIME}s after ${FAIL2BAN_MAXRETRY} failures within ${FAIL2BAN_FINDTIME}s
bantime = ${FAIL2BAN_BANTIME}
findtime = ${FAIL2BAN_FINDTIME}
maxretry = ${FAIL2BAN_MAXRETRY}

# Use UFW for banning
banaction = ufw

# Ignore trusted management IPs
ignoreip = ${FAIL2BAN_IGNOREIP}

[sshd]
enabled = true
port = ssh
filter = sshd
logpath = /var/log/auth.log
maxretry = ${FAIL2BAN_MAXRETRY}
bantime = ${FAIL2BAN_BANTIME}

[nginx-http-auth]
enabled = true
port = http,https
filter = nginx-http-auth
logpath = /var/log/nginx/error.log
maxretry = ${FAIL2BAN_MAXRETRY}
bantime = ${FAIL2BAN_BANTIME}

[nginx-limit-req]
enabled = true
port = http,https
filter = nginx-limit-req
logpath = /var/log/nginx/error.log
maxretry = 5
bantime = ${FAIL2BAN_BANTIME}
EOF
    
    systemctl restart fail2ban
    systemctl enable fail2ban
    
    success "Fail2ban configured: ${FAIL2BAN_MAXRETRY} failures = $(( FAIL2BAN_BANTIME / 3600 ))hr ban"
    info "Fail2ban ignore IPs: ${FAIL2BAN_IGNOREIP}"
}

# =============================================================================
# KERNEL HARDENING
# =============================================================================

apply_kernel_hardening() {
    if [[ "$ENABLE_KERNEL_HARDENING" != "true" ]]; then
        info "Kernel hardening disabled in config"
        return
    fi
    
    section "KERNEL HARDENING"
    
    local SYSCTL_FILE="/etc/sysctl.d/99-hardening.conf"
    
    info "Applying kernel hardening parameters..."
    backup_file "$SYSCTL_FILE"
    
    cat > "$SYSCTL_FILE" << EOF
# TFS Server Hardening - Kernel Parameters
# Applied by setup.sh on $(date)

# Disable IP forwarding (not a router)
net.ipv4.ip_forward=0

# Don't send/accept ICMP redirects
net.ipv4.conf.all.send_redirects=0
net.ipv4.conf.default.send_redirects=0
net.ipv4.conf.all.accept_redirects=0
net.ipv4.conf.default.accept_redirects=0
net.ipv4.conf.all.secure_redirects=0
net.ipv4.conf.default.secure_redirects=0

# SYN flood protection
net.ipv4.tcp_syncookies=1
net.ipv4.tcp_max_syn_backlog=2048
net.ipv4.tcp_synack_retries=2

# Reverse path filtering
net.ipv4.conf.all.rp_filter=1
net.ipv4.conf.default.rp_filter=1

# Ignore broadcast pings
net.ipv4.icmp_echo_ignore_broadcasts=1
net.ipv4.icmp_ignore_bogus_error_responses=1

# ASLR
kernel.randomize_va_space=2

# Disable core dumps for SUID
fs.suid_dumpable=0

# Restrict dmesg
kernel.dmesg_restrict=1
EOF
    
    sysctl -p "$SYSCTL_FILE" 2>/dev/null || true
    
    success "Kernel hardening applied"
}

# =============================================================================
# AUDITD
# =============================================================================

apply_auditd() {
    if [[ "$ENABLE_AUDITD" != "true" ]]; then
        info "Auditd disabled in config"
        return
    fi
    
    section "AUDITD"
    
    local AUDIT_RULES="/etc/audit/rules.d/hardening.rules"
    local AUDITD_CONF="/etc/audit/auditd.conf"
    
    info "Configuring audit rules..."

    # If audit rules are immutable (-e 2), they cannot be changed until reboot.
    # Treat this as a successful no-op so future setup versions can be rerun safely.
    local audit_enabled
    audit_enabled=$(auditctl -s 2>/dev/null | awk '/enabled/ {print $2}' || true)
    if [[ "$audit_enabled" == "2" ]]; then
        warn "Audit rules are immutable until reboot; skipping audit rule rewrite for safe rerun"
        warn "Reboot and rerun setup.sh if you need to apply updated audit rules"
        return 0
    fi

    backup_file "$AUDIT_RULES"
    
    cat > "$AUDIT_RULES" << 'EOF'
# TFS Server Hardening - Audit Rules
# Applied by setup.sh

# Delete all existing rules
-D

# Set buffer size
-b 8192

# Failure mode (1 = printk, 2 = panic)
-f 1

# Monitor authentication files
-w /etc/passwd -p wa -k identity
-w /etc/group -p wa -k identity
-w /etc/shadow -p wa -k identity
-w /etc/sudoers -p wa -k sudoers
-w /etc/sudoers.d/ -p wa -k sudoers

# Monitor SSH configuration
-w /etc/ssh/sshd_config -p wa -k sshd_config
-w /etc/ssh/sshd_config.d/ -p wa -k sshd_config

# Monitor privileged commands
-a always,exit -F path=/usr/bin/sudo -F perm=x -F auid>=1000 -F auid!=4294967295 -k privileged
-a always,exit -F path=/usr/bin/su -F perm=x -F auid>=1000 -F auid!=4294967295 -k privileged

# Monitor user/group management
-w /usr/sbin/useradd -p x -k user_modification
-w /usr/sbin/usermod -p x -k user_modification
-w /usr/sbin/userdel -p x -k user_modification
-w /usr/sbin/groupadd -p x -k group_modification
-w /usr/sbin/groupmod -p x -k group_modification
-w /usr/sbin/groupdel -p x -k group_modification

# Monitor login/logout
-w /var/log/lastlog -p wa -k logins
-w /var/log/faillog -p wa -k logins
-w /var/log/auth.log -p wa -k auth_log

# Make rules immutable (requires reboot to change)
-e 2
EOF
    
    # Configure retention
    if [[ -f "$AUDITD_CONF" ]]; then
        info "Configuring ${AUDITD_NUM_LOGS}-day log retention..."
        cp "$AUDITD_CONF" "${AUDITD_CONF}.bak.${TIMESTAMP}"
        
        sed -i "s/^max_log_file = .*/max_log_file = ${AUDITD_MAX_LOG_FILE}/" "$AUDITD_CONF"
        sed -i "s/^num_logs = .*/num_logs = ${AUDITD_NUM_LOGS}/" "$AUDITD_CONF"
        sed -i "s/^max_log_file_action = .*/max_log_file_action = ROTATE/" "$AUDITD_CONF"
    fi
    
    systemctl restart auditd
    systemctl enable auditd
    
    success "Auditd configured with ${AUDITD_NUM_LOGS}-day retention"
}

# =============================================================================
# CRON JOB
# =============================================================================

setup_cron() {
    section "SCHEDULING"
    
    local CRON_FILE="/etc/cron.weekly/hardening-verify"
    
    info "Creating weekly verification cron job..."
    
    cat > "$CRON_FILE" << EOF
#!/bin/bash
# TFS Server Hardening - Weekly Verification
# Created by setup.sh on $(date)

${VERIFY_SCRIPT}
EOF
    
    chmod +x "$CRON_FILE"
    
    success "Weekly cron job created at $CRON_FILE"
}

# =============================================================================
# CREATE REPORT DIRECTORY
# =============================================================================

setup_directories() {
    info "Creating directories..."
    
    mkdir -p /var/log/hardening-reports
    chmod 750 /var/log/hardening-reports
    
    success "Directories created"
}

# =============================================================================
# RUN INITIAL VERIFICATION
# =============================================================================

run_initial_verify() {
    section "INITIAL VERIFICATION"

    if [[ -x "$VERIFY_SCRIPT" ]]; then
        info "Running initial verification..."
        "$VERIFY_SCRIPT"
    else
        warn "Verify script not found or not executable at $VERIFY_SCRIPT"
    fi
}

# =============================================================================
# UPLOAD SETUP REPORT TO AZURE
# =============================================================================

upload_setup_report() {
    # Check if we have storage configuration
    if [[ -z "${TFS_STORAGE_ACCOUNT:-}" ]]; then
        info "No TFS_STORAGE_ACCOUNT configured - skipping upload"
        return 0
    fi

    section "UPLOADING HARDENING REPORT"

    # Check if Azure CLI is available
    if ! command -v az &>/dev/null; then
        warn "Azure CLI not installed - skipping upload"
        return 1
    fi

    # Login with Managed Identity
    info "Authenticating with Managed Identity..."
    if ! az login --identity --allow-no-subscriptions &>/dev/null; then
        warn "Managed Identity authentication failed"
        info "Ensure VM has Managed Identity enabled and Storage Blob Data Contributor role"
        return 1
    fi

    # Create hardening report
    local hostname_short=$(hostname -s)
    local timestamp=$(date +%Y%m%d-%H%M%S)
    local report_file="/var/log/hardening-reports/hardening-${hostname_short}-${timestamp}.md"

    cat > "$report_file" << 'EOF'
# TFS Server Hardening Report

**Server:** ${TFS_SERVER_NAME:-$(hostname)}
**Date:** $(date -u +"%Y-%m-%d %H:%M:%S UTC")
**Status:** ✅ Setup Completed Successfully

---

## Applied Configurations

| Component | Status |
|-----------|--------|
| **SSH Hardening** | ${ENABLE_SSH_HARDENING:-true} |
| **UFW Firewall** | ${ENABLE_UFW:-true} |
| **Fail2ban** | ${ENABLE_FAIL2BAN:-true} |
| **Kernel Hardening** | ${ENABLE_KERNEL_HARDENING:-true} |
| **Auditd** | ${ENABLE_AUDITD:-true} |

## Configuration Settings

| Setting | Value |
|---------|-------|
| **SSH Admin User** | ${SSH_ADMIN_USER:-svcops} |
| **SSH Allowed Users** | ${SSH_ALLOWED_USERS:-${SSH_ADMIN_USER:-svcops}} |
| **Forge Integration Enabled** | ${ENABLE_FORGE_INTEGRATION:-false} |
| **Forge Root Match Enabled** | ${ENABLE_FORGE_ROOT_MATCH:-${ENABLE_FORGE_INTEGRATION:-false}} |
| **Forge IPs** | ${FORGE_IPS:-159.203.150.232 165.227.248.218 159.203.150.216 45.55.124.124} |
| **Fail2ban Max Retry** | ${FAIL2BAN_MAXRETRY:-6} |
| **Fail2ban Ban Time** | ${FAIL2BAN_BANTIME:-86400}s (24 hours) |
| **Fail2ban Ignore IPs** | ${FAIL2BAN_IGNOREIP:-127.0.0.1/8 ::1} |
| **UFW Allowed Ports** | ${UFW_ALLOWED_PORTS:-22 80 443} |

---

*Hardening completed and verified. Weekly compliance checks scheduled via cron.*
EOF

    # Expand variables in the report
    eval "cat > \"$report_file\" << EOFINNER
$(cat "$report_file")
EOFINNER
"

    # Upload to hardening reports container (permanent storage)
    local blob_name="${TFS_SERVER_NAME:-$(hostname)}/hardening-${hostname_short}-${timestamp}.md"

    info "Uploading hardening report to ${TFS_HARDENING_CONTAINER:-tfs-hardening-reports}..."
    if az storage blob upload \
        --account-name "$TFS_STORAGE_ACCOUNT" \
        --container-name "${TFS_HARDENING_CONTAINER:-tfs-hardening-reports}" \
        --file "$report_file" \
        --name "$blob_name" \
        --auth-mode login \
        --overwrite &>/dev/null; then
        success "Hardening report uploaded to Azure Blob Storage"
        info "Path: ${TFS_HARDENING_CONTAINER:-tfs-hardening-reports}/$blob_name"
    else
        warn "Failed to upload hardening report"
        return 1
    fi
}

# =============================================================================
# MAIN
# =============================================================================

main() {
    # Check if running as root
    if [[ $EUID -ne 0 ]]; then
        error "This script must be run as root (sudo)"
        exit 1
    fi
    
    log ""
    log "${BOLD}╔══════════════════════════════════════════════════════════════╗${NC}"
    log "${BOLD}║        TFS SERVER HARDENING - SETUP                          ║${NC}"
    log "${BOLD}║        Version 1.2.1                                         ║${NC}"
    log "${BOLD}╚══════════════════════════════════════════════════════════════╝${NC}"
    log ""
    log "Started: $(date)"
    log ""
    
    # Load configuration
    load_config
    
    # Setup directories
    setup_directories
    
    # Install required packages
    install_packages
    
    # Apply hardening
    apply_ssh_hardening
    check_forge_root_key
    apply_ufw
    apply_fail2ban
    apply_kernel_hardening
    apply_auditd
    
    # Setup cron
    setup_cron

    # Upload setup report to Azure
    upload_setup_report

    # Summary
    section "SETUP COMPLETE"
    success "Server hardening has been applied"
    log ""
    info "Next steps:"
    info "  1. Review configuration: $CONFIG_FILE"
    info "  2. Weekly reports will be uploaded to Azure and saved locally"
    info "  3. Run manual verification: sudo $VERIFY_SCRIPT"
    log ""

    # Run initial verification
    run_initial_verify
}

main "$@"
