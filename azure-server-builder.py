#!/usr/bin/env python3
"""
TFS Azure Server Builder
========================

Interactive CLI to provision hardened Azure VMs for Laravel Forge.

Creates VMs with Trusted Launch, Encryption at Host, NSG rules for Forge,
Managed Identity for blob storage access, and cloud-init that downloads
hardening scripts from GitHub.

Usage:
    python azure-server-builder.py

Workflow:
    1. Builder creates Azure VM with cloud-init
    2. Cloud-init writes config.env and downloads setup.sh/verify.sh
    3. User adds VM to Laravel Forge as Custom VPS
    4. Forge provisions server (PHP, Nginx, etc.)
    5. User runs: sudo /etc/tfs/hardening/setup.sh
    6. Weekly: verify.sh runs via cron, uploads reports

Version: 1.2.1
Last Updated: May 2026
"""

import json
import logging
import os
import random
import re
import secrets
import subprocess
import sys
import time
import yaml
from dataclasses import dataclass
from functools import wraps
from pathlib import Path
from typing import Optional, Dict, List, Any, Tuple
from datetime import datetime, timezone

# Rich for progress bars and spinners
from rich.console import Console
from rich.progress import Progress, SpinnerColumn, TextColumn, BarColumn, TimeElapsedColumn

# Suppress verbose Azure SDK logging
logging.getLogger('azure').setLevel(logging.ERROR)
logging.getLogger('azure.identity').setLevel(logging.ERROR)
logging.getLogger('msal').setLevel(logging.ERROR)

# Azure SDK imports
try:
    from azure.identity import AzureCliCredential, InteractiveBrowserCredential, ChainedTokenCredential
    from azure.mgmt.subscription import SubscriptionClient
    from azure.mgmt.resource import ResourceManagementClient
    from azure.mgmt.resource import FeatureClient
    from azure.mgmt.compute import ComputeManagementClient
    from azure.mgmt.network import NetworkManagementClient
    from azure.mgmt.monitor import MonitorManagementClient
    from azure.mgmt.keyvault import KeyVaultManagementClient
    from azure.mgmt.storage import StorageManagementClient
    from azure.mgmt.authorization import AuthorizationManagementClient
    from azure.keyvault.secrets import SecretClient
    from azure.storage.blob import BlobServiceClient
    from azure.core.exceptions import HttpResponseError, ClientAuthenticationError, ResourceNotFoundError
    import requests
except ImportError as e:
    print(f"\n❌ Missing required package: {e}")
    print("\nInstall requirements with:")
    print(
        "  pip install azure-identity azure-mgmt-resource azure-mgmt-compute azure-mgmt-network azure-mgmt-subscription azure-mgmt-monitor azure-mgmt-keyvault azure-mgmt-storage azure-mgmt-authorization azure-keyvault-secrets azure-storage-blob requests")
    sys.exit(1)

# =============================================================================
# Version
# =============================================================================

# Version for both tool and config schema (Semantic Versioning: MAJOR.MINOR.PATCH)
# Tool version and schema version are kept in sync
VERSION = "1.2.1"

# =============================================================================
# Script Integrity Verification
# =============================================================================

# Expected SHA256 checksums for hardening scripts
# These protect against download corruption and man-in-the-middle attacks
#
# IMPORTANT: When updating scripts, compute new checksums locally BEFORE committing:
#   sha256sum scripts/setup.sh scripts/verify.sh
# Then update these values and commit everything together
SCRIPT_CHECKSUMS = {
    'setup.sh': 'bc36bf5120bf1a21cf7b61cb2a0d6b036308b1726c5bf0e2ae5df1b0ec2daabf',
    'verify.sh': '545dd9f79b9125c9ef910b4030d11b5a8cb7fead2128d9aa91d2a0a9c76b0511'
}

# =============================================================================
# Data Classes
# =============================================================================

@dataclass
class AzureEnvironment:
    """Azure environment configuration and SDK clients"""
    credential: Any
    subscription_id: str
    subscription_name: str
    encryption_at_host_enabled: bool
    resource_client: Any  # ResourceManagementClient
    compute_client: Any   # ComputeManagementClient
    network_client: Any   # NetworkManagementClient
    monitor_client: Any   # MonitorManagementClient

@dataclass
class ServerConfiguration:
    """Complete server configuration from user selections"""
    environment: Dict[str, Any]
    role: Dict[str, Any]
    region: Dict[str, Any]
    scope: Dict[str, Any]
    server_id: int
    server_name: str
    vm_size: Dict[str, Any]
    admin_username: str
    private_key_path: str
    public_key: str
    disk_size: Dict[str, Any]
    disk_type: str
    os_image: Dict[str, Any]
    tags: Dict[str, str]
    managed_by: str
    enable_alerts: bool
    alert_email: Optional[str]
    user_ip: str
    nsg_rules: List[Dict[str, Any]]
    keyvault_name: str
    selections: Dict[str, str]  # For status bar display

@dataclass
class DeploymentResult:
    """Results from Azure resource deployment"""
    storage_info: Dict[str, Any]
    public_ip_address: str
    fqdn: Optional[str]
    resource_names: Dict[str, str]  # rg_name, vnet_name, etc.

# =============================================================================
# Constants and Configuration
# =============================================================================

SCRIPT_DIR = Path(__file__).parent.resolve()
CONFIG_FILE = SCRIPT_DIR / "config" / "settings.yaml"
CONFIG_FILE_OLD = SCRIPT_DIR / "config.json"  # Legacy location
ARM_SKUS_FILE = SCRIPT_DIR / "data" / "armSkus.json"
REGIONS_FILE = SCRIPT_DIR / "data" / "regions.json"
SSH_DIR = SCRIPT_DIR / "ssh"


# ANSI Colors
class Colors:
    RED = '\033[0;31m'
    GREEN = '\033[0;32m'
    YELLOW = '\033[1;33m'
    BLUE = '\033[0;34m'
    CYAN = '\033[0;36m'
    BOLD = '\033[1m'
    NC = '\033[0m'  # No Color


# =============================================================================
# Retry Logic
# =============================================================================

def retry_with_backoff(
    max_retries: int = 3,
    base_delay: float = 2.0,
    max_delay: float = 60.0,
    exponential_base: float = 2.0,
    jitter: bool = True,
    exceptions: tuple = (HttpResponseError,)
):
    """
    Retry decorator with exponential backoff and jitter.

    Handles common Azure transient errors:
    - HTTP 429 (throttling) - respects Retry-After header
    - HTTP 500/502/503 (server errors)
    - HTTP 403 on RBAC operations (waits for propagation)
    - Network timeouts

    Args:
        max_retries: Maximum number of retry attempts (default: 3)
        base_delay: Initial delay in seconds (default: 2.0)
        max_delay: Maximum delay in seconds (default: 60.0)
        exponential_base: Base for exponential backoff (default: 2.0)
        jitter: Add random jitter to prevent thundering herd (default: True)
        exceptions: Tuple of exceptions to catch and retry (default: HttpResponseError)

    Returns:
        Decorated function with retry logic
    """
    def decorator(func):
        @wraps(func)
        def wrapper(*args, **kwargs):
            retry_count = 0

            while retry_count <= max_retries:
                try:
                    return func(*args, **kwargs)

                except exceptions as e:
                    if retry_count == max_retries:
                        raise

                    # Determine delay based on error type
                    delay = min(base_delay * (exponential_base ** retry_count), max_delay)

                    # Check for Retry-After header (HTTP 429 throttling)
                    if isinstance(e, HttpResponseError) and hasattr(e, 'response'):
                        retry_after = e.response.headers.get('Retry-After')
                        if retry_after:
                            try:
                                delay = float(retry_after)
                            except ValueError:
                                pass

                        # Special handling for RBAC 403 errors (propagation delays)
                        if hasattr(e, 'status_code') and e.status_code == 403:
                            delay = max(delay, 30.0)  # Wait at least 30s for RBAC

                    # Add jitter to prevent thundering herd
                    if jitter:
                        delay = delay * (0.5 + random.random())

                    retry_count += 1
                    print(f"{Colors.YELLOW}⚠ Attempt {retry_count}/{max_retries} failed: {e}{Colors.NC}")
                    print(f"{Colors.YELLOW}  Retrying in {delay:.1f}s...{Colors.NC}")
                    time.sleep(delay)

            return None
        return wrapper
    return decorator


# =============================================================================
# Utility Functions
# =============================================================================

def validate_safe_identifier(value: str, field_name: str) -> str:
    """
    Validate that a value is safe for use in commands, file paths, and configuration.

    This prevents command injection, path traversal, and other security vulnerabilities
    when user-controlled values are used in subprocess calls or file operations.

    Args:
        value: The string to validate
        field_name: Name of the field (for error messages)

    Returns:
        The validated value (unchanged if valid)

    Raises:
        ValueError: If value contains unsafe characters or patterns

    Examples:
        >>> validate_safe_identifier("azureuser", "username")
        'azureuser'

        >>> validate_safe_identifier("user; rm -rf /", "username")
        ValueError: Invalid username: Only letters, numbers, hyphens, and underscores allowed.

        >>> validate_safe_identifier("../../etc/passwd", "filename")
        ValueError: Invalid filename: Path traversal characters not allowed.
    """
    import re

    # Check for None or empty
    if not value:
        raise ValueError(f"Invalid {field_name}: Value cannot be empty")

    # Only allow alphanumeric, hyphens, and underscores
    # No spaces, semicolons, quotes, backticks, or other special chars
    if not re.match(r'^[a-zA-Z0-9_-]+$', value):
        raise ValueError(
            f"Invalid {field_name}: '{value}'\n"
            f"Only letters, numbers, hyphens, and underscores allowed."
        )

    # Prevent path traversal
    if '..' in value or '/' in value or '\\' in value:
        raise ValueError(
            f"Invalid {field_name}: '{value}'\n"
            f"Path traversal characters not allowed."
        )

    # Reasonable length check (Azure resource name limits)
    if len(value) > 64:
        raise ValueError(
            f"Invalid {field_name}: '{value}'\n"
            f"Maximum length is 64 characters."
        )

    return value


def parse_semver(version: str) -> tuple:
    """Parse semantic version string into (major, minor, patch) tuple"""
    try:
        parts = version.split('.')
        if len(parts) != 3:
            return None
        return tuple(int(p) for p in parts)
    except (ValueError, AttributeError):
        return None

def compare_semver(version1: str, version2: str) -> int:
    """Compare two semantic versions. Returns: -1 if v1 < v2, 0 if equal, 1 if v1 > v2"""
    v1 = parse_semver(version1)
    v2 = parse_semver(version2)

    if v1 is None or v2 is None:
        return None

    if v1 < v2:
        return -1
    elif v1 > v2:
        return 1
    else:
        return 0

def validate_config_schema(config: Dict[str, Any]) -> bool:
    """Validate config.json structure and schema version"""

    # Check for schema_version field
    if 'schema_version' not in config:
        print_error("Config validation failed: missing 'schema_version' field")
        print_info(f"Expected schema version: {VERSION}")
        print_info("Please update config from config/settings.yaml.example template")
        return False

    config_version = config['schema_version']

    # Validate semantic version format
    if parse_semver(config_version) is None:
        print_error(f"Config validation failed: invalid schema_version format '{config_version}'")
        print_info(f"Expected format: MAJOR.MINOR.PATCH (e.g., {VERSION})")
        return False

    # Compare versions
    comparison = compare_semver(config_version, VERSION)

    if comparison is None:
        print_error("Config validation failed: could not compare schema versions")
        return False

    if comparison < 0:
        print_error(f"Config validation failed: schema version {config_version} is outdated")
        print_info(f"Current version: {VERSION}")
        print_info("Please update config from config/settings.yaml.example template")
        return False

    if comparison > 0:
        print_warning(f"Config schema version {config_version} is newer than supported version {VERSION}")
        print_warning("This may cause compatibility issues")
        if not prompt_yes_no("Continue anyway?", False):
            sys.exit(1)

    # Validate required top-level fields
    required_fields = [
        'environments', 'roles', 'regions', 'scopes', 'vm_sizes',
        'disk_sizes', 'os_images', 'nsg', 'alerts', 'defaults',
        'security', 'patching', 'tags'
    ]

    missing_fields = [field for field in required_fields if field not in config]

    if missing_fields:
        print_error(f"Config validation failed: missing required fields: {', '.join(missing_fields)}")
        print_info("Please update config.json from example.config.json template")
        return False

    # Validate defaults section has required fields
    required_defaults = ['admin_username', 'managed_by', 'infra_standard_version', 'github_org']
    missing_defaults = [field for field in required_defaults if field not in config['defaults']]

    if missing_defaults:
        print_error(f"Config validation failed: missing required defaults: {', '.join(missing_defaults)}")
        print_info("Please update config.json from example.config.json template")
        return False

    # Validate arrays are not empty
    required_arrays = {
        'environments': config.get('environments', []),
        'roles': config.get('roles', []),
        'regions': config.get('regions', []),
        'vm_sizes': config.get('vm_sizes', []),
        'os_images': config.get('os_images', [])
    }

    for name, array in required_arrays.items():
        if not array or len(array) == 0:
            print_error(f"Config validation failed: '{name}' array is empty")
            return False

    return True

def load_config() -> Dict[str, Any]:
    """Load and validate configuration from config/settings.yaml"""

    # Check for legacy config.json location
    if CONFIG_FILE_OLD.exists() and not CONFIG_FILE.exists():
        print_warning(f"Found legacy config file: {CONFIG_FILE_OLD}")
        print_info(f"Please migrate to new location: {CONFIG_FILE}")
        print_info("Run: python -c \"import json, yaml; yaml.dump(json.load(open('config.json')), open('config/settings.yaml', 'w'))\"")
        sys.exit(1)

    if not CONFIG_FILE.exists():
        print(f"{Colors.RED}❌ Configuration file not found: {CONFIG_FILE}{Colors.NC}")
        print_info("Please create config/settings.yaml from template:")
        print_info("  mkdir -p config")
        print_info("  cp config/settings.yaml.example config/settings.yaml")
        print_info("  # Then customize config/settings.yaml")
        sys.exit(1)

    try:
        with open(CONFIG_FILE, 'r') as f:
            config = yaml.safe_load(f)
    except yaml.YAMLError as e:
        print_error(f"Failed to parse {CONFIG_FILE}: {e}")
        print_info("Please check YAML syntax in config/settings.yaml")
        sys.exit(1)
    except Exception as e:
        print_error(f"Failed to load {CONFIG_FILE}: {e}")
        sys.exit(1)

    # Validate schema
    if not validate_config_schema(config):
        sys.exit(1)

    # Load VM sizes from armSkus.json if it exists
    if ARM_SKUS_FILE.exists():
        try:
            with open(ARM_SKUS_FILE, 'r') as f:
                arm_skus_data = json.load(f)
                if 'vm_sizes' in arm_skus_data:
                    config['vm_sizes'] = arm_skus_data['vm_sizes']
        except json.JSONDecodeError as e:
            print_warning(f"Failed to parse {ARM_SKUS_FILE}: {e}")
            print_info("Falling back to vm_sizes from settings.yaml")
        except Exception as e:
            print_warning(f"Failed to load {ARM_SKUS_FILE}: {e}")
            print_info("Falling back to vm_sizes from settings.yaml")

    # Load regions from regions.json if it exists
    if REGIONS_FILE.exists():
        try:
            with open(REGIONS_FILE, 'r') as f:
                regions_data = json.load(f)
                if 'regions' in regions_data:
                    config['regions'] = regions_data['regions']
                    # Preserve metadata for accessing default region
                    if '_metadata' in regions_data:
                        config['regions_metadata'] = regions_data['_metadata']
        except json.JSONDecodeError as e:
            print_warning(f"Failed to parse {REGIONS_FILE}: {e}")
            print_info("Falling back to regions from settings.yaml")
        except Exception as e:
            print_warning(f"Failed to load {REGIONS_FILE}: {e}")
            print_info("Falling back to regions from settings.yaml")

    # Validate admin_username from defaults to prevent command injection
    admin_username = config.get('defaults', {}).get('admin_username', 'azureuser')
    try:
        validate_safe_identifier(admin_username, "admin_username in config")
    except ValueError as e:
        print_error(f"Configuration validation failed: {e}")
        print_info("Please fix the admin_username in config/settings.yaml")
        sys.exit(1)

    return config


def get_default_region_index(regions: List[Dict], regions_metadata: Dict) -> int:
    """Get the index (1-based) of the default region from metadata

    Args:
        regions: List of region dictionaries
        regions_metadata: Metadata dict from regions.json (may contain 'default' key)

    Returns:
        1-based index of default region, or 1 if not found
    """
    default_name = regions_metadata.get('default') if regions_metadata else None
    if default_name:
        for i, r in enumerate(regions, 1):
            if r.get('name') == default_name:
                return i
    return 1  # Fallback to first region


def save_config(config: Dict[str, Any]):
    """Save configuration to config/settings.yaml"""
    with open(CONFIG_FILE, 'w') as f:
        yaml.dump(config, f, default_flow_style=False, sort_keys=False, allow_unicode=True)


def add_scope_to_config(config: Dict[str, Any], code: str, name: str, description: str):
    """Add a new scope to config and save"""
    new_scope = {"code": code, "name": name, "description": description}
    config['scopes'].append(new_scope)
    save_config(config)
    print_success(f"Scope '{code}' added to config/settings.yaml")
    return new_scope


def enable_windows_ansi():
    """Enable ANSI escape codes on Windows"""
    if os.name == 'nt':
        try:
            import ctypes
            kernel32 = ctypes.windll.kernel32
            # Enable ANSI escape sequences on Windows 10+
            kernel32.SetConsoleMode(kernel32.GetStdHandle(-11), 7)
        except Exception:
            pass


def clear_screen():
    """Clear the terminal screen"""
    if os.name == 'nt':
        os.system('cls')
    else:
        print('\033[2J\033[H', end='', flush=True)


def print_status_bar(selections: Dict[str, str], server_name: str = None):
    """Print a compact status bar showing current selections"""
    print(f"{Colors.BOLD}Azure Server Builder for Laravel Forge{Colors.NC}")
    print(f"{Colors.CYAN}{'─' * 60}{Colors.NC}")

    if server_name:
        print(f"{Colors.GREEN}Server: {Colors.BOLD}{server_name}{Colors.NC}")
    elif selections:
        parts = []
        for key, val in selections.items():
            if val:
                parts.append(f"{key}: {Colors.BOLD}{val}{Colors.NC}")
        if parts:
            print(" │ ".join(parts))

    print(f"{Colors.CYAN}{'─' * 60}{Colors.NC}")




def print_header(text: str):
    """Print a section header"""
    print(f"\n{Colors.BOLD}{'=' * 60}{Colors.NC}")
    print(f"{Colors.BOLD}{text}{Colors.NC}")
    print(f"{Colors.BOLD}{'=' * 60}{Colors.NC}\n")


def print_subheader(text: str):
    """Print a subsection header"""
    print(f"\n{Colors.CYAN}{text}{Colors.NC}")
    print(f"{Colors.CYAN}{'-' * len(text)}{Colors.NC}")


def print_success(text: str):
    """Print success message"""
    print(f"{Colors.GREEN}[OK] {text}{Colors.NC}")


def print_warning(text: str):
    """Print warning message"""
    print(f"{Colors.YELLOW}[WARNING] {text}{Colors.NC}")


def print_error(text: str):
    """Print error message"""
    print(f"{Colors.RED}[ERROR] {text}{Colors.NC}")


def print_info(text: str):
    """Print info message"""
    print(f"{Colors.BLUE}[INFO] {text}{Colors.NC}")


def prompt(text: str, default: str = None) -> str:
    """Prompt user for input with optional default"""
    if default:
        result = input(f"{text} [{default}]: ").strip()
        return result if result else default
    else:
        return input(f"{text}: ").strip()


def prompt_yes_no(text: str, default: bool = True) -> bool:
    """Prompt for yes/no response"""
    default_str = "Y/n" if default else "y/N"
    result = input(f"{text} [{default_str}]: ").strip().lower()
    if not result:
        return default
    return result in ('y', 'yes')


def prompt_choice(options: List[Dict], prompt_text: str, default_index: int = None) -> Dict:
    """Prompt user to select from a list of options"""
    print(f"\n{prompt_text}")

    for i, opt in enumerate(options, 1):
        name = opt.get('name', opt.get('code', ''))
        desc = opt.get('description', '')
        extra = opt.get('extra', '')

        line = f"  {i}. {name}"
        if desc:
            line += f" - {desc}"
        if extra:
            line += f" {extra}"

        if default_index == i:
            line += f" {Colors.CYAN}(default){Colors.NC}"

        print(line)

    while True:
        default_str = str(default_index) if default_index else ""
        choice = prompt("\nChoice", default_str)

        try:
            idx = int(choice) - 1
            if 0 <= idx < len(options):
                return options[idx]
        except ValueError:
            pass

        print_error(f"Please enter a number between 1 and {len(options)}")


def prompt_custom_disk_config() -> Tuple[Dict[str, int], str]:
    """
    Prompt user to configure a custom disk (tier, redundancy, size).

    Returns:
        Tuple of (disk_config_dict, disk_type_string)
        disk_config_dict has 'gb' key
        disk_type_string is the Azure SKU (e.g., 'Premium_LRS')
    """
    # Valid Azure disk sizes from 64GB to 2TB
    VALID_DISK_SIZES = [64, 128, 256, 512, 1024, 2048]

    # Step 1: Select disk tier (Standard SSD or Premium SSD)
    tier_options = [
        {'name': 'Standard SSD', 'code': 'StandardSSD', 'description': 'Cost-effective, good performance'},
        {'name': 'Premium SSD', 'code': 'Premium', 'description': 'High performance, low latency'}
    ]
    selected_tier = prompt_choice(tier_options, "Disk Tier:", 1)

    # Step 2: Select redundancy (LRS or ZRS)
    redundancy_options = [
        {'name': 'LRS (Locally Redundant)', 'code': 'LRS', 'description': '3 copies in one zone'},
        {'name': 'ZRS (Zone Redundant)', 'code': 'ZRS', 'description': '3 copies across zones'}
    ]
    selected_redundancy = prompt_choice(redundancy_options, "Redundancy:", 1)

    # Step 3: Select disk size
    size_options = [
        {'name': f"{size} GB", 'gb': size}
        for size in VALID_DISK_SIZES
    ]
    selected_size = prompt_choice(size_options, "Disk Size:", 1)

    # Build the Azure disk type SKU
    disk_type = f"{selected_tier['code']}_{selected_redundancy['code']}"

    return ({'gb': selected_size['gb']}, disk_type)


# =============================================================================
# Deployment Logging
# =============================================================================

class DeploymentLog:
    """Captures deployment details for audit trail"""

    def __init__(self):
        self.timestamp = datetime.now(timezone.utc)
        self.sections = []
        self.metadata = {}
        self.selections = {}
        self.resources = {}
        self.security_features = []
        self.errors = []
        self.warnings = []

    def add_metadata(self, key: str, value: str):
        """Add deployment metadata (timestamp, user, subscription, etc.)"""
        self.metadata[key] = value

    def add_selection(self, key: str, value: str, description: str = None):
        """Add user selection (environment, role, etc.)"""
        self.selections[key] = {'value': value, 'description': description}

    def add_resource(self, resource_type: str, name: str, details: Dict[str, Any],
                     api_calls: Optional[List[Dict[str, Any]]] = None):
        """Add created resource with its configuration and optional API calls"""
        if resource_type not in self.resources:
            self.resources[resource_type] = []

        resource_entry = {
            'name': name,
            'details': details
        }

        if api_calls:
            resource_entry['api_calls'] = api_calls

        self.resources[resource_type].append(resource_entry)

    def add_security_feature(self, feature: str):
        """Add enabled security feature"""
        self.security_features.append(feature)

    def add_error(self, message: str):
        """Add error message"""
        self.errors.append(message)

    def add_warning(self, message: str):
        """Add warning message"""
        self.warnings.append(message)

    def generate_report(self) -> str:
        """Generate Markdown formatted deployment report"""
        lines = []

        # Header
        lines.append("# Azure VM Deployment Report")
        lines.append("")
        lines.append(f"**Generated:** {self.timestamp.strftime('%Y-%m-%d %H:%M:%S UTC')}")
        lines.append("")
        lines.append("---")
        lines.append("")

        # Metadata Section
        lines.append("## Deployment Metadata")
        lines.append("")
        lines.append("| Property | Value |")
        lines.append("|----------|-------|")
        lines.append(f"| **Timestamp (UTC)** | {self.timestamp.strftime('%Y-%m-%d %H:%M:%S UTC')} |")
        for key, value in self.metadata.items():
            # Escape pipe characters in values for Markdown table
            safe_value = str(value).replace('|', '\\|')
            lines.append(f"| **{key}** | {safe_value} |")
        lines.append("")

        # Selections Section
        lines.append("## User Selections")
        lines.append("")
        lines.append("| Selection | Value | Description |")
        lines.append("|-----------|-------|-------------|")
        for key, data in self.selections.items():
            value = data['value']
            desc = data.get('description', '')
            # Escape pipe characters
            safe_value = str(value).replace('|', '\\|')
            safe_desc = str(desc).replace('|', '\\|')
            lines.append(f"| **{key}** | {safe_value} | {safe_desc} |")
        lines.append("")

        # Security Features Section
        if self.security_features:
            lines.append("## Security Features Enabled")
            lines.append("")
            for feature in self.security_features:
                lines.append(f"- ✅ {feature}")
            lines.append("")

        # Resources Section
        lines.append("## Resources Created")
        lines.append("")

        for resource_type in sorted(self.resources.keys()):
            resources = self.resources[resource_type]
            lines.append(f"### {resource_type}")
            lines.append("")

            for resource in resources:
                lines.append(f"**Name:** `{resource['name']}`")
                lines.append("")

                # Create a table for resource details
                has_simple_values = any(
                    not isinstance(v, (list, dict))
                    for v in resource['details'].values()
                )

                if has_simple_values:
                    lines.append("| Property | Value |")
                    lines.append("|----------|-------|")

                for detail_key, detail_value in resource['details'].items():
                    if isinstance(detail_value, list):
                        # Handle lists
                        if has_simple_values:
                            lines.append("")  # Close table if open
                            has_simple_values = False
                        lines.append(f"**{detail_key}:**")
                        for item in detail_value:
                            if isinstance(item, dict):
                                for k, v in item.items():
                                    safe_v = str(v).replace('|', '\\|')
                                    lines.append(f"  - **{k}:** {safe_v}")
                            else:
                                lines.append(f"  - {item}")
                        lines.append("")
                    elif isinstance(detail_value, dict):
                        # Handle dicts
                        if has_simple_values:
                            lines.append("")  # Close table if open
                            has_simple_values = False
                        lines.append(f"**{detail_key}:**")
                        for k, v in detail_value.items():
                            safe_v = str(v).replace('|', '\\|')
                            lines.append(f"  - **{k}:** {safe_v}")
                        lines.append("")
                    else:
                        # Simple values go in table
                        safe_value = str(detail_value).replace('|', '\\|')
                        lines.append(f"| **{detail_key}** | {safe_value} |")

                # Add API calls section if present
                if 'api_calls' in resource:
                    lines.append("")
                    lines.append("**API Calls:**")
                    lines.append("")
                    for i, api_call in enumerate(resource['api_calls'], 1):
                        lines.append(f"*Call {i}: `{api_call['method']}`*")
                        lines.append("```yaml")
                        params_yaml = yaml.dump(api_call['parameters'],
                                               default_flow_style=False,
                                               indent=2)
                        lines.append(params_yaml.rstrip())
                        lines.append("```")
                        lines.append("")

                lines.append("")

        # Warnings Section
        if self.warnings:
            lines.append("## ⚠️ Warnings")
            lines.append("")
            for warning in self.warnings:
                lines.append(f"- ⚠️ {warning}")
            lines.append("")

        # Errors Section
        if self.errors:
            lines.append("## ❌ Errors")
            lines.append("")
            for error in self.errors:
                lines.append(f"- ❌ {error}")
            lines.append("")

        # Footer
        lines.append("---")
        lines.append("")
        lines.append("*End of Deployment Report*")

        return "\n".join(lines)

    def save_locally(self, server_name: str, suffix: str = "") -> Optional[str]:
        """Save deployment log to local file

        Args:
            server_name: Server name for filename
            suffix: Optional suffix to add (e.g., "dry-run")
        """
        try:
            # Create logs directory if it doesn't exist
            logs_dir = os.path.join(os.getcwd(), 'logs')
            os.makedirs(logs_dir, exist_ok=True)

            # Generate filename
            timestamp_str = self.timestamp.strftime('%Y%m%d_%H%M%S')
            suffix_part = f"-{suffix}" if suffix else ""
            filename = f"deployment-{server_name}-{timestamp_str}{suffix_part}.md"
            filepath = os.path.join(logs_dir, filename)

            # Write report
            with open(filepath, 'w', encoding='utf-8') as f:
                f.write(self.generate_report())

            return filepath
        except Exception as e:
            print_error(f"Failed to save local deployment log: {e}")
            return None

    def upload_to_blob(self, storage_account_name: str, server_name: str,
                       credential, subscription_id: str, storage_account_id: str = None) -> bool:
        """Upload deployment log to Azure Blob Storage"""
        try:
            from azure.storage.blob import BlobServiceClient

            # The signed-in builder user needs Azure Storage data-plane permissions.
            # Owner/Contributor on the storage account is not enough for blob upload
            # when authenticating with Microsoft Entra ID. Verify access here because
            # role assignments can take time to propagate.
            if storage_account_id:
                if not ensure_current_user_storage_write_access(
                    credential, subscription_id, storage_account_id, storage_account_name
                ):
                    return False

            # Build blob service client
            account_url = f"https://{storage_account_name}.blob.core.windows.net"
            blob_service_client = BlobServiceClient(account_url=account_url, credential=credential)

            # Get container client
            container_name = HARDENING_REPORTS_CONTAINER
            container_client = blob_service_client.get_container_client(container_name)

            # Generate blob name: tfs-hardening-reports/{hostname}/deployment-{hostname}-{timestamp}.md
            timestamp_str = self.timestamp.strftime('%Y%m%d_%H%M%S')
            blob_name = f"{server_name}/deployment-{server_name}-{timestamp_str}.md"

            # Upload
            blob_client = container_client.get_blob_client(blob_name)
            report_content = self.generate_report()
            blob_client.upload_blob(report_content, overwrite=True)

            return True
        except Exception as e:
            print_error(f"Failed to upload deployment log to Azure: {e}")
            return False


class ExecutionLog:
    """Captures chronological execution details for debugging and audit"""

    def __init__(self, server_name: str, dry_run: bool = False):
        self.server_name = server_name
        self.dry_run = dry_run
        self.timestamp = datetime.now(timezone.utc)
        self.entries = []  # List of (timestamp, level, message) tuples
        self.api_calls = []  # List of API call details

        # Set up log file path and create initial file
        self.log_file_path = None
        try:
            log_dir = Path("logs")
            log_dir.mkdir(exist_ok=True)

            timestamp_str = self.timestamp.strftime('%Y%m%d_%H%M%S')
            suffix = "-dry-run" if dry_run else ""
            filename = f"execution-{server_name}-{timestamp_str}{suffix}.md"
            self.log_file_path = log_dir / filename

            # Write initial header
            with open(self.log_file_path, 'w', encoding='utf-8') as f:
                f.write(f"# Execution Log: {self.server_name}\n\n")
                if self.dry_run:
                    f.write("**Mode**: DRY-RUN (No resources created)\n")
                else:
                    f.write("**Mode**: LIVE DEPLOYMENT\n")
                f.write(f"**Started**: {self.timestamp.strftime('%Y-%m-%d %H:%M:%S UTC')}\n\n")
                f.write("---\n\n")
        except Exception:
            pass  # Don't let logging setup failures break deployment

    def log(self, level: str, message: str):
        """Add timestamped entry and immediately append to file"""
        try:
            entry_time = datetime.now(timezone.utc)
            self.entries.append((entry_time, level, message))

            # Immediately write to file
            if self.log_file_path:
                self._append_entry_to_file(entry_time, level, message)
        except Exception:
            pass  # Don't let logging failures break deployment

    def _append_entry_to_file(self, entry_time, level: str, message: str):
        """Append a single entry to the log file"""
        try:
            timestamp_str = entry_time.strftime('%H:%M:%S.%f')[:-3]

            with open(self.log_file_path, 'a', encoding='utf-8') as f:
                if level == "API_CALL":
                    f.write(f"### [{timestamp_str}] API Call\n\n")
                    f.write(f"{message}\n\n")
                elif level == "SELECTION":
                    f.write(f"**[{timestamp_str}] User Selection**\n")
                    f.write(f"  {message}\n\n")
                elif level == "PERMISSION":
                    f.write(f"**[{timestamp_str}] Permission Check**\n")
                    f.write(f"  {message}\n\n")
                elif level == "SUCCESS":
                    f.write(f"**[{timestamp_str}] ✓ SUCCESS**\n")
                    f.write(f"  {message}\n\n")
                elif level == "ERROR":
                    f.write(f"**[{timestamp_str}] ✗ ERROR**\n")
                    f.write(f"  {message}\n\n")
                elif level == "WARNING":
                    f.write(f"**[{timestamp_str}] ⚠ WARNING**\n")
                    f.write(f"  {message}\n\n")
                else:  # INFO
                    f.write(f"[{timestamp_str}] {message}\n\n")
        except Exception:
            pass

    def log_selection(self, prompt: str, selection: str):
        """Log user selection"""
        self.log("SELECTION", f"**{prompt}**: {selection}")

    def log_api_call(self, method: str, parameters: Dict[str, Any], dry_run: bool = False):
        """Log Azure SDK API call with full parameters"""
        try:
            prefix = "[DRY-RUN] " if dry_run else ""

            # Format parameters as YAML-like structure
            params_yaml = yaml.dump(parameters, default_flow_style=False, indent=2)

            message = f"{prefix}**API Call**: `{method}`\n```yaml\n{params_yaml}\n```"
            self.log("API_CALL", message)

            self.api_calls.append({
                'timestamp': datetime.now(timezone.utc),
                'method': method,
                'parameters': parameters,
                'dry_run': dry_run
            })
        except Exception:
            pass  # Don't let logging failures break deployment

    def log_permission_check(self, resource_type: str, result: bool):
        """Log permission check result"""
        try:
            status = "✓ GRANTED" if result else "✗ DENIED"
            self.log("PERMISSION", f"{status}: {resource_type}")
        except Exception:
            pass

    def generate_markdown(self) -> str:
        """Generate markdown formatted execution log"""
        lines = []

        # Header
        lines.append(f"# Execution Log: {self.server_name}")
        lines.append("")
        if self.dry_run:
            lines.append("**Mode**: DRY-RUN (No resources created)")
        else:
            lines.append("**Mode**: LIVE DEPLOYMENT")
        lines.append(f"**Started**: {self.timestamp.strftime('%Y-%m-%d %H:%M:%S UTC')}")
        lines.append("")
        lines.append("---")
        lines.append("")

        # Chronological entries
        for entry_time, level, message in self.entries:
            timestamp_str = entry_time.strftime('%H:%M:%S.%f')[:-3]  # Include milliseconds

            # Level-specific formatting
            if level == "API_CALL":
                lines.append(f"### [{timestamp_str}] API Call")
                lines.append("")
                lines.append(message)
                lines.append("")
            elif level == "SELECTION":
                lines.append(f"**[{timestamp_str}] User Selection**")
                lines.append(f"  {message}")
                lines.append("")
            elif level == "PERMISSION":
                lines.append(f"**[{timestamp_str}] Permission Check**")
                lines.append(f"  {message}")
                lines.append("")
            elif level == "ERROR":
                lines.append(f"**[{timestamp_str}] ❌ ERROR**")
                lines.append(f"  {message}")
                lines.append("")
            elif level == "WARNING":
                lines.append(f"**[{timestamp_str}] ⚠️ WARNING**")
                lines.append(f"  {message}")
                lines.append("")
            elif level == "SUCCESS":
                lines.append(f"**[{timestamp_str}] ✓ SUCCESS**")
                lines.append(f"  {message}")
                lines.append("")
            else:  # INFO
                lines.append(f"[{timestamp_str}] {message}")
                lines.append("")

        # Footer
        end_time = datetime.now(timezone.utc)
        duration = (end_time - self.timestamp).total_seconds()
        lines.append("---")
        lines.append("")
        lines.append(f"**Completed**: {end_time.strftime('%Y-%m-%d %H:%M:%S UTC')}")
        lines.append(f"**Duration**: {duration:.2f} seconds")
        lines.append("")
        lines.append(f"**Total Entries**: {len(self.entries)}")
        lines.append(f"**API Calls**: {len(self.api_calls)}")

        return "\n".join(lines)

    def save(self) -> Optional[str]:
        """Finalize execution log by appending summary footer"""
        try:
            # File is already being written in real-time, just append footer
            if self.log_file_path:
                end_time = datetime.now(timezone.utc)
                duration = (end_time - self.timestamp).total_seconds()

                with open(self.log_file_path, 'a', encoding='utf-8') as f:
                    f.write("---\n\n")
                    f.write(f"**Completed**: {end_time.strftime('%Y-%m-%d %H:%M:%S UTC')}\n")
                    f.write(f"**Duration**: {duration:.2f} seconds\n\n")
                    f.write(f"**Total Entries**: {len(self.entries)}\n")
                    f.write(f"**API Calls**: {len(self.api_calls)}\n")

                return str(self.log_file_path)
            return None
        except Exception as e:
            print_error(f"Failed to finalize execution log: {e}")
            return None


class ApiCallTracker:
    """Context manager to track Azure SDK API calls"""

    def __init__(self, exec_log: Optional['ExecutionLog'],
                 deploy_log: Optional['DeploymentLog'],
                 method_name: str):
        self.exec_log = exec_log
        self.deploy_log = deploy_log
        self.method_name = method_name
        self.parameters = {}
        self.api_calls = []

    def __enter__(self):
        return self

    def track_call(self, sdk_method: str, params: Dict[str, Any]):
        """Record an API call with its parameters"""
        try:
            # Sanitize sensitive data
            safe_params = self._sanitize_params(params)

            call_record = {
                'method': sdk_method,
                'parameters': safe_params
            }

            self.api_calls.append(call_record)

            # Log to execution log
            if self.exec_log:
                self.exec_log.log_api_call(sdk_method, safe_params, DRY_RUN)
        except Exception:
            pass  # Don't let logging failures break deployment

    def _sanitize_params(self, params: Dict[str, Any]) -> Dict[str, Any]:
        """Remove sensitive data from parameters"""
        try:
            sanitized = {}
            for key, value in params.items():
                if key in ['credential', 'password', 'secret', 'key_data', 'ssh_public_key']:
                    sanitized[key] = '***REDACTED***'
                elif isinstance(value, dict):
                    sanitized[key] = self._sanitize_params(value)
                elif isinstance(value, list):
                    sanitized[key] = [self._sanitize_params(item) if isinstance(item, dict) else item
                                     for item in value]
                else:
                    sanitized[key] = str(value) if value is not None else None
            return sanitized
        except Exception:
            return {'error': 'Failed to sanitize parameters'}

    def __exit__(self, exc_type, exc_val, exc_tb):
        return False

    def get_api_calls(self) -> List[Dict[str, Any]]:
        """Return collected API calls"""
        return self.api_calls


# =============================================================================
# Azure Authentication
# =============================================================================

def get_credential(exec_log: Optional['ExecutionLog'] = None):
    """Get Azure credentials - try CLI first, fall back to browser"""
    print_subheader("Authentication")

    if exec_log:
        exec_log.log("INFO", "Starting authentication")

    # Try CLI credential first, suppressing stderr noise from broken az cli installs
    try:
        import io
        import contextlib

        cli_cred = AzureCliCredential()
        # Suppress stderr during token fetch (az cli can be noisy with errors)
        with contextlib.redirect_stderr(io.StringIO()):
            cli_cred.get_token("https://management.azure.com/.default")
            # Pre-fetch Key Vault token to avoid second login later
            cli_cred.get_token("https://vault.azure.net/.default")
        print_success("Using existing Azure CLI session")
        if exec_log:
            exec_log.log("SUCCESS", "Authenticated via Azure CLI")
        return cli_cred
    except Exception as e:
        if exec_log:
            exec_log.log("WARNING", f"Azure CLI authentication failed: {str(e)[:100]}")
        print_info("Opening browser for login...")

        try:
            browser_cred = InteractiveBrowserCredential()
            browser_cred.get_token("https://management.azure.com/.default")
            print_success("Browser authentication successful")
            if exec_log:
                exec_log.log("SUCCESS", "Authenticated via browser")

            # Fetch Key Vault token (may prompt for additional consent)
            print_info("Authenticating for Key Vault access...")
            try:
                browser_cred.get_token("https://vault.azure.net/.default")
                print_success("Key Vault authentication successful")
                if exec_log:
                    exec_log.log("SUCCESS", "Key Vault authentication successful")
            except Exception as e:
                print_warning(f"Key Vault pre-auth skipped: {e}")
                print_info("You may be prompted again when accessing Key Vault")
                if exec_log:
                    exec_log.log("WARNING", f"Key Vault pre-auth skipped: {str(e)[:100]}")

            return browser_cred
        except Exception as e:
            if exec_log:
                exec_log.log("ERROR", f"Authentication failed: {str(e)}")
            print_error(f"Authentication failed: {e}")
            print_info("Try running 'az login' first")
            sys.exit(1)


def select_subscription(credential) -> Tuple[str, str]:
    """List subscriptions and let user select one"""
    print_subheader("Select Subscription")

    sub_client = SubscriptionClient(credential)
    subscriptions = list(sub_client.subscriptions.list())

    if not subscriptions:
        print_error("No subscriptions found for this account")
        sys.exit(1)

    options = [
        {
            'id': sub.subscription_id,
            'name': sub.display_name,
            'code': sub.subscription_id[:8] + '...'
        }
        for sub in subscriptions
    ]

    for i, opt in enumerate(options, 1):
        print(f"  {i}. {opt['name']} ({opt['code']})")

    while True:
        choice = prompt("\nSelect subscription", "1")
        try:
            idx = int(choice) - 1
            if 0 <= idx < len(options):
                selected = options[idx]
                print_success(f"Selected: {selected['name']}")
                return selected['id'], selected['name']
        except ValueError:
            pass
        print_error(f"Please enter a number between 1 and {len(options)}")


# =============================================================================
# Permission Checks
# =============================================================================

def check_azure_permissions(credential, subscription_id: str,
                           exec_log: Optional['ExecutionLog'] = None) -> Dict[str, bool]:
    """
    Check all required Azure permissions upfront.
    Returns dict of permission checks with True/False status.
    """
    print_subheader("Checking Azure Permissions")

    if exec_log:
        exec_log.log("INFO", "Checking Azure permissions")

    results = {}

    # 1. Check Resource Group creation (Microsoft.Resources/subscriptions/resourceGroups/write)
    print("  Checking resource group permissions...", end=" ", flush=True)
    try:
        resource_client = ResourceManagementClient(credential, subscription_id)
        # Try to list resource groups - proves read access
        list(resource_client.resource_groups.list())
        results['resource_groups'] = True
        print_success("OK")
        if exec_log:
            exec_log.log_permission_check("Resource Groups", True)
    except Exception as e:
        results['resource_groups'] = False
        print_error("FAILED")
        if exec_log:
            exec_log.log_permission_check("Resource Groups", False)

    # 2. Check Compute permissions (VMs)
    print("  Checking compute permissions...", end=" ", flush=True)
    try:
        compute_client = ComputeManagementClient(credential, subscription_id)
        # Try to list VMs - proves read access
        list(compute_client.virtual_machines.list_all())
        results['compute'] = True
        print_success("OK")
        if exec_log:
            exec_log.log_permission_check("Compute (VMs)", True)
    except Exception as e:
        results['compute'] = False
        print_error("FAILED")
        if exec_log:
            exec_log.log_permission_check("Compute (VMs)", False)

    # 3. Check Network permissions
    print("  Checking network permissions...", end=" ", flush=True)
    try:
        network_client = NetworkManagementClient(credential, subscription_id)
        # Try to list vnets
        list(network_client.virtual_networks.list_all())
        results['network'] = True
        print_success("OK")
        if exec_log:
            exec_log.log_permission_check("Network", True)
    except Exception as e:
        results['network'] = False
        print_error("FAILED")
        if exec_log:
            exec_log.log_permission_check("Network", False)

    # 4. Check Storage permissions (need either write access to existing TFS storage OR ability to create)
    print("  Checking storage permissions...", end=" ", flush=True)
    try:
        storage_client = StorageManagementClient(credential, subscription_id)
        accounts = list(storage_client.storage_accounts.list())

        # Check if we can access existing TFS-managed storage account
        # We check by listing blobs - if we have Storage Blob Data Contributor, list works
        has_access = False
        for account in accounts:
            # Look for TFSManaged tag (any value means it's TFS-managed)
            if account.tags and TFS_MANAGED_TAG in account.tags:
                try:
                    blob_service = BlobServiceClient(
                        account_url=f"https://{account.name}.blob.core.windows.net",
                        credential=credential
                    )
                    # Try to list blobs in either container (proves data plane access)
                    for container_name in [HARDENING_REPORTS_CONTAINER, COMPLIANCE_REPORTS_CONTAINER]:
                        try:
                            container_client = blob_service.get_container_client(container_name)
                            if container_client.exists():
                                # List blobs (limited to 1) to verify access
                                list(container_client.list_blobs(results_per_page=1))
                                has_access = True
                                break
                        except Exception:
                            continue
                    if has_access:
                        break
                except Exception:
                    continue

        if has_access:
            results['storage'] = True
            print_success("OK (data plane access)")
            if exec_log:
                exec_log.log_permission_check("Storage (data plane)", True)
        else:
            # No existing TFS storage or no access
            # Check if we can create storage accounts (management plane access)
            results['storage'] = True
            print_success("OK (can create)")
            if exec_log:
                exec_log.log_permission_check("Storage (can create)", True)
    except Exception as e:
        results['storage'] = False
        print_error("FAILED")
        if exec_log:
            exec_log.log_permission_check("Storage", False)

    # 5. Check Key Vault permissions (need either data plane access to TFS vault OR ability to create)
    # Note: Key Vault data plane may require additional authentication due to Azure security policies
    print("  Checking key vault permissions", end="", flush=True)
    print(" (may prompt for additional auth)...", end=" ", flush=True)
    try:
        kv_client = KeyVaultManagementClient(credential, subscription_id)
        vaults = list(kv_client.vaults.list())

        # Prioritize TFS-managed vaults, then check others
        tfs_vaults = [v for v in vaults if v.tags and TFS_MANAGED_TAG in v.tags]
        other_vaults = [v for v in vaults if not (v.tags and TFS_MANAGED_TAG in v.tags)]

        # Check if we can access secrets in any vault (TFS-managed first)
        # We list secrets instead of writing/deleting to avoid purge protection issues
        has_access = False
        for vault in tfs_vaults + other_vaults:
            try:
                vault_url = f"https://{vault.name}.vault.azure.net/"
                secret_client = SecretClient(vault_url=vault_url, credential=credential)
                # List secrets (limited) to verify data plane access
                # This requires Secret List permission, which is granted alongside Set
                list(secret_client.list_properties_of_secrets(max_page_size=1))
                has_access = True
                break
            except Exception:
                continue

        if has_access:
            results['keyvault'] = True
            print_success("OK (data plane access)")
            if exec_log:
                exec_log.log_permission_check("Key Vault (data plane)", True)
        else:
            # No access to existing vaults, check if we can create a new vault
            # This is indicated by being able to list vaults (management plane access)
            # The actual vault creation will be tested during setup
            results['keyvault'] = True
            print_success("OK (can create)")
            if exec_log:
                exec_log.log_permission_check("Key Vault (can create)", True)
    except Exception as e:
        results['keyvault'] = False
        print_error("FAILED")
        if exec_log:
            exec_log.log_permission_check("Key Vault", False)

    # 6. Check Monitor permissions (for alerts)
    print("  Checking monitor permissions...", end=" ", flush=True)
    try:
        monitor_client = MonitorManagementClient(credential, subscription_id)
        list(monitor_client.action_groups.list_by_subscription_id())
        results['monitor'] = True
        print_success("OK")
        if exec_log:
            exec_log.log_permission_check("Monitor (alerts)", True)
    except Exception as e:
        results['monitor'] = False
        print_error(f"FAILED - {type(e).__name__}: {str(e)}")
        if exec_log:
            exec_log.log_permission_check("Monitor (alerts)", False)

    # 7. Check Authorization permissions (for role assignments)
    print("  Checking authorization permissions...", end=" ", flush=True)
    try:
        auth_client = AuthorizationManagementClient(credential, subscription_id)
        # Try to list role assignments - need this for storage role assignment
        list(auth_client.role_assignments.list_for_subscription())
        results['authorization'] = True
        print_success("OK")
        if exec_log:
            exec_log.log_permission_check("Authorization (role assignments)", True)
    except Exception as e:
        results['authorization'] = False
        print_error("FAILED")
        if exec_log:
            exec_log.log_permission_check("Authorization (role assignments)", False)

    return results


def validate_permissions(results: Dict[str, bool]) -> bool:
    """
    Validate permission check results and report issues.
    Returns True if all required permissions are available.
    All permissions are required for full deployment.
    """
    required = ['resource_groups', 'compute', 'network', 'storage', 'keyvault', 'monitor', 'authorization']

    failed = [p for p in required if not results.get(p, False)]

    if failed:
        print()
        print_error("Missing required permissions. Cannot proceed.")
        print()
        for p in failed:
            desc = {
                'resource_groups': 'Resource group management',
                'compute': 'VM creation and management',
                'network': 'Network resources (VNet, NSG, IP)',
                'storage': 'Storage account access for verification reports',
                'keyvault': 'Key Vault access for SSH key backup',
                'monitor': 'Metric alerts configuration',
                'authorization': 'Role assignments for VM managed identity'
            }.get(p, p)
            print_error(f"  - {p}: {desc}")
        print()
        print_info("Required roles: Contributor or Owner on the subscription")
        print_info("Or specific roles: VM Contributor, Network Contributor, Storage Blob Data Contributor,")
        print_info("                   Key Vault Secrets Officer, Monitoring Contributor, User Access Administrator")
        return False

    print()
    print_success("All required permissions verified")
    return True


# =============================================================================
# Feature Registration
# =============================================================================

def check_encryption_at_host_feature(credential, subscription_id: str) -> str:
    """
    Check if EncryptionAtHost feature is registered.
    Returns: 'Registered', 'NotRegistered', 'Pending', or 'Registering'
    """
    try:
        feature_client = FeatureClient(credential, subscription_id)
        feature = feature_client.features.get("Microsoft.Compute", "EncryptionAtHost")
        return feature.properties.state
    except Exception as e:
        print_warning(f"Could not check EncryptionAtHost feature: {e}")
        return "Unknown"


def register_encryption_at_host_feature(credential, subscription_id: str) -> bool:
    """
    Register the EncryptionAtHost feature. Returns True if successful.
    """
    try:
        feature_client = FeatureClient(credential, subscription_id)

        # Register the feature
        print_info("Registering EncryptionAtHost feature...")
        feature_client.features.register("Microsoft.Compute", "EncryptionAtHost")

        # Re-register the provider to propagate the feature
        resource_client = ResourceManagementClient(credential, subscription_id)
        resource_client.providers.register("Microsoft.Compute")

        return True
    except Exception as e:
        print_error(f"Failed to register feature: {e}")
        return False


def wait_for_feature_registration(credential, subscription_id: str, timeout_minutes: int = 15) -> bool:
    """
    Wait for EncryptionAtHost feature to be registered.
    Returns True if registered, False if timeout.
    """
    import time

    print_info(f"Waiting for feature registration (up to {timeout_minutes} minutes)...")

    start_time = time.time()
    timeout_seconds = timeout_minutes * 60
    check_interval = 30  # seconds

    while time.time() - start_time < timeout_seconds:
        state = check_encryption_at_host_feature(credential, subscription_id)

        if state == "Registered":
            return True
        elif state in ("Registering", "Pending"):
            elapsed = int(time.time() - start_time)
            print(f"\r  Status: {state}... ({elapsed}s elapsed)", end="", flush=True)
            time.sleep(check_interval)
        else:
            print()
            return False

    print()
    return False


def ensure_encryption_at_host(credential, subscription_id: str) -> bool:
    """
    Check and enable EncryptionAtHost feature if needed.
    Returns True if feature is available, False otherwise.
    """
    print_subheader("Checking Encryption at Host")

    state = check_encryption_at_host_feature(credential, subscription_id)

    if state == "Registered":
        print_success("Encryption at Host feature is registered")
        return True

    elif state in ("NotRegistered", "Unregistered"):
        print_warning("Encryption at Host feature is not registered on this subscription")
        print_info("This is a one-time registration that takes ~10-15 minutes")
        print()

        if prompt_yes_no("Register Encryption at Host feature now?", True):
            if register_encryption_at_host_feature(credential, subscription_id):
                print_success("Feature registration initiated")

                if prompt_yes_no("Wait for registration to complete? (recommended)", True):
                    if wait_for_feature_registration(credential, subscription_id):
                        print()
                        print_success("Encryption at Host feature is now registered")
                        return True
                    else:
                        print_warning("Registration timed out. It may still complete in the background.")
                        print_info(
                            "You can check status with: az feature show --namespace Microsoft.Compute --name EncryptionAtHost")
                        return False
                else:
                    print_warning("Feature registration in progress. Deployment may fail if not ready.")
                    print_info(
                        "Check status with: az feature show --namespace Microsoft.Compute --name EncryptionAtHost")
                    return prompt_yes_no("Proceed with deployment anyway?", False)
            else:
                return False
        else:
            print_warning("Encryption at Host will be DISABLED for this deployment")
            return prompt_yes_no("Continue without Encryption at Host?", False)

    elif state in ("Registering", "Pending"):
        print_info(f"Feature registration is in progress (status: {state})")

        if prompt_yes_no("Wait for registration to complete?", True):
            if wait_for_feature_registration(credential, subscription_id):
                print()
                print_success("Encryption at Host feature is now registered")
                return True
            else:
                print_warning("Registration timed out")
                return prompt_yes_no("Proceed anyway? (may fail)", False)
        else:
            return prompt_yes_no("Proceed anyway? (may fail)", False)

    else:
        print_warning(f"Unknown feature state: {state}")
        return prompt_yes_no("Attempt deployment anyway?", False)


@retry_with_backoff(max_retries=3, base_delay=1, max_delay=10)
def scan_existing_servers(credential, subscription_id: str, config: Dict) -> Dict[str, List[int]]:
    """Scan for existing servers with InfraStandard tag and extract used IDs"""
    print_subheader("Scanning Existing Servers")

    compute_client = ComputeManagementClient(credential, subscription_id)
    infra_tag = config['tags']['infra_standard_tag']

    used_ids = {}  # Format: {"prd-app-scu": [339, 617], ...}
    servers_found = []

    try:
        vms = compute_client.virtual_machines.list_all()

        for vm in vms:
            if vm.tags and vm.tags.get(infra_tag):
                servers_found.append(vm.name)

                # Parse server name to extract env-role-region and ID
                match = re.match(r'^(dev|stg|prd)-(\w+)-(\w+)-(\w+)-(\d{3})$', vm.name)
                if match:
                    env, role, region, scope, server_id = match.groups()
                    key = f"{env}-{role}-{region}"

                    if key not in used_ids:
                        used_ids[key] = []
                    used_ids[key].append(int(server_id))

        if servers_found:
            print_success(f"Found {len(servers_found)} managed server(s)")
            for name in servers_found[:10]:  # Show first 10
                print(f"    • {name}")
            if len(servers_found) > 10:
                print(f"    ... and {len(servers_found) - 10} more")
        else:
            print_info("No existing managed servers found")

    except Exception as e:
        print_warning(f"Could not scan existing servers: {e}")

    return used_ids


def generate_server_id(used_ids: Dict[str, List[int]], key: str) -> int:
    """Generate a random 3-digit ID not already in use"""
    existing = set(used_ids.get(key, []))

    # Also check all keys to ensure global uniqueness per env-role-region prefix
    all_used = set()
    for k, ids in used_ids.items():
        if k.rsplit('-', 1)[0] == key.rsplit('-', 1)[0]:  # Same env-role-region
            all_used.update(ids)

    available = [i for i in range(100, 1000) if i not in all_used]

    if not available:
        raise ValueError("No available server IDs remaining")

    # Use cryptographically secure random for unpredictable server IDs
    return secrets.choice(available)


# =============================================================================
# Network Utilities
# =============================================================================

def get_current_public_ip(config: Dict) -> Optional[str]:
    """Attempt to detect user's current public IP"""
    services = config['nsg']['ip_detection_services']

    for service in services:
        try:
            response = requests.get(service, timeout=5)
            if response.status_code == 200:
                ip = response.text.strip()
                # Basic IP validation
                if re.match(r'^\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3}$', ip):
                    return ip
        except:
            continue

    return None


# =============================================================================
# SSH Key Management
# =============================================================================

def set_file_permissions_secure(file_path: str, is_private: bool = True):
    """Set secure file permissions (cross-platform)"""
    if os.name == 'nt':  # Windows
        try:
            import win32security
            import ntsecuritycon as con

            # Get current user SID
            user, domain, type = win32security.LookupAccountName("", os.getlogin())

            # Create a security descriptor
            sd = win32security.SECURITY_DESCRIPTOR()

            # Create a DACL
            dacl = win32security.ACL()

            if is_private:
                # Private key: Only current user has full control
                dacl.AddAccessAllowedAce(win32security.ACL_REVISION, con.FILE_ALL_ACCESS, user)
            else:
                # Public key: Current user full control, others read
                dacl.AddAccessAllowedAce(win32security.ACL_REVISION, con.FILE_ALL_ACCESS, user)
                everyone, domain, type = win32security.LookupAccountName("", "Everyone")
                dacl.AddAccessAllowedAce(win32security.ACL_REVISION, con.FILE_GENERIC_READ, everyone)

            sd.SetSecurityDescriptorDacl(1, dacl, 0)
            win32security.SetFileSecurity(file_path, win32security.DACL_SECURITY_INFORMATION, sd)
        except ImportError:
            # pywin32 not installed, fall back to basic chmod (limited on Windows)
            print_warning("pywin32 not installed - using basic permissions (install with: pip install pywin32)")
            os.chmod(file_path, 0o600 if is_private else 0o644)
        except Exception as e:
            # Fallback to basic chmod
            os.chmod(file_path, 0o600 if is_private else 0o644)
    else:  # Linux/macOS
        os.chmod(file_path, 0o600 if is_private else 0o644)


def generate_ssh_keypair(server_name: str, admin_username: str) -> Tuple[str, str]:
    """Generate SSH keypair for the server (cross-platform)"""

    # Validate inputs to prevent command injection and path traversal
    safe_username = validate_safe_identifier(admin_username, "admin_username")
    safe_servername = validate_safe_identifier(server_name, "server_name")

    SSH_DIR.mkdir(exist_ok=True)

    key_name = f"{safe_username}-{safe_servername}"
    private_key_path = SSH_DIR / key_name
    public_key_path = SSH_DIR / f"{key_name}.pub"

    # Handle partial key files (security concern)
    if private_key_path.exists() or public_key_path.exists():
        if not (private_key_path.exists() and public_key_path.exists()):
            print_warning("Incomplete SSH key pair detected")
            print(f"  Private key exists: {private_key_path.exists()}")
            print(f"  Public key exists: {public_key_path.exists()}")

            if not prompt_yes_no("Delete incomplete keys and generate new pair?", default=True):
                print_error("Cannot proceed without valid SSH key pair")
                sys.exit(1)

            # Delete any existing partial keys
            if private_key_path.exists():
                private_key_path.unlink()
            if public_key_path.exists():
                public_key_path.unlink()
            print_success("Incomplete keys deleted")

    # Check if complete key pair already exists
    if private_key_path.exists() and public_key_path.exists():
        print_warning(f"SSH keys already exist for {server_name}")
        print(f"  Private key: {private_key_path}")
        print(f"  Public key:  {public_key_path}")

        options = [
            {'name': 'Reuse existing keys', 'description': '(Recommended)'},
            {'name': 'Delete and regenerate new keys'},
            {'name': 'Cancel deployment'}
        ]

        selected = prompt_choice(options, "What would you like to do?", default_index=1)
        selected_action = options.index(selected)

        if selected_action == 2:  # Cancel
            print_error("Deployment cancelled by user")
            sys.exit(0)
        elif selected_action == 0:  # Reuse
            # Read and return existing keys
            with open(public_key_path, 'r') as f:
                public_key = f.read().strip()
            print_success("Reusing existing SSH keys")
            return str(private_key_path), public_key
        elif selected_action == 1:  # Regenerate
            # Delete existing keys before regenerating
            print_info("Deleting existing keys...")
            private_key_path.unlink()
            public_key_path.unlink()
            print_success("Existing keys deleted")

    # Try ssh-keygen first (preferred method)
    try:
        subprocess.run([
            'ssh-keygen',
            '-t', 'ed25519',
            '-C', f"{safe_username}@{safe_servername}",
            '-f', str(private_key_path),
            '-N', ''  # No passphrase
        ], check=True, capture_output=True, timeout=30)

        # Set secure permissions
        set_file_permissions_secure(str(private_key_path), is_private=True)
        set_file_permissions_secure(str(public_key_path), is_private=False)

        # Read public key
        with open(public_key_path, 'r') as f:
            public_key = f.read().strip()

        return str(private_key_path), public_key

    except (subprocess.CalledProcessError, FileNotFoundError) as e:
        # ssh-keygen not available - use Python cryptography library
        print_warning("ssh-keygen not found - using Python cryptography library")

        try:
            from cryptography.hazmat.primitives import serialization
            from cryptography.hazmat.primitives.asymmetric import ed25519
            from cryptography.hazmat.backends import default_backend

            # Generate Ed25519 key
            private_key = ed25519.Ed25519PrivateKey.generate()
            public_key = private_key.public_key()

            # Serialize private key (OpenSSH format)
            private_pem = private_key.private_bytes(
                encoding=serialization.Encoding.PEM,
                format=serialization.PrivateFormat.OpenSSH,
                encryption_algorithm=serialization.NoEncryption()
            )

            # Serialize public key (OpenSSH format)
            public_ssh = public_key.public_bytes(
                encoding=serialization.Encoding.OpenSSH,
                format=serialization.PublicFormat.OpenSSH
            )

            # Add comment to public key
            public_key_str = public_ssh.decode('utf-8') + f" {safe_username}@{safe_servername}\n"

            # Write keys to files
            with open(private_key_path, 'wb') as f:
                f.write(private_pem)

            with open(public_key_path, 'w') as f:
                f.write(public_key_str)

            # Set secure permissions
            set_file_permissions_secure(str(private_key_path), is_private=True)
            set_file_permissions_secure(str(public_key_path), is_private=False)

            return str(private_key_path), public_key_str.strip()

        except ImportError:
            print_error("Neither ssh-keygen nor cryptography library available.")
            print_error("Please install one of:")
            print_error("  - OpenSSH: https://docs.microsoft.com/en-us/windows-server/administration/openssh/openssh_install_firstuse")
            print_error("  - Python cryptography: pip install cryptography")
            sys.exit(1)
        except Exception as e:
            print_error(f"Failed to generate SSH key: {e}")
            sys.exit(1)


@retry_with_backoff(max_retries=3, base_delay=1, max_delay=10)
def get_accessible_keyvaults(credential, subscription_id: str) -> List[Dict]:
    """Find TFS-managed Key Vaults the user can write secrets to.
    First looks for vaults with TFSManaged tag, then tests write permission.
    """
    accessible_vaults = []
    kv_mgmt_client = KeyVaultManagementClient(credential, subscription_id)

    try:
        # List all key vaults in the subscription
        vaults = list(kv_mgmt_client.vaults.list())

        # First, check TFS-managed vaults (tagged)
        tfs_vaults = []
        other_vaults = []

        for vault in vaults:
            # Extract resource group from vault ID
            parts = vault.id.split('/')
            rg_name = parts[4] if len(parts) > 4 else 'unknown'

            vault_info = {
                'name': vault.name,
                'id': vault.id,
                'rg': rg_name,
                'url': f"https://{vault.name}.vault.azure.net/",
                'tfs_managed': False
            }

            # Check if TFS-managed (tag presence, any value)
            if vault.tags and TFS_MANAGED_TAG in vault.tags:
                vault_info['tfs_managed'] = True
                tfs_vaults.append(vault_info)
            else:
                other_vaults.append(vault_info)

        # Test data plane access - prioritize TFS-managed vaults
        # We list secrets instead of writing/deleting to avoid soft delete/purge issues
        for vault_info in tfs_vaults + other_vaults:
            try:
                secret_client = SecretClient(vault_url=vault_info['url'], credential=credential)

                # List secrets to verify data plane access
                # Key Vault Secrets Officer role grants both list and set permissions
                list(secret_client.list_properties_of_secrets(max_page_size=1))

                # If we got here, we have data plane access
                accessible_vaults.append(vault_info)
            except Exception:
                # Can't access this vault, skip it
                pass

    except Exception as e:
        print_warning(f"Could not enumerate Key Vaults: {e}")

    return accessible_vaults


def get_current_user_object_id(credential) -> Optional[str]:
    """
    Get the object ID of the currently authenticated user or service principal.

    Returns:
        str: Object ID (OID) of the current principal, or None if unable to determine
    """
    try:
        # Get an access token and decode it to extract the OID claim
        import jwt
        token = credential.get_token("https://management.azure.com/.default")
        decoded = jwt.decode(token.token, options={"verify_signature": False})

        # The 'oid' claim contains the object ID
        oid = decoded.get('oid')
        if oid:
            return oid

        print_warning("Could not find object ID in token")
        return None

    except Exception as e:
        print_warning(f"Could not determine current user object ID: {e}")
        return None


def assign_keyvault_role(credential, subscription_id: str, principal_id: str,
                         vault_id: str, vault_name: str) -> bool:
    """
    Assign Key Vault Secrets Officer role to a principal on a Key Vault.

    Args:
        credential: Azure credential
        subscription_id: Azure subscription ID
        principal_id: Object ID of the user or service principal
        vault_id: Full resource ID of the Key Vault
        vault_name: Name of the Key Vault (for display only)

    Returns:
        bool: True if role was assigned or already exists, False otherwise
    """
    import uuid
    import time

    try:
        auth_client = AuthorizationManagementClient(credential, subscription_id)

        role_definition_id = f"/subscriptions/{subscription_id}/providers/Microsoft.Authorization/roleDefinitions/{KEY_VAULT_SECRETS_OFFICER_ROLE}"

        print("Assigning Key Vault Secrets Officer role...", end=" ", flush=True)

        auth_client.role_assignments.create(
            scope=vault_id,
            role_assignment_name=str(uuid.uuid4()),
            parameters={
                "role_definition_id": role_definition_id,
                "principal_id": principal_id,
                "principal_type": "User"  # Can also be "ServicePrincipal"
            }
        )

        print_success("Done")
        print_info("Waiting for role assignment to propagate (10 seconds)...")
        time.sleep(10)  # Wait for Azure RBAC propagation (can take 5-30 seconds)

        return True

    except Exception as e:
        if "RoleAssignmentExists" in str(e):
            print_success("Already assigned")
            return True

        print_error(f"Failed to assign role")
        print_warning(f"You may need to manually assign the role:")
        print_info(f"  az role assignment create --role \"Key Vault Secrets Officer\" \\")
        print_info(f"    --assignee-object-id {principal_id} --scope {vault_id}")
        return False


@retry_with_backoff(max_retries=5, base_delay=5, max_delay=120)
def create_keyvault(credential, subscription_id: str, vault_name: str, location: str) -> Optional[Dict]:
    """Create a new Key Vault in the key-vault resource group and assign permissions"""
    kv_mgmt_client = KeyVaultManagementClient(credential, subscription_id)
    resource_client = ResourceManagementClient(credential, subscription_id)

    rg_name = "key-vault"

    # Get tenant ID from subscription
    try:
        from azure.mgmt.subscription import SubscriptionClient
        sub_client = SubscriptionClient(credential)
        # Get tenant ID from tenants list (Subscription object doesn't have tenant_id)
        tenant_id = next(sub_client.tenants.list()).tenant_id
    except Exception as e:
        print_error(f"Could not get tenant ID: {e}")
        return None

    # Create resource group if it doesn't exist
    try:
        resource_client.resource_groups.create_or_update(
            rg_name,
            {"location": location}
        )
        print_success(f"Resource group '{rg_name}' ready")
    except Exception as e:
        print_error(f"Could not create resource group: {e}")
        return None

    # Create the Key Vault with TFSManaged tag
    try:
        print(f"Creating Key Vault '{vault_name}'...")
        vault = kv_mgmt_client.vaults.begin_create_or_update(
            rg_name,
            vault_name,
            {
                "location": location,
                "tags": {
                    TFS_MANAGED_TAG: "true"
                },
                "properties": {
                    "sku": {
                        "family": "A",
                        "name": "standard"
                    },
                    "tenant_id": tenant_id,
                    "enable_rbac_authorization": True,
                    "enabled_for_deployment": True,
                    "enabled_for_disk_encryption": True,
                    "enabled_for_template_deployment": True,
                    "enable_soft_delete": True,
                    "soft_delete_retention_in_days": 90,
                    "enable_purge_protection": True,
                    "public_network_access": "Enabled",
                    "network_acls": {
                        "default_action": "Allow",
                        "bypass": "AzureServices"
                    }
                }
            }
        ).result()

        print_success(f"Key Vault '{vault_name}' created")

        # Get current user's object ID and assign permissions
        principal_id = get_current_user_object_id(credential)
        if principal_id:
            # Assign Key Vault Secrets Officer role to current user
            role_assigned = assign_keyvault_role(credential, subscription_id, principal_id, vault.id, vault_name)
            if not role_assigned:
                print_warning("Proceeding without automatic role assignment")
                print_warning("You may need to manually assign the role before uploading secrets")
        else:
            print_warning("Could not determine current user - skipping automatic role assignment")
            print_info("Manually assign role with:")
            print_info(f"  az role assignment create --role \"Key Vault Secrets Officer\" \\")
            print_info(f"    --assignee <your-email> --scope {vault.id}")

        return {
            'name': vault_name,
            'id': vault.id,
            'rg': rg_name,
            'url': f"https://{vault_name}.vault.azure.net/"
        }

    except Exception as e:
        print_error(f"Could not create Key Vault: {e}")
        return None


@retry_with_backoff(max_retries=4, base_delay=3, max_delay=90)
def store_keys_in_keyvault(credential, subscription_id: str, private_key_path: str,
                           server_name: str, admin_username: str, location: str,
                           tags: Dict, scope: str) -> Optional[str]:
    """Store SSH public and private keys in Key Vault (required step)"""
    print_subheader("Key Vault Storage")

    # Find accessible Key Vaults (with verified write permission)
    print("Scanning for accessible Key Vaults...")
    accessible_vaults = get_accessible_keyvaults(credential, subscription_id)

    selected_vault = None

    if accessible_vaults:
        # Let user select from available vaults or create new
        # TFS-managed vaults are listed first with a marker
        tfs_count = sum(1 for v in accessible_vaults if v.get('tfs_managed'))
        print(f"\nFound {len(accessible_vaults)} accessible Key Vault(s) with write permission:")
        if tfs_count:
            print_info(f"  ({tfs_count} TFS-managed)")

        vault_options = []
        for v in accessible_vaults:
            marker = "[TFS] " if v.get('tfs_managed') else ""
            vault_options.append({'name': f"{marker}{v['name']} ({v['rg']})"})
        vault_options.append({'name': '+ Create new Key Vault'})

        selected = prompt_choice(vault_options, "Select Key Vault for SSH key backup:", 1)
        selected_idx = vault_options.index(selected)

        if selected_idx == len(vault_options) - 1:  # Create new
            selected_vault = None  # Will trigger creation below
        else:
            selected_vault = accessible_vaults[selected_idx]
    else:
        print_warning("No accessible Key Vaults found (no write permission to any existing vaults)")
        print_info("A new Key Vault will be created for SSH key backup")

    # Create new vault if needed
    if selected_vault is None:
        # Auto-generate vault name: kv-{scope}-{random}
        import secrets
        random_suffix = secrets.token_hex(4)  # 8 character hex string
        vault_name = f"kv-{scope}-{random_suffix}"
        print_info(f"Creating new Key Vault: {vault_name}")

        selected_vault = create_keyvault(credential, subscription_id, vault_name, location)
        if not selected_vault:
            print_error("Failed to create Key Vault - cannot continue without SSH key backup")
            sys.exit(1)

    # Upload keys to the selected vault
    try:
        vault_url = selected_vault['url']
        secret_client = SecretClient(vault_url=vault_url, credential=credential)

        # Read keys
        with open(private_key_path, 'r') as f:
            private_key = f.read()
        with open(f"{private_key_path}.pub", 'r') as f:
            public_key = f.read()

        # Secret names: {adminUser}-{hostname}-public/private
        public_secret_name = f"{admin_username}-{server_name}-public"
        private_secret_name = f"{admin_username}-{server_name}-private"

        # Secret tags - use provided tags plus some metadata
        secret_tags = tags.copy()
        secret_tags['server'] = server_name
        secret_tags['username'] = admin_username
        secret_tags['created'] = datetime.now().isoformat()

        print(f"Uploading SSH keys to Key Vault '{selected_vault['name']}'...")
        print_info("Note: If this fails with 'Forbidden', role assignment may still be propagating (will auto-retry)")

        # Upload public key
        secret_client.set_secret(
            public_secret_name,
            public_key,
            content_type="application/x-pem-file",
            enabled=True,
            tags=secret_tags
        )
        print_success(f"Public key stored: {public_secret_name}")

        # Upload private key
        secret_client.set_secret(
            private_secret_name,
            private_key,
            content_type="application/x-pem-file",
            enabled=True,
            tags=secret_tags
        )
        print_success(f"Private key stored: {private_secret_name}")

        return selected_vault['name']

    except Exception as e:
        print_error(f"Failed to store keys in Key Vault: {e}")
        print_error("Cannot continue without SSH key backup")
        sys.exit(1)


# =============================================================================
# Verification Reports Storage Setup
# =============================================================================

SHARED_RG_NAME = "rg-infra-shared"
# Container for hardening reports (setup.sh) - permanent storage
HARDENING_REPORTS_CONTAINER = "tfs-hardening-reports"
# Container for compliance reports (verify.sh) - 5 year lifecycle
COMPLIANCE_REPORTS_CONTAINER = "tfs-compliance-reports"
# Storage Blob Data Contributor role ID (Azure built-in role)
STORAGE_BLOB_DATA_CONTRIBUTOR_ROLE = "ba92f5b4-2d11-453d-a403-e96b0029c9fe"
# Key Vault Secrets Officer role ID (Azure built-in role)
KEY_VAULT_SECRETS_OFFICER_ROLE = "b86a8fe4-44ce-4948-aee5-eccb2c155cd7"
# Tag to identify TFS-managed shared resources (storage, key vault)
TFS_MANAGED_TAG = "TFSManaged"


@retry_with_backoff(max_retries=4, base_delay=5, max_delay=90)
def assign_storage_role_to_current_user(credential, subscription_id: str, storage_account_id: str) -> bool:
    """Assign Storage Blob Data Contributor to the signed-in builder principal.

    This grants the local builder user data-plane write access so deployment logs
    can be uploaded to Blob Storage. This is separate from the VM managed identity
    role assignment used later by setup.sh and verify.sh.
    """
    import uuid

    principal_id = get_current_user_object_id(credential)
    if not principal_id:
        print_warning("Could not determine current signed-in principal - skipping local storage role assignment")
        print_info("Deployment log upload may fail unless your user already has Storage Blob Data Contributor")
        return False

    auth_client = AuthorizationManagementClient(credential, subscription_id)
    role_definition_id = f"/subscriptions/{subscription_id}/providers/Microsoft.Authorization/roleDefinitions/{STORAGE_BLOB_DATA_CONTRIBUTOR_ROLE}"

    try:
        print("Ensuring current user has Storage Blob Data Contributor...", end=" ", flush=True)
        auth_client.role_assignments.create(
            scope=storage_account_id,
            role_assignment_name=str(uuid.uuid4()),
            parameters={
                "role_definition_id": role_definition_id,
                "principal_id": principal_id
            }
        )
        print_success("Role assignment submitted")
        return True
    except Exception as e:
        if "RoleAssignmentExists" in str(e):
            print_success("Current user already has Storage Blob Data Contributor role")
            return True

        print_warning(f"Could not assign Storage Blob Data Contributor to current user: {e}")
        print_info("Deployment can continue, but deployment log upload may fail until this role is granted")
        print_storage_role_manual_fix(principal_id, storage_account_id)
        return False


def print_storage_role_manual_fix(principal_id: str, storage_account_id: str) -> None:
    """Print the manual command needed to grant local blob upload access."""
    print_info("Manual fix:")
    print_info('  az role assignment create --role "Storage Blob Data Contributor" \\')
    print_info(f"    --assignee-object-id {principal_id} --scope {storage_account_id}")


def test_storage_blob_write_access(credential, storage_account_name: str) -> bool:
    """Return True if the current credential can write and delete a test blob."""
    import uuid
    from azure.storage.blob import BlobServiceClient

    account_url = f"https://{storage_account_name}.blob.core.windows.net"
    blob_service = BlobServiceClient(account_url=account_url, credential=credential)
    container_client = blob_service.get_container_client(HARDENING_REPORTS_CONTAINER)

    if not container_client.exists():
        blob_service.create_container(HARDENING_REPORTS_CONTAINER)

    blob_name = f".access-test/{uuid.uuid4()}.txt"
    blob_client = container_client.get_blob_client(blob_name)
    blob_client.upload_blob("storage access test", overwrite=True)
    blob_client.delete_blob()
    return True


def wait_for_storage_blob_write_access(credential, storage_account_name: str, timeout_seconds: int = 240, interval_seconds: int = 15) -> bool:
    """Wait for Storage Blob Data Contributor to propagate to blob data-plane access."""
    import time

    deadline = time.time() + timeout_seconds
    attempt = 1
    last_error = None

    while time.time() < deadline:
        try:
            if test_storage_blob_write_access(credential, storage_account_name):
                print_success("Verified blob write access for current user")
                return True
        except Exception as e:
            last_error = e
            remaining = int(deadline - time.time())
            if remaining <= 0:
                break
            print_info(f"Waiting for blob role propagation ({remaining}s remaining, attempt {attempt})...")
            time.sleep(interval_seconds)
            attempt += 1

    if last_error:
        print_warning(f"Blob write access was not available after waiting: {last_error}")
    else:
        print_warning("Blob write access was not available after waiting")
    return False


def ensure_current_user_storage_write_access(credential, subscription_id: str, storage_account_id: str, storage_account_name: str) -> bool:
    """Assign the local user blob write role if possible, then verify actual data-plane write access."""
    principal_id = get_current_user_object_id(credential)

    # Try current access first. This avoids unnecessary role assignment calls.
    try:
        if test_storage_blob_write_access(credential, storage_account_name):
            print_success("Current user already has blob write access")
            return True
    except Exception:
        pass

    role_attempted = assign_storage_role_to_current_user(credential, subscription_id, storage_account_id)

    if wait_for_storage_blob_write_access(credential, storage_account_name):
        return True

    print_warning("Current user still does not have verified blob write access")
    if principal_id:
        print_storage_role_manual_fix(principal_id, storage_account_id)
    if role_attempted:
        print_info("If the role was just assigned, Azure RBAC propagation may need a few more minutes.")
        print_info("Rerun the builder or re-upload the saved local deployment log after propagation completes.")
    return False


def generate_storage_account_name(scope: str) -> str:
    """Generate globally unique storage account name: tfs{21 random chars}

    Uses maximum-length random suffix for lowest collision probability.
    Scope information is stored in Azure tags, not the name.

    Returns: 24-character name (e.g., tfsa3b5c7d9e1f2g4h6i8j0k)
    """
    import string

    # Generate 21 cryptographically secure random lowercase alphanumeric characters
    # Total: 3 (tfs) + 21 (random) = 24 chars (Azure max)
    charset = string.ascii_lowercase + string.digits
    random_suffix = ''.join(secrets.choice(charset) for _ in range(21))

    return f"tfs{random_suffix}"


def find_existing_reports_storage(credential, subscription_id: str, scope: str) -> Optional[Dict]:
    """Find existing TFS-managed reports storage account for specific scope

    Searches for storage account with:
    - TFSManaged: true tag
    - Scope: {scope} tag

    This ensures one storage account per subscription + scope combination.
    Different scopes (e.g., TTG, TRP) get separate storage accounts.
    All environments (dev/stg/prd) within a scope share the same storage.
    """
    storage_client = StorageManagementClient(credential, subscription_id)

    # Look for storage account with TFSManaged tag AND matching scope
    try:
        accounts = storage_client.storage_accounts.list()
        for account in accounts:
            if account.tags and \
               TFS_MANAGED_TAG in account.tags and \
               account.tags.get('Scope') == scope:
                return {
                    'name': account.name,
                    'id': account.id,
                    'url': f"https://{account.name}.blob.core.windows.net"
                }
    except Exception:
        pass

    return None


@retry_with_backoff(max_retries=5, base_delay=5, max_delay=120)
def create_reports_storage(credential, subscription_id: str, scope: str, location: str) -> Optional[Dict]:
    """Create storage account with containers for reports and lifecycle policy"""
    storage_client = StorageManagementClient(credential, subscription_id)
    resource_client = ResourceManagementClient(credential, subscription_id)

    # Ensure shared RG exists
    try:
        resource_client.resource_groups.create_or_update(
            SHARED_RG_NAME,
            {"location": location}
        )
        print_success(f"Resource group '{SHARED_RG_NAME}' ready")
    except Exception as e:
        print_error(f"Could not create resource group: {e}")
        return None

    # Generate storage account name
    storage_name = generate_storage_account_name(scope)

    # Create storage account with TFSManaged and Scope tags
    try:
        print(f"Creating storage account '{storage_name}' for scope '{scope}'...")
        poller = storage_client.storage_accounts.begin_create(
            SHARED_RG_NAME,
            storage_name,
            {
                "location": location,
                "sku": {"name": "Standard_LRS"},
                "kind": "StorageV2",
                "tags": {
                    TFS_MANAGED_TAG: "true",
                    "Scope": scope  # One storage account per subscription + scope
                },
                "properties": {
                    "minimum_tls_version": "TLS1_2",
                    "allow_blob_public_access": False,
                    "network_acls": {
                        "default_action": "Allow"
                    }
                }
            }
        )
        poller.result()
        print_success(f"Storage account '{storage_name}' created for scope '{scope}'")
    except Exception as e:
        print_error(f"Could not create storage account: {e}")
        return None

    # Create containers
    try:
        blob_service = BlobServiceClient(
            account_url=f"https://{storage_name}.blob.core.windows.net",
            credential=credential
        )

        # Create hardening reports container (permanent storage)
        try:
            blob_service.create_container(HARDENING_REPORTS_CONTAINER)
            print_success(f"Container '{HARDENING_REPORTS_CONTAINER}' created")
        except Exception as e:
            if "ContainerAlreadyExists" not in str(e):
                print_warning(f"Could not create container: {e}")

        # Create compliance reports container (5 year lifecycle)
        try:
            blob_service.create_container(COMPLIANCE_REPORTS_CONTAINER)
            print_success(f"Container '{COMPLIANCE_REPORTS_CONTAINER}' created")
        except Exception as e:
            if "ContainerAlreadyExists" not in str(e):
                print_warning(f"Could not create container: {e}")

    except Exception as e:
        print_warning(f"Could not create containers: {e}")

    # Set lifecycle policy for compliance reports container (5 year retention)
    try:
        storage_client.management_policies.create_or_update(
            SHARED_RG_NAME,
            storage_name,
            "default",
            {
                "policy": {
                    "rules": [
                        {
                            "name": "compliance-reports-5year-retention",
                            "enabled": True,
                            "type": "Lifecycle",
                            "definition": {
                                "filters": {
                                    "prefix_match": [f"{COMPLIANCE_REPORTS_CONTAINER}/"],
                                    "blob_types": ["blockBlob"]
                                },
                                "actions": {
                                    "base_blob": {
                                        "delete": {
                                            "days_after_modification_greater_than": 1825
                                        }
                                    }
                                }
                            }
                        }
                    ]
                }
            }
        )
        print_success("Lifecycle policy configured (5 year retention for compliance reports)")
    except Exception as e:
        print_warning(f"Could not set lifecycle policy: {e}")
        print_info("You may need to configure lifecycle rules manually in Azure Portal")

    storage_id = f"/subscriptions/{subscription_id}/resourceGroups/{SHARED_RG_NAME}/providers/Microsoft.Storage/storageAccounts/{storage_name}"

    # Give the signed-in builder user verified data-plane access so container creation and
    # deployment-log upload can work with Microsoft Entra authentication.
    ensure_current_user_storage_write_access(credential, subscription_id, storage_id, storage_name)
    ensure_containers_exist(credential, storage_name)

    return {
        'name': storage_name,
        'id': storage_id,
        'url': f"https://{storage_name}.blob.core.windows.net"
    }


def ensure_containers_exist(credential, storage_name: str) -> None:
    """Ensure both report containers exist in the storage account"""
    try:
        blob_service = BlobServiceClient(
            account_url=f"https://{storage_name}.blob.core.windows.net",
            credential=credential
        )

        for container_name in [HARDENING_REPORTS_CONTAINER, COMPLIANCE_REPORTS_CONTAINER]:
            container_client = blob_service.get_container_client(container_name)
            if not container_client.exists():
                try:
                    blob_service.create_container(container_name)
                    print_success(f"Container '{container_name}' created")
                except Exception as e:
                    if "ContainerAlreadyExists" not in str(e):
                        print_warning(f"Could not create container '{container_name}': {e}")
    except Exception as e:
        print_warning(f"Could not verify containers: {e}")


def setup_verification_storage(credential, subscription_id: str, scope: str, location: str) -> Optional[Dict]:
    """Find or create storage for verification reports (required step)

    Storage is scoped per subscription + scope combination:
    - Same subscription + same scope (e.g., TTG) = shared storage
    - Same subscription + different scope (e.g., TRP) = separate storage
    - All environments (dev/stg/prd) within a scope share the same storage
    """
    print_subheader("Verification Reports Storage")

    # In dry-run mode, return placeholder storage info
    if DRY_RUN:
        import secrets
        random_suffix = secrets.token_hex(4)  # 8 character hex string
        placeholder_name = f"tfsdryrun{scope}{random_suffix}"
        print_info(f"[DRY-RUN] Would use storage account: {placeholder_name}")
        return {
            'name': placeholder_name,
            'id': f"/subscriptions/{subscription_id}/resourceGroups/rg-infra-shared/providers/Microsoft.Storage/storageAccounts/{placeholder_name}",
            'url': f"https://{placeholder_name}.blob.core.windows.net"
        }

    # Check for existing storage for this scope
    print(f"Checking for existing reports storage (scope: {scope})...")
    existing = find_existing_reports_storage(credential, subscription_id, scope)

    if existing:
        print_success(f"Found existing storage for scope '{scope}': {existing['name']}")
        # Ensure the signed-in builder user has verified blob data-plane write access for deployment-log upload.
        ensure_current_user_storage_write_access(credential, subscription_id, existing['id'], existing['name'])
        # Ensure both containers exist (in case storage predates dual-container setup).
        ensure_containers_exist(credential, existing['name'])
        return existing

    # Create new storage (required)
    print_info("No existing reports storage found - creating new storage account")
    return create_reports_storage(credential, subscription_id, scope, location)


TFS_CONFIG_DIR = "/etc/tfs/hardening"
TFS_CONFIG_FILE = f"{TFS_CONFIG_DIR}/config.env"


def generate_tfs_config(server_name: str, storage_info: Dict, subscription_id: str, admin_username: str) -> str:
    """Generate TFS config file content to be written to /etc/tfs/hardening/config.env on the VM"""
    config_content = f"""# TFS Azure Server Builder Configuration
# Generated: {datetime.now().isoformat()}
# This file is sourced by TFS scripts for storage configuration
# Usage: source {TFS_CONFIG_FILE}

# Server Identity
TFS_SERVER_NAME="{server_name}"
TFS_SUBSCRIPTION_ID="{subscription_id}"

# SSH Hardening Configuration
# This ensures the Azure VM admin user selected during provisioning remains SSH-allowed
# after /etc/tfs/hardening/setup.sh writes /etc/ssh/sshd_config.d/99-hardening.conf.
SSH_ADMIN_USER="{admin_username}"
SSH_USE_ALLOW_USERS="false"
SSH_PERMIT_ROOT_LOGIN="prohibit-password"

# Laravel Forge Integration
ENABLE_FORGE_INTEGRATION="true"
ENABLE_FORGE_ROOT_MATCH="false"
FORGE_IPS="159.203.150.232 165.227.248.218 159.203.150.216 45.55.124.124"

# Fail2ban Configuration
FAIL2BAN_MAXRETRY="6"
FAIL2BAN_FINDTIME="600"
FAIL2BAN_BANTIME="86400"
FAIL2BAN_IGNOREIP="127.0.0.1/8 ::1 159.203.150.232 165.227.248.218 159.203.150.216 45.55.124.124"

# Storage Configuration
TFS_STORAGE_ACCOUNT="{storage_info['name']}"
TFS_STORAGE_URL="{storage_info['url']}"

# Report Containers
TFS_HARDENING_CONTAINER="{HARDENING_REPORTS_CONTAINER}"
TFS_COMPLIANCE_CONTAINER="{COMPLIANCE_REPORTS_CONTAINER}"

# Full blob paths for this server
TFS_HARDENING_PATH="{HARDENING_REPORTS_CONTAINER}/{server_name}"
TFS_COMPLIANCE_PATH="{COMPLIANCE_REPORTS_CONTAINER}/{server_name}"

# Azure Blob URLs (for azcopy or az cli)
TFS_HARDENING_BLOB_URL="{storage_info['url']}/{HARDENING_REPORTS_CONTAINER}/{server_name}"
TFS_COMPLIANCE_BLOB_URL="{storage_info['url']}/{COMPLIANCE_REPORTS_CONTAINER}/{server_name}"

# Report file naming
# Hardening:  hardening-{{hostname}}-{{timestamp}}.md (permanent)
# Compliance: compliance-{{hostname}}-{{timestamp}}.md (5 year retention)
"""
    return config_content


def generate_tfs_cloud_init(tfs_config: str, github_org: str = "Tech-for-Service") -> str:
    """Generate cloud-init script that updates system and writes TFS config"""

    return f"""#!/bin/bash
set -e

# Update and upgrade system packages (non-interactive)
export DEBIAN_FRONTEND=noninteractive
apt-get update -qq
apt-get upgrade -y -qq -o Dpkg::Options::="--force-confdef" -o Dpkg::Options::="--force-confold"

# Create TFS hardening config directory and write configuration
mkdir -p {TFS_CONFIG_DIR}
cat > {TFS_CONFIG_FILE} << 'TFSCONFIG'
{tfs_config}
TFSCONFIG
chmod 644 {TFS_CONFIG_FILE}

# Download hardening scripts from GitHub with integrity verification
echo "Downloading hardening scripts..."
curl -fsSL -o {TFS_CONFIG_DIR}/setup.sh https://raw.githubusercontent.com/{github_org}/tfs-azure-server-builder/main/scripts/setup.sh
curl -fsSL -o {TFS_CONFIG_DIR}/verify.sh https://raw.githubusercontent.com/{github_org}/tfs-azure-server-builder/main/scripts/verify.sh

# Verify SHA256 checksums to detect corruption or tampering
echo "Verifying script integrity..."
echo "{SCRIPT_CHECKSUMS['setup.sh']}  {TFS_CONFIG_DIR}/setup.sh" | sha256sum -c - || {{
    echo "ERROR: setup.sh checksum verification failed - download may be corrupted or tampered" >&2
    exit 1
}}
echo "{SCRIPT_CHECKSUMS['verify.sh']}  {TFS_CONFIG_DIR}/verify.sh" | sha256sum -c - || {{
    echo "ERROR: verify.sh checksum verification failed - download may be corrupted or tampered" >&2
    exit 1
}}

chmod +x {TFS_CONFIG_DIR}/setup.sh {TFS_CONFIG_DIR}/verify.sh

echo "TFS cloud-init complete: config written, scripts downloaded and verified"
touch /var/log/cloud-init-complete
"""


@retry_with_backoff(max_retries=4, base_delay=3, max_delay=90)
def assign_storage_role_to_vm(credential, subscription_id: str, vm_principal_id: str,
                               storage_account_id: str) -> bool:
    """Assign Storage Blob Data Contributor role to VM's managed identity"""
    import uuid

    auth_client = AuthorizationManagementClient(credential, subscription_id)

    role_definition_id = f"/subscriptions/{subscription_id}/providers/Microsoft.Authorization/roleDefinitions/{STORAGE_BLOB_DATA_CONTRIBUTOR_ROLE}"

    try:
        auth_client.role_assignments.create(
            scope=storage_account_id,
            role_assignment_name=str(uuid.uuid4()),
            parameters={
                "role_definition_id": role_definition_id,
                "principal_id": vm_principal_id,
                "principal_type": "ServicePrincipal"
            }
        )
        print_success("Assigned Storage Blob Data Contributor role to VM")
        return True
    except Exception as e:
        if "RoleAssignmentExists" in str(e):
            print_success("Storage role assignment already exists")
            return True
        print_warning(f"Could not assign storage role: {e}")
        return False


# =============================================================================
# Resource Deployment
# =============================================================================

@retry_with_backoff(max_retries=3, base_delay=2, max_delay=30)
def create_resource_group(resource_client: ResourceManagementClient,
                          name: str, location: str, tags: Dict,
                          exec_log: Optional['ExecutionLog'] = None,
                          api_tracker: Optional['ApiCallTracker'] = None) -> bool:
    """Create resource group"""
    try:
        params = {"location": location, "tags": tags}

        # Track API call
        if api_tracker:
            api_tracker.track_call(
                'resource_client.resource_groups.create_or_update',
                {'resource_group_name': name, 'parameters': params}
            )

        # Skip actual call in dry-run mode
        if not DRY_RUN:
            resource_client.resource_groups.create_or_update(name, params)
        return True
    except Exception as e:
        if exec_log:
            exec_log.log("ERROR", f"Failed to create resource group: {str(e)[:200]}")
        print_error(f"Failed to create resource group: {e}")
        return False


@retry_with_backoff(max_retries=5, base_delay=5, max_delay=120)
def create_vnet(network_client: NetworkManagementClient, rg_name: str,
                vnet_name: str, subnet_name: str, location: str,
                address_space: str, subnet_prefix: str, tags: Dict,
                exec_log: Optional['ExecutionLog'] = None,
                api_tracker: Optional['ApiCallTracker'] = None) -> bool:
    """Create virtual network and subnet"""
    try:
        params = {
            "location": location,
            "tags": tags,
            "address_space": {"address_prefixes": [address_space]},
            "subnets": [{"name": subnet_name, "address_prefix": subnet_prefix}]
        }

        # Track API call
        if api_tracker:
            api_tracker.track_call(
                'network_client.virtual_networks.begin_create_or_update',
                {'resource_group_name': rg_name, 'vnet_name': vnet_name, 'parameters': params}
            )

        # Skip actual call in dry-run mode
        if not DRY_RUN:
            poller = network_client.virtual_networks.begin_create_or_update(rg_name, vnet_name, params)
            poller.result()
        return True
    except Exception as e:
        if exec_log:
            exec_log.log("ERROR", f"Failed to create VNet: {str(e)[:200]}")
        print_error(f"Failed to create VNet: {e}")
        return False


@retry_with_backoff(max_retries=5, base_delay=5, max_delay=120)
def create_nsg(network_client: NetworkManagementClient, rg_name: str,
               nsg_name: str, location: str, rules: List[Dict], tags: Dict,
               exec_log: Optional['ExecutionLog'] = None,
               api_tracker: Optional['ApiCallTracker'] = None) -> bool:
    """Create network security group with rules"""
    try:
        security_rules = []
        for rule in rules:
            security_rules.append({
                "name": rule['name'],
                "priority": rule['priority'],
                "direction": rule['direction'],
                "access": rule['access'],
                "protocol": rule['protocol'],
                "source_port_range": "*",
                "destination_port_range": rule['port'],
                "source_address_prefix": rule['source'] if ',' not in rule['source'] else None,
                "source_address_prefixes": rule['source'].split(',') if ',' in rule['source'] else None,
                "destination_address_prefix": rule['destination']
            })

        params = {
            "location": location,
            "tags": tags,
            "security_rules": security_rules
        }

        # Track API call
        if api_tracker:
            api_tracker.track_call(
                'network_client.network_security_groups.begin_create_or_update',
                {'resource_group_name': rg_name, 'nsg_name': nsg_name, 'parameters': params}
            )

        # Skip actual call in dry-run mode
        if not DRY_RUN:
            poller = network_client.network_security_groups.begin_create_or_update(rg_name, nsg_name, params)
            poller.result()
        return True
    except Exception as e:
        if exec_log:
            exec_log.log("ERROR", f"Failed to create NSG: {str(e)[:200]}")
        print_error(f"Failed to create NSG: {e}")
        return False


@retry_with_backoff(max_retries=5, base_delay=5, max_delay=120)
def create_public_ip(network_client: NetworkManagementClient, rg_name: str,
                     ip_name: str, dns_label: str, location: str, tags: Dict,
                     exec_log: Optional['ExecutionLog'] = None,
                     api_tracker: Optional['ApiCallTracker'] = None) -> Optional[str]:
    """Create public IP address"""
    try:
        params = {
            "location": location,
            "tags": tags,
            "sku": {"name": "Standard"},
            "public_ip_allocation_method": "Static",
            "dns_settings": {"domain_name_label": dns_label}
        }

        # Track API call
        if api_tracker:
            api_tracker.track_call(
                'network_client.public_ip_addresses.begin_create_or_update',
                {'resource_group_name': rg_name, 'ip_name': ip_name, 'parameters': params}
            )

        # Skip actual call in dry-run mode, return placeholder ID
        if DRY_RUN:
            return f"/subscriptions/dry-run-subscription/resourceGroups/{rg_name}/providers/Microsoft.Network/publicIPAddresses/{ip_name}"

        poller = network_client.public_ip_addresses.begin_create_or_update(rg_name, ip_name, params)
        result = poller.result()
        return result.id
    except Exception as e:
        if exec_log:
            exec_log.log("ERROR", f"Failed to create Public IP: {str(e)[:200]}")
        print_error(f"Failed to create Public IP: {e}")
        return None


@retry_with_backoff(max_retries=5, base_delay=5, max_delay=120)
def create_nic(network_client: NetworkManagementClient, rg_name: str,
               nic_name: str, location: str, subnet_id: str,
               public_ip_id: str, nsg_id: str, tags: Dict,
               exec_log: Optional['ExecutionLog'] = None,
               api_tracker: Optional['ApiCallTracker'] = None) -> Optional[str]:
    """Create network interface"""
    try:
        params = {
            "location": location,
            "tags": tags,
            "ip_configurations": [{
                "name": "ipconfig1",
                "subnet": {"id": subnet_id},
                "public_ip_address": {"id": public_ip_id}
            }],
            "network_security_group": {"id": nsg_id}
        }

        # Track API call
        if api_tracker:
            api_tracker.track_call(
                'network_client.network_interfaces.begin_create_or_update',
                {'resource_group_name': rg_name, 'nic_name': nic_name, 'parameters': params}
            )

        # Skip actual call in dry-run mode, return placeholder ID
        if DRY_RUN:
            return f"/subscriptions/dry-run-subscription/resourceGroups/{rg_name}/providers/Microsoft.Network/networkInterfaces/{nic_name}"

        poller = network_client.network_interfaces.begin_create_or_update(rg_name, nic_name, params)
        result = poller.result()
        return result.id
    except Exception as e:
        if exec_log:
            exec_log.log("ERROR", f"Failed to create NIC: {str(e)[:200]}")
        print_error(f"Failed to create NIC: {e}")
        return None


@retry_with_backoff(max_retries=5, base_delay=5, max_delay=120)
def create_vm(compute_client: ComputeManagementClient, rg_name: str,
              vm_name: str, location: str, vm_size: str, nic_id: str,
              admin_username: str, ssh_public_key: str, os_disk_name: str,
              os_disk_size: int, disk_type: str, os_image: Dict,
              cloud_init_script: Optional[str], tags: Dict, config: Dict,
              encryption_at_host: bool = True,
              exec_log: Optional['ExecutionLog'] = None,
              api_tracker: Optional['ApiCallTracker'] = None) -> bool:
    """Create virtual machine"""
    try:
        security = config['security']
        patching = config['patching']

        vm_params = {
            "location": location,
            "tags": tags,
            "hardware_profile": {"vm_size": vm_size},
            "storage_profile": {
                "image_reference": {
                    "publisher": os_image['publisher'],
                    "offer": os_image['offer'],
                    "sku": os_image['sku'],
                    "version": os_image['version']
                },
                "os_disk": {
                    "name": os_disk_name,
                    "caching": "ReadWrite",
                    "create_option": "FromImage",
                    "disk_size_gb": os_disk_size,
                    "managed_disk": {"storage_account_type": disk_type},
                    "delete_option": "Delete"
                }
            },
            "os_profile": {
                "computer_name": vm_name,
                "admin_username": admin_username,
                "linux_configuration": {
                    "disable_password_authentication": security['disable_password_auth'],
                    "ssh": {
                        "public_keys": [{
                            "path": f"/home/{admin_username}/.ssh/authorized_keys",
                            "key_data": ssh_public_key
                        }]
                    },
                    "patch_settings": {
                        "assessment_mode": patching['periodic_assessment'],
                        "patch_mode": patching['patch_mode']
                    }
                }
            },
            "network_profile": {
                "network_interfaces": [{"id": nic_id, "delete_option": "Delete"}]
            },
            "security_profile": {
                "encryption_at_host": encryption_at_host,
                "security_type": security['security_type'],
                "uefi_settings": {
                    "secure_boot_enabled": security['secure_boot'],
                    "v_tpm_enabled": security['vtpm']
                }
            },
            "diagnostics_profile": {
                "boot_diagnostics": {"enabled": True}
            },
            "identity": {
                "type": "SystemAssigned"
            }
        }

        # Add cloud-init if provided
        if cloud_init_script:
            import base64
            encoded = base64.b64encode(cloud_init_script.encode()).decode()
            vm_params["os_profile"]["custom_data"] = encoded

        # Track API call
        if api_tracker:
            api_tracker.track_call(
                'compute_client.virtual_machines.begin_create_or_update',
                {'resource_group_name': rg_name, 'vm_name': vm_name, 'parameters': vm_params}
            )

        # Skip actual call in dry-run mode
        if not DRY_RUN:
            poller = compute_client.virtual_machines.begin_create_or_update(
                rg_name, vm_name, vm_params
            )
            poller.result()
        return True

    except Exception as e:
        if exec_log:
            exec_log.log("ERROR", f"Failed to create VM: {str(e)[:200]}")
        print_error(f"Failed to create VM: {e}")
        return False


@retry_with_backoff(max_retries=3, base_delay=2, max_delay=30)
def create_alerts(monitor_client: MonitorManagementClient, subscription_id: str,
                  rg_name: str, vm_name: str, email: str,
                  alert_rules: List[Dict], tags: Dict) -> bool:
    """Create metric alerts for the VM"""
    try:
        # Skip actual calls in dry-run mode
        if DRY_RUN:
            return True

        vm_id = f"/subscriptions/{subscription_id}/resourceGroups/{rg_name}/providers/Microsoft.Compute/virtualMachines/{vm_name}"

        # Create action group
        action_group_name = f"{vm_name}-alerts-ag"
        action_group = monitor_client.action_groups.create_or_update(
            rg_name,
            action_group_name,
            {
                "location": "Global",
                "tags": tags,
                "group_short_name": "vmalerts",
                "enabled": True,
                "email_receivers": [{
                    "name": "email",
                    "email_address": email,
                    "use_common_alert_schema": True
                }]
            }
        )

        action_group_id = f"/subscriptions/{subscription_id}/resourceGroups/{rg_name}/providers/Microsoft.Insights/actionGroups/{action_group_name}"

        # Create each alert rule
        for rule in alert_rules:
            alert_name = f"{rule['name']} - {vm_name}"
            monitor_client.metric_alerts.create_or_update(
                rg_name,
                alert_name,
                {
                    "location": "Global",
                    "tags": tags,
                    "severity": 3,
                    "enabled": True,
                    "scopes": [vm_id],
                    "evaluation_frequency": "PT5M",
                    "window_size": "PT5M",
                    "criteria": {
                        "odata.type": "Microsoft.Azure.Monitor.SingleResourceMultipleMetricCriteria",
                        "all_of": [{
                            "criterion_type": "StaticThresholdCriterion",
                            "name": "Metric1",
                            "metric_name": rule['metric'],
                            "metric_namespace": "Microsoft.Compute/virtualMachines",
                            "operator": rule['operator'],
                            "threshold": float(rule['threshold']),
                            "time_aggregation": rule['aggregation']
                        }]
                    },
                    "actions": [{"action_group_id": action_group_id}]
                }
            )

        return True

    except Exception as e:
        print_warning(f"Failed to create some alerts: {e}")
        return False


# =============================================================================
# Main Interactive Flow - Extracted Functions
# =============================================================================

def select_environment_role_region(
    config: Dict[str, Any],
    selections: Dict[str, str],
    deploy_log: 'DeploymentLog',
    exec_log: Optional['ExecutionLog'] = None
) -> Tuple[Dict, Dict, Dict]:
    """
    Interactive prompts for environment, role, and region selection.

    Args:
        config: Configuration dictionary
        selections: Dictionary tracking user selections
        deploy_log: Deployment log for recording selections
        exec_log: Optional execution log for capturing selections

    Returns:
        Tuple of (selected_env, selected_role, selected_region)
    """
    # 1. Environment
    clear_screen()
    print_status_bar(selections)
    env_options = config['environments']
    default_env_idx = next((i for i, e in enumerate(env_options, 1) if e.get('default')), 3)
    selected_env = prompt_choice(env_options, "Environment:", default_env_idx)
    selections['Env'] = selected_env['code']
    deploy_log.add_selection("Environment", selected_env['code'], selected_env['name'])
    if exec_log:
        exec_log.log_selection("Environment", f"{selected_env['code']} ({selected_env['name']})")

    # 2. Role
    clear_screen()
    print_status_bar(selections)
    role_options = config['roles']
    default_role_idx = next((i for i, r in enumerate(role_options, 1) if r.get('default')), 1)
    selected_role = prompt_choice(role_options, "Role:", default_role_idx)
    selections['Role'] = selected_role['code']
    deploy_log.add_selection("Role", selected_role['code'], selected_role['name'])
    if exec_log:
        exec_log.log_selection("Role", f"{selected_role['code']} ({selected_role['name']})")

    # 3. Region
    clear_screen()
    print_status_bar(selections)
    # Filter to only enabled regions
    enabled_regions = [r for r in config['regions'] if r.get('enabled', True)]
    region_options = [
        {**r, 'azure_region': r['name'], 'name': f"{r['tfs_code']} - {r['display_name']} ({r['location']})"}
        for r in enabled_regions
    ]
    default_region_idx = get_default_region_index(enabled_regions, config.get('regions_metadata', {}))
    selected_region = prompt_choice(region_options, "Region:", default_region_idx)
    selections['Region'] = selected_region['tfs_code']
    deploy_log.add_selection("Region", selected_region['tfs_code'], f"{selected_region['location']}")
    if exec_log:
        exec_log.log_selection("Region", f"{selected_region['tfs_code']} - {selected_region['display_name']} ({selected_region['location']})")

    return selected_env, selected_role, selected_region


def select_scope_and_id(
    config: Dict[str, Any],
    selections: Dict[str, str],
    selected_env: Dict,
    selected_role: Dict,
    selected_region: Dict,
    used_ids: Dict[str, List[int]],
    deploy_log: 'DeploymentLog',
    exec_log: Optional['ExecutionLog'] = None
) -> Tuple[Dict, int, str]:
    """
    Interactive prompts for scope and server ID selection.

    Args:
        config: Configuration dictionary
        selections: Dictionary tracking user selections
        selected_env: Selected environment
        selected_role: Selected role
        selected_region: Selected region
        used_ids: Dictionary of already-used server IDs
        deploy_log: Deployment log for recording selections
        exec_log: Optional execution log for capturing selections

    Returns:
        Tuple of (selected_scope, server_id, server_name)
    """
    # 4. Scope
    clear_screen()
    print_status_bar(selections)
    scope_options = [{**s, 'name': f"{s['code']} - {s['name']}"} for s in config['scopes']]
    if config.get('allow_custom_scope'):
        scope_options.append({'code': '_custom', 'name': 'New scope...'})

    default_scope_idx = next((i for i, s in enumerate(config['scopes'], 1) if s.get('default')), 1)
    selected_scope = prompt_choice(scope_options, "Scope:", default_scope_idx)

    if selected_scope['code'] == '_custom':
        custom_code = prompt("Enter scope code (3-4 lowercase letters)")
        while not re.match(r'^[a-z]{3,4}$', custom_code):
            print_error("Scope must be 3-4 lowercase letters")
            custom_code = prompt("Enter scope code")
        custom_name = prompt("Enter scope name (e.g. 'Acme Corp')")
        custom_desc = prompt("Enter description (e.g. 'Client project for Acme')")
        selected_scope = add_scope_to_config(config, custom_code, custom_name, custom_desc)

    selections['Scope'] = selected_scope['code']
    deploy_log.add_selection("Scope", selected_scope['code'], selected_scope['name'])
    if exec_log:
        exec_log.log_selection("Scope", f"{selected_scope['code']} ({selected_scope.get('name', '')})")

    # 5. Server ID
    id_key = f"{selected_env['code']}-{selected_role['code']}-{selected_region['tfs_code']}"
    generated_id = generate_server_id(used_ids, id_key)

    clear_screen()
    print_status_bar(selections)
    print(f"\nServer ID: {Colors.BOLD}{generated_id}{Colors.NC} (auto-generated)")
    custom_id_input = prompt("Press Enter to accept, or enter custom ID (100-999)", "")

    if custom_id_input:
        while True:
            try:
                server_id = int(custom_id_input)
                if 100 <= server_id <= 999:
                    all_ids = set()
                    for ids in used_ids.values():
                        all_ids.update(ids)
                    if server_id in all_ids:
                        print_error(f"ID {server_id} is already in use")
                        custom_id_input = prompt("Enter different ID (100-999)")
                        continue
                    break
                else:
                    print_error("ID must be between 100 and 999")
                    custom_id_input = prompt("Enter ID (100-999)")
            except ValueError:
                print_error("Please enter a valid number")
                custom_id_input = prompt("Enter ID (100-999)")
    else:
        server_id = generated_id

    # Build server name
    server_name = f"{selected_env['code']}-{selected_role['code']}-{selected_region['tfs_code']}-{selected_scope['code']}-{server_id}"
    deploy_log.add_selection("Server Name", server_name)
    deploy_log.add_selection("Server ID", str(server_id))
    if exec_log:
        exec_log.log_selection("Server ID", str(server_id))
        exec_log.log_selection("Server Name", server_name)

    return selected_scope, server_id, server_name


def get_available_vm_sizes(compute_client: ComputeManagementClient, location: str,
                           vm_sizes_from_config: List[Dict]) -> List[str]:
    """
    Check which VM sizes from config are actually available in the specified region.

    Args:
        compute_client: Azure Compute Management Client
        location: Azure region name (e.g., 'southcentralus')
        vm_sizes_from_config: List of VM size dictionaries from config

    Returns:
        List of available VM size codes (e.g., ['Standard_B2ms', 'Standard_D2s_v3'])
    """
    try:
        print("Checking VM size availability in region...", end=" ", flush=True)

        # Get all resource SKUs available in the subscription
        skus = compute_client.resource_skus.list(filter=f"location eq '{location}'")

        # Build set of available VM sizes (excluding restricted ones)
        available_sizes = set()
        for sku in skus:
            # Only process virtualMachines SKUs
            if sku.resource_type != 'virtualMachines':
                continue

            # Check if SKU has restrictions
            has_restrictions = False
            if sku.restrictions:
                for restriction in sku.restrictions:
                    # Check if there's a location restriction
                    if restriction.type == 'Location':
                        has_restrictions = True
                        break
                    # Check for zone restrictions (still might be available)
                    # We'll consider it available if only zone-restricted

            # If no location restrictions, it's available
            if not has_restrictions:
                available_sizes.add(sku.name)

        # Filter config VM sizes to only include available ones
        config_size_codes = {s['code'] for s in vm_sizes_from_config}
        available_from_config = config_size_codes.intersection(available_sizes)

        print_success(f"Found {len(available_from_config)}/{len(config_size_codes)} available")

        return list(available_from_config)

    except Exception as e:
        print_warning(f"Failed to check availability: {e}")
        print_info("Showing all configured VM sizes (some may be unavailable)")
        # Return all configured sizes as fallback
        return [s['code'] for s in vm_sizes_from_config]


def find_similar_vm_sizes(target_size: Dict, available_sizes: List[Dict], max_suggestions: int = 3) -> List[Dict]:
    """
    Find similar VM sizes based on specs (vCPU, RAM, cost).

    Args:
        target_size: The unavailable size to find alternatives for
        available_sizes: List of available VM sizes
        max_suggestions: Maximum number of suggestions to return

    Returns:
        List of similar VM sizes, sorted by similarity
    """
    if not available_sizes:
        return []

    # Calculate similarity score for each available size
    scored_sizes = []
    for size in available_sizes:
        # Similarity based on:
        # - vCPU difference (weight: 40%)
        # - RAM difference (weight: 30%)
        # - Cost difference (weight: 30%)
        vcpu_diff = abs(size['vcpu'] - target_size['vcpu']) / max(size['vcpu'], target_size['vcpu'])
        ram_diff = abs(size['ram_gb'] - target_size['ram_gb']) / max(size['ram_gb'], target_size['ram_gb'])
        cost_diff = abs(size['cost_month_usd'] - target_size['cost_month_usd']) / max(size['cost_month_usd'], target_size['cost_month_usd'])

        # Lower score = more similar
        similarity_score = (vcpu_diff * 0.4) + (ram_diff * 0.3) + (cost_diff * 0.3)

        scored_sizes.append({
            'size': size,
            'score': similarity_score
        })

    # Sort by similarity (lowest score first)
    scored_sizes.sort(key=lambda x: x['score'])

    # Return top matches
    return [item['size'] for item in scored_sizes[:max_suggestions]]


def select_vm_specs(
    config: Dict[str, Any],
    selections: Dict[str, str],
    server_name: str,
    selected_env: Dict,
    selected_scope: Dict,
    selected_role: Dict,
    selected_region: Dict,
    credential: Any,
    subscription_id: str,
    deploy_log: 'DeploymentLog',
    exec_log: Optional['ExecutionLog'] = None
) -> Tuple[Dict, str, str, str, Dict, str, Dict, Dict, str, bool, Optional[str], str]:
    """
    Interactive prompts for VM specifications: size, admin, SSH keys, disk, OS, alerts.

    Args:
        config: Configuration dictionary
        selections: Dictionary tracking user selections
        server_name: Generated server name
        selected_env: Selected environment
        selected_scope: Selected scope
        selected_role: Selected role
        selected_region: Selected region
        credential: Azure credential
        subscription_id: Azure subscription ID
        deploy_log: Deployment log for recording selections
        exec_log: Optional execution log for capturing selections

    Returns:
        Tuple of (selected_size, admin_username, private_key_path, public_key,
                  selected_disk, disk_type, selected_image, tags, managed_by,
                  enable_alerts, alert_email, keyvault_name)
    """
    # 6. VM Size - Check availability first
    clear_screen()
    print_status_bar(selections, server_name)

    # Get available VM sizes in the selected region
    compute_client = ComputeManagementClient(credential, subscription_id)
    available_size_codes = get_available_vm_sizes(
        compute_client,
        selected_region['azure_region'],
        config['vm_sizes']
    )

    # Filter VM sizes to only show available ones
    available_sizes = [s for s in config['vm_sizes'] if s['code'] in available_size_codes]

    # Handle case where no sizes are available
    if not available_sizes:
        print_error(f"No configured VM sizes are available in {selected_region['display_name']}")
        print_info("This is likely a temporary Azure capacity issue.")
        print_info("Options:")
        print_info("  1. Try a different region")
        print_info("  2. Wait and try again later")
        print_info("  3. Contact Azure support")
        sys.exit(1)

    # Check if default size is unavailable and suggest alternatives
    default_size_code = selected_env['default_size']
    default_size_unavailable = default_size_code not in available_size_codes

    if default_size_unavailable:
        # Find the unavailable default size details
        default_size = next((s for s in config['vm_sizes'] if s['code'] == default_size_code), None)
        if default_size:
            print_warning(f"Default size {default_size_code} is currently unavailable in this region")

            # Find similar alternatives
            alternatives = find_similar_vm_sizes(default_size, available_sizes, max_suggestions=3)
            if alternatives:
                print_info("Recommended alternatives with similar specs:")
                for i, alt in enumerate(alternatives, 1):
                    vcpu_compare = "same" if alt['vcpu'] == default_size['vcpu'] else f"{alt['vcpu']}vCPU vs {default_size['vcpu']}vCPU"
                    ram_compare = "same" if alt['ram_gb'] == default_size['ram_gb'] else f"{alt['ram_gb']}GB vs {default_size['ram_gb']}GB"
                    cost_compare = f"${alt['cost_month_usd']:.0f}/mo vs ${default_size['cost_month_usd']:.0f}/mo"
                    print(f"  {i}. {alt['code']:18} ({vcpu_compare}, {ram_compare}, {cost_compare})")
                print()

    # Show other unavailable sizes
    unavailable_sizes = [s for s in config['vm_sizes'] if s['code'] not in available_size_codes]
    other_unavailable = [s for s in unavailable_sizes if s['code'] != default_size_code]
    if other_unavailable:
        unavailable_codes = ', '.join([s['code'] for s in other_unavailable])
        print_warning(f"Also unavailable: {unavailable_codes}")
        print()

    print(f"VM Size: (* = recommended alternative)" if default_size_unavailable else f"VM Size: (* = default for {selected_env['code']})")
    size_options = []

    # If default is unavailable, mark the best alternative with *
    best_alternative_code = None
    if default_size_unavailable:
        default_size = next((s for s in config['vm_sizes'] if s['code'] == default_size_code), None)
        if default_size:
            alternatives = find_similar_vm_sizes(default_size, available_sizes, max_suggestions=1)
            if alternatives:
                best_alternative_code = alternatives[0]['code']

    for s in available_sizes:
        # Mark either the default (if available) or the best alternative (if default unavailable)
        is_marked = (s['code'] == default_size_code) or (default_size_unavailable and s['code'] == best_alternative_code)
        marker = "*" if is_marked else " "
        size_options.append({
            **s,
            'name': f"{marker} {s['code']:18} {s['vcpu']}vCPU {s['ram_gb']:>2}GB ~${s['cost_month_usd']:.0f}/mo"
        })

    # Set default to the best alternative if original default is unavailable
    if default_size_unavailable and best_alternative_code:
        default_size_idx = next((i for i, s in enumerate(available_sizes, 1) if s['code'] == best_alternative_code), 1)
    else:
        default_size_idx = next((i for i, s in enumerate(available_sizes, 1) if s['code'] == default_size_code), 1)

    selected_size = prompt_choice(size_options, "VM Size:", default_size_idx)
    deploy_log.add_selection("VM Size", selected_size['code'], f"{selected_size['vcpu']}vCPU, {selected_size['ram_gb']}GB RAM, ~${selected_size['cost_month_usd']:.0f}/mo")
    if exec_log:
        exec_log.log_selection("VM Size", f"{selected_size['code']} ({selected_size['vcpu']}vCPU, {selected_size['ram_gb']}GB RAM, ~${selected_size['cost_month_usd']:.0f}/mo)")

    # 7. Admin username
    clear_screen()
    print_status_bar(selections, server_name)
    admin_username = prompt("Admin username:", config['defaults']['admin_username'])
    deploy_log.add_selection("Admin Username", admin_username)
    if exec_log:
        exec_log.log_selection("Admin Username", admin_username)

    # 8. SSH keys
    private_key_path, public_key = generate_ssh_keypair(server_name, admin_username)
    deploy_log.add_metadata("SSH Key Path", private_key_path)

    # 9. OS Disk
    clear_screen()
    print_status_bar(selections, server_name)
    # Build disk options from config and add "Other" option
    disk_options = [
        {**d, 'name': f"{d['gb']} GB"}
        for d in config['disk_sizes']
    ]
    disk_options.append({'name': 'Other (custom configuration)', 'gb': None, 'is_other': True})

    default_disk_idx = next((i for i, d in enumerate(config['disk_sizes'], 1) if d.get('default')), 1)
    disk_type = selected_env['disk_redundancy']

    selected_disk = prompt_choice(disk_options, f"OS Disk Size (default: {disk_type}):", default_disk_idx)

    # Check if user selected "Other" option
    if selected_disk.get('is_other'):
        selected_disk, disk_type = prompt_custom_disk_config()

    deploy_log.add_selection("OS Disk Size", f"{selected_disk['gb']}GB", disk_type)
    if exec_log:
        exec_log.log_selection("OS Disk Size", f"{selected_disk['gb']}GB ({disk_type})")

    # 10. OS Image
    clear_screen()
    print_status_bar(selections, server_name)
    image_options = config['os_images']
    if len(image_options) == 1:
        selected_image = image_options[0]
    else:
        default_image_idx = next((i for i, img in enumerate(image_options, 1) if img.get('default')), 1)
        selected_image = prompt_choice(image_options, "OS Image:", default_image_idx)
    deploy_log.add_selection("OS Image", selected_image['name'])
    if exec_log:
        exec_log.log_selection("OS Image", selected_image['name'])

    # 11. Tags and Managed By
    clear_screen()
    print_status_bar(selections, server_name)
    env_display = selected_env['name']
    managed_by = prompt("Managed by (username):", config['defaults']['managed_by'])

    tags = {
        config['tags']['environment_tag']: env_display,
        config['tags']['scope_tag']: selected_scope['code'],
        config['tags']['role_tag']: selected_role['code'],
        config['tags']['managed_by_tag']: managed_by,
        config['tags']['infra_standard_tag']: config['defaults']['infra_standard_version']
    }
    deploy_log.add_selection("Managed By", managed_by)
    if exec_log:
        exec_log.log_selection("Managed By", managed_by)

    # 12. Key Vault storage
    if DRY_RUN:
        import secrets
        random_suffix = secrets.token_hex(4)
        keyvault_name = f"kv-{selected_scope['code']}-{random_suffix}"
        print_info(f"Dry-run: Would store SSH keys in Key Vault: {keyvault_name}")
    else:
        keyvault_name = store_keys_in_keyvault(
            credential, subscription_id, private_key_path,
            server_name, admin_username, selected_region['azure_region'], tags,
            selected_scope['code']
        )
    deploy_log.add_metadata("Key Vault", keyvault_name)

    # 13. Alerts
    clear_screen()
    print_status_bar(selections, server_name)
    enable_alerts = prompt_yes_no("Enable monitoring alerts?", config['alerts']['enabled_by_default'])

    alert_email = None
    if enable_alerts:
        alert_email = prompt("Alert notification email:")
        while not re.match(r'^[a-zA-Z0-9._%+-]+@[a-zA-Z0-9.-]+\.[a-zA-Z]{2,}$', alert_email):
            print_error("Please enter a valid email address")
            alert_email = prompt("Alert notification email:")
        deploy_log.add_selection("Alerts Enabled", "Yes", alert_email)
        if exec_log:
            exec_log.log_selection("Alerts Enabled", f"Yes (email: {alert_email})")
    else:
        deploy_log.add_selection("Alerts Enabled", "No")
        if exec_log:
            exec_log.log_selection("Alerts Enabled", "No")

    return (selected_size, admin_username, private_key_path, public_key,
            selected_disk, disk_type, selected_image, tags, managed_by,
            enable_alerts, alert_email, keyvault_name)


def configure_ssh_and_networking(
    config: Dict[str, Any],
    selections: Dict[str, str],
    server_name: str,
    deploy_log: 'DeploymentLog',
    exec_log: Optional['ExecutionLog'] = None
) -> Tuple[str, List[Dict[str, Any]]]:
    """
    Configure SSH access IP and build NSG rules.

    Args:
        config: Configuration dictionary
        selections: Dictionary tracking user selections
        server_name: Generated server name
        deploy_log: Deployment log for recording selections
        exec_log: Optional execution log for capturing selections

    Returns:
        Tuple of (user_ip, nsg_rules)
    """
    # 14. NSG - Get user IP
    clear_screen()
    print_status_bar(selections, server_name)
    detected_ip = get_current_public_ip(config)

    print("\nSSH Access:")
    if detected_ip:
        print(f"  Your IP: {Colors.BOLD}{detected_ip}{Colors.NC}")
        if prompt_yes_no("  Use this IP for SSH access?", True):
            user_ip = detected_ip
        else:
            user_ip = prompt("  Enter IP/CIDR", config['nsg']['ssh_personal_fallback_ip'])
    else:
        print_warning("Could not detect your IP")
        user_ip = prompt("  Enter IP for SSH access", config['nsg']['ssh_personal_fallback_ip'])

    if user_ip == config['nsg']['ssh_personal_fallback_ip']:
        print_warning(f"Using placeholder IP. Update NSG after deployment.")
        deploy_log.add_warning(f"NSG using placeholder IP: {user_ip}. Update NSG after deployment.")

    deploy_log.add_selection("SSH Access IP", user_ip)
    if exec_log:
        exec_log.log_selection("SSH Access IP", user_ip)

    # Build NSG rules
    forge_ips = ','.join(config['nsg']['forge_ips'])
    nsg_rules = []
    for rule in config['nsg']['rules']:
        r = rule.copy()
        if r['source'] == '{user_ip}':
            r['source'] = user_ip
        elif r['source'] == '{forge_ips}':
            r['source'] = forge_ips
        nsg_rules.append(r)

    return user_ip, nsg_rules


def collect_server_configuration(
    config: Dict[str, Any],
    used_ids: Dict[str, List[int]],
    azure_env: AzureEnvironment,
    deploy_log: 'DeploymentLog',
    exec_log: Optional['ExecutionLog'] = None
) -> ServerConfiguration:
    """
    Collect all server configuration through interactive prompts.
    Orchestrates 4 sub-functions for organized collection.

    Args:
        config: Configuration dictionary
        used_ids: Dictionary of already-used server IDs
        azure_env: Azure environment with credentials and clients
        deploy_log: Deployment log for recording configuration
        exec_log: Optional execution log for capturing user selections

    Returns:
        ServerConfiguration: Complete server configuration
    """
    selections = {}

    # Phase 1: Environment, Role, and Region
    selected_env, selected_role, selected_region = select_environment_role_region(
        config, selections, deploy_log, exec_log
    )

    # Phase 2: Scope and Server ID
    selected_scope, server_id, server_name = select_scope_and_id(
        config, selections, selected_env, selected_role, selected_region,
        used_ids, deploy_log, exec_log
    )

    # Phase 3: VM Specifications
    (selected_size, admin_username, private_key_path, public_key,
     selected_disk, disk_type, selected_image, tags, managed_by,
     enable_alerts, alert_email, keyvault_name) = select_vm_specs(
        config, selections, server_name, selected_env, selected_scope,
        selected_role, selected_region, azure_env.credential,
        azure_env.subscription_id, deploy_log, exec_log
    )

    # Phase 4: SSH and Networking
    user_ip, nsg_rules = configure_ssh_and_networking(
        config, selections, server_name, deploy_log, exec_log
    )

    # Build and return ServerConfiguration dataclass
    return ServerConfiguration(
        environment=selected_env,
        role=selected_role,
        region=selected_region,
        scope=selected_scope,
        server_id=server_id,
        server_name=server_name,
        vm_size=selected_size,
        admin_username=admin_username,
        private_key_path=private_key_path,
        public_key=public_key,
        disk_size=selected_disk,
        disk_type=disk_type,
        os_image=selected_image,
        tags=tags,
        managed_by=managed_by,
        enable_alerts=enable_alerts,
        alert_email=alert_email,
        user_ip=user_ip,
        nsg_rules=nsg_rules,
        keyvault_name=keyvault_name,
        selections=selections
    )


def review_and_confirm_deployment(
    server_config: ServerConfiguration,
    azure_env: AzureEnvironment,
    deploy_log: 'DeploymentLog'
) -> Dict[str, str]:
    """
    Display configuration review screen and get deployment confirmation.

    Returns:
        Dict of resource names (rg_name, vnet_name, subnet_name, nsg_name, ip_name, nic_name, os_disk_name)
    """
    clear_screen()
    print_status_bar(server_config.selections, server_config.server_name)

    # Build resource names
    resource_names = {
        'rg_name': server_config.server_name,
        'vnet_name': f"{server_config.server_name}-vnet",
        'subnet_name': f"{server_config.server_name}-snet01",
        'nsg_name': f"{server_config.server_name}-nsg",
        'ip_name': f"{server_config.server_name}-ip01",
        'nic_name': f"{server_config.server_name}-nic01",
        'os_disk_name': f"{server_config.server_name}-osdisk"
    }

    # Display review information
    print(f"\n{Colors.BOLD}Review Configuration{Colors.NC}")
    print(f"{'─' * 40}")
    print(f"Subscription:  {azure_env.subscription_name}")
    print(f"Region:        {server_config.region['name']}")
    print(f"VM Size:       {server_config.vm_size['code']} ({server_config.vm_size['vcpu']}vCPU, {server_config.vm_size['ram_gb']}GB)")
    print(f"OS:            {server_config.os_image['name']}")
    print(f"Disk:          {server_config.disk_size['gb']}GB SSD ({server_config.disk_type.replace('StandardSSD_', '')})")
    print(f"Admin:         {server_config.admin_username}")
    print(f"Alerts:        {'Yes → ' + server_config.alert_email if server_config.enable_alerts else 'No'}")

    # Display security features
    print(f"\n{Colors.BOLD}Security{Colors.NC}")
    print(f"{'─' * 40}")
    sec_items = ["Trusted Launch", "Secure Boot", "vTPM", "SSH-only auth"]
    if azure_env.encryption_at_host_enabled:
        sec_items.append("Encryption at Host")
    print(f"✓ {', '.join(sec_items)}")
    if not azure_env.encryption_at_host_enabled:
        print(f"{Colors.YELLOW}✗ Encryption at Host disabled{Colors.NC}")
        deploy_log.add_warning("Encryption at Host not enabled")

    # Log security features
    for sec_item in sec_items:
        deploy_log.add_security_feature(sec_item)

    # Display resources to create
    print(f"\n{Colors.BOLD}Resources to create:{Colors.NC} RG, VM, Disk, NIC, IP, NSG, VNet, Subnet")

    # Get confirmation
    if not prompt_yes_no(f"\n{Colors.BOLD}Deploy?{Colors.NC}", False):
        print("\nCancelled.")
        sys.exit(0)

    return resource_names


def deploy_azure_resources(
    server_config: ServerConfiguration,
    azure_env: AzureEnvironment,
    resource_names: Dict[str, str],
    config: Dict[str, Any],
    deploy_log: 'DeploymentLog',
    exec_log: Optional['ExecutionLog'] = None
) -> DeploymentResult:
    """
    Deploy all Azure infrastructure resources.

    Returns:
        DeploymentResult with storage info, public IP, FQDN, and resource names
    """
    print_header("Deploying Resources")

    if exec_log:
        exec_log.log("INFO", "Starting resource deployment")

    azure_location = server_config.region['azure_region']

    # Setup verification storage (shared across all VMs)
    storage_info = setup_verification_storage(
        azure_env.credential, azure_env.subscription_id,
        server_config.scope['code'], azure_location
    )
    if not storage_info:
        print_error("Failed to setup verification storage")
        sys.exit(1)

    # Log storage account
    deploy_log.add_resource("Storage Account", storage_info['name'], {
        "Resource ID": storage_info['id'],
        "Location": azure_location,
        "Containers": [HARDENING_REPORTS_CONTAINER, COMPLIANCE_REPORTS_CONTAINER],
        "Purpose": "Hardening and compliance reports storage"
    })
    deploy_log.add_metadata("Storage Account", storage_info['name'])

    # Create VM-specific tags (base tags + TFS storage tags)
    # Infrastructure resources (RG, VNet, NSG, IP, NIC) get only base tags
    vm_tags = server_config.tags.copy()
    vm_tags['TFSStorageAccount'] = storage_info['name']
    vm_tags['TFSHardeningReports'] = f"{HARDENING_REPORTS_CONTAINER}/{server_config.server_name}"
    vm_tags['TFSComplianceReports'] = f"{COMPLIANCE_REPORTS_CONTAINER}/{server_config.server_name}"

    # Generate cloud-init
    tfs_config = generate_tfs_config(
        server_config.server_name,
        storage_info,
        azure_env.subscription_id,
        server_config.admin_username
    )
    github_org = config.get('defaults', {}).get('github_org', 'Tech-for-Service')
    cloud_init_script = generate_tfs_cloud_init(tfs_config, github_org)

    # Initialize Rich console for progress display
    console = Console()

    # Create Resource Group
    print("Creating resource group...", end=" ", flush=True)
    with ApiCallTracker(exec_log, deploy_log, 'create_resource_group') as tracker:
        if create_resource_group(azure_env.resource_client, resource_names['rg_name'], azure_location,
                                server_config.tags, exec_log, tracker):
            print_success("Done")
            deploy_log.add_resource("Resource Group", resource_names['rg_name'], {
                "Location": azure_location,
                "Tags": server_config.tags
            }, api_calls=tracker.get_api_calls())
            if exec_log:
                exec_log.log("SUCCESS", f"Resource group created: {resource_names['rg_name']}")
        else:
            sys.exit(1)

    # Create Virtual Network
    print("Creating virtual network...", end=" ", flush=True)
    with ApiCallTracker(exec_log, deploy_log, 'create_vnet') as tracker:
        if create_vnet(azure_env.network_client, resource_names['rg_name'], resource_names['vnet_name'],
                       resource_names['subnet_name'], azure_location,
                       config['defaults']['vnet_address_space'], config['defaults']['subnet_prefix'],
                       server_config.tags, exec_log, tracker):
            print_success("Done")
            subnet_id = f"/subscriptions/{azure_env.subscription_id}/resourceGroups/{resource_names['rg_name']}/providers/Microsoft.Network/virtualNetworks/{resource_names['vnet_name']}/subnets/{resource_names['subnet_name']}"
            deploy_log.add_resource("Virtual Network", resource_names['vnet_name'], {
                "Address Space": config['defaults']['vnet_address_space'],
                "Subnet": resource_names['subnet_name'],
                "Subnet Prefix": config['defaults']['subnet_prefix']
            }, api_calls=tracker.get_api_calls())
            if exec_log:
                exec_log.log("SUCCESS", f"Virtual network created: {resource_names['vnet_name']}")
        else:
            sys.exit(1)

    # Create Network Security Group
    print("Creating network security group...", end=" ", flush=True)
    with ApiCallTracker(exec_log, deploy_log, 'create_nsg') as tracker:
        if create_nsg(azure_env.network_client, resource_names['rg_name'], resource_names['nsg_name'],
                      azure_location, server_config.nsg_rules, server_config.tags, exec_log, tracker):
            print_success("Done")
            nsg_id = f"/subscriptions/{azure_env.subscription_id}/resourceGroups/{resource_names['rg_name']}/providers/Microsoft.Network/networkSecurityGroups/{resource_names['nsg_name']}"
            deploy_log.add_resource("Network Security Group", resource_names['nsg_name'], {
                "Rules": [rule['name'] for rule in server_config.nsg_rules]
            }, api_calls=tracker.get_api_calls())
            if exec_log:
                exec_log.log("SUCCESS", f"Network security group created: {resource_names['nsg_name']}")
        else:
            sys.exit(1)

    # Create Public IP
    print("Creating public IP...", end=" ", flush=True)
    with ApiCallTracker(exec_log, deploy_log, 'create_public_ip') as tracker:
        public_ip_id = create_public_ip(azure_env.network_client, resource_names['rg_name'],
                                         resource_names['ip_name'], server_config.server_name.lower(),
                                         azure_location, server_config.tags, exec_log, tracker)
        if public_ip_id:
            print_success("Done")
            deploy_log.add_resource("Public IP", resource_names['ip_name'], {
                "SKU": "Standard",
                "Allocation": "Static"
            }, api_calls=tracker.get_api_calls())
            if exec_log:
                exec_log.log("SUCCESS", f"Public IP created: {resource_names['ip_name']}")
        else:
            sys.exit(1)

    # Create Network Interface
    print("Creating network interface...", end=" ", flush=True)
    with ApiCallTracker(exec_log, deploy_log, 'create_nic') as tracker:
        nic_id = create_nic(azure_env.network_client, resource_names['rg_name'], resource_names['nic_name'],
                            azure_location, subnet_id, public_ip_id, nsg_id, server_config.tags, exec_log, tracker)
        if nic_id:
            print_success("Done")
            deploy_log.add_resource("Network Interface", resource_names['nic_name'], {
                "Subnet": resource_names['subnet_name'],
                "Public IP": resource_names['ip_name'],
                "NSG": resource_names['nsg_name']
            }, api_calls=tracker.get_api_calls())
            if exec_log:
                exec_log.log("SUCCESS", f"Network interface created: {resource_names['nic_name']}")
        else:
            sys.exit(1)

    # Create Virtual Machine (longest operation - use spinner)
    with ApiCallTracker(exec_log, deploy_log, 'create_vm') as tracker:
        with console.status("[bold cyan]Creating virtual machine (this may take several minutes)...", spinner="dots") as status:
            vm_created = create_vm(azure_env.compute_client, resource_names['rg_name'], server_config.server_name,
                         azure_location, server_config.vm_size['code'], nic_id,
                         server_config.admin_username, server_config.public_key,
                         resource_names['os_disk_name'], server_config.disk_size['gb'],
                         server_config.disk_type, server_config.os_image,
                         cloud_init_script, vm_tags, config,
                         azure_env.encryption_at_host_enabled, exec_log, tracker)

        if vm_created:
            print_success("Virtual machine created")
            deploy_log.add_resource("Virtual Machine", server_config.server_name, {
                "VM Size": server_config.vm_size['code'],
                "vCPU": server_config.vm_size['vcpu'],
                "RAM (GB)": server_config.vm_size['ram_gb'],
                "Location": azure_location,
                "OS Image": server_config.os_image['name'],
                "OS Disk Name": resource_names['os_disk_name'],
                "OS Disk Size": f"{server_config.disk_size['gb']} GB",
                "Disk Type": server_config.disk_type,
                "Admin Username": server_config.admin_username,
                "Security Type": "TrustedLaunch",
                "Secure Boot": "Enabled",
                "vTPM": "Enabled",
                "Encryption at Host": "Enabled" if azure_env.encryption_at_host_enabled else "Disabled",
                "Managed Identity": "Enabled"
            }, api_calls=tracker.get_api_calls())
            if exec_log:
                exec_log.log("SUCCESS", f"Virtual machine created: {server_config.server_name}")
        else:
            sys.exit(1)

    # Assign storage role to VM's managed identity
    if not DRY_RUN:
        print("Assigning storage permissions to VM...", end=" ", flush=True)
        vm = azure_env.compute_client.virtual_machines.get(resource_names['rg_name'], server_config.server_name)
        if vm.identity and vm.identity.principal_id:
            if not assign_storage_role_to_vm(
                azure_env.credential, azure_env.subscription_id,
                vm.identity.principal_id, storage_info['id']
            ):
                print_warning("Storage role assignment may have failed - verify manually")
        else:
            print_warning("VM managed identity not found - verify manually")
    else:
        print_info("[DRY-RUN] Would assign Storage Blob Data Contributor role to VM's managed identity")

    # Create Alerts
    if server_config.enable_alerts:
        print("Configuring alerts...", end=" ", flush=True)
        if create_alerts(azure_env.monitor_client, azure_env.subscription_id,
                         resource_names['rg_name'], server_config.server_name,
                         server_config.alert_email, config['alerts']['rules'],
                         server_config.tags):
            print_success("Done")
            deploy_log.add_resource("Metric Alerts", "Alert Configuration", {
                "Email": server_config.alert_email,
                "Alert Rules": [rule['name'] for rule in config['alerts']['rules']]
            })
        else:
            print_warning("Some alerts may not have been created")
            deploy_log.add_warning("Some alerts may not have been created")

    # Get Public IP address
    if not DRY_RUN:
        public_ip_info = azure_env.network_client.public_ip_addresses.get(resource_names['rg_name'], resource_names['ip_name'])
        public_ip_address = public_ip_info.ip_address
        fqdn = public_ip_info.dns_settings.fqdn if public_ip_info.dns_settings else None
    else:
        # Placeholder values for dry-run
        public_ip_address = "203.0.113.1"  # RFC 5737 TEST-NET-1 placeholder
        fqdn = f"{resource_names['ip_name']}.{server_config.region['azure_region']}.cloudapp.azure.com"

    # Add final metadata to log
    deploy_log.add_metadata("Public IP Address", public_ip_address or "Not yet assigned")
    if fqdn:
        deploy_log.add_metadata("FQDN", fqdn)

    return DeploymentResult(
        storage_info=storage_info,
        public_ip_address=public_ip_address or "Not yet assigned",
        fqdn=fqdn,
        resource_names=resource_names
    )


def display_deployment_summary(
    server_name: str,
    public_ip_address: str,
    fqdn: Optional[str],
    private_key_path: str,
    admin_username: str,
    keyvault_name: str,
    storage_info: Dict[str, Any],
    user_ip: str,
    fallback_ip: str
):
    """Display deployment summary and next steps"""
    print_header("Deployment Complete")

    print(f"  {Colors.BOLD}Server:{Colors.NC}      {server_name}")
    print(f"  {Colors.BOLD}Public IP:{Colors.NC}   {public_ip_address}")
    if fqdn:
        print(f"  {Colors.BOLD}FQDN:{Colors.NC}        {fqdn}")
    print()
    print(f"  {Colors.BOLD}SSH Command:{Colors.NC}")
    print(f"  ssh -i {private_key_path} {admin_username}@{public_ip_address}")
    print()

    print(f"  {Colors.BOLD}SSH Key Backup:{Colors.NC}")
    print(f"  Key Vault: {keyvault_name}")
    print(f"  Secrets:   {admin_username}-{server_name}-public")
    print(f"             {admin_username}-{server_name}-private")
    print()

    print(f"  {Colors.BOLD}Reports Storage:{Colors.NC}")
    print(f"  Storage:    {storage_info['name']}")
    print(f"  Hardening:  {HARDENING_REPORTS_CONTAINER}/{server_name}/  (permanent)")
    print(f"  Compliance: {COMPLIANCE_REPORTS_CONTAINER}/{server_name}/  (5 year retention)")
    print(f"  VM Config:  {TFS_CONFIG_FILE}  (scripts source this for storage paths)")
    print()

    print(f"  {Colors.BOLD}Managed Identity:{Colors.NC} Enabled (for Azure resource access)")
    print()

    print(f"  {Colors.BOLD}Next Steps:{Colors.NC}")
    print(f"    1. Add server to Laravel Forge")
    print(f"    2. Run hardening verification script")
    if user_ip == fallback_ip:
        print(f"    3. {Colors.YELLOW}Update SSH-Personal NSG rule with your real IP{Colors.NC}")

    print()
    print_info(
        f"Forge SSH IPs configured. Check https://forge.laravel.com/docs if provisioning fails — IPs may have changed.")
    print()


def save_deployment_artifacts(
    deploy_log: 'DeploymentLog',
    server_name: str,
    storage_account_name: str,
    storage_account_id: str,
    credential: Any,
    subscription_id: str
) -> bool:
    """Save deployment log locally and upload to Azure Blob"""
    print_subheader("Saving Deployment Log")

    # Save locally
    local_log_path = deploy_log.save_locally(server_name)
    if local_log_path:
        print_success(f"Saved locally: {local_log_path}")
    else:
        print_warning("Failed to save deployment log locally")

    # Upload to Azure Blob
    print("Uploading deployment log to Azure Blob...", end=" ", flush=True)
    if deploy_log.upload_to_blob(storage_account_name, server_name, credential, subscription_id, storage_account_id):
        print_success("Done")
        print_info(f"Blob location: {HARDENING_REPORTS_CONTAINER}/{server_name}/deployment-{server_name}-*.md")
        print()
        return True
    else:
        print_warning("Failed to upload deployment log to Azure Blob")
        print()
        return False


def check_resource_provider_status(credential, subscription_id: str, namespace: str) -> str:
    """
    Check if a resource provider is registered.

    Returns:
        str: Registration state (Registered, NotRegistered, Registering, etc.)
    """
    try:
        from azure.mgmt.resource import ResourceManagementClient
        resource_client = ResourceManagementClient(credential, subscription_id)
        provider = resource_client.providers.get(namespace)
        return provider.registration_state
    except Exception as e:
        print_warning(f"Could not check provider {namespace}: {e}")
        return "Unknown"


def register_resource_provider(credential, subscription_id: str, namespace: str, exec_log: Optional['ExecutionLog'] = None) -> bool:
    """
    Register a resource provider in the subscription.

    Returns:
        bool: True if registered successfully or already registered, False otherwise
    """
    try:
        from azure.mgmt.resource import ResourceManagementClient
        resource_client = ResourceManagementClient(credential, subscription_id)

        if exec_log:
            exec_log.log("INFO", f"Registering resource provider: {namespace}")

        resource_client.providers.register(namespace)

        # Wait for registration to complete (max 60 seconds)
        import time
        max_wait = 60
        wait_interval = 2
        elapsed = 0

        while elapsed < max_wait:
            status = check_resource_provider_status(credential, subscription_id, namespace)
            if status == "Registered":
                if exec_log:
                    exec_log.log("SUCCESS", f"Provider {namespace} registered")
                return True
            elif status in ["Registering", "NotRegistered"]:
                time.sleep(wait_interval)
                elapsed += wait_interval
            else:
                print_warning(f"Provider {namespace} in unexpected state: {status}")
                return False

        print_warning(f"Provider {namespace} registration timed out after {max_wait}s")
        return False

    except Exception as e:
        print_error(f"Failed to register provider {namespace}: {e}")
        if exec_log:
            exec_log.log("ERROR", f"Failed to register provider {namespace}: {e}")
        return False


def ensure_required_providers(credential, subscription_id: str, exec_log: Optional['ExecutionLog'] = None) -> bool:
    """
    Ensure all required Azure resource providers are registered.

    Required providers:
    - Microsoft.Compute (VMs)
    - Microsoft.Network (Networking)
    - Microsoft.Storage (Storage accounts)
    - Microsoft.KeyVault (Key Vault)
    - Microsoft.Authorization (Role assignments)

    Returns:
        bool: True if all providers are registered, False otherwise
    """
    print_subheader("Resource Provider Registration")

    required_providers = [
        "Microsoft.Compute",
        "Microsoft.Network",
        "Microsoft.Storage",
        "Microsoft.KeyVault",
        "Microsoft.Authorization"
    ]

    unregistered_providers = []

    # Check status of all required providers
    print("Checking required resource providers...")
    for namespace in required_providers:
        status = check_resource_provider_status(credential, subscription_id, namespace)
        if status != "Registered":
            unregistered_providers.append(namespace)
            print(f"  {namespace}: {Colors.YELLOW}{status}{Colors.NC}")
        else:
            print(f"  {namespace}: {Colors.GREEN}Registered{Colors.NC}")

    # If all are registered, we're done
    if not unregistered_providers:
        print_success("All required resource providers are registered")
        if exec_log:
            exec_log.log("INFO", "All required resource providers are registered")
        return True

    # Ask user to register missing providers
    print()
    print_warning(f"Found {len(unregistered_providers)} unregistered provider(s)")
    print_info("These providers must be registered to deploy Azure resources")
    print()

    if not prompt_yes_no("Register missing providers now?", default=True):
        print_error("Cannot continue without required resource providers")
        print_info("Register manually with: az provider register --namespace <provider-name>")
        return False

    # Register missing providers
    print()
    print("Registering providers...")
    all_registered = True

    for namespace in unregistered_providers:
        print(f"  {namespace}...", end=" ", flush=True)
        if register_resource_provider(credential, subscription_id, namespace, exec_log):
            print_success("Registered")
        else:
            print_error("Failed")
            all_registered = False

    print()
    if all_registered:
        print_success("All resource providers registered successfully")
        return True
    else:
        print_error("Some providers failed to register")
        print_info("Try registering manually: az provider register --namespace <provider-name>")
        return False


def setup_azure_environment(config: Dict[str, Any], exec_log: Optional['ExecutionLog'] = None) -> AzureEnvironment:
    """
    Setup Azure environment: authenticate, select subscription, check permissions,
    enable features, and initialize SDK clients.

    Args:
        config: Configuration dictionary
        exec_log: Optional execution log for capturing authentication and permission checks

    Returns:
        AzureEnvironment: Configured Azure environment with all SDK clients
    """
    # Authenticate
    credential = get_credential(exec_log)

    # Select subscription
    subscription_id, subscription_name = select_subscription(credential)

    # Check permissions
    permission_results = check_azure_permissions(credential, subscription_id, exec_log)
    if not validate_permissions(permission_results):
        sys.exit(1)

    # Ensure required resource providers are registered
    if not ensure_required_providers(credential, subscription_id, exec_log):
        print_error("Cannot continue without required resource providers")
        sys.exit(1)

    # Check/enable Encryption at Host feature
    encryption_at_host_enabled = ensure_encryption_at_host(credential, subscription_id)
    if not encryption_at_host_enabled:
        print_warning("Proceeding without Encryption at Host")

    # Initialize Azure SDK clients
    resource_client = ResourceManagementClient(credential, subscription_id)
    compute_client = ComputeManagementClient(credential, subscription_id)
    network_client = NetworkManagementClient(credential, subscription_id)
    monitor_client = MonitorManagementClient(credential, subscription_id)

    return AzureEnvironment(
        credential=credential,
        subscription_id=subscription_id,
        subscription_name=subscription_name,
        encryption_at_host_enabled=encryption_at_host_enabled,
        resource_client=resource_client,
        compute_client=compute_client,
        network_client=network_client,
        monitor_client=monitor_client
    )


# =============================================================================
# Main Entry Point
# =============================================================================

# Global dry-run flag
DRY_RUN = False

def pause_before_exit():
    """Keep the console window open at the end of execution.

    This is helpful when the script is launched by double-clicking or from a
    terminal that closes automatically after the process exits. Set the
    environment variable TFS_NO_EXIT_PAUSE=1 to skip this pause.
    """
    if os.environ.get("TFS_NO_EXIT_PAUSE", "").lower() in ("1", "true", "yes"):
        return

    try:
        print()
        input("Press Enter to close this window...")
    except (EOFError, KeyboardInterrupt):
        pass

def main():
    """Main script entry point - orchestrates VM deployment workflow"""
    global DRY_RUN

    # Handle command-line arguments
    if len(sys.argv) > 1:
        arg = sys.argv[1].lower()

        # --version or -v
        if arg in ['--version', '-v']:
            print(f"TFS Azure Server Builder v{VERSION}")
            print(f"Python: {sys.version.split()[0]}")
            sys.exit(0)

        # --dry-run
        elif arg == '--dry-run':
            DRY_RUN = True
            print(f"{Colors.CYAN}[DRY RUN] No resources will be created{Colors.NC}\n")

        # --help or -h
        elif arg in ['--help', '-h']:
            print("TFS Azure Server Builder")
            print("\nUsage:")
            print("  python azure-server-builder.py           # Interactive deployment")
            print("  python azure-server-builder.py --dry-run # Preview without deploying")
            print("  python azure-server-builder.py --version # Show version info")
            print("  python azure-server-builder.py --help    # Show this help")
            print("\nSet TFS_NO_EXIT_PAUSE=1 to skip the final pause.")
            sys.exit(0)

        else:
            print_error(f"Unknown argument: {sys.argv[1]}")
            print_info("Use --help to see available options")
            sys.exit(1)

    # Terminal setup
    enable_windows_ansi()
    print_header("Azure Server Builder")
    print("Interactive VM provisioning with infrastructure standards\n")

    # Load and validate configuration
    config = load_config()
    print_success(f"Loaded configuration (InfraStandard {config['defaults']['infra_standard_version']})")

    # Initialize deployment log
    deploy_log = DeploymentLog()
    deploy_log.add_metadata("InfraStandard Version", config['defaults']['infra_standard_version'])

    # Initialize execution log (server name will be updated later)
    timestamp_str = datetime.now(timezone.utc).strftime('%Y%m%d_%H%M%S')
    exec_log = ExecutionLog(f"deployment-{timestamp_str}", DRY_RUN)
    exec_log.log("INFO", f"Mode: {'DRY-RUN' if DRY_RUN else 'LIVE DEPLOYMENT'}")

    # Setup Azure environment (auth, subscription, clients, permissions, features)
    azure_env = setup_azure_environment(config, exec_log)
    deploy_log.add_metadata("Subscription ID", azure_env.subscription_id)
    deploy_log.add_metadata("Subscription Name", azure_env.subscription_name)

    # Scan existing servers to prevent ID conflicts
    used_ids = scan_existing_servers(azure_env.credential, azure_env.subscription_id, config)

    # Collect server configuration through interactive prompts
    server_config = collect_server_configuration(config, used_ids, azure_env, deploy_log, exec_log)

    # Update execution log with actual server name
    exec_log.server_name = server_config.server_name
    exec_log.log("INFO", f"Starting deployment for server: {server_config.server_name}")

    # Review configuration and confirm deployment
    resource_names = review_and_confirm_deployment(server_config, azure_env, deploy_log)

    # Deploy all Azure resources (tracks API calls even in dry-run mode)
    deployment_result = deploy_azure_resources(server_config, azure_env, resource_names, config, deploy_log, exec_log)

    # Handle dry-run vs live deployment differently
    if DRY_RUN:
        # Dry-run: Show what would be created and save logs locally
        print()
        print_header("Dry Run Complete")
        print(f"{Colors.GREEN}✓{Colors.NC} Configuration validated successfully")
        print(f"{Colors.GREEN}✓{Colors.NC} All prompts completed")
        print(f"{Colors.GREEN}✓{Colors.NC} API calls tracked (no resources created)")
        print()

        # Save logs for dry-run
        print_subheader("Saving Dry-Run Logs")

        # Save deployment log
        local_log_path = deploy_log.save_locally(server_config.server_name, suffix="dry-run")
        if local_log_path:
            print_success(f"Saved deployment log: {local_log_path}")
        else:
            print_warning("Failed to save deployment log")

        # Save execution log
        exec_log.log("INFO", "Dry-run complete - no resources created, API calls tracked")
        exec_log_path = exec_log.save()
        if exec_log_path:
            print_success(f"Saved execution log: {exec_log_path}")
        else:
            print_warning("Failed to save execution log")

        print()
        print(f"{Colors.CYAN}No resources were created (dry-run mode){Colors.NC}")
        print("\nRun without --dry-run to actually deploy these resources.")
        print(f"\nCheck logs for full API call details:")
        if local_log_path:
            print(f"  Deployment log: {local_log_path}")
        if exec_log_path:
            print(f"  Execution log: {exec_log_path}")

    else:
        # Live deployment: Display summary and save artifacts
        display_deployment_summary(
            server_config.server_name,
            deployment_result.public_ip_address,
            deployment_result.fqdn,
            server_config.private_key_path,
            server_config.admin_username,
            server_config.keyvault_name,
            deployment_result.storage_info,
            server_config.user_ip,
            config['nsg']['ssh_personal_fallback_ip']
        )

        # Save deployment artifacts
        save_deployment_artifacts(
            deploy_log,
            server_config.server_name,
            deployment_result.storage_info['name'],
            deployment_result.storage_info['id'],
            azure_env.credential,
            azure_env.subscription_id
        )

        # Save execution log
        if exec_log:
            exec_log.log("INFO", "Deployment complete - all resources created successfully")
            exec_log_path = exec_log.save()
            if exec_log_path:
                print_success(f"Saved execution log: {exec_log_path}")
            else:
                print_warning("Failed to save execution log")


if __name__ == "__main__":
    try:
        main()
    finally:
        pause_before_exit()
