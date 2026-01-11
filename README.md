# TFS Azure Server Builder

Provision hardened Azure VMs for Laravel Forge with automated security verification.

## What This Does

1. **Builder** (Python) - Creates Azure VMs with security best practices
2. **Hardening Scripts** (Bash) - Apply and verify server security after Forge provisions

## Quick Start

```bash
# Clone
git clone https://github.com/YOUR_REPO/azure-server-builder.git
cd azure-server-builder

# Configure
mkdir -p config
cp config/settings.yaml.example config/settings.yaml
# Edit config/settings.yaml with your scopes, regions, etc.

# Run builder
python azure-server-builder.py
```

## Workflow

```
1. Run builder       → Creates Azure VM with Managed Identity
2. Add to Forge      → Forge provisions PHP, Nginx, MySQL, etc.
3. Run setup.sh      → Applies hardening (fail2ban, UFW, auditd, SSH)
4. Weekly verify.sh  → Checks compliance, uploads report to Azure Blob
```

## Requirements

- **Azure CLI** - `az login` before running
- **Python 3.8+** - For the builder script
- **ssh-keygen** - Pre-installed on macOS, Linux, Windows 10+

## Project Structure

```
tfs-azure-server-builder/
├── azure-server-builder.py         # Main builder script (Python)
├── builder.bat                     # Windows launcher (deployment)
├── builder-dry-run.bat             # Windows launcher (preview mode)
├── config/
│   ├── settings.yaml               # Your configuration (gitignored)
│   └── settings.yaml.example       # Template configuration (YAML)
├── ssh/                            # Generated SSH keys (gitignored)
├── scripts/                        # Server-side scripts (Bash)
│   ├── setup.sh              # One-time hardening
│   └── verify.sh             # Weekly verification
├── docs/
│   ├── POST-SETUP.md         # First VM setup guide
│   ├── ARCHITECTURE.md       # System design details
│   └── SCRIPTS.md            # Hardening script reference
└── CLAUDE.md                  # AI assistant context
```

## Server Naming

Format: `<env>-<role>-<region>-<scope>-<id>`

Example: `prd-app-scu-tfs-617`

| Part | Values | Description |
|------|--------|-------------|
| env | dev, stg, prd | Environment |
| role | app, db, worker, cache, edge, util | Server role |
| region | scu, eus2, wus2, etc. | Azure region code |
| scope | 3-4 letter code | Project/client identifier |
| id | 100-999 | Unique server ID |

## Security Features

### VM Creation (Builder)
- Trusted Launch with Secure Boot and vTPM
- Encryption at Host
- SSH key-only authentication
- NSG with Forge IPs pre-configured
- Managed Identity for Azure resource access
- SSH keys backed up to Key Vault

### Server Hardening (Scripts)
- SSH hardening (no root, key-only, modern ciphers)
- UFW firewall (22, 80, 443)
- Fail2ban (3 failures = 24hr ban)
- Kernel hardening (sysctl)
- Auditd (90-day retention)
- Weekly compliance reports to Azure Blob

## Reports Storage

The builder creates shared storage for all VMs:

| Container | Purpose | Retention |
|-----------|---------|-----------|
| `tfs-hardening-reports` | Builder logs, initial hardening | Permanent |
| `tfs-compliance-reports` | Weekly compliance checks | 5 years |

VMs use Managed Identity to upload reports - no credentials stored on servers.

## Adding to Laravel Forge

After VM deployment:

1. Copy public IP from builder output
2. In Forge: Servers → Create Server → Custom VPS
3. Enter IP, username (default: `svcops`), port 22
4. SSH into the server and prepare for Forge provisioning:
   ```bash
   # Switch to root with interactive shell
   sudo -i

   # Change to /tmp directory
   cd /tmp
   ```
5. Run Forge's provisioning command (shown in Forge UI)
6. After Forge completes, SSH in and run:
   ```bash
   sudo /etc/tfs/hardening/setup.sh
   ```

## Configuration

Edit `config/settings.yaml` to customize:

| Section | Purpose |
|---------|---------|
| `environments` | dev/stg/prd settings, disk redundancy |
| `roles` | Server role definitions |
| `regions` | Azure regions with short codes |
| `scopes` | Project/client identifiers |
| `vm_sizes` | Available sizes with pricing |
| `nsg.rules` | Firewall rules |
| `alerts.rules` | Metric alert thresholds |

## Fleet Management

Find all managed servers:
```bash
az vm list --query "[?tags.InfraStandard=='v1'].{Name:name, RG:resourceGroup}" -o table
```

Find TFS-managed storage:
```bash
az storage account list --query "[?tags.TFSManaged].name" -o tsv
```

## Documentation

- [Post-Setup Guide](docs/POST-SETUP.md) - Step-by-step verification checklist for your first VM
- [Maintenance Guide](docs/MAINTENANCE.md) - Server maintenance, updates, compliance checks, and Key Vault access
- [Architecture](docs/ARCHITECTURE.md) - System design and decisions
- [Scripts Reference](docs/SCRIPTS.md) - Hardening script details

## Troubleshooting

### Encryption at Host Not Registered
The builder detects this and offers to register. Takes ~10-15 minutes.

### Forge Can't Connect
1. Check VM is running: `az vm show -g <rg> -n <vm> --query powerState`
2. Verify NSG has Forge IPs (45.55.124.124, 159.203.150.216, etc.)

### SSH Locked Out After Hardening
Use Azure Serial Console or "Reset password" blade to recover.

## License

MIT
