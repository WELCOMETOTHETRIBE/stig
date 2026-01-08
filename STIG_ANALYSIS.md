# STIG Files Analysis & Recalibration Plan

## Overview

Analyzed STIG files in `stigs/data/` to understand structure and patterns for recalibrating generators.

## STIG Files Inventory

### Linux/Unix STIGs
- **RHEL 8 V2R5**: `U_RHEL_8_V2R5_STIG/U_RHEL_8_V2R5_Manual_STIG/U_RHEL_8_STIG_V2R5_Manual-xccdf.xml`
- **RHEL 9 V2R6**: `U_RHEL_9_V2R6_STIG/U_RHEL_9_V2R6_Manual_STIG/U_RHEL_9_STIG_V2R6_Manual-xccdf.xml`
  - **447 rules** - Largest Linux STIG

### Windows STIGs
- **Windows 11 V2R5**: `U_MS_Windows_11_V2R5_STIG/U_MS_Windows_11_V2R5_Manual_STIG/U_MS_Windows_11_STIG_V2R5_Manual-xccdf.xml`
  - **265 rules**
- **Windows Server 2022 V2R6**: `U_MS_Windows_Server_2022_V2R6_STIG/U_MS_Windows_Server_2022_V2R6_Manual_STIG/U_MS_Windows_Server_2022_STIG_V2R6_Manual-xccdf.xml`

### Network Device STIGs (Cisco)
- **Cisco IOS Switch NDM V3R5**: `U_Cisco_IOS_Switch_Y25M10_STIG/U_Cisco_IOS_Switch_NDM_V3R5_Manual_STIG/U_Cisco_IOS_Switch_NDM_STIG_V3R5_Manual-xccdf.xml`
  - **43 rules** - Smaller, focused on network device management
- **Cisco IOS Switch L2S V3R1**: Layer 2 Security
- **Cisco IOS Switch RTR V3R2**: Router-specific
- **Cisco IOS Router NDM V3R5**: Router network device management
- **Cisco IOS Router RTR V3R4**: Router-specific
- **Cisco NX-OS Switch** (multiple variants)
- **Cisco ISE** (NAC and NDM variants)

## Key Observations

### Rule ID Patterns
- **Linux/Windows**: `SV-257777r991589_rule` format
  - SV- prefix with 6-digit number
  - Revision suffix (r991589)
  - `_rule` suffix
- **Network Devices**: `SV-220570r960735_rule` format
  - Similar pattern but different number ranges

### Severity Distribution
- **high**, **medium**, **low**, **critical** (normalized by parser)
- Network device STIGs tend to have more **medium** severity

### Content Patterns

#### Linux (RHEL)
- Heavy use of shell commands (`chmod`, `chown`, `systemctl`, `grep`, `cat`)
- File permission controls
- Service management
- Package management (`yum`, `dnf`, `rpm`)
- Sysctl parameters
- SSH configuration
- Audit rules

#### Windows
- PowerShell commands (`Get-ItemProperty`, `Set-ItemProperty`, `Get-ChildItem`)
- Registry paths (`HKEY_LOCAL_MACHINE\...`)
- Group Policy settings
- Service management
- GUI-based verification steps
- Certificate management

#### Network Devices (Cisco)
- IOS CLI commands (`ip access-list`, `line vty`, `banner login`)
- Configuration mode commands
- Show commands for verification
- ACL management
- Banner configuration
- Session management

## Recalibration Requirements

### 1. Parser (`scripts/parse_stig.py`)

**Current Status**: Skeleton with TODO placeholders

**Needs**:
- ✅ Integrate with `app.parsers.xccdf_parser.parse_xccdf()` (already works)
- ✅ Map to simplified `StigControl` dataclass
- ✅ Extract product identifier from STIG filename/path
- ✅ Handle all STIG types (Linux, Windows, Network)

**Action Items**:
1. Wire up `parse_xccdf_file()` to call existing parser
2. Map `app.model.controls.StigControl` to simplified version
3. Extract product from filename (e.g., `U_RHEL_9_V2R6` → `rhel9`)
4. Test with all STIG types

### 2. Hardening Generator (`scripts/generate_hardening.py`)

**Current Status**: Basic category detection, placeholder tasks

**Needs by OS Family**:

#### Linux (RHEL)
- ✅ File permissions (`chmod` → `file` module)
- ✅ File ownership (`chown` → `file` module)
- ✅ Services (`systemctl` → `systemd` module)
- ✅ Packages (`yum/dnf` → `package` module)
- ✅ Sysctl (`sysctl` → `sysctl` module)
- ✅ SSH config (`/etc/ssh/sshd_config` → `lineinfile`/`blockinfile`)
- ✅ Audit rules (`/etc/audit/rules.d/` → `lineinfile`)

#### Windows
- ✅ Registry (`win_regedit` module)
- ✅ Services (`win_service` module)
- ✅ PowerShell scripts (`win_shell` module)
- ✅ Group Policy (manual/debug tasks)

#### Network Devices (Cisco)
- ✅ IOS commands (`cisco.ios.ios_config` module)
- ✅ Multi-line configurations
- ✅ Context-specific commands (interface, line vty, etc.)

**Action Items**:
1. Improve `categorize_control()` with OS-family-specific patterns
2. Implement all category-specific generators
3. Use existing extractors from `app.generators.extractors`
4. Test with RHEL 9 (447 controls) first, then expand

### 3. Checker Generator (`scripts/generate_checker.py`)

**Current Status**: Basic placeholder checks

**Needs by OS Family**:

#### Linux
- ✅ File checks (`stat` module)
- ✅ Package checks (`package_facts` or `command` + `rpm -q`)
- ✅ Service checks (`systemd` module or `command` + `systemctl`)
- ✅ Mount checks (`command` + `mount`)
- ✅ Config file checks (`command` + `grep`)

#### Windows
- ✅ Registry checks (`win_regedit` module)
- ✅ Service checks (`win_service` module)
- ✅ PowerShell checks (`win_shell` module)

#### Network Devices
- ✅ Show commands (`cisco.ios.ios_command` module)
- ✅ Configuration verification

**Action Items**:
1. Implement category-specific checkers
2. Prefer Ansible modules over shell
3. Extract check commands from `check_text`
4. Generate proper assertions

### 4. CTP Generator (`scripts/generate_ctp.py`)

**Current Status**: Basic placeholder rows

**Needs**:
- ✅ Extract real commands from `check_text`
- ✅ Format NIST IDs properly (AU.02.b format)
- ✅ Generate 1-3 steps per control
- ✅ Clean language (remove "Must:", "If it does not, this is a finding.")
- ✅ OS-family-specific command formatting

**Action Items**:
1. Improve command extraction (use existing extractors)
2. Implement `format_nist_control_id()` properly
3. Generate auditor-friendly language
4. Test with all STIG types

## Testing Strategy

### Phase 1: RHEL 9 (Primary Focus)
- **447 controls** - Largest and most complex
- Test parsing → JSON → all three artifacts
- Verify 100% coverage
- Refine category detection
- Improve command extraction

### Phase 2: Windows 11
- **265 controls** - Different OS family
- Test Windows-specific generators
- Verify registry, service, PowerShell handling

### Phase 3: Network Devices
- **43 controls** (Cisco IOS Switch NDM) - Smallest, good for quick validation
- Test IOS command extraction
- Verify multi-line configuration handling

### Phase 4: All STIGs
- Run full pipeline on all STIG files
- Verify coverage tests pass
- Generate final artifacts

## Next Steps

1. **Implement `parse_stig.py`** - Wire up existing parser
2. **Refine `generate_hardening.py`** - Start with RHEL 9 categories
3. **Refine `generate_checker.py`** - Module-based checks
4. **Refine `generate_ctp.py`** - Clean, auditor-friendly language
5. **Test incrementally** - One STIG type at a time
6. **Run coverage tests** - Ensure 100% coverage maintained

## File Organization

Current structure in `stigs/data/`:
```
stigs/data/
├── U_RHEL_8_V2R5_STIG/
├── U_RHEL_9_V2R6_STIG/
├── U_MS_Windows_11_V2R5_STIG/
├── U_MS_Windows_Server_2022_V2R6_STIG/
├── U_Cisco_IOS_Switch_Y25M10_STIG/
├── U_Cisco_IOS_Router_Y25M10_STIG/
├── U_Cisco_NX-OS_Switch_Y25M10_STIG/
└── U_Cisco_ISE_Y24M10_STIG/
```

**Recommendation**: Keep this structure for now. The parser can handle nested paths.

## Key Patterns to Extract

### Linux Commands
- `chmod [0-7]{3,4} /path/to/file`
- `chown user:group /path/to/file`
- `systemctl enable|disable|mask|unmask service`
- `sysctl -w net.ipv4.ip_forward=0`
- `grep -i "pattern" /etc/config/file`
- `dnf install|remove package`

### Windows Commands
- `Get-ItemProperty -Path "HKLM:\..." -Name "Value"`
- `Set-ItemProperty -Path "HKLM:\..." -Name "Value" -Value "Data"`
- `Get-Service -Name "ServiceName"`
- Registry paths: `HKEY_LOCAL_MACHINE\Software\...`

### Network Device Commands
- `ip access-list extended NAME`
- `line vty 0 4`
- `banner login #`
- `show running-config`
- Multi-line configuration blocks

## Success Criteria

✅ All STIG IDs appear in all three artifacts (hardening, checker, CTP)
✅ Generated tasks use proper Ansible modules (not just shell)
✅ CTP language is clean and auditor-friendly
✅ Coverage tests pass for all STIG types
✅ Generated artifacts are production-ready




