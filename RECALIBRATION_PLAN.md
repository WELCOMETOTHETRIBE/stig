# Recalibration Plan for STIG Generator

Based on analysis of actual STIG files in `stigs/data/`, this plan outlines the recalibration steps to ensure high-quality artifact generation.

## Current State

✅ **Parser**: Existing `app.parsers.xccdf_parser` works correctly
- Successfully parsed RHEL 9: 447 controls
- Handles all STIG types (Linux, Windows, Network)

✅ **STIG Files**: 14 XCCDF files available for testing
- RHEL 8, RHEL 9, Windows 11, Windows Server 2022
- Multiple Cisco network device STIGs

⚠️ **Generators**: Skeleton code with TODOs
- Need implementation of category-specific functions
- Need OS-family-specific handling

## Recalibration Steps

### Step 1: Wire Up Parser (Priority: HIGH)

**File**: `scripts/parse_stig.py`

**Current**: Skeleton with TODO placeholders

**Action**:
```python
def parse_xccdf_file(file_path: Path) -> list[StigControl]:
    # Import existing parser
    from app.parsers.xccdf_parser import parse_xccdf as parse_xccdf_legacy
    from app.model.controls import StigControl as LegacyStigControl
    
    # Parse using existing code
    legacy_controls = parse_xccdf_legacy(file_path, os_family=None)
    
    # Map to simplified StigControl
    controls = []
    for legacy in legacy_controls:
        control = StigControl(
            sv_id=legacy.id,  # e.g., "SV-257777r991589_rule"
            nist_id=legacy.nist_family_id,  # e.g., "CM.06.1(iv)"
            severity=legacy.severity,  # "high", "medium", "low", "critical"
            title=legacy.title,
            description=legacy.description,
            check_text=legacy.check_text,
            fix_text=legacy.fix_text,
            product=_extract_product_from_path(file_path),  # "rhel9", "windows11", etc.
            category="other",  # Will be determined later
            automation_level="manual" if not legacy.is_automatable else "automatable"
        )
        controls.append(control)
    
    return controls
```

**Test**:
```bash
python scripts/parse_stig.py \
  --xccdf stigs/data/U_RHEL_9_V2R6_STIG/U_RHEL_9_V2R6_Manual_STIG/U_RHEL_9_STIG_V2R6_Manual-xccdf.xml \
  --output data/json/rhel9_v2r6_controls.json
```

**Success Criteria**: JSON file created with 447 controls

---

### Step 2: Enhance Category Detection (Priority: HIGH)

**File**: `scripts/generate_hardening.py`

**Current**: Basic keyword matching

**Action**: Improve `categorize_control()` with OS-family-specific patterns

**Linux Patterns**:
```python
def categorize_control(control: dict) -> str:
    fix_text = (control.get("fix_text", "") or "").lower()
    check_text = (control.get("check_text", "") or "").lower()
    title = (control.get("title", "") or "").lower()
    combined = f"{fix_text} {check_text} {title}"
    
    # File permissions
    if any(pattern in combined for pattern in ["chmod", "mode", "permission", "0644", "0600"]):
        return "file_permissions"
    
    # File ownership
    if any(pattern in combined for pattern in ["chown", "owner", "chgrp", "group"]):
        return "file_owner"
    
    # Services
    if any(pattern in combined for pattern in ["systemctl", "service", "enable", "disable", "mask"]):
        return "service_enabled" if "disable" not in combined else "service_disabled"
    
    # Packages
    if any(pattern in combined for pattern in ["yum", "dnf", "rpm", "apt", "package"]):
        return "package_absent" if any(w in combined for w in ["remove", "uninstall", "erase"]) else "package_present"
    
    # Sysctl
    if "sysctl" in combined or "/proc/sys/" in combined:
        return "sysctl"
    
    # SSH config
    if "sshd_config" in combined or ("ssh" in combined and "config" in combined):
        return "ssh_config"
    
    # Mount
    if "mount" in combined or "/etc/fstab" in combined:
        return "mount_option"
    
    # Audit
    if "/etc/audit" in combined or "audit.rules" in combined:
        return "audit"
    
    return "other"
```

**Windows Patterns**:
```python
# Registry
if "registry" in combined or "hkey_" in combined or "get-itemproperty" in combined:
    return "registry"

# Service
if "get-service" in combined or "set-service" in combined:
    return "service_enabled"

# Group Policy
if "gpedit" in combined or "group policy" in combined:
    return "gpo"
```

**Network Device Patterns**:
```python
# ACL
if "access-list" in combined or "acl" in combined:
    return "acl"

# Banner
if "banner" in combined:
    return "banner"

# Line configuration
if "line vty" in combined or "line con" in combined:
    return "line_config"
```

**Test**: Run on RHEL 9 JSON and verify categories are assigned correctly

---

### Step 3: Implement Category-Specific Generators (Priority: HIGH)

**File**: `scripts/generate_hardening.py`

**Action**: Implement all category-specific functions using existing extractors

**Example - File Permissions**:
```python
def generate_file_permission_tasks(control: dict) -> list[str]:
    """Generate Ansible tasks for file_permissions category."""
    from app.generators.extractors import extract_file_path, extract_file_mode
    
    fix_text = control.get("fix_text", "")
    check_text = control.get("check_text", "")
    
    # Extract file path and mode
    file_path = extract_file_path(fix_text or check_text)
    mode = extract_file_mode(fix_text or check_text)
    owner = extract_file_owner(fix_text or check_text)
    group = extract_file_group(fix_text or check_text)
    
    if not file_path:
        return _generate_fallback_task(control)
    
    sv_id = control.get("sv_id", "UNKNOWN")
    lines = [
        f"    - name: '{sv_id} | Set file permissions'",
        "      file:",
        f"        path: {file_path}",
    ]
    
    if mode:
        lines.append(f"        mode: '{mode}'")
    if owner:
        lines.append(f"        owner: {owner}")
    if group:
        lines.append(f"        group: {group}")
    
    lines.append("        state: file")
    return lines
```

**Repeat for all categories**:
- `generate_package_present_tasks()`
- `generate_package_absent_tasks()`
- `generate_service_enabled_tasks()`
- `generate_service_disabled_tasks()`
- `generate_sysctl_tasks()`
- `generate_mount_option_tasks()`
- `generate_ssh_config_tasks()`
- `generate_audit_tasks()`
- Windows: `generate_registry_tasks()`, `generate_gpo_tasks()`
- Network: `generate_ios_config_tasks()`

**Test**: Generate hardening playbook for RHEL 9 and verify tasks are correct

---

### Step 4: Implement Checker Generators (Priority: MEDIUM)

**File**: `scripts/generate_checker.py`

**Action**: Create category-specific checker tasks using Ansible modules

**Example - File Permissions Check**:
```python
def generate_file_permission_check(control: dict) -> list[str]:
    """Generate checker task for file permissions."""
    from app.generators.extractors import extract_file_path, extract_file_mode
    
    check_text = control.get("check_text", "")
    file_path = extract_file_path(check_text)
    expected_mode = extract_file_mode(check_text)
    
    if not file_path:
        return _generate_fallback_check(control)
    
    sv_id = control.get("sv_id", "UNKNOWN")
    var_name = _sanitize_var_name(f"{sv_id}_stat")
    
    return [
        f"    - name: '{sv_id} | Check file permissions'",
        "      stat:",
        f"        path: {file_path}",
        f"      register: {var_name}",
        "      tags:",
        "        - stig_check",
        f"        - {sv_id}",
        "",
        f"    - name: '{sv_id} | Assert file permissions'",
        "      assert:",
        "        that:",
        f"          - '{var_name}.stat.mode == \"{expected_mode}\"'",
        f"        fail_msg: \"{sv_id} failed: File permissions do not match\"",
        f"        success_msg: \"{sv_id} passed: File permissions are correct\"",
        "      tags:",
        "        - stig_check",
        f"        - {sv_id}",
    ]
```

**Test**: Generate checker playbook and verify checks are correct

---

### Step 5: Refine CTP Generation (Priority: MEDIUM)

**File**: `scripts/generate_ctp.py`

**Action**: Extract real commands and format properly

**Key Improvements**:
1. Use existing extractors to get commands from `check_text`
2. Format NIST IDs: `CM.06.1(iv)` → `CM.06.1(iv)` (already correct)
3. Clean language: Remove "Must:", "If it does not, this is a finding."
4. Generate 1-3 steps per control

**Example**:
```python
def generate_ctp_rows_for_control(control: dict) -> list[list[str]]:
    """Generate CTP rows with real commands."""
    from app.generators.extractors import extract_check_commands_from_block
    
    sv_id = control.get("sv_id", "UNKNOWN")
    check_text = control.get("check_text", "")
    nist_id = format_nist_control_id(control.get("nist_id"))
    
    # Extract real commands
    check_commands, _ = extract_check_commands_from_block(check_text, control.get("product", "rhel9"))
    
    rows = []
    for step_num, cmd in enumerate(check_commands[:3], start=1):
        # Clean command (remove prose)
        action_cmd = _clean_command(cmd)
        
        # Extract expected result
        expected = _extract_expected_result(check_text, cmd)
        
        # Extract screen output
        screen_output = _extract_screen_output(check_text)
        
        rows.append([
            sv_id,
            nist_id,
            control.get("severity", "medium").upper(),
            str(step_num),
            f"Run: {action_cmd}",  # Clean, no "Must:"
            expected,  # Clean, no "If it does not, this is a finding."
            screen_output,
            f"NIST: {nist_id}" if nist_id != "N/A" else "",
            "[ ] Pass / [ ] Fail"
        ])
    
    return rows
```

**Test**: Generate CTP CSV and verify language is clean

---

## Testing Strategy

### Phase 1: RHEL 9 (447 controls)
1. Parse → JSON
2. Generate hardening playbook
3. Generate checker playbook
4. Generate CTP CSV
5. Run coverage tests
6. Manual review of sample tasks

### Phase 2: Windows 11 (265 controls)
1. Same pipeline
2. Verify Windows-specific generators work
3. Test registry, service, PowerShell handling

### Phase 3: Cisco IOS Switch NDM (43 controls)
1. Same pipeline
2. Verify IOS command extraction
3. Test multi-line configuration handling

### Phase 4: All STIGs
1. Run full pipeline on all files
2. Verify coverage tests pass
3. Generate final artifacts

## Success Metrics

✅ **Coverage**: 100% of STIG IDs in all artifacts
✅ **Quality**: Tasks use proper Ansible modules
✅ **Language**: CTP is clean and auditor-friendly
✅ **Testing**: All coverage tests pass
✅ **Production**: Generated artifacts are ready for use

## Timeline

- **Week 1**: Steps 1-2 (Parser + Category Detection)
- **Week 2**: Step 3 (Category-Specific Generators - Linux)
- **Week 3**: Step 3 (Category-Specific Generators - Windows/Network)
- **Week 4**: Steps 4-5 (Checker + CTP)
- **Week 5**: Testing and refinement

## Next Immediate Action

**Start with Step 1**: Wire up `parse_stig.py` to use existing parser.

Use Cursor with this prompt:
> "Implement parse_xccdf_file() in scripts/parse_stig.py to call app.parsers.xccdf_parser.parse_xccdf() and map the results to the simplified StigControl dataclass. Extract product identifier from the file path (e.g., 'U_RHEL_9_V2R6' → 'rhel9'). Test with stigs/data/U_RHEL_9_V2R6_STIG/U_RHEL_9_V2R6_Manual_STIG/U_RHEL_9_STIG_V2R6_Manual-xccdf.xml"




