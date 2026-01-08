"""Generate Ansible checker playbook for STIG controls."""

import re
from pathlib import Path

from ..model.controls import StigControl
from .utils import extract_cli_commands
from .extractors import extract_check_commands_from_block


def generate_checker_playbook(
    controls: list[StigControl], 
    output_path: Path, 
    stig_metadata: dict[str, str],
    check_type: str = "both"
) -> None:
    """
    Generate an Ansible checker playbook for STIG controls.
    
    Includes ALL controls and uses tags for runtime filtering:
    - validate_scannable_with_nessus: for controls where is_automatable == True
    - validate_not_scannable_with_nessus: for controls where is_automatable == False

    Args:
        controls: List of STIG controls (ALL controls will be included)
        output_path: Path where the playbook YAML file should be written
        stig_metadata: Dictionary with keys: stig_name, stig_release, source_file_name, generated_on
        check_type: DEPRECATED - kept for backward compatibility but no longer filters at generation time
    """
    # Include ALL controls - filtering happens at runtime via tags
    all_controls = controls

    output_path.parent.mkdir(parents=True, exist_ok=True)

    # Get OS family from first control
    if not controls:
        os_family = "rhel"  # Default fallback
    else:
        os_family = controls[0].os_family if controls[0].os_family else "rhel"
    stig_name = stig_metadata.get('stig_name', 'Unknown STIG')
    playbook_name = _get_playbook_name(stig_name, os_family)

    with open(output_path, "w") as f:
        # Write header comments
        f.write(f"# Generated from: {stig_name}\n")
        f.write(f"# STIG Release: {stig_metadata.get('stig_release', 'Unknown')}\n")
        f.write(f"# Source File: {stig_metadata.get('source_file_name', 'Unknown')}\n")
        f.write(f"# Generated On: {stig_metadata.get('generated_on', 'Unknown')}\n")
        f.write(f"# Total Controls: {len(all_controls)}\n")
        scannable_count = sum(1 for c in all_controls if c.is_automatable)
        not_scannable_count = len(all_controls) - scannable_count
        scannable_pct = (scannable_count * 100 // len(all_controls)) if all_controls else 0
        f.write(f"#   - Scannable with Nessus: {scannable_count} ({scannable_pct}%)\n")
        f.write(f"#   - Not Scannable with Nessus: {not_scannable_count} ({100 - scannable_pct}%)\n")
        f.write("\n")
        f.write("# Validation usage:\n")
        f.write("#   - Validate scannable controls only:\n")
        f.write("#       ansible-playbook checker.yml --tags validate_scannable_with_nessus\n")
        f.write("#   - Validate not scannable controls only:\n")
        f.write("#       ansible-playbook checker.yml --tags validate_not_scannable_with_nessus\n")
        f.write("#   - Validate both:\n")
        f.write("#       ansible-playbook checker.yml\n")
        f.write("\n")

        # Write playbook structure
        f.write(f"- name: Validate {playbook_name} STIG controls\n")
        f.write("  hosts: all\n")
        f.write("  become: yes\n")
        f.write("  vars:\n")
        f.write("    # Place any tunable defaults here if needed later\n")
        f.write("  tasks:\n")

        # Write tasks for ALL controls
        for control in all_controls:
            f.write("\n")
            task_lines = _format_checker_task(control, os_family)
            f.write(task_lines)
            f.write("\n")


def _get_playbook_name(stig_name: str, os_family: str) -> str:
    """Extract playbook name from STIG name or OS family."""
    stig_lower = stig_name.lower()
    
    if "rhel" in stig_lower or "red hat" in stig_lower:
        if "rhel8" in stig_lower or "rhel_8" in stig_lower:
            return "RHEL 8"
        elif "rhel7" in stig_lower or "rhel_7" in stig_lower:
            return "RHEL 7"
        elif "rhel9" in stig_lower or "rhel_9" in stig_lower:
            return "RHEL 9"
        return "RHEL"
    elif "windows" in stig_lower:
        if "windows11" in stig_lower or "windows_11" in stig_lower:
            return "Windows 11"
        elif "windows2022" in stig_lower or "windows_2022" in stig_lower:
            return "Windows 2022"
        elif "windows2019" in stig_lower or "windows_2019" in stig_lower:
            return "Windows 2019"
        return "Windows"
    elif "cisco" in stig_lower or "network" in stig_lower:
        return "Network Device"
    elif "ubuntu" in stig_lower:
        return "Ubuntu"
    else:
        return os_family.upper()


def _format_checker_task(control: StigControl, os_family: str) -> list[str]:
    """Format a checker task for a control."""
    check_lower = control.check_text.lower()
    check_text = control.check_text

    lines = []

    # Clean category and severity for comments - ensure no YAML-breaking characters
    def clean_comment(text: str) -> str:
        """Clean text for use in YAML comments."""
        text = str(text).replace('\n', ' ').replace('\r', ' ')
        text = text.replace(':', ' -')  # Replace colons
        text = ''.join(c if c.isprintable() or c in [' ', '\t'] else ' ' for c in text)
        return ' '.join(text.split())
    
    category_clean = clean_comment(control.category)
    severity_clean = clean_comment(control.severity)
    nist_clean = clean_comment(control.nist_family_id or 'N/A')

    # Add metadata comments
    lines.append(f"    # Category: {category_clean}")
    lines.append(f"    # STIG Severity: {severity_clean}")
    lines.append(f"    # NIST: {nist_clean}")
    lines.append(f"    # Scannability: {'Scannable with Nessus' if control.is_automatable else 'Not Scannable with Nessus'}")

    # Generate check based on OS family
    if os_family == "rhel" or os_family == "ubuntu":
        task = _generate_linux_check(control, check_text)
    elif os_family == "windows":
        task = _generate_windows_check(control, check_text)
    elif os_family == "network":
        task = _generate_network_check(control, check_text)
    else:
        task = _generate_generic_check(control, check_text)
    
    lines.extend(task)
    
    return "\n".join(lines)


def _generate_linux_check(control: StigControl, check_text: str) -> list[str]:
    """Generate Linux check task using structured check_commands with improved sanitization."""
    from .extractors import is_probable_cli_command, normalize_command_line
    
    # Prose prefixes that should be rejected
    PROSE_PREFIXES = (
        "Configure ", "If ", "Document ", "To ", "NOTE:", "Must:", "The following condition",
        "All verification requirements", "Output must be:", "File location:",
        "Configuration: ", "Command output", "Review the command output",
    )
    
    # Prefer structured check_commands from control
    check_commands = control.check_commands or control.candidate_check_blocks
    
    # If no structured commands, use the extractor (same as hardening/CTP)
    if not check_commands and check_text:
        extracted_cmds, _ = extract_check_commands_from_block(check_text, control.os_family or "rhel")
        check_commands = extracted_cmds
    
    # Filter out degenerate grep patterns and prose using robust command detection
    valid_commands = []
    
    for cmd in check_commands:
        if not cmd or len(cmd.strip()) < 3:
            continue
        
        # Normalize and check for prose prefixes
        normalized = normalize_command_line(cmd)
        if any(normalized.startswith(p) for p in PROSE_PREFIXES):
            continue
        
        # Only keep real CLI commands
        if not is_probable_cli_command(cmd):
            continue
        
        # Additional grep validation
        if normalized.lower().startswith('grep'):
            # Check if grep command has a meaningful pattern (not just flags)
            parts = normalized.split()
            has_meaningful_pattern = False
            for part in parts:
                # Skip flags
                if part.startswith('-'):
                    continue
                # Check if it's a real pattern (not just a flag or placeholder)
                if len(part) >= 3 and re.match(r'[A-Za-z0-9_.=-]{3,}', part):
                    if part not in ['-r', '-i', '-n', '-E', '-A1', 'args']:
                        has_meaningful_pattern = True
                        break
            
            if has_meaningful_pattern:
                valid_commands.append(cmd)
            # else: skip degenerate grep command
        else:
            # Not a grep command, keep it if it's a real command
            valid_commands.append(cmd)
    
    # Use valid commands
    commands = valid_commands
    
    # Use structured commands if available
    if commands:
        cmd = commands[0]
        var_name = _sanitize_var_name(f"{control.id}_check")
        
        # Clean command to avoid YAML issues
        cmd_clean = cmd.replace(':', ' -') if ':' in cmd and not cmd.strip().startswith('/') else cmd
        
        return [
            f"    - name: '{control.id} | Run check command'",
            "      shell:",
            f"        cmd: {cmd_clean}",
            f"      register: {var_name}_result",
            "      changed_when: false",
            "      failed_when: false",
            "      tags:",
            "        - stig_check",
            f"        - {control.id}",
            f"        - {control.category}",
            f"        - severity_{control.severity}",
            f"        - {'validate_scannable_with_nessus' if control.is_automatable else 'validate_not_scannable_with_nessus'}",
            "",
            f"    - name: '{control.id} | Display check result'",
            "      debug:",
            f"        var: {var_name}_result.stdout",
            "      tags:",
            "        - stig_check",
            f"        - {control.id}",
            f"        - {control.category}",
            f"        - severity_{control.severity}",
            f"        - {'validate_scannable_with_nessus' if control.is_automatable else 'validate_not_scannable_with_nessus'}",
        ]
    
    # Check if it mentions a file path (fallback)
    file_paths = _extract_file_paths(check_text)
    if file_paths:
        file_path = file_paths[0]
        var_name = _sanitize_var_name(f"{control.id}_{file_path}")
        
        return [
            f"    - name: '{control.id} | Check {file_path}'",
            "      stat:",
            f"        path: {file_path}",
            f"      register: {var_name}_stat",
            "      tags:",
            "        - stig_check",
            f"        - {control.id}",
            f"        - {control.category}",
            f"        - severity_{control.severity}",
            f"        - {'validate_scannable_with_nessus' if control.is_automatable else 'validate_not_scannable_with_nessus'}",
            "",
            f"    - name: '{control.id} | Assert {file_path} exists'",
            "      assert:",
            "        that:",
            f"          - {var_name}_stat.stat.exists",
            f"        fail_msg: \"{control.id} failed: {file_path} does not exist\"",
            f"        success_msg: \"{control.id} passed: {file_path} exists\"",
            "      tags:",
            "        - stig_check",
            f"        - {control.id}",
            f"        - {control.category}",
            f"        - severity_{control.severity}",
            f"        - {'validate_scannable_with_nessus' if control.is_automatable else 'validate_not_scannable_with_nessus'}",
            "",
            f"    - name: '{control.id} | Display file permissions'",
            "      debug:",
            f"        msg: \"Mode: {{{{{var_name}_stat.stat.mode}}}}, Owner: {{{{{var_name}_stat.stat.pw_name}}}}, Group: {{{{{var_name}_stat.stat.gr_name}}}}\"",
            "      tags:",
            "        - stig_check",
            f"        - {control.id}",
            f"        - {control.category}",
            f"        - severity_{control.severity}",
            f"        - {'validate_scannable_with_nessus' if control.is_automatable else 'validate_not_scannable_with_nessus'}",
        ]
    
    # Manual check placeholder - use manual_notes if available
    title_clean = control.title.replace(':', ' -').replace(chr(10), ' ').replace(chr(13), ' ').replace('[', '(').replace(']', ')')[:80]
    
    manual_msg = f"{control.id} requires manual verification."
    if control.manual_notes:
        manual_msg += f" See STIG documentation for procedure."
    
    return [
        f"    - name: '{control.id} | {title_clean}'",
        "      debug:",
        f"        msg: \"{manual_msg}\"",
        "      tags:",
        "        - stig_check",
        f"        - {control.id}",
        f"        - {control.category}",
        f"        - severity_{control.severity}",
        f"        - {'validate_scannable_with_nessus' if control.is_automatable else 'validate_not_scannable_with_nessus'}",
    ]


def _generate_windows_check(control: StigControl, check_text: str) -> list[str]:
    """Generate Windows check task."""
    # Use structured check commands from control
    check_commands = control.check_commands or control.candidate_check_blocks
    
    reg_path = _extract_registry_path(check_text)
    reg_value = _extract_registry_value_name(check_text)
    ps_commands = check_commands or _extract_powershell_commands(check_text)
    
    if reg_path and reg_value:
        # Registry check
        var_name = _sanitize_var_name(f"{control.id}_reg")
        
        return [
            f"    - name: '{control.id} | Check registry value'",
            "      win_regedit:",
            f"        path: {reg_path}",
            f"        name: {reg_value}",
            f"      register: {var_name}_result",
            "      tags:",
            "        - stig_check",
            f"        - {control.id}",
            f"        - {control.category}",
            f"        - severity_{control.severity}",
            f"        - {'validate_scannable_with_nessus' if control.is_automatable else 'validate_not_scannable_with_nessus'}",
            "",
            f"    - name: '{control.id} | Display registry value'",
            "      debug:",
            f"        var: {var_name}_result.value",
            "      tags:",
            "        - stig_check",
            f"        - {control.id}",
            f"        - {control.category}",
            f"        - severity_{control.severity}",
            f"        - {'validate_scannable_with_nessus' if control.is_automatable else 'validate_not_scannable_with_nessus'}",
        ]
    
    elif ps_commands:
        # PowerShell command check
        cmd = ps_commands[0]
        var_name = _sanitize_var_name(f"{control.id}_ps")
        
        return [
            f"    - name: '{control.id} | Run PowerShell check'",
            "      win_shell:",
            f"        cmd: {cmd}",
            f"      register: {var_name}_result",
            "      tags:",
            "        - stig_check",
            f"        - {control.id}",
            f"        - {control.category}",
            f"        - severity_{control.severity}",
            f"        - {'validate_scannable_with_nessus' if control.is_automatable else 'validate_not_scannable_with_nessus'}",
            "",
            f"    - name: '{control.id} | Display PowerShell result'",
            "      debug:",
            f"        var: {var_name}_result.stdout",
            "      tags:",
            "        - stig_check",
            f"        - {control.id}",
            f"        - {control.category}",
            f"        - severity_{control.severity}",
            f"        - {'validate_scannable_with_nessus' if control.is_automatable else 'validate_not_scannable_with_nessus'}",
        ]
    
    else:
        # Manual check
        # Clean title to avoid YAML issues
        title_clean = control.title.replace(':', ' -').replace(chr(10), ' ').replace(chr(13), ' ').replace('[', '(').replace(']', ')')[:80]
        return [
            f"    # Manual check required - see CTP document for procedure",
            f"    - name: '{control.id} | {title_clean}'",
            "      debug:",
            f"        msg: \"{control.id} requires manual verification. See CTP document for procedure.\"",
            "      tags:",
            "        - stig_check",
            f"        - {control.id}",
            f"        - {control.category}",
            f"        - severity_{control.severity}",
            f"        - {'validate_scannable_with_nessus' if control.is_automatable else 'validate_not_scannable_with_nessus'}",
        ]


def _generate_network_check(control: StigControl, check_text: str) -> list[str]:
    """Generate network device check task."""
    # Use structured check commands from control
    check_commands = control.check_commands or control.candidate_check_blocks
    
    # If no structured commands, extract from check_text
    if not check_commands and check_text:
        extracted_cmds, _ = extract_check_commands_from_block(check_text, control.os_family or "network")
        check_commands = extracted_cmds
    
    # Filter for show commands ONLY (checker must use show commands, not config commands)
    show_commands = [cmd for cmd in check_commands if cmd.lower().startswith('show ')]
    
    # Remove any prompts that might have been missed
    cleaned_show_commands = []
    for cmd in show_commands:
        # Remove prompts like "Switch#", "SW1#", etc.
        cmd_clean = re.sub(r'^[A-Z0-9]+(?:\([^)]+\))?#\s*', '', cmd, flags=re.IGNORECASE)
        cmd_clean = cmd_clean.strip()
        # Only keep if it's a show command
        if cmd_clean.lower().startswith('show ') and len(cmd_clean) > 5:
            cleaned_show_commands.append(cmd_clean)
    
    if cleaned_show_commands:
        cmd = cleaned_show_commands[0]
        var_name = _sanitize_var_name(f"{control.id}_ios")
        cmd_clean = cmd.replace('"', '\\"').replace("'", "\\'")
        
        return [
            f"    - name: '{control.id} | Run IOS show command'",
            "      cisco.ios.ios_command:",
            "        commands:",
            f"          - {cmd_clean}",
            f"      register: {var_name}_result",
            "      changed_when: false",
            "      failed_when: false",
            "      tags:",
            "        - stig_check",
            f"        - {control.id}",
            f"        - {control.category}",
            f"        - severity_{control.severity}",
            f"        - {'validate_scannable_with_nessus' if control.is_automatable else 'validate_not_scannable_with_nessus'}",
            "",
            f"    - name: '{control.id} | Display IOS command result'",
            "      debug:",
            f"        var: {var_name}_result.stdout",
            "      tags:",
            "        - stig_check",
            f"        - {control.id}",
            f"        - {control.category}",
            f"        - severity_{control.severity}",
            f"        - {'validate_scannable_with_nessus' if control.is_automatable else 'validate_not_scannable_with_nessus'}",
        ]
    
    else:
        # Manual check - no real commands found
        # Clean title to avoid YAML issues
        title_clean = control.title.replace(':', ' -').replace(chr(10), ' ').replace(chr(13), ' ').replace('[', '(').replace(']', ')')[:80]
        return [
            f"    # Manual check required - see CTP document for procedure",
            f"    - name: '{control.id} | {title_clean}'",
            "      debug:",
            f"        msg: \"{control.id} requires manual verification. See CTP document for procedure.\"",
            "      tags:",
            "        - stig_check",
            f"        - {control.id}",
            f"        - {control.category}",
            f"        - severity_{control.severity}",
            f"        - {'validate_scannable_with_nessus' if control.is_automatable else 'validate_not_scannable_with_nessus'}",
        ]


def _generate_generic_check(control: StigControl, check_text: str) -> list[str]:
    """Generate generic check task."""
    title_clean = control.title.replace(':', ' -').replace(chr(10), ' ').replace(chr(13), ' ').replace('[', '(').replace(']', ')')[:80]
    return [
        f"    # Manual check required - see CTP document for procedure",
        f"    - name: '{control.id} | {title_clean}'",
        "      debug:",
        f"        msg: \"{control.id} requires manual verification. See CTP document for procedure.\"",
        "      tags:",
        "        - stig_check",
        f"        - {control.id}",
        f"        - {control.category}",
        f"        - severity_{control.severity}",
        f"        - {'validate_scannable_with_nessus' if control.is_automatable else 'validate_not_scannable_with_nessus'}",
    ]


def _extract_file_paths(text: str) -> list[str]:
    """Extract file paths from check text."""
    patterns = [
        r"/etc/[a-zA-Z0-9_/.-]+",
        r"/usr/[a-zA-Z0-9_/.-]+",
        r"/var/[a-zA-Z0-9_/.-]+",
        r"/opt/[a-zA-Z0-9_/.-]+",
        r"/home/[a-zA-Z0-9_/.-]+",
        r"/root/[a-zA-Z0-9_/.-]+",
    ]

    paths = []
    for pattern in patterns:
        matches = re.findall(pattern, text)
        paths.extend(matches)

    # Remove duplicates and sort
    return sorted(list(set(paths)))


def _extract_commands(text: str) -> list[str]:
    """Extract command patterns from check text."""
    commands = []

    cmd_patterns = [
        r'run\s+["\']([^"\']+)["\']',
        r'execute\s+["\']([^"\']+)["\']',
        r'command:\s+["\']([^"\']+)["\']',
        r'`([^`]+)`',
        r'Run\s+([^\n]+)',
    ]

    for pattern in cmd_patterns:
        matches = re.findall(pattern, text, re.IGNORECASE)
        commands.extend(matches)

    return commands[:3]


def _extract_grep_patterns(text: str) -> list[str]:
    """Extract grep patterns from check text."""
    patterns = []
    
    # Look for grep commands
    grep_matches = re.findall(r'grep\s+["\']?([^"\'\s]+)["\']?', text, re.IGNORECASE)
    patterns.extend(grep_matches)
    
    # Look for patterns in quotes after "verify" or "check"
    verify_matches = re.findall(r'(?:verify|check)\s+["\']([^"\']+)["\']', text, re.IGNORECASE)
    patterns.extend(verify_matches)
    
    return patterns[:2]


def _extract_powershell_commands(text: str) -> list[str]:
    """Extract PowerShell commands from check text."""
    commands = []
    
    # Look for Get-ItemProperty, Get-ChildItem, etc.
    ps_patterns = [
        r'Get-ItemProperty[^\n]+',
        r'Get-ChildItem[^\n]+',
        r'Get-Service[^\n]+',
        r'Get-Process[^\n]+',
    ]
    
    for pattern in ps_patterns:
        matches = re.findall(pattern, text, re.IGNORECASE)
        commands.extend(matches)
    
    return commands[:3]


def _extract_registry_path(text: str) -> str | None:
    """Extract Windows registry path from text."""
    match = re.search(r'HKEY_[A-Z_]+\\([^\\\n]+(?:\\[^\\\n]+)*)', text, re.IGNORECASE)
    if match:
        hive_match = re.search(r'(HKEY_[A-Z_]+)', text, re.IGNORECASE)
        hive = hive_match.group(1) if hive_match else "HKEY_LOCAL_MACHINE"
        return f"{hive}\\{match.group(1)}"
    return None


def _extract_registry_value_name(text: str) -> str | None:
    """Extract registry value name from text."""
    match = re.search(r'Value Name:\s*([^\n]+)', text, re.IGNORECASE)
    if match:
        return match.group(1).strip()
    return None


def _extract_ios_show_commands(text: str) -> list[str]:
    """
    Extract Cisco IOS show commands from text.
    
    DEPRECATED: Use extract_cli_commands from utils.py instead.
    This function is kept for backward compatibility but delegates to extract_cli_commands.
    """
    raw_lines = [line.strip() for line in text.split('\n') if line.strip()]
    cli_commands, _ = extract_cli_commands(raw_lines)
    # Filter for show commands
    show_commands = [cmd for cmd in cli_commands if cmd.lower().startswith('show ')]
    return show_commands[:3]


def _sanitize_var_name(name: str) -> str:
    """Sanitize variable name for Ansible."""
    # Replace special characters with underscores
    name = re.sub(r'[^a-zA-Z0-9_]', '_', name)
    # Remove multiple underscores
    name = re.sub(r'_+', '_', name)
    # Remove leading/trailing underscores
    name = name.strip('_')
    return name
