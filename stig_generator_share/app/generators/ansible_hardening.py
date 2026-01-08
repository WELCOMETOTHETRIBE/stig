"""Generate Ansible hardening playbook from STIG controls."""

import re
from pathlib import Path

from ..model.controls import StigControl
from .utils import extract_cli_commands
from .extractors import extract_package_names_from_commands


def generate_hardening_playbook(
    controls: list[StigControl], output_path: Path, stig_metadata: dict[str, str]
) -> None:
    """
    Generate an Ansible hardening playbook for ALL STIG controls.
    
    For automatable controls, generates actual Ansible tasks.
    For manual controls, generates command/shell tasks based on fix_text.

    Args:
        controls: List of STIG controls (ALL controls, not just automatable)
        output_path: Path where the playbook YAML file should be written
        stig_metadata: Dictionary with keys: stig_name, stig_release, source_file_name, generated_on
    """
    # Include ALL controls - we'll handle both automatable and manual
    all_controls = controls

    # Write the playbook file with comments
    output_path.parent.mkdir(parents=True, exist_ok=True)

    # Get OS family from first control
    if not controls:
        os_family = "rhel"  # Default fallback
    else:
        os_family = controls[0].os_family if controls[0].os_family else "rhel"
    stig_name = stig_metadata.get('stig_name', 'Unknown STIG')
    
    # Determine playbook name from STIG
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

        # Write playbook structure
        f.write(f"- name: Apply {playbook_name} STIG hardening\n")
        f.write("  hosts: all\n")
        f.write("  become: yes\n")
        f.write("  vars:\n")
        f.write("    # Place any tunable defaults here if needed later\n")
        f.write("  tasks:\n")

        # Write tasks for ALL controls
        # Every control should have a task - either with real commands or a manual debug task
        for control in all_controls:
            f.write("\n")
            task_lines = _format_task_with_comments(control, os_family)
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


def _format_task_with_comments(control: StigControl, os_family: str) -> str:
    """Format a task with comments and real Ansible implementation."""
    # Clean description and fix_text thoroughly to avoid YAML issues
    def clean_text(text: str, max_len: int = 100) -> list[str]:
        """Clean text and split into safe comment lines."""
        # Truncate
        text = text[:max_len] + "..." if len(text) > max_len else text
        # Replace newlines
        text = text.replace('\n', ' ').replace('\r', ' ')
        # Replace colons (YAML key separator)
        text = text.replace(':', ' -')
        # Remove non-printable except space/tab
        text = ''.join(c if c.isprintable() or c in [' ', '\t'] else ' ' for c in text)
        # Collapse spaces
        text = ' '.join(text.split())
        # Don't split - just truncate to avoid multi-line comment issues
        # Multi-line comments can cause YAML parsing issues
        if len(text) > 75:  # Leave room for comment prefix
            return [text[:75] + "..."]
        return [text] if text else []
    
    desc_lines = clean_text(control.description, 100)
    fix_lines = clean_text(control.fix_text, 100)
    nist_id = control.nist_family_id or "N/A"

    lines = [
        f"    # Category: {control.category}",
        f"    # STIG Severity: {control.severity}",
        f"    # NIST: {nist_id}",
    ]
    
    # Add description lines - ensure no YAML-breaking characters
    if desc_lines:
        first_desc = desc_lines[0].replace(':', ' -')[:80]  # Extra safety
        lines.append(f"    # Description: {first_desc}")
        for desc_line in desc_lines[1:]:
            clean_line = desc_line.replace(':', ' -')[:80]
            lines.append(f"    #   {clean_line}")
    
    # Add fix text lines - ensure no YAML-breaking characters
    if fix_lines:
        first_fix = fix_lines[0].replace(':', ' -')[:80]  # Extra safety
        lines.append(f"    # Fix Text: {first_fix}")
        for fix_line in fix_lines[1:]:
            clean_line = fix_line.replace(':', ' -')[:80]
            lines.append(f"    #   {clean_line}")

    # Generate actual Ansible task based on category and OS
    task = _generate_ansible_task(control, os_family)
    lines.extend(task)

    return "\n".join(lines)


def _generate_ansible_task(control: StigControl, os_family: str) -> list[str]:
    """Generate actual Ansible task implementation based on control."""
    # Quote the name to handle colons and special characters
    task_name = f"{control.id} | {control.title}"
    # Escape quotes in the name
    task_name = task_name.replace("'", "''")
    lines = [f"    - name: '{task_name}'"]
    
    # Check if we have REAL concrete commands available (not just prose)
    has_real_commands = control.has_real_commands()
    
    # Generate task based on OS family and whether we have real commands
    if has_real_commands:
        # We have real commands - generate real config task
        if os_family == "rhel" or os_family == "ubuntu":
            task = _generate_linux_task(control)
        elif os_family == "windows":
            task = _generate_windows_task(control)
        elif os_family == "network":
            task = _generate_network_task(control)
        else:
            task = _generate_generic_task(control)
    else:
        # No real commands available - generate manual debug task
        task = _generate_manual_debug_task(control)
    
    lines.extend(task)
    
    # Add tags
    scannability_tag = "scannable_with_nessus" if control.is_automatable else "not_scannable_with_nessus"
    lines.extend([
        "      tags:",
        "        - stig",
        f"        - {control.id}",
        f"        - {control.category}",
        f"        - severity_{control.severity}",
        f"        - {scannability_tag}",
    ])
    
    return lines


def _generate_linux_task(control: StigControl) -> list[str]:
    """Generate Linux/Unix Ansible task."""
    fix_text = control.fix_text
    check_text = control.check_text
    
    # File permissions
    if control.category == "file_permission":
        return _generate_file_permission_task(control, fix_text, check_text)
    
    # Service management
    elif control.category == "service":
        return _generate_service_task(control, fix_text, check_text)
    
    # Sysctl settings
    elif control.category == "sysctl":
        return _generate_sysctl_task(control, fix_text, check_text)
    
    # Package management
    elif control.category == "package":
        return _generate_package_task(control, fix_text, check_text)
    
    # Audit rules
    elif control.category == "audit":
        return _generate_audit_task(control, fix_text, check_text)
    
    # Configuration files
    elif control.category == "config":
        return _generate_config_task(control, fix_text, check_text)
    
    # Default: try to infer from fix_text
    else:
        return _infer_task_from_fix_text(control, fix_text, check_text)


def _generate_file_permission_task(control: StigControl, fix_text: str, check_text: str) -> list[str]:
    """Generate file permission task."""
    # Extract file path and mode
    file_path = _extract_file_path(fix_text or check_text)
    mode = _extract_file_mode(fix_text or check_text)
    owner = _extract_file_owner(fix_text or check_text)
    group = _extract_file_group(fix_text or check_text)
    
    if not file_path:
        return _generate_fallback_task(control)
    
    lines = ["      file:"]
    lines.append(f"        path: {file_path}")
    
    if mode:
        lines.append(f"        mode: '{mode}'")
    if owner:
        lines.append(f"        owner: {owner}")
    if group:
        lines.append(f"        group: {group}")
    
    lines.append("        state: file")
    
    return lines


def _generate_service_task(control: StigControl, fix_text: str, check_text: str) -> list[str]:
    """Generate service management task using structured service_actions if available."""
    from .extractors import parse_systemctl_command
    
    # Prefer structured service_actions from extractor
    if control.service_actions:
        service_action = control.service_actions[0]  # Use first action
        unit = service_action.get("unit")
        action = service_action.get("action")
        
        # Validate unit name - must not be a flag or empty
        invalid_flags = {"--now", "--mask", "--unmask", "--force", "--status", "--no-reload", "--no-block"}
        invalid_names = {"run", "with", "on", "following"}
        if unit and unit not in invalid_flags and unit.lower() not in invalid_names and not unit.startswith('-') and len(unit.strip()) > 0:
            lines = ["      systemd:"]
            lines.append(f"        name: {unit}")
            
            if action == "enable_and_start":
                lines.append("        enabled: yes")
                lines.append("        state: started")
            elif action == "mask":
                lines.append("        masked: yes")
                lines.append("        state: stopped")
            elif action == "unmask":
                lines.append("        masked: no")
            elif action == "disable":
                lines.append("        enabled: no")
                lines.append("        state: stopped")
            elif action == "stop":
                lines.append("        state: stopped")
            elif action == "start":
                lines.append("        state: started")
            elif action == "restart":
                lines.append("        state: restarted")
            else:  # enable (without --now)
                lines.append("        enabled: yes")
            
            return lines
    
    # Try parsing from fix_text/check_text using parse_systemctl_command
    combined_text = f"{fix_text or ''} {check_text or ''}"
    # Extract systemctl commands from text
    lines_list = combined_text.split('\n')
    for line in lines_list:
        parsed = parse_systemctl_command(line)
        if parsed:
            unit = parsed.get("unit")
            action = parsed.get("action")
            invalid_names = {"run", "with", "on", "following"}
            if unit and unit.lower() not in invalid_names:
                lines = ["      systemd:"]
                lines.append(f"        name: {unit}")
                
                if action == "enable_and_start":
                    lines.append("        enabled: yes")
                    lines.append("        state: started")
                elif action == "mask":
                    lines.append("        masked: yes")
                    lines.append("        state: stopped")
                elif action == "unmask":
                    lines.append("        masked: no")
                elif action == "disable":
                    lines.append("        enabled: no")
                    lines.append("        state: stopped")
                elif action == "stop":
                    lines.append("        state: stopped")
                elif action == "start":
                    lines.append("        state: started")
                elif action == "restart":
                    lines.append("        state: restarted")
                else:  # enable (without --now)
                    lines.append("        enabled: yes")
                
                return lines
    
    # Fallback to text extraction - but be very careful about flags
    service_name = _extract_service_name(fix_text or check_text)
    enabled = "enabled" in (fix_text or check_text).lower() or "enable" in (fix_text or check_text).lower()
    disabled = "disabled" in (fix_text or check_text).lower() or "disable" in (fix_text or check_text).lower()
    masked = "masked" in (fix_text or check_text).lower() or "mask" in (fix_text or check_text).lower()
    unmasked = "unmasked" in (fix_text or check_text).lower() or "unmask" in (fix_text or check_text).lower()
    
    # Validate service name - must not be a flag or invalid name
    invalid_flags = {"--now", "--mask", "--unmask", "--force", "--status", "--no-reload", "--no-block"}
    invalid_names = {"run", "with", "on", "following"}
    if not service_name or service_name in invalid_flags or service_name.lower() in invalid_names or service_name.startswith('-'):
        return _generate_manual_debug_task(control)
    
    lines = ["      systemd:"]
    lines.append(f"        name: {service_name}")
    
    if masked:
        lines.append("        masked: yes")
        lines.append("        state: stopped")
    elif unmasked:
        lines.append("        masked: no")
    elif disabled:
        lines.append("        enabled: no")
        lines.append("        state: stopped")
    elif enabled:
        lines.append("        enabled: yes")
        lines.append("        state: started")
    else:
        lines.append("        enabled: yes")
        lines.append("        state: started")
    
    return lines


def _generate_sysctl_task(control: StigControl, fix_text: str, check_text: str) -> list[str]:
    """Generate sysctl task using structured sysctl_params if available."""
    # Prefer structured sysctl_params from extractor
    if control.sysctl_params:
        sysctl_param = control.sysctl_params[0]  # Use first parameter
        param_name = sysctl_param.get("name")
        param_value = sysctl_param.get("value")
        
        if param_name and param_value:
            lines = ["      sysctl:"]
            lines.append(f"        name: {param_name}")
            lines.append(f"        value: '{param_value}'")
            lines.append("        state: present")
            lines.append("        sysctl_set: yes")
            lines.append("        reload: yes")
            return lines
    
    # Fallback to text extraction
    sysctl_param = _extract_sysctl_param(fix_text or check_text)
    sysctl_value = _extract_sysctl_value(fix_text or check_text)
    
    if not sysctl_param:
        return _generate_manual_debug_task(control)
    
    # CRITICAL: Do not emit sysctl task without a value
    if not sysctl_value:
        # Generate manual debug task instead
        return _generate_manual_debug_task(control)
    
    lines = ["      sysctl:"]
    lines.append(f"        name: {sysctl_param}")
    lines.append(f"        value: '{sysctl_value}'")
    lines.append("        state: present")
    lines.append("        sysctl_set: yes")
    lines.append("        reload: yes")
    
    return lines


def _generate_package_task(control: StigControl, fix_text: str, check_text: str) -> list[str]:
    """Generate package management task using conservative extraction."""
    # Use the improved extractor that only extracts from command lines
    combined_text = f"{fix_text or ''} {check_text or ''}"
    package_names = extract_package_names_from_commands(combined_text)
    
    # Stopwords blacklist - never generate tasks with these
    blacklist = {"that", "all", "is", "contents", "red", "run", "--now", "--mask"}
    
    # Filter out any blacklisted names
    valid_package_names = [pkg for pkg in package_names if pkg.lower() not in blacklist]
    
    # Determine if this is a removal or installation
    text_lower = combined_text.lower()
    remove = any(word in text_lower for word in ["remove", "uninstall", "erase"])
    
    # If we have a valid package name from commands, use it
    if valid_package_names:
        package_name = valid_package_names[0]  # Use first valid package name
        
        lines = ["      package:"]
        lines.append(f"        name: {package_name}")
        
        if remove:
            lines.append("        state: absent")
        else:
            lines.append("        state: present")
        
        return lines
    
    # Fallback: try the old extractor as last resort (but still validate)
    package_name = _extract_package_name(combined_text)
    if package_name and package_name.lower() not in blacklist:
        # Additional validation: must look like a real package name
        if len(package_name) >= 2 and re.match(r'^[a-z0-9][a-z0-9_.-]*$', package_name, re.IGNORECASE):
            lines = ["      package:"]
            lines.append(f"        name: {package_name}")
            
            if remove:
                lines.append("        state: absent")
            else:
                lines.append("        state: present")
            
            return lines
    
    # No confident package name found - generate manual debug task
    return _generate_manual_debug_task(control)


def _generate_audit_task(control: StigControl, fix_text: str, check_text: str) -> list[str]:
    """Generate audit rule task."""
    # Extract audit rule from fix_text
    audit_rule = _extract_audit_rule(fix_text or check_text)
    
    if audit_rule:
        lines = ["      lineinfile:"]
        lines.append("        path: /etc/audit/rules.d/audit.rules")
        lines.append(f"        line: '{audit_rule}'")
        lines.append("        create: yes")
        lines.append("        mode: '0640'")
        return lines
    
    return _generate_fallback_task(control)


def _generate_config_task(control: StigControl, fix_text: str, check_text: str) -> list[str]:
    """Generate configuration file task."""
    file_path = _extract_file_path(fix_text or check_text)
    config_line = _extract_config_line(fix_text or check_text)
    
    # Try to extract config line more flexibly
    if not config_line:
        # Look for key=value patterns in quotes or after "set" or "configure"
        text = fix_text or check_text
        # Pattern: "KEY VALUE" or "KEY=VALUE" or "set KEY to VALUE"
        key_value_match = re.search(r'["\']?([A-Z_][A-Z0-9_]+)\s+([^\s"\']+)["\']?', text, re.IGNORECASE)
        if key_value_match:
            key = key_value_match.group(1)
            value = key_value_match.group(2)
            config_line = f"{key} {value}"
        else:
            # Look for lines that should be added/modified
            lines_in_text = text.split('\n')
            for line in lines_in_text:
                line = line.strip()
                # Skip empty, comments, or instructions
                if line and not line.startswith(('#', 'Note:', 'Step', 'Edit', 'Configure', 'Run', '$')):
                    # Check if it looks like a config line (has alphanumeric and possibly = or space)
                    if re.match(r'^[A-Za-z0-9_][A-Za-z0-9_\s=]+$', line) and len(line) < 200:
                        config_line = line
                        break
    
    if file_path:
        if config_line:
            # Use lineinfile to add/modify the config line
            lines = ["      lineinfile:"]
            lines.append(f"        path: {file_path}")
            lines.append(f"        line: '{config_line}'")
            # Extract key for regexp matching
            if '=' in config_line:
                key = config_line.split('=')[0].strip()
                lines.append(f"        regexp: '^#?\\s*{re.escape(key)}\\s*='")
            else:
                # Try to extract first word as key
                first_word = config_line.split()[0] if config_line.split() else ""
                if first_word:
                    lines.append(f"        regexp: '^#?\\s*{re.escape(first_word)}\\s+'")
            lines.append("        create: yes")
            lines.append("        backup: yes")
            return lines
        else:
            # We have a file path but no config line - try to extract from fix_text more aggressively
            # Look for sed/awk patterns or direct file modifications
            sed_pattern = re.search(r'sed\s+[^\n]+', fix_text, re.IGNORECASE)
            if sed_pattern:
                # Extract the sed command and convert to lineinfile
                sed_cmd = sed_pattern.group(0)
                # Try to extract the replacement pattern
                replacement_match = re.search(r"s/[^/]+/([^/]+)/", sed_cmd)
                if replacement_match:
                    new_line = replacement_match.group(1)
                    lines = ["      lineinfile:"]
                    lines.append(f"        path: {file_path}")
                    lines.append(f"        line: '{new_line}'")
                    lines.append("        create: yes")
                    lines.append("        backup: yes")
                    return lines
            
            # Last resort: use blockinfile to add a comment with instructions
            # Clean fix_text to avoid YAML issues
            fix_clean = fix_text[:200].replace('\n', ' ').replace('"', "'")
            lines = ["      blockinfile:"]
            lines.append(f"        path: {file_path}")
            lines.append("        block: |")
            lines.append(f"          # STIG: {control.id}")
            lines.append(f"          # {fix_clean}")
            lines.append("        create: yes")
            lines.append("        backup: yes")
            lines.append("        marker: '# {mark} STIG {mark}'")
            return lines
    
    # If we can't extract file path, try to infer from control description
    if "login.defs" in (fix_text or check_text).lower():
        file_path = "/etc/login.defs"
    elif "sshd_config" in (fix_text or check_text).lower():
        file_path = "/etc/ssh/sshd_config"
    elif "pam.d" in (fix_text or check_text).lower():
        # Extract PAM service name
        pam_match = re.search(r'/etc/pam\.d/([a-z-]+)', fix_text or check_text, re.IGNORECASE)
        if pam_match:
            file_path = f"/etc/pam.d/{pam_match.group(1)}"
        else:
            file_path = "/etc/pam.d/system-auth"
    elif "systemd" in (fix_text or check_text).lower():
        if "system.conf" in (fix_text or check_text).lower():
            file_path = "/etc/systemd/system.conf"
        else:
            file_path = "/etc/systemd/system.conf"
    
    if file_path and config_line:
        lines = ["      lineinfile:"]
        lines.append(f"        path: {file_path}")
        lines.append(f"        line: '{config_line}'")
        if '=' in config_line:
            key = config_line.split('=')[0].strip()
            lines.append(f"        regexp: '^#?\\s*{re.escape(key)}\\s*='")
        lines.append("        create: yes")
        lines.append("        backup: yes")
        return lines
    
    return _generate_fallback_task(control)


def _generate_windows_task(control: StigControl) -> list[str]:
    """Generate Windows Ansible task."""
    fix_text = control.fix_text
    check_text = control.check_text
    
    # Registry settings
    if control.category == "registry":
        return _generate_registry_task(control, fix_text, check_text)
    
    # GPO settings
    elif control.category == "gpo":
        return _generate_gpo_task(control, fix_text, check_text)
    
    # Service management
    elif control.category == "service":
        return _generate_windows_service_task(control, fix_text, check_text)
    
    # Default
    else:
        return _infer_task_from_fix_text(control, fix_text, check_text)


def _generate_registry_task(control: StigControl, fix_text: str, check_text: str) -> list[str]:
    """Generate Windows registry task."""
    reg_path = _extract_registry_path(fix_text or check_text)
    reg_value = _extract_registry_value_name(fix_text or check_text)
    reg_data = _extract_registry_data(fix_text or check_text)
    reg_type = _extract_registry_type(fix_text or check_text) or "REG_DWORD"
    
    if not reg_path or not reg_value:
        return _generate_fallback_task(control)
    
    lines = ["      win_regedit:"]
    lines.append(f"        path: {reg_path}")
    lines.append(f"        name: {reg_value}")
    
    if reg_data:
        lines.append(f"        data: {reg_data}")
    if reg_type:
        lines.append(f"        type: {reg_type}")
    
    lines.append("        state: present")
    
    return lines


def _generate_gpo_task(control: StigControl, fix_text: str, check_text: str) -> list[str]:
    """Generate GPO task (fallback to registry for now)."""
    return _generate_registry_task(control, fix_text, check_text)


def _generate_windows_service_task(control: StigControl, fix_text: str, check_text: str) -> list[str]:
    """Generate Windows service task."""
    service_name = _extract_service_name(fix_text or check_text)
    start_mode = "automatic" if "automatic" in (fix_text or check_text).lower() else "manual"
    
    if not service_name:
        return _generate_fallback_task(control)
    
    lines = ["      win_service:"]
    lines.append(f"        name: {service_name}")
    lines.append(f"        start_mode: {start_mode}")
    lines.append("        state: started")
    
    return lines


def _generate_network_task(control: StigControl) -> list[str]:
    """Generate network device task."""
    # Use structured commands from control
    cli_commands = control.automatable_commands or control.candidate_cli_blocks
    
    # If no structured commands, try to extract from fix_text
    if not cli_commands and control.fix_text:
        from .extractors import extract_cli_commands_from_block
        extracted_cmds, _ = extract_cli_commands_from_block(control.fix_text, purpose="hardening")
        cli_commands = extracted_cmds
    
    # Filter out show commands (hardening uses config commands, not show commands)
    config_commands = []
    for cmd in cli_commands:
        # Remove prompts
        cmd_clean = re.sub(r'^[A-Z0-9]+(?:\([^)]+\))?#\s*', '', cmd, flags=re.IGNORECASE).strip()
        # Skip show commands for hardening
        if not cmd_clean.lower().startswith('show '):
            # Remove any remaining prompts
            cmd_clean = re.sub(r'^[A-Z0-9]+#\s*', '', cmd_clean, flags=re.IGNORECASE).strip()
            if cmd_clean and len(cmd_clean) > 2:
                config_commands.append(cmd_clean)
    
    # Generate ios_config task if we have real CLI commands
    if config_commands:
        lines = ["      cisco.ios.ios_config:"]
        lines.append("        lines:")
        for cmd in config_commands[:10]:  # Limit to 10 commands
            # Ensure command is properly quoted
            cmd_clean = cmd.replace('"', '\\"').replace("'", "\\'")
            lines.append(f"          - {cmd_clean}")
        # Only add parents if we have interface/router context commands
        has_interface = any('interface' in cmd.lower() for cmd in config_commands)
        has_router = any('router' in cmd.lower() for cmd in config_commands)
        if not (has_interface or has_router):
            lines.append("        parents: []")
        return lines
    
    # No real commands found - fallback to manual debug task
    return _generate_manual_debug_task(control)


def _generate_generic_task(control: StigControl) -> list[str]:
    """Generate generic fallback task."""
    return _generate_fallback_task(control)


def _generate_manual_debug_task(control: StigControl) -> list[str]:
    """Generate debug task for controls without concrete commands."""
    # Clean title and description for the message
    title_clean = control.title.replace('"', "'").replace('\n', ' ').replace('\r', ' ')[:100]
    
    # Create concise message with STIG ID and summary
    fix_summary = control.fix_text[:100].replace('"', "'").replace('\n', ' ').replace('\r', ' ') if control.fix_text else ""
    
    msg = f"Manual hardening required for {control.id}: {title_clean}"
    if fix_summary:
        msg += f" - {fix_summary}"
    msg += " Refer to STIG FixText for detailed steps."
    
    return [
        "      debug:",
        f"        msg: \"{msg}\"",
    ]


def _extract_linux_commands_from_fix(control: StigControl, fix_text: str) -> list[str]:
    """Extract Linux commands from fix_text and create shell/command tasks."""
    from .extractors import split_command_and_prose, is_placeholder_command, is_probable_cli_command, normalize_command_line
    
    # Prose prefixes that should be rejected
    PROSE_PREFIXES = (
        "Configure ", "If ", "Document ", "To ", "NOTE:", "Must:", "The following condition",
        "All verification requirements", "Output must be:", "File location:",
        "Configuration: ", "Command output", "Review the command output",
    )
    
    # Use structured commands from control
    commands = control.automatable_commands or control.candidate_shell_blocks
    
    if commands:
        # Filter and clean commands
        clean_commands = []
        for cmd in commands:
            # Skip placeholder commands
            if is_placeholder_command(cmd):
                continue
            
            # Normalize and check for prose prefixes
            normalized = normalize_command_line(cmd)
            if any(normalized.startswith(p) for p in PROSE_PREFIXES):
                continue
            
            # Only keep real CLI commands
            if not is_probable_cli_command(cmd):
                continue
            
            # Split command from prose
            cmd_part, _ = split_command_and_prose(cmd)
            if cmd_part:
                # Final check: ensure it's a real command
                if is_probable_cli_command(cmd_part):
                    clean_commands.append(cmd_part)
        
        if clean_commands:
            lines = ["      shell: |"]
            for cmd in clean_commands[:5]:
                # Ensure command is clean and properly formatted
                cmd_clean = cmd.strip()
                # Split on newlines to handle multi-line commands
                for line in cmd_clean.split('\n'):
                    line = line.strip()
                    if line:
                        # Final check: reject prose lines
                        normalized_line = normalize_command_line(line)
                        if not any(normalized_line.startswith(p) for p in PROSE_PREFIXES):
                            if is_probable_cli_command(line):
                                lines.append(f"        {line}")
            if len(lines) > 1:  # More than just "shell: |"
                return lines
    
    # Fallback: debug message
    return [
        "      debug:",
        f"        msg: \"{control.id} - Manual configuration required. See STIG documentation for details.\"",
    ]


def _extract_windows_commands_from_fix(control: StigControl, fix_text: str) -> list[str]:
    """Extract Windows commands from fix_text."""
    commands = []
    
    # Look for PowerShell commands
    ps_patterns = [
        r'Get-ItemProperty[^\n]+',
        r'Set-ItemProperty[^\n]+',
        r'New-ItemProperty[^\n]+',
        r'Remove-ItemProperty[^\n]+',
        r'Get-ChildItem[^\n]+',
        r'Set-Service[^\n]+',
        r'Execute the following command:\s*\n\s*([^\n]+)',
    ]
    
    for pattern in ps_patterns:
        matches = re.findall(pattern, fix_text, re.IGNORECASE)
        for match in matches:
            cmd = match.strip() if isinstance(match, str) else match[0].strip()
            if cmd and len(cmd) > 5 and len(cmd) < 500:
                commands.append(cmd)
    
    # Look for reg commands
    if "reg add" in fix_text.lower() or "reg.exe" in fix_text.lower():
        reg_match = re.search(r'reg\s+(?:add|delete)\s+[^\n]+', fix_text, re.IGNORECASE)
        if reg_match:
            commands.append(reg_match.group(0))
    
    # Remove duplicates
    seen = set()
    unique_commands = []
    for cmd in commands:
        if cmd not in seen:
            seen.add(cmd)
            unique_commands.append(cmd)
    
    if unique_commands:
        lines = ["      win_shell: |"]
        for cmd in unique_commands[:5]:
            lines.append(f"        {cmd}")
        return lines
    
    # Fallback
    return [
        "      win_shell: |",
        f"        # Manual fix required for {control.id}",
        f"        # Fix text: {fix_text[:200]}",
        "        Write-Host 'Manual intervention required - see STIG documentation'",
    ]


def _extract_network_commands_from_fix(control: StigControl, fix_text: str) -> list[str]:
    """Extract network device commands from fix_text."""
    # Use structured commands from control
    cli_commands = control.automatable_commands or control.candidate_cli_blocks
    
    if cli_commands:
        lines = ["      cisco.ios.ios_config:"]
        lines.append("        lines:")
        for cmd in cli_commands[:10]:
            cmd_clean = cmd.replace('"', '\\"').replace("'", "\\'")
            lines.append(f"          - {cmd_clean}")
        lines.append("        parents: []")
        return lines
    
    # Fallback - no real commands found
    return [
        "      debug:",
        f"        msg: \"{control.id} - Manual configuration required. See STIG documentation for details.\"",
    ]


def _extract_generic_commands_from_fix(control: StigControl, fix_text: str) -> list[str]:
    """Extract generic commands from fix_text."""
    return [
        "      shell: |",
        f"        # Manual fix required for {control.id}",
        f"        # Fix text: {fix_text[:200]}",
        "        echo 'Manual intervention required - see STIG documentation'",
    ]


def _generate_fallback_task(control: StigControl) -> list[str]:
    """Generate fallback task when specific implementation can't be determined."""
    from .extractors import split_command_and_prose, is_placeholder_command, is_probable_cli_command, normalize_command_line
    
    # Prose prefixes that should be rejected
    PROSE_PREFIXES = (
        "Configure ", "If ", "Document ", "To ", "NOTE:", "Must:", "The following condition",
        "All verification requirements", "Output must be:", "File location:",
        "Configuration: ", "Command output", "Review the command output",
    )
    
    # Use structured commands if available
    commands = control.automatable_commands or control.candidate_shell_blocks
    
    if commands:
        # Filter out placeholder commands and split command/prose
        clean_commands = []
        for cmd in commands:
            if is_placeholder_command(cmd):
                continue
            
            # Normalize and check for prose prefixes
            normalized = normalize_command_line(cmd)
            if any(normalized.startswith(p) for p in PROSE_PREFIXES):
                continue
            
            # Only keep real CLI commands
            if not is_probable_cli_command(cmd):
                continue
            
            cmd_part, prose_part = split_command_and_prose(cmd)
            if cmd_part:
                # Final check: ensure it's a real command
                if is_probable_cli_command(cmd_part):
                    clean_commands.append(cmd_part)
        
        if clean_commands:
            # Use shell module to execute the commands
            lines = ["      shell: |"]
            for cmd in clean_commands[:5]:  # Limit to 5 commands
                # Ensure command is clean (no prose)
                cmd_clean = cmd.strip()
                # Split on newlines and add each line properly indented
                for line in cmd_clean.split('\n'):
                    line = line.strip()
                    if line:
                        # Final check: reject prose lines
                        normalized_line = normalize_command_line(line)
                        if not any(normalized_line.startswith(p) for p in PROSE_PREFIXES):
                            if is_probable_cli_command(line):
                                lines.append(f"        {line}")
            if len(lines) > 1:  # More than just "shell: |"
                return lines
    
    # No valid commands - use manual debug task
    return _generate_manual_debug_task(control)


def _infer_task_from_fix_text(control: StigControl, fix_text: str, check_text: str) -> list[str]:
    """Try to infer task type from fix_text."""
    text = (fix_text or check_text).lower()
    
    # Check for chmod
    if "chmod" in text:
        return _generate_file_permission_task(control, fix_text, check_text)
    
    # Check for systemctl
    if "systemctl" in text:
        return _generate_service_task(control, fix_text, check_text)
    
    # Check for sysctl
    if "sysctl" in text or "/proc/sys/" in text:
        return _generate_sysctl_task(control, fix_text, check_text)
    
    # Check for yum/dnf/rpm
    if any(cmd in text for cmd in ["yum", "dnf", "rpm", "apt"]):
        return _generate_package_task(control, fix_text, check_text)
    
    return _generate_fallback_task(control)


# Extraction helper functions

def _extract_file_path(text: str) -> str | None:
    """Extract file path from text."""
    patterns = [
        r'(/etc/[a-zA-Z0-9_/.-]+)',
        r'(/usr/[a-zA-Z0-9_/.-]+)',
        r'(/var/[a-zA-Z0-9_/.-]+)',
        r'(/opt/[a-zA-Z0-9_/.-]+)',
        r'(/root/[a-zA-Z0-9_/.-]+)',
        r'(/home/[a-zA-Z0-9_/.-]+)',
    ]
    for pattern in patterns:
        match = re.search(pattern, text)
        if match:
            return match.group(1)
    return None


def _extract_file_mode(text: str) -> str | None:
    """Extract file mode from text."""
    # Look for chmod patterns
    match = re.search(r'chmod\s+(\d{3,4})', text)
    if match:
        return match.group(1)
    # Look for mode patterns
    match = re.search(r'mode[:\s]+(\d{3,4})', text, re.IGNORECASE)
    if match:
        return match.group(1)
    return None


def _extract_file_owner(text: str) -> str | None:
    """Extract file owner from text."""
    match = re.search(r'chown\s+([a-zA-Z0-9_]+)', text)
    if match:
        return match.group(1)
    match = re.search(r'owner[:\s]+([a-zA-Z0-9_]+)', text, re.IGNORECASE)
    if match:
        return match.group(1)
    return None


def _extract_file_group(text: str) -> str | None:
    """Extract file group from text."""
    match = re.search(r'chown\s+[^:]+:([a-zA-Z0-9_]+)', text)
    if match:
        return match.group(1)
    match = re.search(r'group[:\s]+([a-zA-Z0-9_]+)', text, re.IGNORECASE)
    if match:
        return match.group(1)
    return None


def _extract_service_name(text: str) -> str | None:
    """Extract service name from text, carefully avoiding flags."""
    # Known flags that should never be treated as unit names
    invalid_flags = {'--now', '--mask', '--unmask', '--force', '--status', '--no-reload', '--no-block'}
    
    # Pattern 1: systemctl <action> <unit> [flags]
    # Pattern 2: systemctl [flags] <action> <unit>
    patterns = [
        # Standard: systemctl enable rngd
        r'systemctl\s+(?:enable|disable|mask|unmask|stop|start|restart)\s+([a-zA-Z0-9@.-]+)',
        # With --now: systemctl enable rngd --now or systemctl --now enable rngd
        r'systemctl\s+(?:--now\s+)?(?:enable|disable|mask|unmask|stop|start|restart)\s+([a-zA-Z0-9@.-]+)',
        # service <name> start/stop
        r'service\s+([a-zA-Z0-9@.-]+)',
    ]
    
    for pattern in patterns:
        match = re.search(pattern, text, re.IGNORECASE)
        if match:
            unit = match.group(1).strip()
            # Validate unit name
            if unit and unit not in invalid_flags and not unit.startswith('-') and len(unit) > 0:
                # Unit must contain at least one alphanumeric character
                if re.search(r'[a-zA-Z0-9]', unit):
                    return unit
    
    return None


def _extract_sysctl_param(text: str) -> str | None:
    """Extract sysctl parameter from text."""
    # net.ipv4.ip_forward = 0
    match = re.search(r'(net\.[a-zA-Z0-9_.]+|kernel\.[a-zA-Z0-9_.]+|fs\.[a-zA-Z0-9_.]+)', text)
    if match:
        return match.group(1)
    # /proc/sys/net/ipv4/ip_forward
    match = re.search(r'/proc/sys/([a-zA-Z0-9_/.-]+)', text)
    if match:
        param = match.group(1).replace('/', '.')
        return param
    return None


def _extract_sysctl_value(text: str) -> str | None:
    """Extract sysctl value from text."""
    match = re.search(r'=\s*([01]|yes|no|true|false)', text, re.IGNORECASE)
    if match:
        return match.group(1)
    return None


def _extract_package_name(text: str) -> str | None:
    """Extract package name from text."""
    # yum install <package>
    match = re.search(r'(?:yum|dnf|apt|rpm)\s+(?:install|remove)\s+([a-zA-Z0-9_.-]+)', text)
    if match:
        return match.group(1)
    return None


def _extract_audit_rule(text: str) -> str | None:
    """Extract audit rule from text."""
    # Look for -w or -a patterns
    match = re.search(r'(-[wa]\s+[^\n]+)', text)
    if match:
        return match.group(1).strip()
    return None


def _extract_config_line(text: str) -> str | None:
    """Extract configuration line from text."""
    # First, look for explicit config lines shown as examples
    # Pattern: Lines that are on their own, often after "set" or "add" or in quotes
    # Example: "SHA_CRYPT_MIN_ROUNDS 100000" on its own line
    
    lines = text.split('\n')
    for i, line in enumerate(lines):
        line = line.strip()
        # Skip empty, comments, instructions
        if not line or len(line) < 5:
            continue
        
        # Skip instruction lines
        if any(line.startswith(prefix) for prefix in ['#', 'Note:', 'Step', 'Edit', 'Configure', 'Run', '$', 'To ', 'The ', 'Add', 'Modify', 'Set']):
            continue
        
        # Skip sentences (end with period and have common words)
        if line.endswith('.') and any(word in line.lower() for word in ['the', 'and', 'or', 'must', 'should', 'will', 'can']):
            continue
        
        # Look for config patterns:
        # 1. KEY=VALUE or KEY VALUE (uppercase key)
        if re.match(r'^[A-Z_][A-Z0-9_]+(?:\s+|=)[^\s]+', line):
            # Make sure it's not part of a sentence
            if len(line) < 200 and not any(word in line.lower() for word in ['configure', 'edit', 'modify', 'set', 'add']):
                # Clean up
                line = line.strip('"\'.,;')
                return line
        
        # 2. lowercase_key=value (common in config files)
        if re.match(r'^[a-z_][a-z0-9_]+\s*=\s*[^\s\n]+', line):
            if len(line) < 200:
                return line.strip('"\'.,;')
    
    # Look for key=value patterns in the text
    match = re.search(r'([a-zA-Z0-9_]+\s*=\s*[^\n\s,;]+)', text)
    if match:
        line = match.group(1).strip()
        # Make sure it's not part of a sentence
        if not any(word in line.lower() for word in ['configure', 'edit', 'modify', 'set', 'add', 'the', 'and']):
            return line
    
    # Look for KEY VALUE patterns (like "SHA_CRYPT_MIN_ROUNDS 100000")
    # But be more careful - look for patterns that are clearly config, not sentences
    match = re.search(r'([A-Z_][A-Z0-9_]+)\s+([0-9]+|[a-z]+)', text)
    if match:
        key = match.group(1)
        value = match.group(2)
        # Check context - make sure it's not part of a sentence
        start_pos = match.start()
        context_before = text[max(0, start_pos-20):start_pos].lower()
        if not any(word in context_before for word in ['configure', 'edit', 'modify', 'set', 'add', 'the', 'and', 'or']):
            return f"{key} {value}"
    
    # Look for lines in quotes that look like config
    quoted_match = re.search(r'["\']([A-Z_][A-Z0-9_\s=]+)["\']', text)
    if quoted_match:
        line = quoted_match.group(1).strip()
        if len(line) < 200 and not line.startswith(('Note', 'Step', 'Edit', 'Configure', 'Run')):
            return line
    
    return None


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


def _extract_registry_data(text: str) -> str | None:
    """Extract registry data value from text."""
    match = re.search(r'Value:\s*([^\n]+)', text, re.IGNORECASE)
    if match:
        return match.group(1).strip()
    return None


def _extract_registry_type(text: str) -> str | None:
    """Extract registry type from text."""
    match = re.search(r'Type:\s*(REG_[A-Z]+)', text, re.IGNORECASE)
    if match:
        return match.group(1)
    return None


def _extract_ios_commands(text: str) -> list[str]:
    """
    Extract Cisco IOS commands from text.
    
    DEPRECATED: Use extract_cli_commands from utils.py instead.
    This function is kept for backward compatibility but delegates to extract_cli_commands.
    """
    raw_lines = [line.strip() for line in text.split('\n') if line.strip()]
    cli_commands, _ = extract_cli_commands(raw_lines)
    return cli_commands[:10]  # Limit to 10 commands
