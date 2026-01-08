"""Generate Ansible checker playbook from StigControl JSON.

This script:
1. Reads StigControl objects from JSON
2. For each control, generates a checker task that asserts the required state
3. Prefers Ansible modules; falls back to shell when needed
4. Ensures tasks are tagged with `stig` and `sv_id`
5. Guarantees 1 checker per `sv_id` at minimum

Usage:
    python scripts/generate_checker.py --input data/rhel9_stig_controls.json --output ansible/stig_rhel9_checker.yml
"""

import argparse
import json
import logging
import re
import sys
from pathlib import Path
from typing import Optional

# Add parent directory to path to import app modules
sys.path.insert(0, str(Path(__file__).parent.parent))

from app.generators.extractors import (
    extract_check_commands_from_block,
    is_probable_cli_command,
    normalize_command_line,
)

logging.basicConfig(level=logging.INFO, format="%(levelname)s: %(message)s")
logger = logging.getLogger(__name__)


def load_controls_from_json(json_path: Path) -> list[dict]:
    """Load StigControl objects from JSON file."""
    with open(json_path, "r", encoding="utf-8") as f:
        controls = json.load(f)
    logger.info(f"Loaded {len(controls)} controls from {json_path}")
    return controls


def _sanitize_var_name(name: str) -> str:
    """Sanitize variable name for Ansible."""
    name = re.sub(r'[^a-zA-Z0-9_]', '_', name)
    name = re.sub(r'_+', '_', name)
    name = name.strip('_')
    return name


def format_cmd_for_yaml(cmd: str) -> str:
    """
    Format command string for YAML, using block scalar if needed.
    
    Args:
        cmd: Command string
        
    Returns:
        Formatted cmd line(s) as string - either inline or block scalar
    """
    # Check if command needs block scalar (contains special chars that break YAML)
    needs_block = any(char in cmd for char in [':', "'", '"', '|', '&', ';', '>', '<', '$', '`', '\\'])
    
    if needs_block:
        # Use block scalar (>) - single line commands
        return f"        cmd: >\n          {cmd}"
    else:
        # Simple inline
        return f"        cmd: {cmd}"


def _extract_file_path(text: str) -> Optional[str]:
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


def _extract_file_mode(text: str) -> Optional[str]:
    """Extract expected file mode from text."""
    match = re.search(r'mode[:\s]+(\d{3,4})', text, re.IGNORECASE)
    if match:
        return match.group(1)
    match = re.search(r'\b(0[0-7]{3})\b', text)
    if match:
        return match.group(1)
    return None


def _extract_service_name(text: str) -> Optional[str]:
    """Extract service name from text."""
    invalid_flags = {'--now', '--mask', '--unmask', '--force', '--status'}
    patterns = [
        r'systemctl\s+(?:is-active|is-enabled|status)\s+([a-zA-Z0-9@.-]+)',
        r'service\s+([a-zA-Z0-9@.-]+)',
    ]
    for pattern in patterns:
        match = re.search(pattern, text, re.IGNORECASE)
        if match:
            unit = match.group(1).strip()
            if unit and unit not in invalid_flags and not unit.startswith('-') and len(unit) > 0:
                if re.search(r'[a-zA-Z0-9]', unit):
                    return unit
    return None


def _extract_package_name(text: str) -> Optional[str]:
    """Extract package name from text."""
    from app.generators.extractors import extract_package_names_from_commands
    package_names = extract_package_names_from_commands(text)
    blacklist = {"that", "all", "is", "contents", "red", "run"}
    valid_names = [pkg for pkg in package_names if pkg.lower() not in blacklist]
    return valid_names[0] if valid_names else None


def _extract_sysctl_param(text: str) -> Optional[str]:
    """Extract sysctl parameter name from text."""
    match = re.search(r'sysctl\s+([a-z0-9_.]+)', text, re.IGNORECASE)
    if match:
        return match.group(1)
    match = re.search(r'([a-z0-9_]+(?:\.[a-z0-9_]+)+)', text)
    if match and 'kernel' in match.group(1) or 'fs' in match.group(1) or 'net' in match.group(1):
        return match.group(1)
    return None


def _extract_mount_path(text: str) -> Optional[str]:
    """Extract mount path from text."""
    match = re.search(r'mount[^\n]*\s+([/\w]+)', text, re.IGNORECASE)
    if match:
        return match.group(1)
    match = re.search(r'(/var|/tmp|/home|/usr|/opt|/boot)', text)
    if match:
        return match.group(1)
    return None


def generate_checker_task(control: dict) -> list[str]:
    """
    Generate checker task for a control.
    
    Args:
        control: StigControl dict
        
    Returns:
        List of YAML lines for the checker task
    """
    sv_id = control.get("sv_id", "UNKNOWN")
    check_text = control.get("check_text", "") or ""
    category = control.get("category", "other")
    product = control.get("product", "rhel9")
    automation_level = control.get("automation_level", "unknown")
    automation_source = control.get("automation_source", "none")
    # Normalize automation_level
    # New values: "automated", "manual_only", "unknown"
    # Legacy: "scannable_with_nessus", "not_scannable_with_nessus", "automatable", "semi_automatable", "manual"
    if automation_level in ["automatable", "scannable_with_nessus"]:
        automation_level_normalized = "automated"
    elif automation_level == "semi_automatable":
        automation_level_normalized = "manual_only"  # OCIL is not fully automated
    elif automation_level in ["manual", "not_scannable_with_nessus"]:
        automation_level_normalized = "manual_only"
    elif automation_level == "unknown":
        automation_level_normalized = "unknown"
    else:
        automation_level_normalized = automation_level
    
    title = control.get("title", "")[:80]
    
    var_name = _sanitize_var_name(f"{sv_id}_check")
    
    # Extract check commands using existing extractor
    check_commands, _ = extract_check_commands_from_block(check_text, product)
    
    # Filter for real commands
    valid_commands = [cmd for cmd in check_commands if is_probable_cli_command(cmd)]
    
    # For automated controls: prefer modules that mirror SCAP/OVAL/Nessus checks
    # For manual_only: focus on guiding human tester with clear manual verification steps
    
    if category == "file_permissions" or category == "file_owner":
        # Use stat module
        file_path = _extract_file_path(check_text)
        expected_mode = _extract_file_mode(check_text)
        
        if file_path:
            lines = [
                f"    - name: '{sv_id} | Check file'",
                "      stat:",
                f"        path: {file_path}",
                f"      register: {var_name}",
                "      tags:",
                "        - stig_check",
                f"        - {sv_id}",
            ]
            
            if expected_mode:
                lines.extend([
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
                ])
            
            return lines
    
    elif category == "package_absent":
        # Use package_facts
        package_name = _extract_package_name(check_text)
        if package_name:
            return [
                f"    - name: '{sv_id} | Check if package is absent'",
                "      package_facts:",
                "        manager: auto",
                f"      register: {var_name}",
                "      tags:",
                "        - stig_check",
                f"        - {sv_id}",
                "",
                f"    - name: '{sv_id} | Assert package is not installed'",
                "      assert:",
                "        that:",
                f"          - '{package_name} not in {var_name}.packages'",
                f"        fail_msg: \"{sv_id} failed: Package {package_name} is installed (should be absent)\"",
                f"        success_msg: \"{sv_id} passed: Package {package_name} is not installed\"",
                "      tags:",
                "        - stig_check",
                f"        - {sv_id}",
            ]
    
    elif category == "package_present":
        # Use package_facts
        package_name = _extract_package_name(check_text)
        if package_name:
            return [
                f"    - name: '{sv_id} | Check if package is installed'",
                "      package_facts:",
                "        manager: auto",
                f"      register: {var_name}",
                "      tags:",
                "        - stig_check",
                f"        - {sv_id}",
                "",
                f"    - name: '{sv_id} | Assert package is installed'",
                "      assert:",
                "        that:",
                f"          - '{package_name} in {var_name}.packages'",
                f"        fail_msg: \"{sv_id} failed: Package {package_name} is not installed\"",
                f"        success_msg: \"{sv_id} passed: Package {package_name} is installed\"",
                "      tags:",
                "        - stig_check",
                f"        - {sv_id}",
            ]
    
    elif category == "service_enabled" or category == "service_disabled":
        # Use service_facts module for better reliability
        service_name = _extract_service_name(check_text)
        if service_name:
            expected_state = "enabled" if category == "service_enabled" else "disabled"
            expected_active = "active" if category == "service_enabled" else "inactive"
            return [
                f"    - name: '{sv_id} | Gather service facts'",
                "      service_facts:",
                f"      register: {var_name}",
                "      tags:",
                "        - stig_check",
                f"        - {sv_id}",
                "",
                f"    - name: '{sv_id} | Assert service {service_name} is {expected_state}'",
                "      assert:",
                "        that:",
                f"          - '{service_name} in ansible_facts.services'",
                f"          - 'ansible_facts.services[service_name].state == \"{expected_active}\"'",
                f"          - 'ansible_facts.services[service_name].status == \"{expected_state}\"'",
                f"        fail_msg: \"{sv_id} failed: Service {service_name} is not {expected_state}\"",
                f"        success_msg: \"{sv_id} passed: Service {service_name} is {expected_state}\"",
                "      vars:",
                f"        service_name: {service_name}",
                "      tags:",
                "        - stig_check",
                f"        - {sv_id}",
            ]
    
    # For sysctl category: use sysctl module
    if category == "sysctl":
        sysctl_param = _extract_sysctl_param(check_text)
        if sysctl_param:
            return [
                f"    - name: '{sv_id} | Check sysctl parameter'",
                "      sysctl:",
                f"        name: {sysctl_param}",
                f"      register: {var_name}",
                "      tags:",
                "        - stig_check",
                f"        - {sv_id}",
                "",
                f"    - name: '{sv_id} | Display sysctl value'",
                "      debug:",
                f"        msg: \"{sysctl_param} = {{ {var_name}.value }}\"",
                "      tags:",
                "        - stig_check",
                f"        - {sv_id}",
            ]
    
    # For mount checks: use mount facts
    if category == "mount_option":
        mount_path = _extract_mount_path(check_text)
        if mount_path:
            return [
                f"    - name: '{sv_id} | Gather mount facts'",
                "      setup:",
                f"      register: {var_name}",
                "      tags:",
                "        - stig_check",
                f"        - {sv_id}",
                "",
                f"    - name: '{sv_id} | Check mount options for {mount_path}'",
                "      debug:",
                f"        msg: \"Mount point {mount_path} options: {{ ansible_facts.mounts | selectattr('mount', 'equalto', '{mount_path}') | map(attribute='options') | list }}\"",
                "      tags:",
                "        - stig_check",
                f"        - {sv_id}",
            ]
    
    # Fallback: use extracted check commands, but prefer command module over shell
    if valid_commands:
        cmd = valid_commands[0]
        cmd_clean = normalize_command_line(cmd)
        
        # Use command module instead of shell when possible (safer, no shell interpretation)
        use_shell = any(char in cmd_clean for char in ['|', '&', ';', '>', '<', '$', '`'])
        
        module = "shell" if use_shell else "command"
        
        # Format cmd using block scalar if needed
        cmd_formatted = format_cmd_for_yaml(cmd_clean)
        
        # Split into lines if it's a block scalar
        cmd_lines = cmd_formatted.split('\n')
        
        return [
            f"    - name: '{sv_id} | {title}'",
            f"      {module}:",
        ] + cmd_lines + [
            f"      register: {var_name}",
            "      changed_when: false",
            "      failed_when: false",
            "      tags:",
            "        - stig_check",
            f"        - {sv_id}",
            "",
            f"    - name: '{sv_id} | Display check result'",
            "      debug:",
            f"        var: {var_name}.stdout",
            "      tags:",
            "        - stig_check",
            f"        - {sv_id}",
        ]
    
    # Manual check placeholder
    # For automated/semi_automated: still try to generate a check
    # For manual: provide guidance
    if automation_level_normalized == "automated":
        # Should have had valid commands, but if not, use shell as fallback
        if valid_commands:
            cmd = valid_commands[0]
            cmd_clean = normalize_command_line(cmd)
            # Format cmd using block scalar if needed
            cmd_formatted = format_cmd_for_yaml(cmd_clean)
            cmd_lines = cmd_formatted.split('\n')
            return [
                f"    - name: '{sv_id} | {title}'",
                "      shell:",
            ] + cmd_lines + [
                f"      register: {var_name}",
                "      changed_when: false",
                "      failed_when: false",
                "      tags:",
                "        - stig_check",
                f"        - {sv_id}",
                "",
                f"    - name: '{sv_id} | Display check result'",
                "      debug:",
                f"        var: {var_name}.stdout",
                "      tags:",
                "        - stig_check",
                f"        - {sv_id}",
            ]
    
    # Manual or no valid commands
    manual_msg = f"{sv_id} requires manual verification"
    if automation_level_normalized == "manual_only":
        if automation_source in ["scap", "nessus"]:
            manual_msg += f". Not covered by {automation_source} automated scans. See CTP document for procedure."
        else:
            manual_msg += ". See CTP document for procedure."
    elif automation_level_normalized == "unknown":
        manual_msg += ". Automation status unknown. See CTP document for procedure."
    
    return [
        f"    - name: '{sv_id} | {title}'",
        "      debug:",
        f"        msg: \"{manual_msg}\"",
        "      tags:",
        "        - stig_check",
        f"        - {sv_id}",
    ]


def os_family_for_product(product: str) -> str:
    """Determine OS family from product identifier."""
    if product.startswith("windows"):
        return "Windows"
    elif product.startswith("rhel"):
        return "RedHat"
    elif product.startswith("ubuntu"):
        return "Debian"
    elif product.startswith("cisco"):
        return "network"
    return ""


def format_product_name(product: str) -> str:
    """Format product identifier for display."""
    if product.startswith("rhel"):
        version = product.replace("rhel", "")
        return f"RHEL {version}"
    elif product.startswith("windows"):
        version = product.replace("windows", "")
        if version == "2022":
            return "Windows Server 2022"
        elif version == "2019":
            return "Windows Server 2019"
        elif version == "11":
            return "Windows 11"
        elif version == "10":
            return "Windows 10"
        return f"Windows {version}"
    elif product.startswith("ubuntu"):
        version = product.replace("ubuntu", "")
        return f"Ubuntu {version}"
    elif product.startswith("cisco"):
        return product.replace("_", " ").title()
    return product.upper()


def get_product_tag_from_controls(controls: list[dict], fallback: str = "rhel9") -> str:
    """Extract product tag from controls, with fallback."""
    if controls:
        product = controls[0].get("product", "")
        if product and product != "unknown":
            return product
    return fallback


def generate_checker_playbook(controls: list[dict], output_path: Path, product: str = "rhel9") -> None:
    """
    Generate Ansible checker playbook from StigControl objects.
    
    Args:
        controls: List of StigControl dicts
        output_path: Path where playbook YAML should be written
        product: Product identifier (e.g., "rhel9") - used as fallback if not in controls
    """
    output_path.parent.mkdir(parents=True, exist_ok=True)
    
    # Extract product from controls or use fallback
    product_tag = get_product_tag_from_controls(controls, product)
    os_family = os_family_for_product(product_tag)
    product_name = format_product_name(product_tag)
    
    with open(output_path, "w") as f:
        # Write header with SCAP-based automation level counts
        f.write(f"# Generated checker playbook for {product_tag}\n")
        f.write(f"# Total Controls: {len(controls)}\n")
        
        # Count by automation level
        automated = sum(1 for c in controls if c.get("automation_level") in ["automated", "automatable", "scannable_with_nessus"])
        manual_only = sum(1 for c in controls if c.get("automation_level") in ["manual_only", "manual", "not_scannable_with_nessus"])
        unknown = sum(1 for c in controls if c.get("automation_level") == "unknown")
        
        f.write(f"#   - Automated: {automated} ({automated*100//len(controls) if controls else 0}%)\n")
        f.write(f"#   - Manual-only: {manual_only} ({manual_only*100//len(controls) if controls else 0}%)\n")
        if unknown > 0:
            f.write(f"#   - Unknown: {unknown} ({unknown*100//len(controls) if controls else 0}%)\n")
        
        f.write("\n")
        f.write("# Validation usage:\n")
        f.write("#   - Validate automated controls only:\n")
        f.write("#       ansible-playbook checker.yml --tags validate_automated\n")
        f.write("#   - Validate manual-only controls only:\n")
        f.write("#       ansible-playbook checker.yml --tags validate_manual_only\n")
        f.write("#   - Validate all controls:\n")
        f.write("#       ansible-playbook checker.yml\n")
        f.write("\n")
        
        # Write playbook structure
        f.write(f"- name: Validate {product_name} STIG controls\n")
        f.write("  hosts: all\n")
        f.write("  become: yes\n")
        f.write("  gather_facts: yes\n")
        f.write("  vars:\n")
        f.write("    # Place any tunable defaults here if needed later\n")
        
        # Add OS assert pre_tasks
        if os_family == "RedHat":
            f.write("  pre_tasks:\n")
            # Extract version from product (e.g., "rhel8" -> "8")
            version_match = re.search(r'(\d+)', product_tag)
            version = version_match.group(1) if version_match else "9"
            f.write(f"    - name: Verify {product_name} OS family\n")
            f.write("      ansible.builtin.assert:\n")
            f.write("        that:\n")
            f.write(f"          - ansible_facts['os_family'] == '{os_family}'\n")
            f.write(f"          - ansible_facts['distribution_major_version'] == '{version}'\n")
            f.write(f"        fail_msg: 'This playbook is designed for {product_name} only. Detected OS: {{ {{ ansible_facts[''os_family''] }} }} {{ {{ ansible_facts[''distribution_major_version''] }} }}'\n")
            f.write(f"        success_msg: 'OS verification passed: {product_name} detected'\n")
        elif os_family == "Windows":
            f.write("  pre_tasks:\n")
            f.write(f"    - name: Verify {product_name} OS family\n")
            f.write("      ansible.builtin.assert:\n")
            f.write("        that:\n")
            f.write(f"          - ansible_facts['os_family'] == '{os_family}'\n")
            if "2022" in product_tag:
                f.write("          - ansible_facts['os_version'] is version('10.0.20348', '>=')\n")
            elif "2019" in product_tag:
                f.write("          - ansible_facts['os_version'] is version('10.0.17763', '>=')\n")
            f.write(f"        fail_msg: 'This playbook is designed for {product_name} only. Detected OS: {{ {{ ansible_facts[''os_family''] }} }} {{ {{ ansible_facts[''os_version''] }} }}'\n")
            f.write(f"        success_msg: 'OS verification passed: {product_name} detected'\n")
        elif os_family:
            f.write("  pre_tasks:\n")
            f.write(f"    - name: Verify {product_name} OS family\n")
            f.write("      ansible.builtin.assert:\n")
            f.write("        that:\n")
            f.write(f"          - ansible_facts['os_family'] == '{os_family}'\n")
            f.write(f"        fail_msg: 'This playbook is designed for {product_name} only. Detected OS: {{ {{ ansible_facts[''os_family''] }} }}'\n")
            f.write(f"        success_msg: 'OS verification passed: {product_name} detected'\n")
        
        f.write("\n")
        f.write("  tasks:\n")
        
        # Generate tasks for each control
        for control in controls:
            sv_id = control.get("sv_id", "UNKNOWN")
            automation_level = control.get("automation_level", "manual")
            # Normalize automation_level for tagging
            if automation_level in ["automatable", "scannable_with_nessus"]:
                tag_level = "automated"
            elif automation_level == "semi_automatable":
                tag_level = "manual_only"  # OCIL is not fully automated
            elif automation_level in ["manual", "not_scannable_with_nessus"]:
                tag_level = "manual_only"
            elif automation_level == "unknown":
                tag_level = "unknown"
            else:
                tag_level = automation_level  # "automated", "manual_only", "unknown"
            
            # Generate task lines
            task_lines = generate_checker_task(control)
            
            # Add automation level tag to all tag sections
            task_lines_str = "\n".join(task_lines)
            tag_name = f"validate_{tag_level}"
            if tag_name not in task_lines_str:
                # Find all "tags:" sections and add automation level
                new_task_lines = []
                for i, line in enumerate(task_lines):
                    new_task_lines.append(line)
                    if line.strip() == "tags:":
                        # Look ahead to find where tags end
                        j = i + 1
                        while j < len(task_lines) and (task_lines[j].startswith("        -") or task_lines[j].strip() == ""):
                            j += 1
                        # Insert automation level tag before the closing
                        if j < len(task_lines):
                            new_task_lines.append(f"        - {tag_name}")
                task_lines = new_task_lines
            
            # Write task
            f.write("\n")
            for line in task_lines:
                f.write(f"{line}\n")
            f.write("\n")
    
    logger.info(f"Generated checker playbook with {len(controls)} tasks")


def verify_coverage(controls: list[dict], playbook_path: Path) -> bool:
    """
    Verify that all STIG IDs appear in the playbook.
    
    Args:
        controls: List of StigControl dicts
        playbook_path: Path to generated playbook
        
    Returns:
        True if all STIG IDs are covered, False otherwise
    """
    # Extract all STIG IDs from controls
    control_ids = {control.get("sv_id") for control in controls}
    
    # Read playbook and extract STIG IDs from tags
    playbook_ids = set()
    with open(playbook_path, "r") as f:
        content = f.read()
        # Look for tag patterns like "- RHEL-09-010010"
        import re
        tag_matches = re.findall(r'-\s+([A-Z]+-\d+-\d+)', content)
        playbook_ids.update(tag_matches)
    
    # Check for missing IDs
    missing_ids = control_ids - playbook_ids
    
    if missing_ids:
        logger.error(f"Missing STIG IDs in playbook: {missing_ids}")
        return False
    
    logger.info(f"✓ Coverage verified: all {len(control_ids)} STIG IDs present in playbook")
    return True


def main():
    """Main entry point for the checker generator script."""
    parser = argparse.ArgumentParser(
        description="Generate Ansible checker playbook from StigControl JSON"
    )
    parser.add_argument(
        "--input", "-i",
        type=Path,
        required=True,
        help="Path to input JSON file (StigControl objects)"
    )
    parser.add_argument(
        "--output", "-o",
        type=Path,
        required=True,
        help="Path to output YAML file"
    )
    parser.add_argument(
        "--product", "-p",
        type=str,
        default="rhel9",
        help="Product identifier (e.g., rhel9)"
    )
    parser.add_argument(
        "--verify-coverage",
        action="store_true",
        help="Verify that all STIG IDs are covered in the playbook"
    )
    
    args = parser.parse_args()
    
    try:
        # Load controls from JSON
        controls = load_controls_from_json(args.input)
        
        if not controls:
            logger.warning("No controls found in input file")
            return 1
        
        # Generate checker playbook
        generate_checker_playbook(controls, args.output, args.product)
        
        # Verify coverage if requested
        if args.verify_coverage:
            if not verify_coverage(controls, args.output):
                logger.error("Coverage verification failed")
                return 1
        
        logger.info("✓ Checker playbook generation complete!")
        
    except FileNotFoundError as e:
        logger.error(f"File not found: {e}")
        return 1
    except Exception as e:
        logger.error(f"Error: {e}", exc_info=True)
        return 1
    
    return 0


if __name__ == "__main__":
    exit(main())


