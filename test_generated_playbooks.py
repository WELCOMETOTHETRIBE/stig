#!/usr/bin/env python3
"""
Self-test script to validate all generated Ansible playbooks.

Checks:
1. YAML syntax validity (using PyYAML)
2. Ansible syntax (using ansible-playbook --syntax-check)
3. Product-specific requirements (OS checks, tags, handlers)
4. No prose in config lines
5. Automation alignment (automated controls have real tasks)
"""

import json
import re
import subprocess
import sys
from pathlib import Path
from typing import Dict, List, Tuple

try:
    import yaml
    HAS_YAML = True
except ImportError:
    HAS_YAML = False
    print("WARNING: PyYAML not installed. YAML syntax checks will be limited.")


def check_yaml_syntax(file_path: Path) -> Tuple[bool, str]:
    """Check if YAML file is syntactically valid."""
    if not HAS_YAML:
        # Basic check: look for common YAML syntax errors
        with open(file_path, 'r', encoding='utf-8') as f:
            content = f.read()
            # Check for unquoted colons in name values
            if re.search(r'^\s+- name:\s+[^"\'].*:.*[^"\']', content, re.MULTILINE):
                return False, "Found unquoted name values with colons"
        return True, "Basic check passed (PyYAML not available for full validation)"
    
    try:
        with open(file_path, 'r', encoding='utf-8') as f:
            content = f.read()
            yaml.safe_load_all(content)
        return True, ""
    except yaml.YAMLError as e:
        return False, str(e)
    except Exception as e:
        return False, f"Unexpected error: {e}"


def check_ansible_syntax(file_path: Path) -> Tuple[bool, str]:
    """Check if playbook passes ansible-playbook --syntax-check."""
    try:
        result = subprocess.run(
            ['ansible-playbook', '--syntax-check', str(file_path)],
            capture_output=True,
            text=True,
            timeout=30
        )
        if result.returncode == 0:
            return True, ""
        else:
            return False, result.stderr or result.stdout
    except FileNotFoundError:
        return None, "ansible-playbook not found (skipping)"
    except subprocess.TimeoutExpired:
        return False, "Timeout after 30 seconds"
    except Exception as e:
        return False, f"Error: {e}"


def check_quoted_names(file_path: Path) -> List[str]:
    """Check that all task/handler names are quoted."""
    errors = []
    with open(file_path, 'r', encoding='utf-8') as f:
        for line_num, line in enumerate(f, 1):
            # Check for unquoted name: values
            # Match: - name: VALUE (where VALUE doesn't start with quote)
            # But allow: - name: "VALUE" or - name: 'VALUE'
            if re.match(r'^\s+- name:\s+[^"\']', line):
                # Allow simple play names at top level (no leading spaces)
                if re.match(r'^- name:\s+[A-Z][^:]*STIG Hardening', line):
                    continue
                # Check if it's actually unquoted (has colon or pipe without quotes)
                stripped = line.strip()
                if 'name:' in stripped:
                    name_part = stripped.split('name:', 1)[1].strip()
                    # If it starts with quote, it's fine
                    if name_part.startswith('"') or name_part.startswith("'"):
                        continue
                    # If it contains colons, pipes, or other special chars, it should be quoted
                    if ':' in name_part or '|' in name_part or len(name_part) > 50:
                        errors.append(f"Line {line_num}: Unquoted name value with special chars: {name_part[:80]}")
    return errors


def check_product_metadata(file_path: Path, expected_product: str) -> List[str]:
    """Check that playbook has correct product-specific metadata."""
    errors = []
    content = file_path.read_text(encoding='utf-8')
    
    # Extract product from filename
    if 'rhel8' in file_path.name:
        expected_play = "RHEL 8 STIG Hardening"
        expected_version = "'8'"
        expected_tag = "rhel8"
        expected_os = "RedHat"
    elif 'rhel9' in file_path.name:
        expected_play = "RHEL 9 STIG Hardening"
        expected_version = "'9'"
        expected_tag = "rhel9"
        expected_os = "RedHat"
    elif 'windows2022' in file_path.name:
        expected_play = "Windows Server 2022 STIG Hardening"
        expected_version = None  # Windows uses os_version, not distribution_major_version
        expected_tag = "windows2022"
        expected_os = "Windows"
    else:
        return errors  # Unknown product, skip checks
    
    # Check play name
    if f'- name: "{expected_play}"' not in content and f"- name: {expected_play}" not in content:
        errors.append(f"Play name should be '{expected_play}'")
    
    # Check OS assert
    if expected_os == "RedHat":
        if f"ansible_facts['os_family'] == '{expected_os}'" not in content:
            errors.append(f"Missing OS family check for {expected_os}")
        if expected_version and f"distribution_major_version'] == {expected_version}" not in content:
            errors.append(f"Missing version check for {expected_version}")
    elif expected_os == "Windows":
        if "ansible_facts['os_family'] == 'Windows'" not in content:
            errors.append("Missing Windows OS family check")
        if "distribution_major_version" in content:
            errors.append("Windows playbook should not check distribution_major_version")
    
    # Check tags
    tag_count = content.count(f"- {expected_tag}")
    wrong_tag = "rhel9" if expected_tag != "rhel9" else "rhel8"
    wrong_tag_count = content.count(f"- {wrong_tag}")
    if wrong_tag_count > 0:
        errors.append(f"Found {wrong_tag_count} instances of wrong tag '{wrong_tag}' (should be '{expected_tag}')")
    
    # Check handlers (Windows should not have Linux handlers)
    if expected_os == "Windows":
        linux_handlers = ["grub2-mkconfig", "sshd", "systemd", "sysctl", "firewalld", "dconf"]
        for handler in linux_handlers:
            if handler in content.lower():
                errors.append(f"Windows playbook should not contain Linux handler: {handler}")
    
    return errors


def check_config_lines(file_path: Path) -> List[str]:
    """Check that config lines don't contain prose."""
    errors = []
    prose_indicators = [
        'verify the system', 'check the system', 'configure the system',
        'the following command', 'with the following', 'following line',
        'shadow file is configured', 'representations of passwords',
        'hash value', 'command:', 'file:', 'directory:'
    ]
    
    with open(file_path, 'r', encoding='utf-8') as f:
        content = f.read()
        lines = content.split('\n')
        
        for line_num, line in enumerate(lines, 1):
            # Check lineinfile line: values
            if 'line:' in line and 'ansible.builtin.lineinfile' in '\n'.join(lines[max(0, line_num-5):line_num]):
                line_value = line.split('line:')[1].strip().strip('"\'')
                line_lower = line_value.lower()
                
                for indicator in prose_indicators:
                    if indicator in line_lower:
                        errors.append(f"Line {line_num}: Config line contains prose: {line_value[:100]}")
                        break
                
                # Check for very long lines (likely prose)
                if len(line_value) > 150:
                    errors.append(f"Line {line_num}: Config line too long (likely prose): {line_value[:100]}")
    
    return errors


def check_automation_alignment(file_path: Path) -> List[str]:
    """Check that automated controls have real tasks, not just debug."""
    errors = []
    
    try:
        with open(file_path, 'r', encoding='utf-8') as f:
            content = f.read()
        
        # Use regex-based parsing if YAML not available
        if not HAS_YAML:
            # Find tasks with automation_automated tag
            task_pattern = r'^\s+- name:\s+"([^"]+)"[^\n]*\n(?:[^\n]*\n)*?\s+tags:\s*\n(?:(?:[^\n]*\n)*?\s+-\s+automation_automated\s*\n)'
            tasks = re.finditer(r'^\s+- name:\s+"([^"]+)"(.*?)(?=^\s+- name:|^\s*$)', content, re.MULTILINE | re.DOTALL)
            
            for task_match in tasks:
                task_name = task_match.group(1)
                task_content = task_match.group(2)
                
                # Check if tagged as automated
                if 'automation_automated' in task_content:
                    # Check if only has debug
                    has_debug = 'ansible.builtin.debug' in task_content or 'debug:' in task_content
                    
                    # Check for real modules
                    real_modules = [
                        'ansible.builtin.file', 'ansible.builtin.lineinfile', 'ansible.builtin.sysctl',
                        'ansible.builtin.systemd', 'ansible.builtin.service', 'ansible.builtin.dnf',
                        'ansible.builtin.yum', 'ansible.builtin.command', 'ansible.builtin.shell',
                        'ansible.builtin.copy', 'ansible.builtin.template', 'ansible.builtin.blockinfile',
                        'ansible.windows.win_regedit', 'ansible.windows.win_security_policy',
                        'ansible.windows.win_user_right', 'ansible.windows.win_audit_policy'
                    ]
                    has_real_module = any(module in task_content for module in real_modules)
                    
                    if has_debug and not has_real_module:
                        errors.append(f"Automated control has only debug task: {task_name[:80]}")
        else:
            # Parse YAML to find tasks
            try:
                docs = list(yaml.safe_load_all(content))
                if not docs:
                    return errors
                
                playbook = docs[0]
                if 'tasks' not in playbook:
                    return errors
                
                tasks = playbook['tasks']
                
                for task in tasks:
                    if not isinstance(task, dict) or 'name' not in task:
                        continue
                    
                    # Check if task is tagged as automated
                    tags = task.get('tags', [])
                    is_automated = any('automation_automated' in str(tag) for tag in tags)
                    
                    if is_automated:
                        # Check if task only has debug module
                        has_debug_only = (
                            'debug' in task or 
                            'ansible.builtin.debug' in str(task) or
                            (len(task) == 2 and 'name' in task and ('debug' in task or 'msg' in task))
                        )
                        
                        # Check if task has a real enforcing module
                        real_modules = [
                            'file', 'lineinfile', 'sysctl', 'systemd', 'service', 'dnf', 'yum',
                            'apt', 'command', 'shell', 'copy', 'template', 'blockinfile',
                            'win_regedit', 'win_security_policy', 'win_user_right', 'win_audit_policy'
                        ]
                        has_real_module = any(module in str(task) for module in real_modules)
                        
                        if has_debug_only and not has_real_module:
                            task_name = task.get('name', 'Unknown')
                            errors.append(f"Automated control has only debug task: {task_name[:80]}")
            except Exception as e:
                # If YAML parsing fails, skip this check (will be caught by syntax check)
                pass
    
    except Exception as e:
        errors.append(f"Error checking automation alignment: {e}")
    
    return errors


def main():
    """Run all validation checks on generated playbooks."""
    base_dir = Path(__file__).parent
    output_dir = base_dir / 'output' / 'ansible'
    
    if not output_dir.exists():
        print(f"ERROR: Output directory not found: {output_dir}")
        sys.exit(1)
    
    # Find all hardening playbooks
    playbooks = list(output_dir.glob('stig_*_hardening.yml'))
    
    if not playbooks:
        print("No hardening playbooks found to test")
        sys.exit(0)
    
    print("=" * 80)
    print("STIG Generator Playbook Validation")
    print("=" * 80)
    print()
    
    all_errors = {}
    all_warnings = {}
    
    for playbook in sorted(playbooks):
        print(f"Testing: {playbook.name}")
        print("-" * 80)
        
        errors = []
        warnings = []
        
        # 1. YAML syntax
        valid, msg = check_yaml_syntax(playbook)
        if not valid:
            errors.append(f"YAML syntax error: {msg}")
        else:
            print("  ✓ YAML syntax valid")
        
        # 2. Ansible syntax
        ansible_result, ansible_msg = check_ansible_syntax(playbook)
        if ansible_result is False:
            errors.append(f"Ansible syntax error: {ansible_msg}")
        elif ansible_result is True:
            print("  ✓ Ansible syntax valid")
        else:
            warnings.append(f"Ansible check skipped: {ansible_msg}")
        
        # 3. Quoted names
        name_errors = check_quoted_names(playbook)
        if name_errors:
            errors.extend(name_errors)
        else:
            print("  ✓ All names are quoted")
        
        # 4. Product metadata
        product_errors = check_product_metadata(playbook, "")
        if product_errors:
            errors.extend(product_errors)
        else:
            print("  ✓ Product metadata correct")
        
        # 5. Config lines
        config_errors = check_config_lines(playbook)
        if config_errors:
            errors.extend(config_errors)
        else:
            print("  ✓ Config lines are clean")
        
        # 6. Automation alignment
        auto_errors = check_automation_alignment(playbook)
        if auto_errors:
            warnings.extend(auto_errors)  # Warnings, not errors
        else:
            print("  ✓ Automation alignment OK")
        
        if errors:
            all_errors[playbook.name] = errors
            print(f"  ✗ Found {len(errors)} error(s)")
        else:
            print("  ✓ All checks passed")
        
        if warnings:
            all_warnings[playbook.name] = warnings
        
        print()
    
    # Summary
    print("=" * 80)
    print("Summary")
    print("=" * 80)
    
    if all_errors:
        print(f"\n❌ ERRORS FOUND in {len(all_errors)} file(s):")
        for filename, file_errors in all_errors.items():
            print(f"\n  {filename}:")
            for error in file_errors[:10]:  # Show first 10 errors
                print(f"    - {error}")
            if len(file_errors) > 10:
                print(f"    ... and {len(file_errors) - 10} more errors")
        return 1
    else:
        print("\n✅ All playbooks passed validation!")
    
    if all_warnings:
        print(f"\n⚠️  WARNINGS in {len(all_warnings)} file(s):")
        for filename, file_warnings in all_warnings.items():
            print(f"\n  {filename}:")
            for warning in file_warnings[:5]:  # Show first 5 warnings
                print(f"    - {warning}")
            if len(file_warnings) > 5:
                print(f"    ... and {len(file_warnings) - 5} more warnings")
    
    return 0


if __name__ == '__main__':
    sys.exit(main())

