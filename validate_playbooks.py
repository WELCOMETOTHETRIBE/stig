#!/usr/bin/env python3
"""
Comprehensive playbook validation script.
Checks for the same issues the 3rd party checker was finding.
"""

import re
import sys
from pathlib import Path

# Try to import yaml for actual parsing validation
try:
    import yaml
    HAS_YAML = True
except ImportError:
    HAS_YAML = False
    print("Warning: PyYAML not available, skipping actual YAML parsing validation")


def check_yaml_syntax(file_path: Path) -> list[str]:
    """Check for YAML syntax issues."""
    issues = []
    
    try:
        with open(file_path, 'r') as f:
            content = f.read()
            lines = content.split('\n')
    except Exception as e:
        return [f"Error reading file: {e}"]
    
    # Check for unquoted task names with |
    for i, line in enumerate(lines, 1):
        if '- name:' in line and '|' in line:
            # Check if quoted
            if not ('"' in line or "'" in line):
                issues.append(f"Line {i}: Unquoted task name with | character")
                issues.append(f"  Content: {line.strip()[:100]}")
    
    # Try actual YAML parsing if available
    if HAS_YAML:
        try:
            list(yaml.safe_load_all(content))
        except yaml.YAMLError as e:
            issues.append(f"YAML parsing error: {str(e)[:200]}")
    
    return issues


def check_os_wrapper(file_path: Path, expected_product: str) -> list[str]:
    """Check OS wrapper and play name."""
    issues = []
    
    try:
        with open(file_path, 'r') as f:
            content = f.read()
    except Exception as e:
        return [f"Error reading file: {e}"]
    
    # Expected play names
    expected_names = {
        'rhel8': 'RHEL 8 STIG Hardening',
        'rhel9': 'RHEL 9 STIG Hardening',
        'windows11': 'Windows 11 STIG Hardening',
        'windows2022': 'Windows Server 2022 STIG Hardening',
    }
    
    expected_name = expected_names.get(expected_product)
    if expected_name:
        if expected_name not in content:
            issues.append(f"Wrong play name: Expected '{expected_name}'")
            # Find what play name is actually there
            match = re.search(r'- name:\s*["\']?([^"\'\n]+)', content)
            if match:
                issues.append(f"  Found: '{match.group(1)}'")
    
    # Check OS assertions
    if expected_product.startswith('rhel'):
        version = expected_product.replace('rhel', '')
        if f"distribution_major_version'] == '{version}'" not in content:
            issues.append(f"Wrong OS version assertion: Expected version {version}")
        if "os_family'] == 'RedHat'" not in content:
            issues.append("Wrong OS family assertion: Expected RedHat")
        if "os_family'] == 'Windows'" in content:
            issues.append("Found Windows OS assertion in RHEL playbook (WRONG)")
    elif expected_product.startswith('windows'):
        if "os_family'] == 'Windows'" not in content:
            issues.append("Wrong OS family assertion: Expected Windows")
        if "os_family'] == 'RedHat'" in content:
            issues.append("Found RedHat OS assertion in Windows playbook (WRONG)")
        if "distribution_major_version'] == '9'" in content:
            issues.append("Found RHEL 9 version assertion in Windows playbook (WRONG)")
    
    return issues


def check_product_tags(file_path: Path, expected_product: str) -> list[str]:
    """Check product tags."""
    issues = []
    
    try:
        with open(file_path, 'r') as f:
            content = f.read()
    except Exception as e:
        return [f"Error reading file: {e}"]
    
    # Count tags
    expected_tag = expected_product
    expected_tag_count = content.count(f'- {expected_tag}')
    
    # Check for wrong tags
    wrong_tags = {
        'rhel8': ['rhel9', 'windows11', 'windows2022'],
        'rhel9': ['rhel8', 'windows11', 'windows2022'],
        'windows11': ['rhel8', 'rhel9', 'windows2022'],
        'windows2022': ['rhel8', 'rhel9', 'windows11'],
    }
    
    wrong_tag_list = wrong_tags.get(expected_product, [])
    for wrong_tag in wrong_tag_list:
        wrong_count = content.count(f'- {wrong_tag}')
        if wrong_count > 0:
            issues.append(f"Found wrong product tag: {wrong_tag} ({wrong_count} occurrences)")
    
    if expected_tag_count == 0:
        issues.append(f"No {expected_tag} tags found")
    
    return issues


def check_config_prose(file_path: Path) -> list[str]:
    """Check for prose in config fields (line/regexp)."""
    issues = []
    
    try:
        with open(file_path, 'r') as f:
            lines = f.readlines()
    except Exception as e:
        return [f"Error reading file: {e}"]
    
    prose_indicators = [
        'verify', 'check', 'configure', 'system', 'file', 'command', 'following',
        'shadow', 'encrypted', 'representations', 'passwords', 'hash', 'value',
        'with the following', 'the following command'
    ]
    
    in_lineinfile = False
    line_value = None
    regexp_value = None
    
    for i, line in enumerate(lines, 1):
        stripped = line.strip()
        
        if 'ansible.builtin.lineinfile:' in stripped or 'ansible.builtin.blockinfile:' in stripped:
            in_lineinfile = True
            line_value = None
            regexp_value = None
            continue
        
        if in_lineinfile:
            if stripped.startswith('line:'):
                # Extract line value
                match = re.search(r'line:\s*["\']?([^"\'\n]+)', line)
                if match:
                    line_value = match.group(1).strip()
            elif stripped.startswith('regexp:'):
                # Extract regexp value
                match = re.search(r'regexp:\s*["\']?([^"\'\n]+)', line)
                if match:
                    regexp_value = match.group(1).strip()
            elif stripped and not stripped.startswith('-') and not stripped.startswith('#'):
                # End of lineinfile block
                if line_value:
                    line_lower = line_value.lower()
                    if any(indicator in line_lower for indicator in prose_indicators):
                        issues.append(f"Line {i}: Prose found in 'line:' field")
                        issues.append(f"  Content: {line_value[:100]}")
                if regexp_value:
                    regexp_lower = regexp_value.lower()
                    if any(indicator in regexp_lower for indicator in prose_indicators):
                        issues.append(f"Line {i}: Prose found in 'regexp:' field")
                        issues.append(f"  Content: {regexp_value[:100]}")
                in_lineinfile = False
                line_value = None
                regexp_value = None
    
    return issues


def check_windows_modules(file_path: Path) -> list[str]:
    """Check if Windows playbooks use Windows modules."""
    issues = []
    
    try:
        with open(file_path, 'r') as f:
            content = f.read()
    except Exception as e:
        return [f"Error reading file: {e}"]
    
    # Only check Windows playbooks
    if 'windows' not in file_path.name.lower():
        return issues
    
    # Count Windows modules
    win_modules = content.count('ansible.windows.win_')
    debug_count = content.count('ansible.builtin.debug')
    
    # Count automation_automated tags
    automated_count = content.count('automation_automated')
    
    if win_modules == 0 and automated_count > 0:
        issues.append(f"No Windows modules found, but {automated_count} controls tagged as automated")
        issues.append(f"  Debug tasks: {debug_count}")
        issues.append("  All automated controls should use Windows modules, not debug")
    
    # Check for Linux-specific handlers in Windows playbooks
    linux_handlers = ['grub2-mkconfig', 'firewall-cmd', 'dconf update', 'sysctl -p']
    for handler in linux_handlers:
        if handler in content:
            issues.append(f"Found Linux handler in Windows playbook: {handler}")
    
    return issues


def check_linux_handlers(file_path: Path, expected_product: str) -> list[str]:
    """Check for Linux handlers in non-Linux playbooks."""
    issues = []
    
    try:
        with open(file_path, 'r') as f:
            content = f.read()
    except Exception as e:
        return [f"Error reading file: {e}"]
    
    # Only check non-Linux playbooks
    if expected_product.startswith('rhel'):
        return issues
    
    # Check for Linux-specific handlers
    linux_handlers = [
        'grub2-mkconfig',
        'firewall-cmd',
        'dconf update',
        'sysctl -p',
        'Regenerate grub configuration',
        'Reload firewalld',
        'Update dconf database',
    ]
    
    for handler in linux_handlers:
        if handler in content:
            issues.append(f"Found Linux handler in {expected_product} playbook: {handler}")
    
    return issues


def validate_playbook(file_path: Path, expected_product: str) -> dict:
    """Comprehensive validation of a playbook."""
    print(f"\n{'='*60}")
    print(f"Validating: {file_path.name}")
    print(f"Expected product: {expected_product}")
    print(f"{'='*60}\n")
    
    all_issues = []
    
    # 1. YAML syntax
    print("1. Checking YAML syntax...")
    yaml_issues = check_yaml_syntax(file_path)
    if yaml_issues:
        print(f"   ❌ Found {len(yaml_issues)} YAML syntax issues")
        all_issues.extend(yaml_issues)
    else:
        print("   ✅ YAML syntax OK")
    
    # 2. OS wrapper
    print("2. Checking OS wrapper and play name...")
    os_issues = check_os_wrapper(file_path, expected_product)
    if os_issues:
        print(f"   ❌ Found {len(os_issues)} OS wrapper issues")
        all_issues.extend(os_issues)
    else:
        print("   ✅ OS wrapper OK")
    
    # 3. Product tags
    print("3. Checking product tags...")
    tag_issues = check_product_tags(file_path, expected_product)
    if tag_issues:
        print(f"   ❌ Found {len(tag_issues)} tag issues")
        all_issues.extend(tag_issues)
    else:
        print("   ✅ Product tags OK")
    
    # 4. Config prose
    print("4. Checking for prose in config fields...")
    prose_issues = check_config_prose(file_path)
    if prose_issues:
        print(f"   ❌ Found {len(prose_issues)} prose issues")
        all_issues.extend(prose_issues)
    else:
        print("   ✅ Config fields OK")
    
    # 5. Windows modules (for Windows playbooks)
    if expected_product.startswith('windows'):
        print("5. Checking Windows modules...")
        win_issues = check_windows_modules(file_path)
        if win_issues:
            print(f"   ❌ Found {len(win_issues)} Windows module issues")
            all_issues.extend(win_issues)
        else:
            print("   ✅ Windows modules OK")
    
    # 6. Linux handlers in non-Linux playbooks
    print("6. Checking for Linux handlers in non-Linux playbooks...")
    handler_issues = check_linux_handlers(file_path, expected_product)
    if handler_issues:
        print(f"   ❌ Found {len(handler_issues)} handler issues")
        all_issues.extend(handler_issues)
    else:
        print("   ✅ Handlers OK")
    
    return {
        'file': file_path.name,
        'product': expected_product,
        'issues': all_issues,
        'issue_count': len(all_issues)
    }


def main():
    """Main validation function."""
    base_dir = Path(__file__).parent
    output_dir = base_dir / 'output' / 'ansible'
    
    playbooks = [
        (output_dir / 'stig_rhel8_hardening.yml', 'rhel8'),
        (output_dir / 'stig_rhel9_hardening.yml', 'rhel9'),
        (output_dir / 'stig_windows11_hardening.yml', 'windows11'),
        (output_dir / 'stig_windows2022_hardening.yml', 'windows2022'),
    ]
    
    results = []
    for playbook_path, product in playbooks:
        if not playbook_path.exists():
            print(f"❌ File not found: {playbook_path}")
            continue
        
        result = validate_playbook(playbook_path, product)
        results.append(result)
    
    # Summary
    print(f"\n{'='*60}")
    print("VALIDATION SUMMARY")
    print(f"{'='*60}\n")
    
    total_issues = 0
    for result in results:
        status = "❌ FAILED" if result['issue_count'] > 0 else "✅ PASSED"
        print(f"{status} {result['file']}: {result['issue_count']} issues")
        total_issues += result['issue_count']
        
        if result['issues']:
            print("\n   Issues found:")
            for issue in result['issues'][:10]:  # Show first 10 issues
                print(f"   - {issue}")
            if len(result['issues']) > 10:
                print(f"   ... and {len(result['issues']) - 10} more")
    
    print(f"\n{'='*60}")
    if total_issues == 0:
        print("✅ ALL PLAYBOOKS PASSED VALIDATION!")
    else:
        print(f"❌ TOTAL ISSUES FOUND: {total_issues}")
        sys.exit(1)
    print(f"{'='*60}\n")


if __name__ == '__main__':
    main()

