"""Generate Ansible hardening playbook from StigControl JSON.

This script:
1. Reads StigControl objects from JSON
2. Maps each control to a category
3. Uses category-specific functions to generate Ansible tasks
4. Emits a single playbook with proper modules and tags
5. Ensures every STIG ID yields at least one task

Usage:
    python scripts/generate_hardening.py --input data/rhel9_stig_controls.json --output ansible/stig_rhel9_hardening.yml
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
    extract_sysctl_params,
    extract_systemd_actions,
    extract_package_names_from_commands,
)

logging.basicConfig(level=logging.INFO, format="%(levelname)s: %(message)s")
logger = logging.getLogger(__name__)


def quote_yaml_string(value: str) -> str:
    """
    Quote a YAML string value to ensure it's safe for YAML parsing.
    
    Always quotes the value to handle colons, special characters, etc.
    
    Args:
        value: String value to quote
        
    Returns:
        Quoted YAML string
    """
    # Escape any existing quotes
    escaped = value.replace('"', '\\"')
    return f'"{escaped}"'


def yaml_safe_scalar(text: str) -> str:
    """
    Convert text to a YAML-safe string representation.
    
    Returns either:
    - A single-quoted string (if text contains no single quotes or is simple)
    - A YAML block scalar (if text contains both single and double quotes or is multi-line)
    
    Args:
        text: Input text that may contain quotes, newlines, etc.
        
    Returns:
        YAML-safe string representation
    """
    if not text:
        return "''"
    
    # Clean up the text first
    text = text.strip()
    
    # Check if text contains both single and double quotes
    has_single_quote = "'" in text
    has_double_quote = '"' in text
    has_newline = '\n' in text
    
    # If text has both quote types or is multi-line, use block scalar
    if (has_single_quote and has_double_quote) or has_newline or len(text) > 200:
        # Use block scalar (folded style)
        # Escape any trailing backslashes or special sequences
        lines = text.split('\n')
        # Clean each line
        cleaned_lines = []
        for line in lines:
            # Remove trailing backslashes that could break YAML
            line = line.rstrip('\\')
            cleaned_lines.append(line)
        # Join with newlines and use block scalar
        block_content = '\n'.join(cleaned_lines)
        # Use literal block scalar (|) for multi-line, folded (>) for long single-line
        if has_newline:
            # Format as multi-line block scalar with proper indentation
            indented_lines = '\n          '.join(cleaned_lines)
            return f"|\n          {indented_lines}"
        else:
            # For long single-line, use folded block scalar
            return f">-\n          {block_content}"
    
    # If text has only single quotes, use double-quoted string with escaped quotes
    if has_single_quote:
        # Escape backslashes and double quotes
        escaped = text.replace('\\', '\\\\').replace('"', '\\"')
        return f'"{escaped}"'
    
    # If text has only double quotes, use single-quoted string
    if has_double_quote:
        # Escape single quotes by doubling them
        escaped = text.replace("'", "''")
        return f"'{escaped}'"
    
    # Simple case: use single quotes (preferred for YAML)
    # Escape any single quotes by doubling them
    escaped = text.replace("'", "''")
    return f"'{escaped}'"


def load_controls_from_json(json_path: Path) -> list[dict]:
    """Load StigControl objects from JSON file."""
    with open(json_path, "r", encoding="utf-8") as f:
        controls = json.load(f)
    logger.info(f"Loaded {len(controls)} controls from {json_path}")
    return controls


def categorize_control(control: dict) -> str:
    """
    Derive category for a control based on its content.
    
    Uses OS-family-specific patterns for better accuracy.
    First checks existing category from parser, then infers from content.
    
    Args:
        control: StigControl dict
        
    Returns:
        Category string (e.g., "file_permissions", "package_present", etc.)
    """
    fix_text = (control.get("fix_text", "") or "").lower()
    check_text = (control.get("check_text", "") or "").lower()
    title = (control.get("title", "") or "").lower()
    product = control.get("product", "").lower()
    combined = f"{fix_text} {check_text} {title}"
    
    # Check for specific categories FIRST (before using existing category)
    # This ensures we detect GRUB, SSH, dconf, etc. even if JSON has "config"
    
    # Systemd default target - check FIRST (before service categorization)
    if ("default target" in combined or "set-default" in combined or 
        ("graphical" in combined and "target" in combined and "default" in combined) or
        ("multi-user" in combined and "target" in combined and "default" in combined)):
        return "config"  # Handled in generate_config_tasks
    
    # GRUB kernel arguments - check early (highest priority for specific configs)
    if (re.search(r'GRUB_CMDLINE_LINUX', combined, re.IGNORECASE) or
        re.search(r'grubby\s+--args', combined, re.IGNORECASE) or
        re.search(r'/etc/default/grub', combined) or
        any(param in combined for param in ["vsyscall", "page_poison", "init_on_free", "audit=1", "pti=", "slab_common", "page_alloc"])):
        return "grub_kernel_args"
    
    # SSH config - check early
    if ("sshd_config" in combined or
        ("ssh" in combined and "config" in combined and ("/etc/ssh" in combined or "sshd" in combined)) or
        any(ssh_key in combined for ssh_key in ["Ciphers", "MACs", "HostbasedAuthentication", "PermitEmptyPasswords", 
                                                 "ClientAliveInterval", "ClientAliveCountMax", "PermitRootLogin", 
                                                 "PubkeyAuthentication", "GSSAPIAuthentication"])):
        return "ssh_config"
    
    # dconf/GNOME - check early
    if (re.search(r'gsettings\s+', combined, re.IGNORECASE) or
        "/etc/dconf" in combined or
        "dconf" in combined or
        any(gnome_key in combined for gnome_key in ["org.gnome", "org/gnome", "banner-message", "lock-screen", "screensaver"])):
        return "dconf"
    
    # OS-family-specific categorization - CHECK BEFORE existing_category to ensure Windows controls get proper categories
    if "windows" in product or "win" in product:
        # Windows patterns - check in priority order
        # Registry
        if ("registry" in combined or "hkey_" in combined or "get-itemproperty" in combined or 
            "set-itemproperty" in combined or "reg add" in combined or "reg.exe" in combined or
            re.search(r'HKLM:|HKCU:|HKCR:|HKU:', combined, re.IGNORECASE)):
            return "windows_registry"
        # User rights - check BEFORE security policy (many controls mention both)
        if ("user rights assignment" in combined or "user right" in combined and "assignment" in combined or
            "access this computer from the network" in combined or "allow log on" in combined or
            "deny log on" in combined or "add workstations to domain" in combined):
            return "windows_user_right"
        
        # Security policy
        elif ("security policy" in combined or "secedit" in combined or "gpedit.msc" in combined or
              "local security policy" in combined or "minimum password length" in combined or
              "account lockout" in combined or "password policy" in combined or
              "audit policy" in combined or "advanced audit policy" in combined):
            return "windows_security_policy"
        # User rights - be more aggressive in detection
        elif ("user rights" in combined or "user right" in combined or 
              "log on as" in combined or "deny log on" in combined or "allow log on" in combined or
              "log on locally" in combined or "log on through" in combined or
              "SeDeny" in combined or "SeInteractive" in combined or "SeNetwork" in combined or
              "SeBackup" in combined or "SeRestore" in combined or "SeDebug" in combined or
              "SeTakeOwnership" in combined or "SeSecurity" in combined or "SeSystemtime" in combined or
              "SeRemoteShutdown" in combined or "SeShutdown" in combined or "SeLoadDriver" in combined or
              "SeIncreaseQuota" in combined or "SeTcb" in combined or "SeCreateToken" in combined or
              "SeLockMemory" in combined or "privilege" in combined and ("assign" in combined or "remove" in combined)):
            return "windows_user_right"
        # Firewall - be more aggressive
        elif ("firewall" in combined and ("windows" in combined or "rule" in combined or "allow" in combined or "deny" in combined)) or \
             "new-netfirewallrule" in combined or "netsh advfirewall" in combined or \
             "remove-netfirewallrule" in combined or "get-netfirewallrule" in combined or \
             "firewall rule" in combined:
            return "windows_firewall"
        # Windows features
        elif ("install-windowsfeature" in combined or "uninstall-windowsfeature" in combined or
              "enable-windowsoptionalfeature" in combined or "disable-windowsoptionalfeature" in combined or
              "get-windowsfeature" in combined):
            return "windows_feature"
        # Windows services
        elif ("get-service" in combined or "set-service" in combined or "stop-service" in combined or
              "start-service" in combined or "winrm" in combined):
            return "windows_service"
        # Group Policy (fallback to manual)
        elif "gpedit" in combined or "group policy" in combined:
            return "other"  # Manual-only, will generate debug task
        else:
            return "other"
    
    # Use existing category if available and not "other", BUT override if we detect specific config patterns
    existing_category = control.get("category", "other")
    
    # Override existing category if we detect specific config file patterns
    # These take precedence over the existing category
    if "/etc/systemd/" in combined and ("system.conf" in combined or "user.conf" in combined):
        return "config"  # Systemd config files should be handled as config tasks
    if "/etc/issue" in combined or ("issue" in combined and "banner" in combined.lower()):
        return "config"  # Banner files should be handled as config tasks
    if "/etc/motd" in combined or ("motd" in combined and "banner" in combined.lower()):
        return "config"  # MOTD files should be handled as config tasks
    
    if existing_category and existing_category != "other":
        # Map legacy category names to new names
        category_map = {
            "file_permission": "file_permissions",
            "service": "service_enabled",  # Default to enabled, will check fix_text for disabled
        }
        mapped_category = category_map.get(existing_category, existing_category)
        
        # For service category, check if it should be disabled
        if mapped_category == "service_enabled" and ("disable" in combined or "mask" in combined or "stop" in combined):
            return "service_disabled"
        
        return mapped_category
    
    elif "cisco" in product or "network" in product:
        # Network device patterns
        if "access-list" in combined or "acl" in combined:
            return "acl"
        elif "banner" in combined:
            return "banner"
        elif "line vty" in combined or "line con" in combined:
            return "line_config"
        else:
            return "other"
    
    else:
        # Linux/Unix patterns (RHEL, Ubuntu, etc.)
        # Check fix_text more thoroughly for actual commands
        
        # File permissions - check for chmod, stat, or mode patterns
        if (re.search(r'\bchmod\s+\d{3,4}', fix_text, re.IGNORECASE) or
            re.search(r'\bmode[:\s]+\d{3,4}', combined, re.IGNORECASE) or
            re.search(r'\b0[0-7]{3}\b', combined) or
            any(pattern in combined for pattern in ["chmod", "permission", "0644", "0600", "0755", "0640", "0750"])):
            return "file_permissions"
        
        # File ownership - check for chown or owner patterns
        if (re.search(r'\bchown\s+', fix_text, re.IGNORECASE) or
            re.search(r'\bowner[:\s]+', combined, re.IGNORECASE) or
            any(pattern in combined for pattern in ["chown", "owner", "chgrp"])):
            return "file_owner"
        
        # Services - check for systemctl commands
        if (re.search(r'\bsystemctl\s+', fix_text, re.IGNORECASE) or
            "systemctl" in combined or "service" in combined):
            if any(word in combined for word in ["disable", "mask", "stop", "not enabled"]):
                return "service_disabled"
            elif any(word in combined for word in ["enable", "start", "active"]):
                return "service_enabled"
            else:
                return "service_enabled"  # Default
        
        # Packages - check for package manager commands
        if (re.search(r'\b(yum|dnf|rpm|apt)\s+', fix_text, re.IGNORECASE) or
            any(pattern in combined for pattern in ["yum", "dnf", "rpm", "apt", "package"])):
            # Check for update/upgrade first (these should be handled as config tasks)
            if any(word in combined for word in ["update", "upgrade", "security patches", "patches and updates"]):
                return "config"  # Package updates are handled in config tasks
            elif any(word in combined for word in ["remove", "uninstall", "erase", "purge", "not installed", "must not be"]):
                return "package_absent"
            elif any(word in combined for word in ["install", "present", "must be installed"]):
                return "package_present"
            else:
                # Default based on context
                if "not" in combined or "absent" in combined:
                    return "package_absent"
                else:
                    return "package_present"
        
        # Sysctl - check for sysctl commands or /proc/sys paths
        if (re.search(r'\bsysctl\s+', fix_text, re.IGNORECASE) or
            "/proc/sys/" in combined or
            re.search(r'kernel\.[a-z_]+', combined)):
            return "sysctl"
        
        # Note: GRUB, SSH, and dconf checks already done above before existing category check
        
        # Mount - check for mount or fstab
        if ("mount" in combined and ("/etc/fstab" in combined or "mount | grep" in combined or "mount option" in combined) or
            any(opt in combined for opt in ["nodev", "nosuid", "noexec", "sec="])):
            return "mount_option"
        
        # Audit - check for audit rules
        if ("/etc/audit" in combined or "audit.rules" in combined or "auditd" in combined or "auditctl" in combined):
            return "audit"
        
        # Firewalld - check for firewalld commands
        if ("firewalld" in combined or ("firewall" in combined and "firewall-cmd" in combined)):
            return "firewalld"
        
        # Config files - check for lineinfile patterns or config file paths
        if (re.search(r'\b(lineinfile|sed|grep)\s+', fix_text, re.IGNORECASE) or
            any(path in combined for path in ["/etc/login.defs", "/etc/pam.d/", "/etc/systemd/", "/etc/rsyslog", "/etc/issue", "/etc/motd"])):
            return "config"
        
        # Generic config if we see file paths
        if any(path in combined for path in ["/etc/", "/usr/", "/var/", "/opt/"]):
            return "config"
        
        return "other"


def _extract_file_path(text: str) -> Optional[str]:
    """Extract file path from text."""
    patterns = [
        r'(/boot/[a-zA-Z0-9_/.-]+)',  # Add /boot for GRUB files
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
    """Extract file mode from text."""
    # Look for chmod patterns
    match = re.search(r'chmod\s+(\d{3,4})', text)
    if match:
        return match.group(1)
    # Look for mode patterns
    match = re.search(r'mode[:\s]+(\d{3,4})', text, re.IGNORECASE)
    if match:
        return match.group(1)
    # Look for octal patterns in context
    match = re.search(r'\b(0[0-7]{3})\b', text)
    if match:
        return match.group(1)
    return None


def _extract_file_owner(text: str) -> Optional[str]:
    """Extract file owner from text."""
    match = re.search(r'chown\s+([a-zA-Z0-9_]+)', text)
    if match:
        return match.group(1)
    match = re.search(r'owner[:\s]+([a-zA-Z0-9_]+)', text, re.IGNORECASE)
    if match:
        return match.group(1)
    return None


def _extract_file_group(text: str) -> Optional[str]:
    """Extract file group from text."""
    # First, try chown pattern (most reliable)
    match = re.search(r'chown\s+[^:]+:([a-zA-Z0-9_]+)', text)
    if match:
        return match.group(1)
    # Try "group: root" pattern (colon separator)
    match = re.search(r'group\s*:\s*([a-zA-Z0-9_]+)', text, re.IGNORECASE)
    if match:
        return match.group(1)
    # Try "group owner of root" pattern (but not "group-owned")
    match = re.search(r'group\s+owner\s+of\s+([a-zA-Z0-9_]+)', text, re.IGNORECASE)
    if match:
        return match.group(1)
    return None


def generate_file_permission_tasks(control: dict) -> list[str]:
    """Generate Ansible tasks for file_permissions category."""
    fix_text = control.get("fix_text", "") or ""
    check_text = control.get("check_text", "") or ""
    sv_id = control.get("sv_id", "UNKNOWN")
    vul_id = control.get("vul_id", "")
    rule_id = control.get("rule_id", "")
    title = _clean_title_for_task_name(control.get("title", ""), max_length=80)
    combined_text = f"{fix_text} {check_text}"
    
    # Extract file path and mode - try multiple strategies
    file_path = _extract_file_path(combined_text)
    
    # If no path found, try to extract from check_text patterns like "stat -c ... /path"
    if not file_path:
        stat_match = re.search(r'stat\s+[^\s]+\s+([/\w.-]+)', combined_text)
        if stat_match:
            file_path = stat_match.group(1)
    
    # Extract mode - look for "0644 or less permissive", "0640 or more restrictive", etc.
    mode = _extract_file_mode(combined_text)
    if not mode:
        # Look for patterns like "mode of 0644" or "permissions of 0600"
        mode_match = re.search(r'(?:mode|permission)[^\d]*(\d{3,4})', combined_text, re.IGNORECASE)
        if mode_match:
            mode = mode_match.group(1)
    
    # Use title to determine what to extract
    title_lower = title.lower()
    is_owner_task = ("owned by" in title_lower or "must be owned" in title_lower) and "group" not in title_lower
    is_group_task = "group-owned" in title_lower or "group owner" in title_lower or ("group-owned" in title_lower and "by" in title_lower)
    
    owner = None
    group = None
    
    # Only extract owner if this is an owner task (not a group task)
    if is_owner_task and not is_group_task:
        owner = _extract_file_owner(combined_text)
        # If still no owner, look for patterns like "owner of root" or "owned by root"
        if not owner:
            # Look for "owned by root" or "owner of root" or "must be owned by root"
            # Prioritize finding "root" specifically
            # First check for explicit "root" patterns
            root_owner_match = re.search(r'(?:owned\s+by|owner\s+of|must\s+be\s+owned\s+by|chown)\s+root\b', combined_text, re.IGNORECASE)
            if root_owner_match:
                owner = "root"
            else:
                owner_patterns = [
                    r'chown\s+([a-zA-Z0-9_]+)(?:\s|$)',
                    r'owned\s+by\s+([a-zA-Z0-9_]+)',
                    r'owner\s+of\s+([a-zA-Z0-9_]+)',
                ]
                for pattern in owner_patterns:
                    owner_match = re.search(pattern, combined_text, re.IGNORECASE)
                    if owner_match:
                        candidate = owner_match.group(1).strip()
                        # Filter out common false positives
                        if candidate.lower() not in ["of", "to", "verify", "check", "the", "a", "an", "is", "must", "be", "file"]:
                            owner = candidate
                            break
    
    # Only extract group if this is a group task
    if is_group_task:
        # Prioritize checking for explicit "root" patterns FIRST (most reliable)
        if re.search(r'chgrp\s+root\b', combined_text, re.IGNORECASE):
            group = "root"
        elif re.search(r'chown\s+(?:[^:]+:|\s*:)\s*root\b', combined_text, re.IGNORECASE):
            group = "root"
        elif re.search(r'root\s*:\s*root', combined_text, re.IGNORECASE):
            group = "root"
        elif re.search(r'(?:group-owned\s+by|group\s+owner\s+of|must\s+be\s+group-owned\s+by)\s+root\b', combined_text, re.IGNORECASE):
            group = "root"
        else:
            # Fall back to extractor, but filter results carefully
            group = _extract_file_group(combined_text)
            # If extractor found something, validate it
            if group:
                # Filter out common false positives
                if group.lower() in ["of", "to", "verify", "check", "the", "a", "an", "is", "must", "be", "owner", "ownership", "file"]:
                    group = None
            
            # If still no group, try other patterns
            if not group:
                group_patterns = [
                    r'chgrp\s+([a-zA-Z0-9_]+)(?:\s|$)',
                    r'chown\s+(?:[^:]+:|\s*:)\s*([a-zA-Z0-9_]+)',
                    r'group-owned\s+by\s+([a-zA-Z0-9_]+)',
                ]
                for pattern in group_patterns:
                    group_match = re.search(pattern, combined_text, re.IGNORECASE)
                    if group_match:
                        candidate = group_match.group(1).strip()
                        # Filter out common false positives
                        if candidate.lower() not in ["of", "to", "verify", "check", "the", "a", "an", "is", "must", "be", "owner", "ownership", "file", "owned"]:
                            group = candidate
                            break
    
    if not file_path:
        return _generate_fallback_task(control)
    
    # Build task name with all IDs
    task_name_parts = []
    if vul_id:
        task_name_parts.append(vul_id)
    task_name_parts.append(title)
    if sv_id and sv_id != "UNKNOWN":
        task_name_parts.append(f"({sv_id})")
    if rule_id:
        task_name_parts.append(f"({rule_id})")
    task_name = " - ".join(task_name_parts)
    
    lines = [
        f"    - name: {quote_yaml_string(task_name)}",
        "      ansible.builtin.file:",
        f"        path: {file_path}",
    ]
    
    if mode:
        lines.append(f"        mode: '{mode}'")
    if owner:
        lines.append(f"        owner: {owner}")
    if group:
        lines.append(f"        group: {group}")
    
    # Determine if it's a directory or file based on path and title
    # Files typically have extensions or are specific files mentioned in title
    # Directories are typically mentioned as "directory" in title or are common dir paths
    title_lower = title.lower()
    is_directory = False
    
    # Check title for explicit mentions
    if "directory" in title_lower or "directories" in title_lower:
        is_directory = True
    elif "file" in title_lower and "directory" not in title_lower:
        is_directory = False
    else:
        # Heuristic: common directories vs files
        # Files: /etc/passwd, /etc/shadow, /etc/group, /var/log/messages, etc.
        # Directories: /usr/bin, /usr/lib, /var/log (when title says directory), /etc/cron, etc.
        known_files = ["/etc/passwd", "/etc/shadow", "/etc/group", "/etc/gshadow", 
                       "/etc/passwd-", "/etc/shadow-", "/etc/group-", "/etc/gshadow-",
                       "/var/log/messages", "/boot/grub2/grub.cfg", "/etc/fstab"]
        known_dirs = ["/usr/bin", "/usr/lib", "/usr/lib64", "/var/log", "/var/tmp", 
                      "/tmp", "/home", "/boot", "/etc/cron", "/etc"]
        
        if file_path in known_files:
            is_directory = False
        elif file_path in known_dirs:
            is_directory = True
        elif file_path.endswith('/'):
            is_directory = True
        else:
            # Default: assume file unless path looks like a directory
            is_directory = False
    
    if is_directory:
        lines.append("        state: directory")
    else:
        lines.append("        state: file")
    
    return lines


def generate_package_present_tasks(control: dict) -> list[str]:
    """Generate Ansible tasks for package_present category."""
    fix_text = control.get("fix_text", "") or ""
    check_text = control.get("check_text", "") or ""
    sv_id = control.get("sv_id", "UNKNOWN")
    vul_id = control.get("vul_id", "")
    rule_id = control.get("rule_id", "")
    title = _clean_title_for_task_name(control.get("title", ""), max_length=80)
    combined_text = f"{fix_text} {check_text}"
    
    # Use existing extractor
    package_names = extract_package_names_from_commands(combined_text)
    
    # Blacklist
    blacklist = {"that", "all", "is", "contents", "red", "run", "--now", "--mask"}
    valid_package_names = [pkg for pkg in package_names if pkg.lower() not in blacklist]
    
    if valid_package_names:
        package_name = valid_package_names[0]
        
        # Build task name
        task_name_parts = []
        if vul_id:
            task_name_parts.append(vul_id)
        task_name_parts.append(title)
        if sv_id and sv_id != "UNKNOWN":
            task_name_parts.append(f"({sv_id})")
        if rule_id:
            task_name_parts.append(f"({rule_id})")
        task_name = " - ".join(task_name_parts)
        
        # Use dnf for RHEL 9
        return [
            f"    - name: {quote_yaml_string(task_name)}",
            "      ansible.builtin.dnf:",
            f"        name: {package_name}",
            "        state: present",
        ]
    
    # Fallback
    return _generate_fallback_task(control)


def generate_package_absent_tasks(control: dict) -> list[str]:
    """Generate Ansible tasks for package_absent category."""
    fix_text = control.get("fix_text", "") or ""
    check_text = control.get("check_text", "") or ""
    sv_id = control.get("sv_id", "UNKNOWN")
    vul_id = control.get("vul_id", "")
    rule_id = control.get("rule_id", "")
    title = _clean_title_for_task_name(control.get("title", ""), max_length=80)
    combined_text = f"{fix_text} {check_text}"
    
    # Check for package update/upgrade commands first (these should generate update tasks, not removal)
    update_keywords = ["update", "upgrade", "security patches", "patches and updates"]
    has_update_keyword = any(keyword in combined_text.lower() for keyword in update_keywords)
    has_update_regex = bool(re.search(r'install.*update|apply.*patch', combined_text, re.IGNORECASE))
    has_package_cmd = any(cmd in combined_text.lower() for cmd in ["dnf", "yum", "rpm"])
    
    if (has_update_keyword or has_update_regex) and has_package_cmd:
        # This is actually a package update task, not a removal
        task_name_parts = []
        if vul_id:
            task_name_parts.append(vul_id)
        task_name_parts.append(title)
        if sv_id and sv_id != "UNKNOWN":
            task_name_parts.append(f"({sv_id})")
        if rule_id:
            task_name_parts.append(f"({rule_id})")
        task_name = " - ".join(task_name_parts)
        
        # Use dnf for RHEL 9
        return [
            f"    - name: {quote_yaml_string(task_name)}",
            "      ansible.builtin.dnf:",
            "        name: '*'",
            "        state: latest",
            "        update_cache: yes",
        ]
    
    # Use existing extractor
    package_names = extract_package_names_from_commands(combined_text)
    
    # Blacklist
    blacklist = {"that", "all", "is", "contents", "red", "run", "--now", "--mask"}
    valid_package_names = [pkg for pkg in package_names if pkg.lower() not in blacklist]
    
    if valid_package_names:
        package_name = valid_package_names[0]
        
        # Build task name
        task_name_parts = []
        if vul_id:
            task_name_parts.append(vul_id)
        task_name_parts.append(title)
        if sv_id and sv_id != "UNKNOWN":
            task_name_parts.append(f"({sv_id})")
        if rule_id:
            task_name_parts.append(f"({rule_id})")
        task_name = " - ".join(task_name_parts)
        
        # Use dnf for RHEL 9
        return [
            f"    - name: {quote_yaml_string(task_name)}",
            "      ansible.builtin.dnf:",
            f"        name: {package_name}",
            "        state: absent",
        ]
    
    # Fallback
    return _generate_fallback_task(control)


def _extract_service_name(text: str) -> Optional[str]:
    """Extract service name from text, carefully avoiding flags."""
    invalid_flags = {'--now', '--mask', '--unmask', '--force', '--status', '--no-reload', '--no-block'}
    
    patterns = [
        r'systemctl\s+(?:enable|disable|mask|unmask|stop|start|restart)\s+([a-zA-Z0-9@.-]+)',
        r'systemctl\s+(?:--now\s+)?(?:enable|disable|mask|unmask|stop|start|restart)\s+([a-zA-Z0-9@.-]+)',
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


def generate_service_enabled_tasks(control: dict) -> list[str]:
    """Generate Ansible tasks for service_enabled category."""
    fix_text = control.get("fix_text", "") or ""
    check_text = control.get("check_text", "") or ""
    sv_id = control.get("sv_id", "UNKNOWN")
    vul_id = control.get("vul_id", "")
    rule_id = control.get("rule_id", "")
    title = _clean_title_for_task_name(control.get("title", ""), max_length=80)
    combined_text = f"{fix_text} {check_text}"
    
    # Use existing extractor for structured actions
    service_actions = extract_systemd_actions(combined_text)
    
    if service_actions:
        service_action = service_actions[0]
        unit = service_action.get("unit")
        action = service_action.get("action")
        
        invalid_flags = {"--now", "--mask", "--unmask", "--force", "--status", "--no-reload", "--no-block"}
        invalid_names = {"run", "with", "on", "following", "is", "the", "a", "an", "and", "or", "to", "for", "from", "that", "this", "all", "any", "some", "each", "every", "command", "sudo", "then", "enable", "disable", "start", "stop"}
        
        # Additional validation: service name should be alphanumeric with dots/dashes, not just common words
        if unit:
            unit_lower = unit.lower().strip()
            # Reject if it's too short
            if len(unit_lower) < 2:
                unit = None
            # Reject if it contains spaces (likely prose, not a service name)
            elif ' ' in unit_lower:
                unit = None
            # Reject if it's a flag
            elif unit_lower in invalid_flags:
                unit = None
            # Reject if it's a stopword
            elif unit_lower in invalid_names:
                unit = None
            # Reject if it starts with a dash
            elif unit.startswith('-'):
                unit = None
            # Reject if it doesn't contain at least one letter (service names have letters)
            elif not re.search(r'[a-zA-Z]', unit):
                unit = None
        
        if unit:
            # Build task name
            task_name_parts = []
            if vul_id:
                task_name_parts.append(vul_id)
            task_name_parts.append(f"Ensure {unit} is {action}")
            if sv_id and sv_id != "UNKNOWN":
                task_name_parts.append(f"({sv_id})")
            if rule_id:
                task_name_parts.append(f"({rule_id})")
            task_name = " - ".join(task_name_parts)
            
            lines = [
                f"    - name: {quote_yaml_string(task_name)}",
                "      ansible.builtin.systemd:",
                f"        name: {unit}",
            ]
            
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
            else:  # enable
                lines.append("        enabled: yes")
            
            # Fix task name if it says "mask" instead of "masked"
            task_name_str = "\n".join(lines)
            if "is mask" in task_name_str:
                lines[0] = lines[0].replace("is mask", "is masked")
            
            return lines
    
    # Fallback: extract from text
    service_name = _extract_service_name(combined_text)
    # Additional validation for extracted service name
    if service_name:
        invalid_names = {"run", "with", "on", "following", "is", "the", "a", "an", "and", "or", "to", "for", "from", "that", "this", "all", "any", "some", "each", "every", "command", "sudo", "then", "enable", "disable", "start", "stop"}
        if service_name.lower() in invalid_names or len(service_name.strip()) < 2 or ' ' in service_name or not re.search(r'[a-zA-Z]', service_name):
            service_name = None
    
    if service_name:
        text_lower = combined_text.lower()
        disabled = "disabled" in text_lower or "disable" in text_lower
        masked = "masked" in text_lower or "mask" in text_lower
        
        # Build task name
        task_name_parts = []
        if vul_id:
            task_name_parts.append(vul_id)
        if masked:
            task_name_parts.append(f"Ensure {service_name} is masked and stopped")
        elif disabled:
            task_name_parts.append(f"Ensure {service_name} is disabled and stopped")
        else:
            task_name_parts.append(f"Ensure {service_name} is enabled and running")
        if sv_id and sv_id != "UNKNOWN":
            task_name_parts.append(f"({sv_id})")
        if rule_id:
            task_name_parts.append(f"({rule_id})")
        task_name = " - ".join(task_name_parts)
        
        lines = [
            f"    - name: {quote_yaml_string(task_name)}",
            "      ansible.builtin.systemd:",
            f"        name: {service_name}",
        ]
        
        if masked:
            lines.append("        masked: yes")
            lines.append("        state: stopped")
        elif disabled:
            lines.append("        enabled: no")
            lines.append("        state: stopped")
        else:
            lines.append("        enabled: yes")
            lines.append("        state: started")
        
        return lines
    
    # Fallback
    return _generate_fallback_task(control)


def generate_service_disabled_tasks(control: dict) -> list[str]:
    """Generate Ansible tasks for service_disabled category."""
    # Similar to enabled but with disabled/masked logic
    return generate_service_enabled_tasks(control)


def generate_sysctl_tasks(control: dict) -> list[str]:
    """Generate Ansible tasks for sysctl category."""
    fix_text = control.get("fix_text", "") or ""
    check_text = control.get("check_text", "") or ""
    sv_id = control.get("sv_id", "UNKNOWN")
    vul_id = control.get("vul_id", "")
    rule_id = control.get("rule_id", "")
    title = _clean_title_for_task_name(control.get("title", ""), max_length=80)
    combined_text = f"{fix_text} {check_text}"
    
    # Use existing extractor
    sysctl_params = extract_sysctl_params(combined_text)
    
    if sysctl_params:
        param = sysctl_params[0]
        param_name = param.get("name")
        param_value = param.get("value")
        
        if param_name and param_value:
            # Build task name
            task_name_parts = []
            if vul_id:
                task_name_parts.append(vul_id)
            task_name_parts.append(title)
            if sv_id and sv_id != "UNKNOWN":
                task_name_parts.append(f"({sv_id})")
            if rule_id:
                task_name_parts.append(f"({rule_id})")
            task_name = " - ".join(task_name_parts)
            
            return [
                f"    - name: {quote_yaml_string(task_name)}",
                "      ansible.builtin.sysctl:",
                f"        name: {param_name}",
                f"        value: '{param_value}'",
                "        state: present",
                "        sysctl_set: yes",
                "        reload: yes",
                "      notify: Reload sysctl",
            ]
    
    # Fallback
    return _generate_fallback_task(control)


def _extract_grub_kernel_arg(text: str) -> Optional[str]:
    """Extract kernel argument from GRUB configuration text."""
    # First, try to find known kernel args mentioned in text (most reliable)
    kernel_args = ["vsyscall=none", "page_poison=1", "init_on_free=1", "audit=1", 
                   "pti=on", "slab_common=1", "page_alloc=1", "slub_debug=P", "slab_nomerge"]
    for arg in kernel_args:
        if arg.lower() in text.lower():
            return arg
    
    # Look for patterns in GRUB_CMDLINE_LINUX lines
    grub_match = re.search(r'GRUB_CMDLINE_LINUX="[^"]*([a-zA-Z0-9_]+=[a-zA-Z0-9_-]+)', text, re.IGNORECASE)
    if grub_match:
        arg = grub_match.group(1)
        # Filter out common false positives
        if arg not in ["more", "less", "permissive", "restrictive"] and len(arg) > 3:
            return arg
    
    # Look for grubby command patterns
    grubby_match = re.search(r'grubby\s+--args=["\']([a-zA-Z0-9_]+=[a-zA-Z0-9_-]+)', text, re.IGNORECASE)
    if grubby_match:
        arg = grubby_match.group(1)
        if arg not in ["more", "less", "permissive", "restrictive"] and len(arg) > 3:
            return arg
    
    # Look for standalone kernel arg patterns before prose
    standalone_match = re.search(r'([a-zA-Z0-9_]+=[a-zA-Z0-9_-]+)\s+(?:Verify|Check|If|with|the|following)', text, re.IGNORECASE)
    if standalone_match:
        arg = standalone_match.group(1)
        if arg not in ["more", "less", "permissive", "restrictive"] and len(arg) > 3:
            return arg
    
    return None


def generate_grub_kernel_args_tasks(control: dict) -> list[str]:
    """Generate Ansible tasks for GRUB kernel arguments category."""
    fix_text = control.get("fix_text", "") or ""
    check_text = control.get("check_text", "") or ""
    sv_id = control.get("sv_id", "UNKNOWN")
    vul_id = control.get("vul_id", "")
    rule_id = control.get("rule_id", "")
    title = _clean_title_for_task_name(control.get("title", ""), max_length=80)
    combined_text = f"{fix_text} {check_text}"
    
    kernel_arg = _extract_grub_kernel_arg(combined_text)
    
    if not kernel_arg:
        return _generate_fallback_task(control)
    
    # Build task name
    task_name_parts = []
    if vul_id:
        task_name_parts.append(vul_id)
    task_name_parts.append(title)
    if sv_id and sv_id != "UNKNOWN":
        task_name_parts.append(f"({sv_id})")
    if rule_id:
        task_name_parts.append(f"({rule_id})")
    task_name = " - ".join(task_name_parts)
    
    # Use lineinfile with backrefs to preserve existing content and append kernel arg
    # Build the replacement line that appends the kernel arg if not present
    # Use backrefs to capture existing content - escape backrefs properly
    replacement_line = f'GRUB_CMDLINE_LINUX="\\1 {kernel_arg}"'
    
    lines = [
        f"    - name: {quote_yaml_string(task_name)}",
        "      ansible.builtin.lineinfile:",
        "        path: /etc/default/grub",
        "        regexp: '^GRUB_CMDLINE_LINUX=\"(.*)\"$'",
        f"        line: {yaml_safe_scalar(replacement_line)}",
        "        backrefs: yes",
        "        create: yes",
        "        backup: yes",
        "      notify: Regenerate grub configuration",
    ]
    
    return lines


def generate_mount_option_tasks(control: dict) -> list[str]:
    """Generate Ansible tasks for mount_option category."""
    fix_text = control.get("fix_text", "") or ""
    check_text = control.get("check_text", "") or ""
    sv_id = control.get("sv_id", "UNKNOWN")
    vul_id = control.get("vul_id", "")
    rule_id = control.get("rule_id", "")
    title = _clean_title_for_task_name(control.get("title", ""), max_length=80)
    combined_text = f"{fix_text} {check_text} {title}"
    
    # Extract mount point - prioritize title first, then text
    mount_point = None
    
    # FIRST: Check title for mount point (most reliable)
    if title:
        # Look for patterns like "for /tmp", "for /var/tmp", "for /home"
        title_mount_match = re.search(r'for\s+([/\w-]+)', title, re.IGNORECASE)
        if title_mount_match:
            candidate = title_mount_match.group(1)
            if candidate.startswith('/') and len(candidate) > 1 and candidate not in ['/the', '/grep', '/system', '/has']:
                mount_point = candidate
        # Also check for mount point in title directly
        if not mount_point:
            # Prioritize longer paths first (e.g., /var/tmp before /tmp)
            common_mounts_ordered = ["/var/tmp", "/var/log/audit", "/var/log", "/boot/efi", "/dev/shm", "/home", "/tmp", "/var", "/usr", "/boot"]
            for mp in common_mounts_ordered:
                if mp in title:
                    mount_point = mp
                    break
    
    # SECOND: If not in title, look in text
    if not mount_point:
        # Look for explicit mount point patterns in text
        # Common patterns: "mount /tmp", "/tmp must be mounted", "for /var/log"
        mount_patterns = [
            r'mount\s+([/\w-]+)',  # "mount /tmp"
            r'for\s+([/\w-]+)',  # "for /var/log"
            r'([/\w-]+)\s+must\s+(?:not\s+)?be\s+mounted',  # "/tmp must be mounted"
            r'mount\s+point[^\s]*\s+([/\w-]+)',  # "mount point /home"
            r'([/\w-]+)\s+with\s+the\s+',  # "/tmp with the nodev option"
        ]
        for pattern in mount_patterns:
            match = re.search(pattern, combined_text, re.IGNORECASE)
            if match:
                candidate = match.group(1)
                # Validate it's actually a mount point (starts with / and is reasonable)
                if candidate.startswith('/') and len(candidate) > 1 and candidate not in ['/the', '/grep', '/system', '/has']:
                    mount_point = candidate
                    break
    
    # THIRD: If still not found, check for common mount points mentioned in text
    if not mount_point:
        # Prioritize longer paths first
        common_mounts_ordered = ["/var/tmp", "/var/log/audit", "/var/log", "/boot/efi", "/dev/shm", "/home", "/tmp", "/var", "/usr", "/boot"]
        for mp in common_mounts_ordered:
            # Check if mount point appears in context (not just as part of another word)
            if re.search(r'\b' + re.escape(mp) + r'\b', combined_text, re.IGNORECASE):
                mount_point = mp
                break
    
    # Extract mount options
    mount_opts = []
    if "nodev" in combined_text.lower():
        mount_opts.append("nodev")
    if "nosuid" in combined_text.lower():
        mount_opts.append("nosuid")
    if "noexec" in combined_text.lower():
        mount_opts.append("noexec")
    
    # Look for sec= option
    sec_match = re.search(r'sec=([a-zA-Z0-9_-]+)', combined_text, re.IGNORECASE)
    if sec_match:
        mount_opts.append(f"sec={sec_match.group(1)}")
    
    if not mount_point:
        return _generate_fallback_task(control)
    
    # Build task name
    task_name_parts = []
    if vul_id:
        task_name_parts.append(vul_id)
    task_name_parts.append(title)
    if sv_id and sv_id != "UNKNOWN":
        task_name_parts.append(f"({sv_id})")
    if rule_id:
        task_name_parts.append(f"({rule_id})")
    task_name = " - ".join(task_name_parts)
    
    # Use lineinfile to update /etc/fstab with mount options
    # First, get existing fstab entry to preserve device and fstype
    # For simplicity, we'll use a more generic approach with mount module
    opts_str = ",".join(mount_opts) if mount_opts else "defaults"
    
    # Use lineinfile to ensure fstab has the correct options
    # This is more idempotent than using mount module directly
    lines = [
        f"    - name: {quote_yaml_string(f'{task_name} - Ensure mount options in fstab')}",
        "      ansible.builtin.lineinfile:",
        "        path: /etc/fstab",
        # Use single quotes for regex to avoid YAML escape issues with backslashes
        f"        regexp: '^([^#]\\S+\\s+{re.escape(mount_point)}\\s+\\S+\\s+)([^\\s]+)(.*)$'",
        f"        line: '\\1\\2,{opts_str}\\3'",
        "        backrefs: yes",
        "        state: present",
        "        backup: yes",
    ]
    
    # Also ensure the mount is active with correct options
    lines.extend([
        "",
        f"    - name: {quote_yaml_string(f'{task_name} - Remount with correct options')}",
        "      ansible.builtin.mount:",
        f"        path: {mount_point}",
        f"        opts: \"defaults,{opts_str}\"",
        "        state: mounted",
        "        fstype: auto",
    ])
    
    return lines


def _extract_ssh_config_key_value(text: str) -> Optional[tuple]:
    """Extract SSH config key and value from text."""
    # Common SSH config keys
    ssh_keys = [
        "Ciphers", "MACs", "HostbasedAuthentication", "PermitEmptyPasswords",
        "ClientAliveInterval", "ClientAliveCountMax", "PermitRootLogin",
        "PubkeyAuthentication", "GSSAPIAuthentication", "KerberosAuthentication",
        "X11Forwarding", "MaxAuthTries", "Protocol", "PermitUserEnvironment",
        "Banner", "IgnoreRhosts", "RhostsRSAAuthentication", "StrictModes",
        "UsePAM", "LogLevel",
    ]
    
    for key in ssh_keys:
        # Special case for Banner - look for file path like /etc/issue or /etc/issue.net FIRST
        if key == "Banner":
            # Look for Banner /path/to/file pattern
            banner_match = re.search(r'Banner\s+([/\w.-]+)', text, re.IGNORECASE)
            if banner_match:
                banner_path = banner_match.group(1)
                # Only accept if it looks like a file path (starts with /)
                if banner_path.startswith('/'):
                    return (key, banner_path)
            # Also check for /etc/issue mentioned in context
            if "/etc/issue" in text:
                return (key, "/etc/issue")
            # Skip generic pattern matching for Banner to avoid matching "before"
            continue
        
        # Special case for UsePAM - should be yes, not "interface" FIRST
        if key == "UsePAM":
            pam_match = re.search(r'UsePAM\s+(yes|no|true|false)', text, re.IGNORECASE)
            if pam_match:
                value = "yes" if pam_match.group(1).lower() in ["yes", "true"] else "no"
                return (key, value)
            # Default to yes if UsePAM is mentioned
            if "usepam" in text.lower() and "yes" in text.lower():
                return (key, "yes")
            # Skip generic pattern matching for UsePAM
            continue
        
        # Look for patterns like "HostbasedAuthentication no"
        pattern = rf'{key}\s+(yes|no|true|false)'
        match = re.search(pattern, text, re.IGNORECASE)
        if match:
            value = "yes" if match.group(1).lower() in ["yes", "true"] else "no"
            return (key, value)
        
        # Look for numeric values like "ClientAliveInterval 600"
        pattern = rf'{key}\s+(\d+)'
        match = re.search(pattern, text, re.IGNORECASE)
        if match:
            return (key, match.group(1))
        
        # Look for patterns like "Ciphers hmac-sha2-256", "MACs hmac-sha2-256", etc.
        # But exclude if the value is clearly prose (like "before" for Banner)
        pattern = rf'{key}\s+([^\s\n]+)'
        match = re.search(pattern, text, re.IGNORECASE)
        if match:
            value = match.group(1).strip('"\'')
            # Filter out prose words
            if value.lower() not in ["before", "after", "the", "a", "an", "is", "must", "be", "interface"]:
                return (key, value)
    
    return None


def generate_ssh_config_tasks(control: dict) -> list[str]:
    """Generate Ansible tasks for ssh_config category."""
    fix_text = control.get("fix_text", "") or ""
    check_text = control.get("check_text", "") or ""
    sv_id = control.get("sv_id", "UNKNOWN")
    vul_id = control.get("vul_id", "")
    rule_id = control.get("rule_id", "")
    title = _clean_title_for_task_name(control.get("title", ""), max_length=80)
    combined_text = f"{fix_text} {check_text}"
    
    # Try to extract SSH config key-value pair
    ssh_config = _extract_ssh_config_key_value(combined_text)
    
    if not ssh_config:
        # Fallback: try to extract any config line
        config_line = _extract_config_line(combined_text)
        if config_line and ("ssh" in config_line.lower() or "sshd" in combined_text.lower()):
            ssh_config = (config_line.split()[0], " ".join(config_line.split()[1:]) if len(config_line.split()) > 1 else "")
    
    if not ssh_config:
        return _generate_fallback_task(control)
    
    key, value = ssh_config
    
    # Build task name
    task_name_parts = []
    if vul_id:
        task_name_parts.append(vul_id)
    task_name_parts.append(title)
    if sv_id and sv_id != "UNKNOWN":
        task_name_parts.append(f"({sv_id})")
    if rule_id:
        task_name_parts.append(f"({rule_id})")
    task_name = " - ".join(task_name_parts)
    
    # Use lineinfile to set SSH config in sshd_config.d for better organization
    config_file = "/etc/ssh/sshd_config.d/99-stig-hardening.conf"
    
    # Use YAML-safe string for the line
    ssh_line = f"{key} {value}"
    safe_line = yaml_safe_scalar(ssh_line)
    
    lines = [
        f"    - name: {quote_yaml_string(task_name)}",
        "      ansible.builtin.lineinfile:",
        f"        path: {config_file}",
        f"        regexp: '^#?\\s*{re.escape(key)}\\s+'",
        f"        line: {safe_line}",
        "        create: yes",
        "        backup: yes",
        "      notify: Restart sshd",
    ]
    
    return lines


def _extract_dconf_key_value(text: str) -> Optional[tuple]:
    """Extract dconf key and value from text."""
    # Look for gsettings patterns
    gsettings_match = re.search(r'gsettings\s+set\s+([^\s]+)\s+([^\s]+)\s+([^\s\n]+)', text, re.IGNORECASE)
    if gsettings_match:
        schema = gsettings_match.group(1)
        key = gsettings_match.group(2)
        value = gsettings_match.group(3).strip("'\"")
        return (schema, key, value)
    
    # Look for dconf key patterns like "org/gnome/login-screen/banner-message-enable"
    dconf_match = re.search(r'([a-z/]+)/([a-z-]+)\s*=\s*([^\s\n]+)', text, re.IGNORECASE)
    if dconf_match:
        path = dconf_match.group(1)
        key = dconf_match.group(2)
        value = dconf_match.group(3).strip("'\"")
        return (path, key, value)
    
    return None


def generate_dconf_tasks(control: dict) -> list[str]:
    """Generate Ansible tasks for dconf/GNOME category."""
    fix_text = control.get("fix_text", "") or ""
    check_text = control.get("check_text", "") or ""
    sv_id = control.get("sv_id", "UNKNOWN")
    vul_id = control.get("vul_id", "")
    rule_id = control.get("rule_id", "")
    title = _clean_title_for_task_name(control.get("title", ""), max_length=80)
    combined_text = f"{fix_text} {check_text}"
    
    dconf_config = _extract_dconf_key_value(combined_text)
    
    if not dconf_config:
        return _generate_fallback_task(control)
    
    if len(dconf_config) == 3:
        path, key, value = dconf_config
    else:
        return _generate_fallback_task(control)
    
    # Build task name
    task_name_parts = []
    if vul_id:
        task_name_parts.append(vul_id)
    task_name_parts.append(title)
    if sv_id and sv_id != "UNKNOWN":
        task_name_parts.append(f"({sv_id})")
    if rule_id:
        task_name_parts.append(f"({rule_id})")
    task_name = " - ".join(task_name_parts)
    
    # Convert path to dconf format (e.g., "org/gnome/login-screen" -> "[org/gnome/login-screen]")
    dconf_path = f"[{path}]"
    dconf_key = f"{key}={value}"
    
    # Write to dconf database file
    dconf_file = f"/etc/dconf/db/local.d/00-stig-{key.replace('-', '_')}"
    
    lines = [
        f"    - name: {quote_yaml_string(f'{task_name} - Configure dconf setting')}",
        "      ansible.builtin.copy:",
        f"        dest: {dconf_file}",
        "        content: |",
        f"          {dconf_path}",
        f"          {dconf_key}",
        "        mode: '0644'",
        "      notify: Update dconf database",
        "",
        f"    - name: {quote_yaml_string(f'{task_name} - Lock dconf setting')}",
        "      ansible.builtin.copy:",
        f"        dest: /etc/dconf/db/local.d/locks/{key.replace('-', '_')}",
        "        content: |",
        f"          /{path}/{key}",
        "        mode: '0644'",
        "      notify: Update dconf database",
    ]
    
    return lines


def generate_audit_tasks(control: dict) -> list[str]:
    """Generate Ansible tasks for audit category."""
    fix_text = control.get("fix_text", "") or ""
    check_text = control.get("check_text", "") or ""
    sv_id = control.get("sv_id", "UNKNOWN")
    vul_id = control.get("vul_id", "")
    rule_id = control.get("rule_id", "")
    title = _clean_title_for_task_name(control.get("title", ""), max_length=80)
    
    # Try to extract audit rule
    audit_rule = _extract_audit_rule(fix_text or check_text)
    if audit_rule:
        # Build task name
        task_name_parts = []
        if vul_id:
            task_name_parts.append(vul_id)
        task_name_parts.append(title)
        if sv_id and sv_id != "UNKNOWN":
            task_name_parts.append(f"({sv_id})")
        if rule_id:
            task_name_parts.append(f"({rule_id})")
        task_name = " - ".join(task_name_parts)
        
        escaped_rule = re.escape(audit_rule)
        safe_rule = yaml_safe_scalar(audit_rule)
        return [
            f"    - name: {quote_yaml_string(task_name)}",
            "      ansible.builtin.lineinfile:",
            "        path: /etc/audit/rules.d/audit.rules",
            f"        line: {safe_rule}",
            f"        regexp: '^{escaped_rule}$'",
            "        create: yes",
            "        mode: '0640'",
            "        owner: root",
            "        group: root",
        ]
    
    return _generate_fallback_task(control)


def generate_firewalld_tasks(control: dict) -> list[str]:
    """Generate Ansible tasks for firewalld category."""
    fix_text = control.get("fix_text", "") or ""
    check_text = control.get("check_text", "") or ""
    sv_id = control.get("sv_id", "UNKNOWN")
    vul_id = control.get("vul_id", "")
    rule_id = control.get("rule_id", "")
    title = _clean_title_for_task_name(control.get("title", ""), max_length=80)
    combined_text = f"{fix_text} {check_text}"
    
    # Extract firewall-cmd commands
    firewall_patterns = [
        r'firewall-cmd\s+--permanent\s+--(add|remove)-service=([a-zA-Z0-9_-]+)',
        r'firewall-cmd\s+--permanent\s+--(add|remove)-port=([0-9]+/[a-z]+)',
        r'firewall-cmd\s+--permanent\s+--set-default-zone=([a-zA-Z0-9_-]+)',
        r'firewall-cmd\s+--permanent\s+--zone=([a-zA-Z0-9_-]+)\s+--(add|remove)-service=([a-zA-Z0-9_-]+)',
    ]
    
    for pattern in firewall_patterns:
        match = re.search(pattern, combined_text, re.IGNORECASE)
        if match:
            # Build task name
            task_name_parts = []
            if vul_id:
                task_name_parts.append(vul_id)
            task_name_parts.append(title)
            if sv_id and sv_id != "UNKNOWN":
                task_name_parts.append(f"({sv_id})")
            if rule_id:
                task_name_parts.append(f"({rule_id})")
            task_name = " - ".join(task_name_parts)
            
            # Use ansible.posix.firewalld if available, otherwise use command
            # For now, use command with idempotence checks
            return [
                f"    - name: {quote_yaml_string(task_name)}",
                "      ansible.builtin.command:",
                f"        cmd: {match.group(0)}",
                "      register: firewall_result",
                "      changed_when: firewall_result.rc == 0",
                "      failed_when: firewall_result.rc != 0 and 'ALREADY_ENABLED' not in firewall_result.stderr",
                "      notify: Reload firewalld",
            ]
    
    # Fallback for complex firewalld rules
    return _generate_fallback_task(control)


def _extract_systemd_default_target(text: str) -> Optional[str]:
    """Extract systemd default target from text (e.g., multi-user.target, graphical.target)."""
    # Look for systemctl set-default commands
    match = re.search(r'systemctl\s+set-default\s+([a-zA-Z0-9@.-]+)', text, re.IGNORECASE)
    if match:
        return match.group(1)
    # Look for mentions of default target
    targets = ["multi-user.target", "graphical.target", "rescue.target", "emergency.target"]
    for target in targets:
        if target in text.lower():
            return target
    return None


def generate_config_tasks(control: dict) -> list[str]:
    """Generate Ansible tasks for config category."""
    fix_text = control.get("fix_text", "") or ""
    check_text = control.get("check_text", "") or ""
    sv_id = control.get("sv_id", "UNKNOWN")
    vul_id = control.get("vul_id", "")
    rule_id = control.get("rule_id", "")
    title = _clean_title_for_task_name(control.get("title", ""), max_length=80)
    combined_text = f"{fix_text} {check_text}"
    
    # Check for systemd default target first (special case)
    default_target = _extract_systemd_default_target(combined_text)
    if default_target:
        task_name_parts = []
        if vul_id:
            task_name_parts.append(vul_id)
        task_name_parts.append(title)
        if sv_id and sv_id != "UNKNOWN":
            task_name_parts.append(f"({sv_id})")
        if rule_id:
            task_name_parts.append(f"({rule_id})")
        task_name = " - ".join(task_name_parts)
        
        # Use shell with idempotence check
        return [
            f"    - name: {quote_yaml_string(task_name)}",
            "      ansible.builtin.shell: |",
            f"        current=$(systemctl get-default)",
            f"        if [ \"$current\" != \"{default_target}\" ]; then",
            f"          systemctl set-default {default_target}",
            "          echo changed",
            "        fi",
            "      register: default_target_result",
            "      changed_when: default_target_result.stdout == 'changed'",
        ]
    
    # Check for package update/upgrade commands - be more aggressive in detection
    update_keywords = ["update", "upgrade", "security patches", "patches and updates", "apply.*patches"]
    has_update_keyword = any(keyword in combined_text.lower() for keyword in update_keywords)
    has_update_regex = bool(re.search(r'install.*update|apply.*patch', combined_text, re.IGNORECASE))
    has_package_cmd = any(cmd in combined_text.lower() for cmd in ["dnf", "yum", "rpm"])
    if (has_update_keyword or has_update_regex) and has_package_cmd:
        # This is a package update task
        task_name_parts = []
        if vul_id:
            task_name_parts.append(vul_id)
        task_name_parts.append(title)
        if sv_id and sv_id != "UNKNOWN":
            task_name_parts.append(f"({sv_id})")
        if rule_id:
            task_name_parts.append(f"({rule_id})")
        task_name = " - ".join(task_name_parts)
        
        # Use dnf for RHEL 9
        return [
            f"    - name: {quote_yaml_string(task_name)}",
            "      ansible.builtin.dnf:",
            "        name: '*'",
            "        state: latest",
            "        update_cache: yes",
        ]
    
    # Try multiple extraction strategies
    file_path = _extract_file_path(combined_text)
    config_line = _extract_config_line(combined_text)
    
    # Special handling for banner files (/etc/issue, /etc/motd)
    if "/etc/issue" in combined_text or ("issue" in combined_text and "banner" in combined_text.lower()):
        file_path = "/etc/issue"
        # Extract banner text from fix_text - try multiple patterns
        banner_text = None
        # Try quoted string first
        banner_match = re.search(r'"(.*?)"', fix_text, re.DOTALL)
        if banner_match:
            banner_text = banner_match.group(1).strip()
        # If no quoted string, look for banner content after keywords
        if not banner_text:
            # Look for content after "banner" or "message"
            banner_match = re.search(r'(?:banner|message)[:\s]+(.*?)(?:$|\n\n)', fix_text, re.DOTALL | re.IGNORECASE)
            if banner_match:
                banner_text = banner_match.group(1).strip()
        
        if banner_text:
            # Build task name
            task_name_parts = []
            if vul_id:
                task_name_parts.append(vul_id)
            task_name_parts.append(title)
            if sv_id and sv_id != "UNKNOWN":
                task_name_parts.append(f"({sv_id})")
            if rule_id:
                task_name_parts.append(f"({rule_id})")
            task_name = " - ".join(task_name_parts)
            
            # Split banner into lines and ensure proper indentation
            banner_lines = [line.rstrip() for line in banner_text.split('\n') if line.strip()]
            
            return [
                f"    - name: {quote_yaml_string(task_name)}",
                "      ansible.builtin.copy:",
                "        dest: /etc/issue",
                "        content: |",
            ] + [f"          {line}" for line in banner_lines] + [
                "        mode: '0644'",
                "        owner: root",
                "        group: root",
            ]
    
    if "/etc/motd" in combined_text or ("motd" in combined_text and "banner" in combined_text.lower()):
        file_path = "/etc/motd"
        # Extract banner text from fix_text - try multiple patterns
        banner_text = None
        # Try quoted string first
        banner_match = re.search(r'"(.*?)"', fix_text, re.DOTALL)
        if banner_match:
            banner_text = banner_match.group(1).strip()
        # If no quoted string, look for banner content after keywords
        if not banner_text:
            # Look for content after "banner" or "message"
            banner_match = re.search(r'(?:banner|message)[:\s]+(.*?)(?:$|\n\n)', fix_text, re.DOTALL | re.IGNORECASE)
            if banner_match:
                banner_text = banner_match.group(1).strip()
        
        if banner_text:
            # Build task name
            task_name_parts = []
            if vul_id:
                task_name_parts.append(vul_id)
            task_name_parts.append(title)
            if sv_id and sv_id != "UNKNOWN":
                task_name_parts.append(f"({sv_id})")
            if rule_id:
                task_name_parts.append(f"({rule_id})")
            task_name = " - ".join(task_name_parts)
            
            # Split banner into lines and ensure proper indentation
            banner_lines = [line.rstrip() for line in banner_text.split('\n') if line.strip()]
            
            return [
                f"    - name: {quote_yaml_string(task_name)}",
                "      ansible.builtin.copy:",
                "        dest: /etc/motd",
                "        content: |",
            ] + [f"          {line}" for line in banner_lines] + [
                "        mode: '0644'",
                "        owner: root",
                "        group: root",
            ]
    
    # If no file path found, try common config file paths based on content
    if not file_path:
        if "/etc/login.defs" in combined_text or "login.defs" in combined_text:
            file_path = "/etc/login.defs"
        elif "/etc/pam.d/" in combined_text or "pam.d" in combined_text:
            # Try to extract specific PAM file
            pam_match = re.search(r'/etc/pam\.d/([a-zA-Z0-9_-]+)', combined_text)
            if pam_match:
                file_path = f"/etc/pam.d/{pam_match.group(1)}"
            else:
                file_path = "/etc/pam.d/system-auth"  # Default
        elif "/etc/systemd/" in combined_text or "systemd" in combined_text:
            systemd_match = re.search(r'/etc/systemd/[^\s]+', combined_text)
            if systemd_match:
                file_path = systemd_match.group(0)
        elif "/etc/rsyslog" in combined_text or "rsyslog" in combined_text:
            rsyslog_match = re.search(r'/etc/rsyslog[^\s]*', combined_text)
            if rsyslog_match:
                file_path = rsyslog_match.group(0)
            else:
                file_path = "/etc/rsyslog.conf"
        elif "/etc/grub" in combined_text or "grub" in combined_text:
            grub_match = re.search(r'/etc/grub[^\s]*', combined_text)
            if grub_match:
                file_path = grub_match.group(0)
            else:
                file_path = "/etc/default/grub"
        elif "/etc/issue" in combined_text or "issue" in combined_text:
            file_path = "/etc/issue"
        elif "/etc/motd" in combined_text or "motd" in combined_text:
            file_path = "/etc/motd"
    
    # If no config line found, try to extract from fix_text more aggressively
    # But be strict - only extract actual config, not prose
    if not config_line:
        prose_indicators = ['verify', 'check', 'configure', 'the following', 'with the following', 
                          'following command', 'system\'s', 'shadow file', 'is configured', 
                          'representations', 'passwords', 'hash value', 'command:', 'line:', 
                          'file:', 'directory:', 'must', 'should', 'edit', 'add']
        
        # Also check check_text for config lines
        all_text = f"{fix_text}\n{check_text}"
        
        for line in all_text.split('\n'):
            line = line.strip()
            # Skip command lines and obvious prose
            if line.startswith('$') or line.startswith('#') or 'sudo' in line or 'systemctl' in line:
                continue
            
            # Skip lines that are clearly commands
            if line.startswith('grep') or line.startswith('cat') or line.startswith('ls ') or line.startswith('stat '):
                continue
            
            # Skip lines with prose indicators - REJECT ENTIRELY, don't try to extract
            line_lower = line.lower()
            if any(indicator in line_lower for indicator in prose_indicators):
                # Don't try to extract from prose lines - reject entirely
                continue
            
            # Look for KEY=VALUE or KEY VALUE patterns (VERY strict - must be short and match exact pattern)
            # CRITICAL: Only accept lines that are EXACTLY 2 words (KEY VALUE) or KEY=VALUE format
            # Must have NO prose indicators at all
            if not any(indicator in line_lower for indicator in prose_indicators):
                if re.match(r'^[A-Z_][A-Z0-9_]+\s+[A-Z0-9_]+$', line):
                    # Must be exactly 2 words, very short (< 30 chars), no punctuation
                    words = line.split()
                    if len(words) == 2 and len(line) < 30:
                        if not any(c in line for c in ['.', ':', ';', ',', '!', '?', '...']):
                            # Final check: no prose words in either word
                            prose_words = ['verify', 'check', 'configure', 'system', 'file', 'command', 'following', 'shadow', 'encrypted', 'representations', 'passwords', 'hash', 'value', 'with', 'the', 'is', 'are', 'that', 'running', 'by', 'number', 'minimum', 'rounds', 'configured']
                            if not any(word in line_lower for word in prose_words):
                                config_line = line
                                break
                if re.match(r'^[A-Z_][A-Z0-9_]+\s*=\s*[A-Z0-9_]+$', line):
                    # Must be exactly KEY=VALUE format, very short (< 30 chars), no punctuation
                    if len(line) < 30:
                        if not any(c in line for c in ['.', ':', ';', ',', '!', '?', '...']):
                            # Final check: no prose words
                            prose_words = ['verify', 'check', 'configure', 'system', 'file', 'command', 'following', 'shadow', 'encrypted', 'representations', 'passwords', 'hash', 'value', 'with', 'the', 'is', 'are', 'that', 'running', 'by', 'number', 'minimum', 'rounds', 'configured']
                            if not any(word in line_lower for word in prose_words):
                                config_line = line
                                break
    
    if file_path and config_line:
        # STRICT validation: config_line must be a real config directive, not prose
        # This is the FINAL gate - reject anything that looks like prose
        prose_indicators = ['verify', 'check', 'configure', 'the following', 'with the following', 
                          'following command', 'system\'s', 'shadow file', 'is configured', 
                          'representations', 'passwords', 'hash value', 'command:', 'line:', 
                          'file:', 'directory:', 'must', 'should', 'edit', 'add', 'the system',
                          'verify the', 'check the', 'configure the', 'with a hash', 'with the',
                          'following:', '...', 'ellipsis', 'with the following command']
        
        config_lower = config_line.lower()
        
        # REJECT if config_line contains ANY prose indicators (even partial matches)
        if any(indicator in config_lower for indicator in prose_indicators):
            logger.debug(f"Rejecting config_line with prose: {config_line[:50]}")
            return _generate_fallback_task(control)
        
        # REJECT if config_line is too long (config directives are typically < 30 chars)
        if len(config_line) > 30:
            logger.debug(f"Rejecting config_line too long ({len(config_line)} chars): {config_line[:50]}")
            return _generate_fallback_task(control)
        
        # REJECT if config_line contains sentence punctuation (likely prose)
        if any(c in config_line for c in ['.', ':', ';', ',', '!', '?', '...']):
            logger.debug(f"Rejecting config_line with punctuation: {config_line[:50]}")
            return _generate_fallback_task(control)
        
        # REJECT if config_line doesn't match strict config patterns (KEY VALUE or KEY=VALUE only)
        if not re.match(r'^[A-Z_][A-Z0-9_]+\s+[A-Z0-9_]+$', config_line) and not re.match(r'^[A-Z_][A-Z0-9_]+\s*=\s*[A-Z0-9_]+$', config_line):
            logger.debug(f"Rejecting config_line doesn't match pattern: {config_line[:50]}")
            return _generate_fallback_task(control)
        
        # Final check: reject if it contains common prose words (even as substrings)
        # Expanded list to catch more prose patterns
        prose_words = ['verify', 'check', 'configure', 'system', 'file', 'command', 'following', 'shadow', 'encrypted', 'representations', 'passwords', 'hash', 'value', 'with', 'the', 'is', 'are', 'that', 'running', 'by', 'number', 'minimum', 'rounds', 'configured']
        if any(word in config_lower for word in prose_words):
            logger.debug(f"Rejecting config_line with prose words: {config_line[:50]}")
            return _generate_fallback_task(control)
        
        # Additional check: if config_line has more than 2 words, it's likely prose
        word_count = len(config_line.split())
        if word_count > 2:
            logger.debug(f"Rejecting config_line too many words ({word_count}): {config_line[:50]}")
            return _generate_fallback_task(control)
        
        # Build task name
        task_name_parts = []
        if vul_id:
            task_name_parts.append(vul_id)
        task_name_parts.append(title)
        if sv_id and sv_id != "UNKNOWN":
            task_name_parts.append(f"({sv_id})")
        if rule_id:
            task_name_parts.append(f"({rule_id})")
        task_name = " - ".join(task_name_parts)
        
        # Final validation: config_line must be pure config (no prose)
        # Double-check that config_line doesn't contain prose (safety check)
        config_lower_final = config_line.lower()
        prose_words_final = ['verify', 'check', 'configure', 'system', 'file', 'command', 'following', 'shadow', 'encrypted', 'representations', 'passwords', 'hash', 'value', 'with', 'the', 'is', 'are', 'that', 'running', 'by', 'number', 'minimum', 'rounds', 'configured']
        if any(word in config_lower_final for word in prose_words_final):
            logger.debug(f"Final rejection: config_line contains prose: {config_line[:50]}")
            return _generate_fallback_task(control)
        
        # Additional safety: if more than 2 words, reject (config directives are typically KEY VALUE or KEY=VALUE)
        if len(config_line.split()) > 2:
            logger.debug(f"Final rejection: config_line has too many words: {config_line[:50]}")
            return _generate_fallback_task(control)
        
        # Use YAML-safe string for config_line (but only if it passed all checks)
        safe_line = yaml_safe_scalar(config_line)
        
        lines = [
            f"    - name: {quote_yaml_string(task_name)}",
            "      ansible.builtin.lineinfile:",
            f"        path: {file_path}",
            f"        line: {safe_line}",
        ]
        
        if '=' in config_line:
            key = config_line.split('=')[0].strip()
            # Use single quotes for regex to avoid YAML escape issues
            lines.append(f"        regexp: '^#?\\s*{re.escape(key)}\\s*='")
        elif ':' in config_line:
            key = config_line.split(':')[0].strip()
            # Use single quotes for regex to avoid YAML escape issues
            lines.append(f"        regexp: '^#?\\s*{re.escape(key)}\\s*:'")
        else:
            # For space-separated config (KEY VALUE), extract just the key
            key = config_line.split()[0].strip() if config_line.split() else ""
            if key:
                # Use single quotes for regex to avoid YAML escape issues
                lines.append(f"        regexp: '^#?\\s*{re.escape(key)}\\s+'")
        
        lines.append("        create: yes")
        lines.append("        backup: yes")
        
        # Add handler notification for systemd config files
        if "/etc/systemd/" in file_path:
            lines.append("      notify: Reload systemd daemon")
        
        return lines
    
    # Try blockinfile for multi-line configs
    if file_path and not config_line:
        # Look for multi-line patterns
        if "Add the following" in fix_text or "Add or update" in fix_text:
            # Extract block between markers
            block_match = re.search(r'(?:Add|Configure|Set)\s+(?:the\s+)?following[:\s]+(.*?)(?:Verify|Check|If)', fix_text, re.DOTALL | re.IGNORECASE)
            if block_match:
                block_content = block_match.group(1).strip()
                # Clean up the block
                block_lines = [l.strip() for l in block_content.split('\n') if l.strip() and not l.strip().startswith('$')]
                if block_lines:
                    block_text = '\n'.join(block_lines[:10])  # Limit to 10 lines
                    # Build task name
                    task_name_parts = []
                    if vul_id:
                        task_name_parts.append(vul_id)
                    task_name_parts.append(title)
                    if sv_id and sv_id != "UNKNOWN":
                        task_name_parts.append(f"({sv_id})")
                    if rule_id:
                        task_name_parts.append(f"({rule_id})")
                    task_name = " - ".join(task_name_parts)
                    
                    result = [
                        f"    - name: {quote_yaml_string(task_name)}",
                        "      ansible.builtin.blockinfile:",
                        f"        path: {file_path}",
                        f"        block: |",
                    ] + [f"          {line}" for line in block_text.split('\n')] + [
                        "        marker: '# {mark} ANSIBLE MANAGED BLOCK'",
                        "        create: yes",
                        "        backup: yes",
                    ]
                    
                    # Add handler notification for systemd config files
                    if "/etc/systemd/" in file_path:
                        result.append("      notify: Reload systemd daemon")
                    
                    return result
    
    return _generate_fallback_task(control)


def _extract_config_line(text: str) -> Optional[str]:
    """Extract configuration line from text.
    
    Only extracts actual config directives, not prose or explanations.
    Very strict - rejects anything that looks like prose.
    """
    # Comprehensive prose indicators
    prose_indicators = [
        'verify', 'check', 'configure', 'edit', 'add', 'set', 'must', 'should',
        'the following', 'with the following', 'following command', 'following line',
        'system\'s', 'shadow file', 'is configured', 'representations', 'passwords',
        'hash value', 'command:', 'line:', 'file:', 'directory:', 'verify the',
        'check the', 'configure the', 'the system', 'with a hash', 'with the',
        'following:', '...', 'ellipsis'
    ]
    
    lines = text.split('\n')
    for line in lines:
        line = line.strip()
        if not line or len(line) < 3:
            continue
        
        # Skip obvious prose/instructions
        if any(line.startswith(prefix) for prefix in ['#', 'Note:', 'Step', 'Edit', 'Configure', 'Run', '$', 'sudo', 'Verify', 'Check']):
            continue
        
        # Skip lines with ellipsis or truncation
        if '...' in line or line.endswith('...'):
            continue
        
        # Skip lines that are clearly sentences (end with period and contain prose words)
        if line.endswith('.') and len(line) > 50:
            continue
        
        # Skip lines that contain prose indicators anywhere - REJECT ENTIRELY
        line_lower = line.lower()
        if any(indicator in line_lower for indicator in prose_indicators):
            # Don't try to extract - if prose is present, reject the whole line
            # This prevents prose from getting into config lines
            continue
        
        # Match ONLY pure config lines: KEY=VALUE or KEY VALUE (strict patterns)
        # Must be short, no prose, no special chars except = or space
        # CRITICAL: Reject if line contains ANY prose words or is too long
        if re.match(r'^[A-Z_][A-Z0-9_]+\s+[A-Z0-9_]+$', line):
            # Additional validation: no prose, short, no special chars, no prose words anywhere
            if not any(indicator in line_lower for indicator in prose_indicators):
                # Must be very short (config directives are typically < 30 chars)
                if len(line) < 30 and not any(c in line for c in ['.', ':', ';', ',', '!', '?', '...']):
                    # Final check: no common prose words
                    prose_words = ['verify', 'check', 'configure', 'system', 'file', 'command', 'following', 'shadow', 'encrypted', 'representations', 'passwords', 'hash', 'value']
                    if not any(word in line_lower for word in prose_words):
                        return line.strip('"\'.,;')
        
        if re.match(r'^[A-Z_][A-Z0-9_]+\s*=\s*[A-Z0-9_]+$', line):
            # Additional validation: no prose, short, no special chars
            if not any(indicator in line_lower for indicator in prose_indicators):
                # Must be very short
                if len(line) < 30 and not any(c in line for c in ['.', ':', ';', ',', '!', '?', '...']):
                    prose_words = ['verify', 'check', 'configure', 'system', 'file', 'command', 'following', 'shadow', 'encrypted', 'representations', 'passwords', 'hash', 'value']
                    if not any(word in line_lower for word in prose_words):
                        return line.strip('"\'.,;')
        
        if re.match(r'^[a-z_][a-z0-9_]+\s*=\s*[a-z0-9_]+$', line):
            # Additional validation: no prose, short
            if not any(indicator in line_lower for indicator in prose_indicators):
                # Must be very short
                if len(line) < 30:
                    prose_words = ['verify', 'check', 'configure', 'system', 'file', 'command', 'following']
                    if not any(word in line_lower for word in prose_words):
                        return line.strip('"\'.,;')
    
    return None


def _extract_audit_rule(text: str) -> Optional[str]:
    """Extract audit rule from text."""
    match = re.search(r'(-[wa]\s+[^\n]+)', text)
    if match:
        return match.group(1).strip()
    return None


def _clean_title_for_task_name(title: str, max_length: int = 100) -> str:
    """
    Clean title for use in task names.
    
    Removes/replaces special characters that can break YAML, truncates safely.
    Removes trailing ellipses.
    """
    # Replace pipe with dash
    title = title.replace("|", "-")
    # Remove or replace other problematic characters
    title = title.replace(":", " -")
    # Remove trailing ellipses
    title = title.rstrip("...").rstrip(".")
    # Truncate at word boundary if too long
    if len(title) > max_length:
        # Find last space before max_length
        truncate_at = title[:max_length].rfind(" ")
        if truncate_at > max_length * 0.7:  # Only truncate if we keep at least 70%
            title = title[:truncate_at]
        else:
            title = title[:max_length]
    return title.strip()


def _generate_fallback_task(control: dict) -> list[str]:
    """
    Generate fallback task when specific implementation can't be determined.
    
    This should only be used for truly non-automatable controls.
    For hardening, we try to generate real tasks first, and only use debug
    as a last resort for controls that truly cannot be automated.
    """
    sv_id = control.get("sv_id", "UNKNOWN")
    vul_id = control.get("vul_id", "")
    rule_id = control.get("rule_id", "")
    title = _clean_title_for_task_name(control.get("title", ""), max_length=80)
    fix_text = (control.get("fix_text", "") or "")[:500]
    
    # Build task name - use simple format without quotes if possible
    task_name_parts = []
    if vul_id:
        task_name_parts.append(vul_id)
    task_name_parts.append(title)
    if sv_id and sv_id != "UNKNOWN":
        task_name_parts.append(f"({sv_id})")
    if rule_id:
        task_name_parts.append(f"({rule_id})")
    task_name = " - ".join(task_name_parts)
    
    # Clean fix_text for message
    fix_clean = fix_text.replace(chr(10), ' ').replace(chr(13), ' ').strip()
    
    # Build message - keep it concise
    msg = f"Manual hardening required for {sv_id}: {title}"
    if fix_clean:
        # Truncate fix_clean if too long
        if len(fix_clean) > 200:
            fix_clean = fix_clean[:200] + "..."
        msg += f" - {fix_clean}"
    msg += " Refer to STIG FixText for detailed steps."
    
    # Use debug (not fail) for manual tasks - they should not fail the playbook
    # Use YAML-safe message formatting
    safe_msg = yaml_safe_scalar(msg)
    
    return [
        f"    - name: {quote_yaml_string(task_name)}",
        "      ansible.builtin.debug:",
        f"        msg: {safe_msg}",
    ]


# ============================================================================
# Windows-specific task generators
# ============================================================================

def _extract_registry_path(text: str) -> Optional[dict]:
    """Extract Windows registry path, name, value, and type from text."""
    # Pattern 1: Direct format - HKLM:\SYSTEM\CurrentControlSet\Control\Lsa\LmCompatibilityLevel = 5
    path_match = re.search(r'(HKLM|HKCU|HKCR|HKU):\\([^\\s\n]+)', text, re.IGNORECASE)
    if path_match:
        hive = path_match.group(1)
        key_path = path_match.group(2)
        
        # Look for value name and data
        # Pattern: ValueName = 5 or ValueName = "string"
        value_match = re.search(r'([A-Za-z_][A-Za-z0-9_]*)\s*[=:]\s*(\d+|"[^"]+"|"[^"]*")', text, re.IGNORECASE)
        if value_match:
            value_name = value_match.group(1)
            value_data = value_match.group(2).strip('"')
            
            # Determine type
            if value_data.isdigit():
                reg_type = 'dword'
            else:
                reg_type = 'string'
            
            return {
                'path': f"{hive}:\\{key_path}",
                'name': value_name,
                'data': value_data,
                'type': reg_type
            }
        else:
            # No value name, just path
            return {
                'path': f"{hive}:\\{key_path}",
                'name': None,
                'data': None,
                'type': None
            }
    
    # Pattern 2: Group Policy Administrative Templates -> Registry mapping
    # Many Windows STIGs use "Configure the policy value for Computer Configuration >> Administrative Templates >> ..."
    # These map to registry keys under HKLM:\SOFTWARE\Policies\Microsoft or HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Policies
    if 'Administrative Templates' in text and 'Configure the policy value' in text:
        # Extract policy path from "Computer Configuration >> Administrative Templates >> Category >> Policy"
        policy_match = re.search(r'Computer Configuration\s*>>\s*Administrative Templates\s*>>\s*([^>>]+)\s*>>\s*([^>>]+)\s*>>\s*([^>>]+)', text, re.IGNORECASE)
        if not policy_match:
            policy_match = re.search(r'Computer Configuration\s*>>\s*Administrative Templates\s*>>\s*([^>>]+)\s*>>\s*([^>>]+)', text, re.IGNORECASE)
        
        if policy_match:
            # Extract policy name and value
            policy_name_match = re.search(r'>>\s*([^>>]+?)\s+to\s+["\']([^"\']+)["\']', text, re.IGNORECASE)
            if policy_name_match:
                policy_name = policy_name_match.group(1).strip()
                policy_value = policy_name_match.group(2).strip()
                
                # Map common Administrative Template categories to registry paths
                category = policy_match.group(1).strip() if len(policy_match.groups()) >= 1 else ''
                subcategory = policy_match.group(2).strip() if len(policy_match.groups()) >= 2 else ''
                
                # Common mappings - Group Policy Administrative Templates map to specific registry locations
                if 'MS Security Guide' in category:
                    # MS Security Guide policies map to various locations
                    if 'SMB' in policy_name or 'smb' in policy_name.lower():
                        base_path = 'SYSTEM\\CurrentControlSet\\Services\\LanmanServer\\Parameters'
                    elif 'WDigest' in policy_name or 'wdigest' in policy_name.lower():
                        base_path = 'SYSTEM\\CurrentControlSet\\Control\\SecurityProviders\\Wdigest'
                    else:
                        base_path = 'SYSTEM\\CurrentControlSet\\Services\\Tcpip\\Parameters'
                elif 'MSS (Legacy)' in category:
                    # MSS Legacy policies map to TCP/IP parameters
                    base_path = 'SYSTEM\\CurrentControlSet\\Services\\Tcpip\\Parameters'
                elif 'Control Panel' in category:
                    if 'Personalization' in subcategory:
                        base_path = 'SOFTWARE\\Policies\\Microsoft\\Windows\\Personalization'
                    else:
                        base_path = 'SOFTWARE\\Policies\\Microsoft\\Windows\\Control Panel'
                elif 'Network' in category:
                    if 'Lanman Workstation' in subcategory or 'Workstation' in subcategory:
                        base_path = 'SOFTWARE\\Policies\\Microsoft\\Windows\\NetworkProvider'
                    elif 'Network Provider' in subcategory:
                        base_path = 'SOFTWARE\\Policies\\Microsoft\\Windows\\NetworkProvider'
                    else:
                        base_path = 'SOFTWARE\\Policies\\Microsoft\\Windows\\NetworkProvider'
                elif 'System' in category:
                    if 'Audit Process Creation' in subcategory:
                        base_path = 'SOFTWARE\\Policies\\Microsoft\\Windows\\EventLog\\EventLog-Windows Defender'
                    elif 'Credentials Delegation' in subcategory:
                        base_path = 'SOFTWARE\\Policies\\Microsoft\\Windows\\CredentialsDelegation'
                    elif 'Device Guard' in subcategory:
                        base_path = 'SOFTWARE\\Policies\\Microsoft\\Windows\\DeviceGuard'
                    elif 'Group Policy' in subcategory:
                        base_path = 'SOFTWARE\\Policies\\Microsoft\\Windows\\Group Policy'
                    elif 'Internet Communication Management' in subcategory:
                        base_path = 'SOFTWARE\\Policies\\Microsoft\\Windows\\Internet Communication Management'
                    elif 'Logon' in subcategory:
                        base_path = 'SOFTWARE\\Policies\\Microsoft\\Windows\\System'
                    elif 'Power Management' in subcategory:
                        base_path = 'SOFTWARE\\Policies\\Microsoft\\Windows\\Power'
                    else:
                        base_path = 'SOFTWARE\\Policies\\Microsoft\\Windows\\System'
                else:
                    base_path = 'SOFTWARE\\Policies\\Microsoft\\Windows'
                
                # Extract value name from policy name - try to find the actual registry value name
                # Many Group Policy settings have specific registry value names
                value_name = None
                
                # Try to extract from common patterns
                # Look for specific value names mentioned in the text
                value_name_patterns = [
                    r'Value\s+Name[:\s]+([A-Za-z0-9_]+)',
                    r'registry\s+value[:\s]+([A-Za-z0-9_]+)',
                    r'DWORD\s+value[:\s]+([A-Za-z0-9_]+)',
                ]
                for pattern in value_name_patterns:
                    vname_match = re.search(pattern, text, re.IGNORECASE)
                    if vname_match:
                        value_name = vname_match.group(1)
                        break
                
                # If no explicit value name, derive from policy name
                if not value_name:
                    # Clean up policy name to create a reasonable value name
                    value_name = policy_name.replace(' ', '').replace('(', '').replace(')', '').replace(':', '').replace('-', '')
                    # Limit length
                    if len(value_name) > 50:
                        value_name = value_name[:50]
                
                # Determine value data and type
                if policy_value.lower() in ['enabled', 'disabled']:
                    value_data = '1' if policy_value.lower() == 'enabled' else '0'
                    value_type = 'dword'
                elif policy_value.isdigit():
                    value_data = policy_value
                    value_type = 'dword'
                else:
                    value_data = policy_value
                    value_type = 'string'
                
                return {
                    'path': f"HKLM:\\{base_path}",
                    'name': value_name,
                    'data': value_data,
                    'type': value_type
                }
    
    # Pattern 3: Registry Path prose - "Registry Path: \SYSTEM\CurrentControlSet\Control\Lsa"
    # Look for "Registry Path:" or "Registry Hive:" patterns
    reg_path_match = re.search(r'Registry\s+Path[:\s]+[\\\\]?([A-Z_\\\\]+)', text, re.IGNORECASE)
    if reg_path_match:
        key_path = reg_path_match.group(1).replace('\\\\', '\\').strip('\\')
        hive = 'HKLM'  # Default
        
        # Look for "Registry Hive:" to determine hive
        hive_match = re.search(r'Registry\s+Hive[:\s]+(HKEY_LOCAL_MACHINE|HKEY_CURRENT_USER|HKEY_CLASSES_ROOT|HKEY_USERS|HKLM|HKCU|HKCR|HKU)', text, re.IGNORECASE)
        if hive_match:
            hive_name = hive_match.group(1).upper()
            hive_map = {
                'HKEY_LOCAL_MACHINE': 'HKLM',
                'HKEY_CURRENT_USER': 'HKCU',
                'HKEY_CLASSES_ROOT': 'HKCR',
                'HKEY_USERS': 'HKU'
            }
            hive = hive_map.get(hive_name, 'HKLM' if 'HKLM' in hive_name else 'HKLM')
        
        # Look for "Value Name:"
        value_name_match = re.search(r'Value\s+Name[:\s]+([A-Za-z0-9_]+)', text, re.IGNORECASE)
        value_name = value_name_match.group(1) if value_name_match else None
        
        # Look for "Value:" with hex or decimal
        value_match = re.search(r'Value[:\s]+0x[0-9a-f]+.*?\((\d+)\)', text, re.IGNORECASE)
        if not value_match:
            value_match = re.search(r'Value[:\s]+(\d+)', text, re.IGNORECASE)
        value_data = value_match.group(1) if value_match else '1'  # Default to 1 if not found
        
        if value_name:
            return {
                'path': f"{hive}:\\{key_path}",
                'name': value_name,
                'data': value_data,
                'type': 'dword'
            }
    
    # Pattern 4: SYSTEM\CurrentControlSet patterns in prose
    system_path_match = re.search(r'SYSTEM[\\\\\s]+CurrentControlSet[\\\\\s]+Control[\\\\\s]+([A-Za-z]+)', text, re.IGNORECASE)
    if system_path_match:
        control_key = system_path_match.group(1)
        # Common registry paths for security settings
        key_path = f"SYSTEM\\CurrentControlSet\\Control\\{control_key}"
        hive = 'HKLM'
        
        # Look for value name in nearby text
        value_names = [
            'LmCompatibilityLevel', 'NtlmMinClientSec', 'NtlmMinServerSec', 'RestrictAnonymous', 
            'NoLMHash', 'FullPrivilegeAuditing', 'AuditBaseObjects', 'AuditBaseDirectories',
            'RestrictAnonymousSam', 'RestrictRemoteSAM', 'RestrictNullSessAccess', 'LSAAnonymousNameLookup',
            'DisablePasswordChange', 'RequireSecuritySignature', 'EnableSecuritySignature', 'RequireStrongKey',
            'SealSecureChannel', 'SignSecureChannel', 'AutoAdminLogon', 'DontDisplayLastUserName',
            'ScForceOption', 'ScreenSaverGracePeriod', 'ScreenSaverIsSecure', 'PasswordExpiryWarning',
            'DisableCAD', 'NoDriveTypeAutoRun', 'NoAutorun', 'NoSimpleFileSharing', 'ForceGuest'
        ]
        
        for vname in value_names:
            if vname.lower() in text.lower():
                # Look for value near the value name
                vname_idx = text.lower().find(vname.lower())
                value_match = re.search(r'\d+', text[vname_idx:vname_idx+100])
                if value_match:
                    return {
                        'path': f"{hive}:\\{key_path}",
                        'name': vname,
                        'data': value_match.group(0),
                        'type': 'dword'
                    }
                # Return with value name even without explicit value
                return {
                    'path': f"{hive}:\\{key_path}",
                    'name': vname,
                    'data': '1',  # Default enabled value
                    'type': 'dword'
                }
    
    # Pattern 3: Direct prose path match
    prose_path_match = re.search(r'(?:HKEY_LOCAL_MACHINE|HKEY_CURRENT_USER|HKEY_CLASSES_ROOT|HKEY_USERS|HKLM|HKCU|HKCR|HKU)[\\\s]+([A-Z_\\\s]+)', text, re.IGNORECASE)
    if prose_path_match:
        # Convert HKEY_LOCAL_MACHINE to HKLM
        hive_map = {
            'HKEY_LOCAL_MACHINE': 'HKLM',
            'HKEY_CURRENT_USER': 'HKCU',
            'HKEY_CLASSES_ROOT': 'HKCR',
            'HKEY_USERS': 'HKU'
        }
        
        full_path = prose_path_match.group(0)
        hive = 'HKLM'  # Default
        for hkey, short in hive_map.items():
            if hkey in full_path.upper() or short.upper() in full_path.upper():
                hive = short
                break
        
        # Extract key path (remove hive prefix)
        key_path = re.sub(r'^(?:HKEY_LOCAL_MACHINE|HKEY_CURRENT_USER|HKEY_CLASSES_ROOT|HKEY_USERS|HKLM|HKCU|HKCR|HKU)[\\\s]+', '', full_path, flags=re.IGNORECASE)
        # Normalize backslashes and spaces
        key_path = key_path.replace('\\\\', '\\').replace('/', '\\').replace(' ', '\\').strip()
        
        # Look for value name in nearby text
        # Common registry value names
        value_names = ['LmCompatibilityLevel', 'NtlmMinClientSec', 'NtlmMinServerSec', 'RestrictAnonymous', 
                      'NoLMHash', 'FullPrivilegeAuditing', 'AuditBaseObjects', 'AuditBaseDirectories']
        
        for vname in value_names:
            if vname.lower() in text.lower():
                # Look for value near the value name
                vname_idx = text.lower().find(vname.lower())
                value_match = re.search(r'\d+', text[vname_idx:vname_idx+100])
                if value_match:
                    return {
                        'path': f"{hive}:\\{key_path}",
                        'name': vname,
                        'data': value_match.group(0),
                        'type': 'dword'
                    }
        
        # Return path even without value (might be a permission check)
        return {
            'path': f"{hive}:\\{key_path}",
            'name': None,
            'data': None,
            'type': None
        }
    
    return None


def generate_windows_registry_tasks(control: dict) -> list[str]:
    """Generate Ansible tasks for Windows registry category."""
    fix_text = control.get("fix_text", "") or ""
    check_text = control.get("check_text", "") or ""
    sv_id = control.get("sv_id", "UNKNOWN")
    vul_id = control.get("vul_id", "")
    rule_id = control.get("rule_id", "")
    title = _clean_title_for_task_name(control.get("title", ""), max_length=80)
    combined_text = f"{fix_text} {check_text}"
    
    registry_info = _extract_registry_path(combined_text)
    
    # Allow registry tasks even if data is None but we have path and name (for permission checks)
    if registry_info and (registry_info.get('data') is not None or (registry_info.get('path') and registry_info.get('name'))):
        task_name_parts = []
        if vul_id:
            task_name_parts.append(vul_id)
        task_name_parts.append(title)
        if sv_id and sv_id != "UNKNOWN":
            task_name_parts.append(f"({sv_id})")
        if rule_id:
            task_name_parts.append(f"({rule_id})")
        task_name = " - ".join(task_name_parts)
        
        lines = [
            f"    - name: {quote_yaml_string(task_name)}",
            "      ansible.windows.win_regedit:",
            f"        path: '{registry_info['path']}'",  # Use single quotes for Windows paths to avoid backslash escaping
        ]
        
        if registry_info['name']:
            lines.append(f"        name: {quote_yaml_string(registry_info['name'])}")
        
        # Use single quotes for data to avoid YAML escaping issues
        if registry_info.get('data') is not None:
            lines.append(f"        data: '{registry_info['data']}'")
        if registry_info['type']:
            lines.append(f"        type: {registry_info['type']}")
        lines.append("        state: present")
        
        return lines
    
    return _generate_fallback_task(control)


def _extract_security_policy(text: str) -> Optional[dict]:
    """Extract Windows security policy section, key, and value from text."""
    # Pattern 1: Direct format - System Access: MinimumPasswordLength = 14
    match = re.search(r'(System Access|Local Policies|Event Audit|Registry Values|Kerberos Policy)[:\s]+([A-Za-z0-9_]+)\s*[=:]\s*(\d+|"[^"]+"|[A-Za-z\s]+)', text, re.IGNORECASE)
    if match:
        return {
            'section': match.group(1),
            'key': match.group(2),
            'value': match.group(3).strip('"')
        }
    
    # Pattern 2: Group Policy Administrative Templates that map to Security Policy
    # Some Group Policy settings actually map to Local Security Policy, not registry
    if 'Administrative Templates' in text and 'Security Settings' in text:
        # These are security policy settings, not registry
        # Extract policy name and try to map to security policy
        policy_name_match = re.search(r'>>\s*([^>>]+?)\s+to\s+["\']([^"\']+)["\']', text, re.IGNORECASE)
        if policy_name_match:
            policy_name = policy_name_match.group(1).strip().lower()
            policy_value = policy_name_match.group(2).strip()
            
            # Map common security policy names
            security_policy_map = {
                'minimum password length': ('System Access', 'MinimumPasswordLength'),
                'maximum password age': ('System Access', 'MaximumPasswordAge'),
                'minimum password age': ('System Access', 'MinimumPasswordAge'),
                'password history': ('System Access', 'PasswordHistorySize'),
                'password complexity': ('System Access', 'PasswordComplexity'),
                'account lockout duration': ('System Access', 'LockoutDuration'),
                'account lockout threshold': ('System Access', 'LockoutBadCount'),
                'reset account lockout counter': ('System Access', 'ResetLockoutCount'),
            }
            
            for pattern, (section, key) in security_policy_map.items():
                if pattern in policy_name:
                    # Extract value
                    if policy_value.isdigit():
                        return {
                            'section': section,
                            'key': key,
                            'value': policy_value
                        }
    
    # Pattern 3: Group Policy prose - "Configure the policy value for Computer Configuration >> ... >> PolicyName to Value"
    # Expanded policy mappings with more patterns
    policy_mappings = {
        # Account Lockout Policies
        'account lockout duration': ('System Access', 'LockoutDuration'),
        'lockout duration': ('System Access', 'LockoutDuration'),
        'account lockout threshold': ('System Access', 'LockoutBadCount'),
        'lockout threshold': ('System Access', 'LockoutBadCount'),
        'reset account lockout counter': ('System Access', 'ResetLockoutCount'),
        'reset lockout counter': ('System Access', 'ResetLockoutCount'),
        'reset lockout counter after': ('System Access', 'ResetLockoutCount'),
        # Password Policies
        'minimum password length': ('System Access', 'MinimumPasswordLength'),
        'password length': ('System Access', 'MinimumPasswordLength'),
        'maximum password age': ('System Access', 'MaximumPasswordAge'),
        'minimum password age': ('System Access', 'MinimumPasswordAge'),
        'password history': ('System Access', 'PasswordHistorySize'),
        'enforce password history': ('System Access', 'PasswordHistorySize'),
        'password complexity': ('System Access', 'PasswordComplexity'),
        'password must meet complexity requirements': ('System Access', 'PasswordComplexity'),
        'store passwords using reversible encryption': ('System Access', 'ClearTextPassword'),
        'password age': ('System Access', 'MaximumPasswordAge'),  # Generic
        'password must be changed': ('System Access', 'MaximumPasswordAge'),  # Generic
        # Audit Policies
        'audit account logon events': ('Event Audit', 'AuditAccountLogon'),
        'audit account management': ('Event Audit', 'AuditAccountManagement'),
        'audit logon events': ('Event Audit', 'AuditLogonEvents'),
        'audit object access': ('Event Audit', 'AuditObjectAccess'),
        'audit policy change': ('Event Audit', 'AuditPolicyChange'),
        'audit privilege use': ('Event Audit', 'AuditPrivilegeUse'),
        'audit system events': ('Event Audit', 'AuditSystemEvents'),
        'audit process tracking': ('Event Audit', 'AuditProcessTracking'),
        'audit directory service access': ('Event Audit', 'AuditDirectoryServiceAccess'),
        'audit ds access': ('Event Audit', 'AuditDSAccess'),
        # Security Options (mapped to Local Policies)
        'network access: allow anonymous sid/name translation': ('Local Policies', 'LSAAnonymousNameLookup'),
        'network access: do not allow anonymous enumeration': ('Local Policies', 'RestrictAnonymous'),
        'network access: restrict anonymous access to named pipes': ('Local Policies', 'RestrictNullSessAccess'),
        'network security: minimum session security': ('Local Policies', 'NTLMMinServerSec'),
        'network security: lan manager authentication level': ('Local Policies', 'LmCompatibilityLevel'),
    }
    
    text_lower = text.lower()
    
    # First, try direct policy name matches
    policy_names = [
        'MinimumPasswordLength', 'MaximumPasswordAge', 'MinimumPasswordAge', 'PasswordHistorySize',
        'PasswordComplexity', 'LockoutBadCount', 'ResetLockoutCount', 'LockoutDuration',
        'AuditAccountLogon', 'AuditAccountManagement', 'AuditLogonEvents', 'AuditObjectAccess',
        'AuditPolicyChange', 'AuditPrivilegeUse', 'AuditSystemEvents', 'AuditProcessTracking',
        'AuditDSAccess', 'AuditDirectoryServiceAccess', 'ClearTextPassword', 'LmCompatibilityLevel',
        'NTLMMinServerSec', 'NTLMMinClientSec', 'RestrictAnonymous', 'RestrictNullSessAccess'
    ]
    
    for policy_name in policy_names:
        if policy_name.lower() in text_lower:
            # Try to extract value - look for numbers after policy name or "to" keyword
            value_match = re.search(rf'{re.escape(policy_name)}[^0-9]*(\d+)', text, re.IGNORECASE)
            if not value_match:
                # Try "to \"value\"" pattern
                value_match = re.search(r'to\s+"(\d+)"', text, re.IGNORECASE)
            if value_match:
                value = value_match.group(1)
                # Determine section
                if 'Password' in policy_name or 'Lockout' in policy_name or 'ClearText' in policy_name:
                    section = 'System Access'
                elif 'Audit' in policy_name:
                    section = 'Event Audit'
                else:
                    section = 'Local Policies'
                
                return {
                    'section': section,
                    'key': policy_name,
                    'value': value
                }
    
    # Then try prose pattern mappings
    for pattern, (section, key) in policy_mappings.items():
        if pattern in text_lower:
            # Extract value - look for number near the pattern
            pattern_idx = text_lower.find(pattern)
            # Look for "to \"value\"" or just number within 150 chars after pattern
            value_match = re.search(r'to\s+"(\d+)"', text[pattern_idx:pattern_idx+150], re.IGNORECASE)
            if not value_match:
                value_match = re.search(r'\b(\d+)\b', text[pattern_idx:pattern_idx+150])
            if value_match:
                return {
                    'section': section,
                    'key': key,
                    'value': value_match.group(1)
                }
    
    # Pattern 4: Look for "Configure the policy value" with numbers - more lenient
    if 'policy value' in text_lower and 'configure' in text_lower:
        # Try to extract any number that might be a policy value
        # Look for patterns like "to \"15\"" or "to 15" or "15 minutes" or "15 days"
        value_match = re.search(r'to\s+["\']?(\d+)["\']?', text, re.IGNORECASE)
        if not value_match:
            value_match = re.search(r'\b(\d+)\s+(?:minutes?|days?|hours?|attempts?|logons?|passwords?)', text, re.IGNORECASE)
        if value_match:
            value = value_match.group(1)
            # Try to determine policy from context - be more aggressive
            if 'lockout' in text_lower and 'duration' in text_lower:
                return {'section': 'System Access', 'key': 'LockoutDuration', 'value': value}
            elif 'lockout' in text_lower and ('threshold' in text_lower or 'bad logon' in text_lower or 'invalid logon' in text_lower):
                return {'section': 'System Access', 'key': 'LockoutBadCount', 'value': value}
            elif 'lockout' in text_lower and ('reset' in text_lower or 'counter' in text_lower):
                return {'section': 'System Access', 'key': 'ResetLockoutCount', 'value': value}
            elif 'password' in text_lower and ('length' in text_lower or 'characters' in text_lower):
                return {'section': 'System Access', 'key': 'MinimumPasswordLength', 'value': value}
            elif 'password' in text_lower and 'age' in text_lower and ('maximum' in text_lower or 'max' in text_lower):
                return {'section': 'System Access', 'key': 'MaximumPasswordAge', 'value': value}
            elif 'password' in text_lower and 'age' in text_lower and ('minimum' in text_lower or 'min' in text_lower):
                return {'section': 'System Access', 'key': 'MinimumPasswordAge', 'value': value}
            elif 'password' in text_lower and ('history' in text_lower or 'remembered' in text_lower):
                return {'section': 'System Access', 'key': 'PasswordHistorySize', 'value': value}
            elif 'password' in text_lower and 'complexity' in text_lower:
                # Complexity is usually 0 (disabled) or 1 (enabled)
                return {'section': 'System Access', 'key': 'PasswordComplexity', 'value': '1' if value != '0' else '0'}
            elif 'password' in text_lower and 'reversible' in text_lower:
                return {'section': 'System Access', 'key': 'ClearTextPassword', 'value': '0'}
    
    # Pattern 5: User Rights Assignment detection (these are actually user rights, not security policy)
    # But if they come through security policy extraction, try to handle them
    user_right_patterns = {
        'access this computer from the network': ('Local Policies', 'SeNetworkLogonRight'),
        'allow log on through remote desktop services': ('Local Policies', 'SeRemoteInteractiveLogonRight'),
        'allow log on locally': ('Local Policies', 'SeInteractiveLogonRight'),
        'add workstations to domain': ('Local Policies', 'SeMachineAccountPrivilege'),
        'deny log on locally': ('Local Policies', 'SeDenyInteractiveLogonRight'),
        'deny access to this computer from the network': ('Local Policies', 'SeDenyNetworkLogonRight'),
    }
    
    for pattern, (section, key) in user_right_patterns.items():
        if pattern in text_lower:
            # These are user rights, but if we're in security policy extraction, return None
            # so they can be handled by user rights extraction instead
            return None
    
    # Pattern 6: Audit policy detection - look for "audit" + policy type
    if 'audit' in text_lower and ('policy' in text_lower or 'configuration' in text_lower):
        audit_types = {
            'account logon': ('Event Audit', 'AuditAccountLogon'),
            'account management': ('Event Audit', 'AuditAccountManagement'),
            'logon events': ('Event Audit', 'AuditLogonEvents'),
            'object access': ('Event Audit', 'AuditObjectAccess'),
            'policy change': ('Event Audit', 'AuditPolicyChange'),
            'privilege use': ('Event Audit', 'AuditPrivilegeUse'),
            'system events': ('Event Audit', 'AuditSystemEvents'),
            'process tracking': ('Event Audit', 'AuditProcessTracking'),
            'directory service access': ('Event Audit', 'AuditDirectoryServiceAccess'),
            'ds access': ('Event Audit', 'AuditDSAccess'),
        }
        
        for audit_type, (section, key) in audit_types.items():
            if audit_type in text_lower:
                # Look for success/failure values
                if 'success' in text_lower and 'failure' in text_lower:
                    return {'section': section, 'key': key, 'value': '3'}  # Both
                elif 'success' in text_lower:
                    return {'section': section, 'key': key, 'value': '1'}  # Success only
                elif 'failure' in text_lower:
                    return {'section': section, 'key': key, 'value': '2'}  # Failure only
                else:
                    # Default to both if not specified
                    return {'section': section, 'key': key, 'value': '3'}
    
    return None


def generate_windows_security_policy_tasks(control: dict) -> list[str]:
    """Generate Ansible tasks for Windows security policy category."""
    fix_text = control.get("fix_text", "") or ""
    check_text = control.get("check_text", "") or ""
    sv_id = control.get("sv_id", "UNKNOWN")
    vul_id = control.get("vul_id", "")
    rule_id = control.get("rule_id", "")
    title = _clean_title_for_task_name(control.get("title", ""), max_length=80)
    combined_text = f"{fix_text} {check_text}"
    
    policy_info = _extract_security_policy(combined_text)
    
    if policy_info:
        task_name_parts = []
        if vul_id:
            task_name_parts.append(vul_id)
        task_name_parts.append(title)
        if sv_id and sv_id != "UNKNOWN":
            task_name_parts.append(f"({sv_id})")
        if rule_id:
            task_name_parts.append(f"({rule_id})")
        task_name = " - ".join(task_name_parts)
        
        return [
            f"    - name: {quote_yaml_string(task_name)}",
            "      ansible.windows.win_security_policy:",
            f"        section: {quote_yaml_string(policy_info['section'])}",
            f"        key: {quote_yaml_string(policy_info['key'])}",
            f"        value: {quote_yaml_string(policy_info['value'])}",
        ]
    
    return _generate_fallback_task(control)


def _extract_user_right(text: str) -> Optional[dict]:
    """Extract Windows user right assignment from text."""
    user_rights = [
        'SeDenyInteractiveLogonRight', 'SeDenyNetworkLogonRight', 'SeDenyBatchLogonRight',
        'SeDenyServiceLogonRight', 'SeInteractiveLogonRight', 'SeNetworkLogonRight',
        'SeBatchLogonRight', 'SeServiceLogonRight', 'SeBackupPrivilege', 'SeRestorePrivilege',
        'SeDebugPrivilege', 'SeTakeOwnershipPrivilege', 'SeSecurityPrivilege', 'SeSystemtimePrivilege',
        'SeRemoteShutdownPrivilege', 'SeShutdownPrivilege', 'SeLoadDriverPrivilege', 'SeIncreaseQuotaPrivilege',
        'SeAssignPrimaryTokenPrivilege', 'SeCreateTokenPrivilege', 'SeLockMemoryPrivilege', 'SeTcbPrivilege'
    ]
    
    # Pattern 1: Direct format - SeDenyInteractiveLogonRight = Guest
    for right in user_rights:
        pattern = rf'{right}\s*[=:]\s*([A-Za-z0-9_,\s]+)'
        match = re.search(pattern, text, re.IGNORECASE)
        if match:
            users_str = match.group(1).strip()
            users = [u.strip() for u in users_str.split(',')]
            return {
                'name': right,
                'users': users,
                'action': 'set'
            }
    
    # Pattern 2: Prose descriptions - map common descriptions to rights
    text_lower = text.lower()
    right_mappings = {
        # Deny rights
        'deny log on locally': 'SeDenyInteractiveLogonRight',
        'deny log on as a service': 'SeDenyServiceLogonRight',
        'deny log on as a batch job': 'SeDenyBatchLogonRight',
        'deny access to this computer from the network': 'SeDenyNetworkLogonRight',
        'deny log on through remote desktop services': 'SeDenyRemoteInteractiveLogonRight',
        'deny log on through terminal services': 'SeDenyRemoteInteractiveLogonRight',
        # Allow rights
        'log on locally': 'SeInteractiveLogonRight',
        'log on as a service': 'SeServiceLogonRight',
        'log on as a batch job': 'SeBatchLogonRight',
        'access this computer from the network': 'SeNetworkLogonRight',
        'log on through remote desktop services': 'SeRemoteInteractiveLogonRight',
        'log on through terminal services': 'SeRemoteInteractiveLogonRight',
        # Privileges
        'back up files and directories': 'SeBackupPrivilege',
        'restore files and directories': 'SeRestorePrivilege',
        'debug programs': 'SeDebugPrivilege',
        'take ownership of files': 'SeTakeOwnershipPrivilege',
        'take ownership of files or other objects': 'SeTakeOwnershipPrivilege',
        'manage auditing and security log': 'SeSecurityPrivilege',
        'change the system time': 'SeSystemtimePrivilege',
        'force shutdown from a remote system': 'SeRemoteShutdownPrivilege',
        'shut down the system': 'SeShutdownPrivilege',
        'load and unload device drivers': 'SeLoadDriverPrivilege',
        'increase quotas': 'SeIncreaseQuotaPrivilege',
        'act as part of the operating system': 'SeTcbPrivilege',
        'create a token object': 'SeCreateTokenPrivilege',
        'lock pages in memory': 'SeLockMemoryPrivilege',
    }
    
    for description, right_name in right_mappings.items():
        if description in text_lower:
            # Look for user/group names near the description
            # Common ones: Guest, Administrators, Backup Operators, etc.
            common_users = ['Guest', 'Administrators', 'Backup Operators', 'Users', 'Everyone', 
                          'Authenticated Users', 'SYSTEM', 'Service']
            
            users = []
            for user in common_users:
                # Check if user is mentioned near the right description
                desc_idx = text_lower.find(description)
                user_match = re.search(re.escape(user), text[desc_idx:desc_idx+200], re.IGNORECASE)
                if user_match:
                    users.append(user)
            
            if users:
                return {
                    'name': right_name,
                    'users': users,
                    'action': 'set'
                }
            # Return with right name even if no users specified - can be set to empty or default
            else:
                # For deny rights, typically want to ensure they're set (even if empty)
                # For allow rights, might need to check what's appropriate
                return {
                    'name': right_name,
                    'users': [],  # Empty list means "ensure this right is configured"
                    'action': 'set'
                }
            
            # Return with empty users list - will need manual specification
            if 'deny' in description or 'remove' in text_lower:
                return {
                    'name': right_name,
                    'users': [],
                    'action': 'set'
                }
    
    return None


def generate_windows_user_right_tasks(control: dict) -> list[str]:
    """Generate Ansible tasks for Windows user rights category."""
    fix_text = control.get("fix_text", "") or ""
    check_text = control.get("check_text", "") or ""
    sv_id = control.get("sv_id", "UNKNOWN")
    vul_id = control.get("vul_id", "")
    rule_id = control.get("rule_id", "")
    title = _clean_title_for_task_name(control.get("title", ""), max_length=80)
    combined_text = f"{fix_text} {check_text}"
    
    right_info = _extract_user_right(combined_text)
    
    # If we can identify the right name, generate a task even without explicit users
    if right_info and right_info.get('name'):
        task_name_parts = []
        if vul_id:
            task_name_parts.append(vul_id)
        task_name_parts.append(title)
        if sv_id and sv_id != "UNKNOWN":
            task_name_parts.append(f"({sv_id})")
        if rule_id:
            task_name_parts.append(f"({rule_id})")
        task_name = " - ".join(task_name_parts)
        
        users_list = str(right_info['users'])
        
        return [
            f"    - name: {quote_yaml_string(task_name)}",
            "      ansible.windows.win_user_right:",
            f"        name: {right_info['name']}",
            f"        users: {users_list}",
            f"        action: {right_info['action']}",
        ]
    
    return _generate_fallback_task(control)


def _extract_firewall_rule(text: str) -> Optional[dict]:
    """Extract Windows firewall rule from text."""
    # New-NetFirewallRule -DisplayName "Block SMB" -Direction Inbound -Protocol TCP -LocalPort 445 -Action Block
    match = re.search(r'New-NetFirewallRule.*-DisplayName\s+"([^"]+)".*-Direction\s+(\w+).*-Protocol\s+(\w+)(?:.*-LocalPort\s+(\d+))?.*-Action\s+(\w+)', text, re.IGNORECASE | re.DOTALL)
    if match:
        return {
            'name': match.group(1),
            'direction': match.group(2).lower(),
            'protocol': match.group(3).upper(),
            'localport': match.group(4),
            'action': match.group(5).lower(),
        }
    
    return None


def generate_windows_firewall_tasks(control: dict) -> list[str]:
    """Generate Ansible tasks for Windows firewall category."""
    fix_text = control.get("fix_text", "") or ""
    check_text = control.get("check_text", "") or ""
    sv_id = control.get("sv_id", "UNKNOWN")
    vul_id = control.get("vul_id", "")
    rule_id = control.get("rule_id", "")
    title = _clean_title_for_task_name(control.get("title", ""), max_length=80)
    combined_text = f"{fix_text} {check_text}"
    
    firewall_info = _extract_firewall_rule(combined_text)
    
    if firewall_info:
        task_name_parts = []
        if vul_id:
            task_name_parts.append(vul_id)
        task_name_parts.append(title)
        if sv_id and sv_id != "UNKNOWN":
            task_name_parts.append(f"({sv_id})")
        if rule_id:
            task_name_parts.append(f"({rule_id})")
        task_name = " - ".join(task_name_parts)
        
        lines = [
            f"    - name: {quote_yaml_string(task_name)}",
            "      ansible.windows.win_firewall_rule:",
            f"        name: {quote_yaml_string(firewall_info['name'])}",
            f"        direction: {firewall_info['direction']}",
            f"        protocol: {firewall_info['protocol']}",
            f"        action: {firewall_info['action']}",
            "        state: present",
            "        enabled: yes",
        ]
        
        if firewall_info.get('localport'):
            lines.append(f"        localport: {firewall_info['localport']}")
        
        return lines
    
    return _generate_fallback_task(control)


def _extract_windows_feature(text: str) -> Optional[dict]:
    """Extract Windows feature name and state from text."""
    # Pattern 1: Install-WindowsFeature -Name FeatureName
    install_match = re.search(r'(Install|Enable)-Windows(Feature|OptionalFeature)\s+(?:-Name\s+)?([A-Za-z0-9_-]+)', text, re.IGNORECASE)
    if install_match:
        return {
            'name': install_match.group(3),
            'state': 'present'
        }
    
    # Pattern 2: Uninstall-WindowsFeature -Name FeatureName
    uninstall_match = re.search(r'(Uninstall|Disable)-Windows(Feature|OptionalFeature)\s+(?:-Name\s+)?([A-Za-z0-9_-]+)', text, re.IGNORECASE)
    if uninstall_match:
        return {
            'name': uninstall_match.group(3),
            'state': 'absent'
        }
    
    # Pattern 3: Prose descriptions - "Uninstall the Fax Server role" or "Remove the FTP feature"
    text_lower = text.lower()
    feature_keywords = {
        # Features to remove
        'fax server': ('Fax-Server', 'absent'),
        'fax': ('Fax-Server', 'absent'),
        'ftp server': ('FTP-Server', 'absent'),
        'ftp publishing service': ('FTP-Server', 'absent'),
        'microsoft ftp service': ('FTP-Server', 'absent'),
        'telnet client': ('Telnet-Client', 'absent'),
        'telnet server': ('Telnet-Server', 'absent'),
        'simple tcp/ip services': ('Simple-TCPIP', 'absent'),
        'simple tcpip services': ('Simple-TCPIP', 'absent'),
        'snmp service': ('SNMP-Service', 'absent'),
        'snmp': ('SNMP-Service', 'absent'),
        'iis': ('IIS-WebServerRole', 'absent'),
        'internet information services': ('IIS-WebServerRole', 'absent'),
        'webdav': ('WebDAV', 'absent'),
        # Features that should be installed
        'windows defender': ('Windows-Defender', 'present'),
        'windows firewall': ('Windows-Firewall', 'present'),
    }
    
    for keyword, (feature_name, state) in feature_keywords.items():
        if keyword in text_lower and ('uninstall' in text_lower or 'remove' in text_lower or 'disable' in text_lower):
            return {
                'name': feature_name,
                'state': 'absent' if state == 'absent' else 'present'
            }
        elif keyword in text_lower and ('install' in text_lower or 'enable' in text_lower):
            return {
                'name': feature_name,
                'state': 'present'
            }
    
    return None


def generate_windows_feature_tasks(control: dict) -> list[str]:
    """Generate Ansible tasks for Windows feature category."""
    fix_text = control.get("fix_text", "") or ""
    check_text = control.get("check_text", "") or ""
    sv_id = control.get("sv_id", "UNKNOWN")
    vul_id = control.get("vul_id", "")
    rule_id = control.get("rule_id", "")
    title = _clean_title_for_task_name(control.get("title", ""), max_length=80)
    combined_text = f"{fix_text} {check_text}"
    
    feature_info = _extract_windows_feature(combined_text)
    
    if feature_info:
        task_name_parts = []
        if vul_id:
            task_name_parts.append(vul_id)
        task_name_parts.append(title)
        if sv_id and sv_id != "UNKNOWN":
            task_name_parts.append(f"({sv_id})")
        if rule_id:
            task_name_parts.append(f"({rule_id})")
        task_name = " - ".join(task_name_parts)
        
        return [
            f"    - name: {quote_yaml_string(task_name)}",
            "      ansible.windows.win_feature:",
            f"        name: {feature_info['name']}",
            f"        state: {feature_info['state']}",
        ]
    
    return _generate_fallback_task(control)


def _extract_windows_service(text: str) -> Optional[dict]:
    """Extract Windows service name and state from text."""
    # Pattern 1: Set-Service -Name "ServiceName" -StartupType Disabled
    match = re.search(r'Set-Service\s+(?:-Name\s+)?(?:")?([A-Za-z0-9_-]+)(?:")?\s+-StartupType\s+(\w+)', text, re.IGNORECASE)
    if match:
        service_name = match.group(1)
        startup_type = match.group(2).lower()
        return {
            'name': service_name,
            'startup_type': startup_type,
            'state': 'started' if startup_type in ['automatic', 'automaticdelayedstart'] else 'stopped'
        }
    
    # Pattern 2: Stop-Service -Name "ServiceName"
    stop_match = re.search(r'Stop-Service\s+(?:-Name\s+)?(?:")?([A-Za-z0-9_-]+)(?:")?', text, re.IGNORECASE)
    if stop_match:
        return {
            'name': stop_match.group(1),
            'state': 'stopped'
        }
    
    # Pattern 3: Prose descriptions - "disable the Fax service" or "stop the FTP service"
    text_lower = text.lower()
    service_keywords = {
        # Services to disable
        'fax': ('Fax', 'disabled'),
        'fax server': ('Fax', 'disabled'),
        'ftp': ('FTPSVC', 'disabled'),
        'ftp publishing service': ('FTPSVC', 'disabled'),
        'microsoft ftp service': ('FTPSVC', 'disabled'),
        'telnet': ('Telnet', 'disabled'),
        'telnet service': ('Telnet', 'disabled'),
        'snmp': ('SNMP', 'disabled'),
        'snmp service': ('SNMP', 'disabled'),
        'simple tcp/ip services': ('SimpTcp', 'disabled'),
        'simple tcpip services': ('SimpTcp', 'disabled'),
        'iis admin': ('IISADMIN', 'disabled'),
        'iis admin service': ('IISADMIN', 'disabled'),
        'world wide web': ('W3SVC', 'disabled'),
        'world wide web publishing service': ('W3SVC', 'disabled'),
        'webdav': ('WebDAV', 'disabled'),
        'webdav publishing': ('WebDAV', 'disabled'),
        'remote registry': ('RemoteRegistry', 'disabled'),
        'print spooler': ('Spooler', 'automatic'),  # Usually should be enabled
        'windows time': ('W32Time', 'automatic'),
        'windows update': ('wuauserv', 'automatic'),
        # Services that should be enabled
        'remote desktop': ('TermService', 'automatic'),
        'remote desktop services': ('TermService', 'automatic'),
        'windows firewall': ('MpsSvc', 'automatic'),
        'windows defender': ('WinDefend', 'automatic'),
    }
    
    for keyword, (service_name, state_or_startup) in service_keywords.items():
        if keyword in text_lower and ('disable' in text_lower or 'stop' in text_lower or 'remove' in text_lower):
            return {
                'name': service_name,
                'startup_type': 'disabled' if state_or_startup == 'disabled' else 'automatic',
                'state': 'stopped' if state_or_startup == 'disabled' else 'started'
            }
        elif keyword in text_lower and ('enable' in text_lower or 'start' in text_lower):
            return {
                'name': service_name,
                'startup_type': 'automatic',
                'state': 'started'
            }
    
    return None


def generate_windows_service_tasks(control: dict) -> list[str]:
    """Generate Ansible tasks for Windows service category."""
    fix_text = control.get("fix_text", "") or ""
    check_text = control.get("check_text", "") or ""
    sv_id = control.get("sv_id", "UNKNOWN")
    vul_id = control.get("vul_id", "")
    rule_id = control.get("rule_id", "")
    title = _clean_title_for_task_name(control.get("title", ""), max_length=80)
    combined_text = f"{fix_text} {check_text}"
    
    service_info = _extract_windows_service(combined_text)
    
    # Generate task if we have service name
    if service_info and service_info.get('name'):
        task_name_parts = []
        if vul_id:
            task_name_parts.append(vul_id)
        task_name_parts.append(title)
        if sv_id and sv_id != "UNKNOWN":
            task_name_parts.append(f"({sv_id})")
        if rule_id:
            task_name_parts.append(f"({rule_id})")
        task_name = " - ".join(task_name_parts)
        
        lines = [
            f"    - name: {quote_yaml_string(task_name)}",
            "      ansible.windows.win_service:",
            f"        name: {quote_yaml_string(service_info['name'])}",
        ]
        
        if 'startup_type' in service_info:
            lines.append(f"        startup_type: {service_info['startup_type']}")
        
        if 'state' in service_info:
            lines.append(f"        state: {service_info['state']}")
        
        return lines
    
    return _generate_fallback_task(control)


def generate_category_task(control: dict, category: str) -> list[str]:
    """
    Generate Ansible task based on category and automation_level.
    
    Args:
        control: StigControl dict
        category: Category string
        
    Returns:
        List of YAML lines for the task
    """
    automation_level = control.get("automation_level", "manual")
    
    # For automated controls: generate full Ansible tasks
    # For semi_automated: generate tasks with comments about partial validation
    # For manual: generate placeholder tasks or best-effort tasks
    
    category_map = {
        # Linux/Unix categories
        "file_permissions": generate_file_permission_tasks,
        "file_owner": generate_file_permission_tasks,  # Reuse same generator
        "package_present": generate_package_present_tasks,
        "package_absent": generate_package_absent_tasks,
        "service_enabled": generate_service_enabled_tasks,
        "service_disabled": generate_service_disabled_tasks,
        "sysctl": generate_sysctl_tasks,
        "mount_option": generate_mount_option_tasks,
        "ssh_config": generate_ssh_config_tasks,
        "grub_kernel_args": generate_grub_kernel_args_tasks,
        "dconf": generate_dconf_tasks,
        "audit": generate_audit_tasks,
        "firewalld": generate_firewalld_tasks,
        "config": generate_config_tasks,
        # Windows categories
        "windows_registry": generate_windows_registry_tasks,
        "windows_security_policy": generate_windows_security_policy_tasks,
        "windows_user_right": generate_windows_user_right_tasks,
        "windows_firewall": generate_windows_firewall_tasks,
        "windows_feature": generate_windows_feature_tasks,
        "windows_service": generate_windows_service_tasks,
        # Legacy Windows category names (for backward compatibility)
        "registry": generate_windows_registry_tasks,
    }
    
    generator = category_map.get(category)
    if generator:
        tasks = generator(control)
        
        # For manual/manual_only controls: if they generated a real module task, convert to debug-only
        # This ensures manual-only controls don't actually change the system
        if automation_level in ["manual", "manual_only"]:
            tasks_str = "\n".join(tasks).lower()
            # Check if task uses a real Windows module (not just debug)
            has_windows_module = any(module in tasks_str for module in [
                "win_regedit", "win_security_policy", "win_user_right", 
                "win_feature", "win_service", "win_firewall_rule"
            ])
            
            if has_windows_module:
                # Manual-only control generated a real module - convert to debug-only
                logger.debug(f"Converting manual-only control {control.get('sv_id', 'UNKNOWN')} from module task to debug-only")
                return _generate_fallback_task(control)
            elif "debug" in tasks_str:
                # Already debug-only, good
                pass
            elif not tasks:
                # No tasks generated, use fallback
                return _generate_fallback_task(control)
        
        return tasks
    else:
        # Default fallback
        return _generate_fallback_task(control)


def os_family_for_product(product: str) -> str:
    """
    Determine OS family from product identifier.
    
    Args:
        product: Product identifier (e.g., "rhel9", "windows2022")
        
    Returns:
        OS family string (e.g., "RedHat", "Windows")
    """
    if product.startswith("windows"):
        return "Windows"
    elif product.startswith("rhel"):
        return "RedHat"
    elif product.startswith("ubuntu"):
        return "Debian"
    elif product.startswith("cisco"):
        return "network"
    # Fallback
    return ""


def get_product_tag_from_controls(controls: list[dict], fallback: str = "rhel9") -> str:
    """
    Extract product tag from controls, with fallback.
    
    Args:
        controls: List of control dicts
        fallback: Fallback product if not found in controls
        
    Returns:
        Product tag (e.g., "rhel9", "windows2022")
    """
    if controls:
        # Try to get product from first control
        product = controls[0].get("product", "")
        if product and product != "unknown":
            return product
    
    return fallback


def format_product_name(product: str) -> str:
    """
    Format product identifier for display in playbook name.
    
    Args:
        product: Product identifier (e.g., "rhel9", "windows2022")
        
    Returns:
        Formatted product name (e.g., "RHEL 9", "Windows Server 2022")
    """
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


def generate_hardening_playbook(controls: list[dict], output_path: Path, product: str = "rhel9") -> None:
    """
    Generate Ansible hardening playbook from StigControl objects.
    
    Args:
        controls: List of StigControl dicts
        output_path: Path where playbook YAML should be written
        product: Product identifier (e.g., "rhel9") - used as fallback if not in controls
    """
    output_path.parent.mkdir(parents=True, exist_ok=True)
    
    # Extract product from controls or use fallback
    product_tag = get_product_tag_from_controls(controls, product)
    # Log for debugging
    logger.info(f"Product detection: fallback={product}, detected={product_tag}, from_controls={controls[0].get('product', 'not_set') if controls else 'no_controls'}")
    os_family = os_family_for_product(product_tag)
    product_name = format_product_name(product_tag)
    logger.info(f"Product metadata: tag={product_tag}, os_family={os_family}, name={product_name}")
    
    with open(output_path, "w") as f:
        # Write header with SCAP-based automation level counts
        f.write(f"# Generated hardening playbook for {product_tag}\n")
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
        
        # Write playbook structure - product-aware with quoted names
        play_name_quoted = quote_yaml_string(f"{product_name} STIG Hardening")
        f.write(f"- name: {play_name_quoted}\n")
        f.write("  hosts: all\n")
        f.write("  become: yes\n")
        f.write("  gather_facts: yes\n")
        f.write("  vars:\n")
        f.write("    # Place any tunable defaults here if needed later\n")
        
        # Write OS-specific pre_tasks
        if os_family == "RedHat":
            f.write("  pre_tasks:\n")
            # Extract version from product (e.g., "rhel8" -> "8", "rhel9" -> "9")
            version_match = re.search(r'(\d+)', product_tag)
            version = version_match.group(1) if version_match else "9"
            pre_task_name = quote_yaml_string(f"Verify {product_name} OS family")
            f.write(f"    - name: {pre_task_name}\n")
            f.write("      ansible.builtin.assert:\n")
            f.write("        that:\n")
            f.write(f"          - ansible_facts['os_family'] == '{os_family}'\n")
            f.write(f"          - ansible_facts['distribution_major_version'] == '{version}'\n")
            f.write(f"        fail_msg: 'This playbook is designed for {product_name} only. Detected OS: {{ {{ ansible_facts[''os_family''] }} }} {{ {{ ansible_facts[''distribution_major_version''] }} }}'\n")
            f.write(f"        success_msg: 'OS verification passed: {product_name} detected'\n")
        elif os_family == "Windows":
            f.write("  pre_tasks:\n")
            pre_task_name = quote_yaml_string(f"Verify {product_name} OS family")
            f.write(f"    - name: {pre_task_name}\n")
            f.write("      ansible.builtin.assert:\n")
            f.write("        that:\n")
            f.write(f"          - ansible_facts['os_family'] == '{os_family}'\n")
            # Windows version check - extract from product
            if "2022" in product_tag:
                f.write("          - ansible_facts['os_version'] is version('10.0.20348', '>=')\n")
            elif "2019" in product_tag:
                f.write("          - ansible_facts['os_version'] is version('10.0.17763', '>=')\n")
            f.write(f"        fail_msg: 'This playbook is designed for {product_name} only. Detected OS: {{ {{ ansible_facts[''os_family''] }} }} {{ {{ ansible_facts[''os_version''] }} }}'\n")
            f.write(f"        success_msg: 'OS verification passed: {product_name} detected'\n")
        else:
            # Generic OS check for other products
            if os_family:
                f.write("  pre_tasks:\n")
                pre_task_name = quote_yaml_string(f"Verify {product_name} OS family")
                f.write(f"    - name: {pre_task_name}\n")
                f.write("      ansible.builtin.assert:\n")
                f.write("        that:\n")
                f.write(f"          - ansible_facts['os_family'] == '{os_family}'\n")
                f.write(f"        fail_msg: 'This playbook is designed for {product_name} only. Detected OS: {{ {{ ansible_facts[''os_family''] }} }}'\n")
                f.write(f"        success_msg: 'OS verification passed: {product_name} detected'\n")
        
        f.write("\n")
        
        # Write OS-specific handlers (only Linux handlers for Linux, none for Windows)
        if os_family == "RedHat":
            f.write("  handlers:\n")
            # Regenerate grub configuration
            handler_name = quote_yaml_string("Regenerate grub configuration")
            f.write(f"    - name: {handler_name}\n")
            f.write("      ansible.builtin.command:\n")
            f.write("        cmd: grub2-mkconfig -o /boot/grub2/grub.cfg\n")
            f.write("      when: ansible_os_family == 'RedHat'\n")
            f.write("\n")
            # Restart sshd
            handler_name = quote_yaml_string("Restart sshd")
            f.write(f"    - name: {handler_name}\n")
            f.write("      ansible.builtin.service:\n")
            f.write("        name: sshd\n")
            f.write("        state: restarted\n")
            f.write("\n")
            # Reload systemd daemon
            handler_name = quote_yaml_string("Reload systemd daemon")
            f.write(f"    - name: {handler_name}\n")
            f.write("      ansible.builtin.systemd:\n")
            f.write("        daemon_reload: yes\n")
            f.write("\n")
            # Reload sysctl
            handler_name = quote_yaml_string("Reload sysctl")
            f.write(f"    - name: {handler_name}\n")
            f.write("      ansible.builtin.command:\n")
            f.write("        cmd: sysctl -p\n")
            f.write("      ignore_errors: yes\n")
            f.write("\n")
            # Reload firewalld
            handler_name = quote_yaml_string("Reload firewalld")
            f.write(f"    - name: {handler_name}\n")
            f.write("      ansible.builtin.command:\n")
            f.write("        cmd: firewall-cmd --reload\n")
            f.write("      when: ansible_facts['os_family'] == 'RedHat'\n")
            f.write("      ignore_errors: yes\n")
            f.write("\n")
            # Update dconf database
            handler_name = quote_yaml_string("Update dconf database")
            f.write(f"    - name: {handler_name}\n")
            f.write("      ansible.builtin.command:\n")
            f.write("        cmd: dconf update\n")
            f.write("      when: ansible_pkg_mgr == 'dnf' or ansible_pkg_mgr == 'yum'\n")
            f.write("\n")
        # For Windows and other OSes, handlers section is empty or minimal
        # (Windows-specific handlers can be added here in the future if needed)
        
        f.write("  tasks:\n")
        
        # Generate tasks for each control
        for control in controls:
            sv_id = control.get("sv_id", "UNKNOWN")
            category = categorize_control(control)
            control["category"] = category  # Update control with category
            
            # Generate task lines
            task_lines = generate_category_task(control, category)
            
            # Check if the generated task is actually a real enforcing task (not just debug)
            task_lines_str = "\n".join(task_lines)
            has_debug_only = (
                'ansible.builtin.debug' in task_lines_str or
                'debug:' in task_lines_str
            )
            # Check for real enforcing modules
            real_modules = [
                'ansible.builtin.file', 'ansible.builtin.lineinfile', 'ansible.builtin.sysctl',
                'ansible.builtin.systemd', 'ansible.builtin.service', 'ansible.builtin.dnf',
                'ansible.builtin.yum', 'ansible.builtin.command', 'ansible.builtin.shell',
                'ansible.builtin.copy', 'ansible.builtin.template', 'ansible.builtin.blockinfile',
                'ansible.windows.win_regedit', 'ansible.windows.win_security_policy',
                'ansible.windows.win_user_right', 'ansible.windows.win_audit_policy',
                'ansible.posix.firewalld', 'ansible.builtin.mount'
            ]
            has_real_module = any(module in task_lines_str for module in real_modules)
            
            # Add tags and comments based on automation_level
            severity = control.get("severity", "medium")
            automation_level = control.get("automation_level", "manual")
            
            # Normalize automation_level
            # New values: "automated", "manual_only", "unknown"
            # Legacy: "scannable_with_nessus", "not_scannable_with_nessus", "automatable", "semi_automatable", "manual"
            if automation_level in ["automatable", "scannable_with_nessus"]:
                automation_level = "automated"  # Treat as automated for tagging
            elif automation_level == "semi_automatable":
                automation_level = "manual_only"  # OCIL is not fully automated
            elif automation_level in ["manual", "not_scannable_with_nessus"]:
                automation_level = "manual_only"
            elif automation_level == "unknown":
                automation_level = "unknown"
            
            # If tagged as automated but only has debug task, downgrade to manual_only
            if automation_level == "automated" and has_debug_only and not has_real_module:
                automation_level = "manual_only"
                logger.debug(f"Downgraded {sv_id} from automated to manual_only (only debug task generated)")
            
            # If tagged as manual_only but has a real Windows module, convert to debug-only
            if automation_level in ["manual", "manual_only"] and has_real_module:
                logger.debug(f"Converting manual-only control {sv_id} from module task to debug-only")
                # Replace the task with a debug-only fallback
                task_lines = _generate_fallback_task(control)
                has_real_module = False
                has_debug_only = True
            
            # Add automation level comment
            automation_source = control.get("automation_source", "none")
            if automation_level == "automated":
                # Insert comment before task
                comment_idx = 0
                for i, line in enumerate(task_lines):
                    if line.strip().startswith("- name:"):
                        comment_idx = i
                        break
                if automation_source == "scap":
                    task_lines.insert(comment_idx, f"    # STIG ID: {sv_id} | Automation: automated via SCAP")
                elif automation_source == "nessus":
                    task_lines.insert(comment_idx, f"    # STIG ID: {sv_id} | Automation: automated via Nessus")
                else:
                    task_lines.insert(comment_idx, f"    # STIG ID: {sv_id} | Automation: automated")
            elif automation_level == "manual_only":
                # Insert comment before task
                comment_idx = 0
                for i, line in enumerate(task_lines):
                    if line.strip().startswith("- name:"):
                        comment_idx = i
                        break
                if automation_source in ["scap", "nessus"]:
                    task_lines.insert(comment_idx, f"    # STIG ID: {sv_id} | Automation: manual-only (not covered by {automation_source})")
                else:
                    task_lines.insert(comment_idx, f"    # STIG ID: {sv_id} | Automation: manual-only")
            
            # Ensure tags are added to all tasks (handle multi-task scenarios)
            # Also replace any existing product tags with the correct one
            task_lines_str = "\n".join(task_lines)
            
            # Replace any existing product tags (rhel8, rhel9, windows2022, etc.) with the correct one
            # This ensures tasks generated by category functions get the right tag
            for i, line in enumerate(task_lines):
                # Replace any product tag with the correct one
                if "        - rhel8" in line or "        - rhel9" in line or "        - windows" in line or "        - windows11" in line or "        - windows2022" in line:
                    # Find the product tag line and replace it
                    task_lines[i] = f"        - {product_tag}"
            
            if "tags:" not in task_lines_str:
                # Find the last task in the list (in case of multiple tasks)
                last_task_idx = len(task_lines) - 1
                for i in range(len(task_lines) - 1, -1, -1):
                    if task_lines[i].strip().startswith("- name:"):
                        last_task_idx = i
                        break
                
                # Find where to insert tags (after the module/action, before next task)
                insert_idx = last_task_idx + 1
                for i in range(last_task_idx + 1, len(task_lines)):
                    if task_lines[i].strip().startswith("- name:"):
                        insert_idx = i
                        break
                    if task_lines[i].strip() and not task_lines[i].strip().startswith(" ") and not task_lines[i].strip().startswith("#"):
                        insert_idx = i
                        break
                
                # Insert tags with product tag
                task_lines.insert(insert_idx, "      tags:")
                task_lines.insert(insert_idx + 1, "        - stig")
                task_lines.insert(insert_idx + 2, f"        - {sv_id}")
                task_lines.insert(insert_idx + 3, f"        - {category}")
                task_lines.insert(insert_idx + 4, f"        - severity_{severity}")
                task_lines.insert(insert_idx + 5, f"        - automation_{automation_level}")
                task_lines.insert(insert_idx + 6, f"        - {product_tag}")
            
            # Write task - ensure all task names are quoted
            f.write("\n")
            for line in task_lines:
                # Remove any trailing newline first
                line = line.rstrip()
                
                # Post-process: if this is a task name line and it's not quoted, quote it
                stripped = line.strip()
                if stripped.startswith("- name:"):
                    # Check if already quoted (has quotes at start of value)
                    if "name:" in line:
                        line_after_name = line.split("name:", 1)[1].strip()
                        # Check if it starts and ends with quotes
                        is_quoted = (line_after_name.startswith('"') and line_after_name.endswith('"')) or \
                                    (line_after_name.startswith("'") and line_after_name.endswith("'"))
                    else:
                        is_quoted = False
                        line_after_name = ""
                    
                    if not is_quoted:
                        # Extract the name value and quote it
                        name_match = re.match(r'(\s*-\s+name:\s+)(.+)$', line)
                        if name_match:
                            indent = name_match.group(1)
                            name_value = name_match.group(2).strip()
                            # Clean the name value (remove |, replace with -)
                            name_value = name_value.replace("|", "-")
                            # Remove trailing ellipses
                            name_value = name_value.rstrip("...").rstrip(".")
                            # Quote it
                            quoted_name = quote_yaml_string(name_value)
                            line = f"{indent}{quoted_name}"
                        else:
                            # Fallback: just quote the whole thing after name:
                            if "name:" in line:
                                parts = line.split("name:", 1)
                                indent_and_name = parts[0] + "name:"
                                name_value = parts[1].strip()
                                name_value = name_value.replace("|", "-").rstrip("...").rstrip(".")
                                quoted_name = quote_yaml_string(name_value)
                                line = f"{indent_and_name} {quoted_name}"
                
                # Write the line with newline
                f.write(f"{line}\n")
            f.write("\n")
    
    logger.info(f"Generated hardening playbook with {len(controls)} tasks")


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
    """Main entry point for the hardening generator script."""
    parser = argparse.ArgumentParser(
        description="Generate Ansible hardening playbook from StigControl JSON"
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
        
        # Generate hardening playbook
        generate_hardening_playbook(controls, args.output, args.product)
        
        # Verify coverage if requested
        if args.verify_coverage:
            if not verify_coverage(controls, args.output):
                logger.error("Coverage verification failed")
                return 1
        
        logger.info("✓ Hardening playbook generation complete!")
        
    except FileNotFoundError as e:
        logger.error(f"File not found: {e}")
        return 1
    except Exception as e:
        logger.error(f"Error: {e}", exc_info=True)
        return 1
    
    return 0


if __name__ == "__main__":
    exit(main())


