"""Classify STIG controls as scannable with Nessus vs not scannable."""

from ..model.controls import StigControl


def classify_control(control: StigControl) -> StigControl:
    """
    Classify a STIG control as scannable with Nessus or not scannable and assign a category.

    Rules of thumb:
    - Scannable with Nessus if:
      * Has check commands (check_text contains executable commands that Nessus can run)
      * Refers to file permissions, ownership, modes
      * Service enabled/disabled
      * Sysctl settings
      * Packages installed
      * Auditd rules
      * Configuration file settings
      * Any control with a check command that can be automated

    - Not Scannable with Nessus if:
      * GUI-only configuration (no CLI check possible)
      * Policy or process reviews (subjective)
      * Screenshots of settings (visual only)
      * Interviews or subjective analysis
      * No check commands available

    - When in doubt, default to scannable (is_automatable = True) if check commands exist
    - Target: 70-80% of controls should be scannable

    Args:
        control: The STIG control to classify

    Returns:
        The same control object with is_automatable (True = Scannable with Nessus) and category set
    """
    check_lower = control.check_text.lower()
    fix_lower = control.fix_text.lower()
    combined_text = f"{check_lower} {fix_lower}"
    
    # Check if we have extractable commands
    has_cli_commands = len(control.candidate_cli_blocks) > 0
    has_shell_commands = len(control.candidate_shell_blocks) > 0
    has_check_commands = len(control.candidate_check_blocks) > 0
    has_extractable_commands = has_cli_commands or has_shell_commands
    
    # Key insight: If we have check commands, Nessus can scan it
    # This is the primary indicator for scannability
    has_real_commands = control.has_real_commands()
    
    # More permissive: If check commands exist, it's likely scannable
    # Even if they're not "perfect", Nessus can often still scan them

    # File permission indicators
    file_permission_keywords = [
        "chmod",
        "chown",
        "permission",
        "mode",
        "ownership",
        "umask",
        "file mode",
        "directory mode",
        "octal mode",
        "/etc/passwd",
        "/etc/shadow",
        "/etc/gshadow",
        "/etc/group",
    ]

    # Service indicators
    service_keywords = [
        "systemctl",
        "service",
        "enabled",
        "disabled",
        "masked",
        "active",
        "inactive",
        "chkconfig",
    ]

    # Sysctl indicators
    sysctl_keywords = [
        "sysctl",
        "/proc/sys/",
        "kernel parameter",
        "net.ipv4",
        "net.ipv6",
        "fs.protected",
    ]

    # Package indicators
    package_keywords = [
        "yum install",
        "dnf install",
        "rpm",
        "package",
        "remove",
        "uninstall",
        "installed",
    ]

    # Audit indicators
    audit_keywords = [
        "auditd",
        "auditctl",
        "audit rule",
        "/etc/audit/",
        "audit.rules",
        "ausearch",
        "aureport",
    ]

    # Config file indicators
    config_keywords = [
        "/etc/",
        "configuration file",
        "config file",
        "grep",
        "sed",
        "awk",
        "lineinfile",
        "replace",
        "set",
        "parameter",
    ]

    # Network device indicators (Cisco IOS, etc.)
    network_keywords = [
        "interface",
        "vlan",
        "access-list",
        "ip address",
        "switchport",
        "spanning-tree",
        "vtp",
        "qos",
        "mls",
        "cisco",
        "ios",
        "show running-config",
        "configure terminal",
        "config t",
    ]

    # Manual/GUI indicators
    manual_keywords = [
        "screenshot",
        "gui",
        "graphical",
        "interview",
        "review policy",
        "review process",
        "review the",
        "verify that",
        "verify the",
        "subjective",
        "visual inspection",
        "manual review",
        "documentation review",
        "show running-config",
        "show vtp",
        "show spanning-tree",
    ]

    # Check for truly manual indicators first (higher priority)
    # These are things Nessus definitely cannot scan
    truly_manual_keywords = [
        "screenshot",
        "gui",
        "graphical",
        "interview",
        "subjective",
        "visual inspection",
        "manual review",
        "documentation review",
        "upgrade to",  # OS upgrades require manual intervention
        "document the",  # Documentation requirements
        "configure the operating system to implement",  # Complex multi-step configs
        "disk encryption",  # Complex setup that requires manual verification
    ]
    
    # Also check for manual indicators in check_text specifically
    # These suggest the check requires human judgment or manual review
    manual_check_indicators = [
        "review the",
        "verify that",
        "verify the",
        "check that",
        "inspect",
        "examine",
        "document",
        "interview",
        "upgrade to",  # OS upgrades
        "configure the operating system to implement",  # Complex multi-step
        "disk encryption",  # Complex setup
        "document the",  # Documentation requirements
        "potential command",  # Uncertain commands
        "not recognized",  # Commands that aren't recognized
    ]
    
    # If check_text has manual indicators, it's likely not scannable
    has_manual_check = any(indicator in check_lower for indicator in manual_check_indicators)
    
    # Also check if fix_text suggests complex manual configuration
    complex_manual_indicators = [
        "upgrade to",
        "configure the operating system to implement",
        "disk encryption",
        "document the",
        "following the steps below",
        "with the following command:",  # Often followed by complex multi-step process
    ]
    has_complex_fix = any(indicator in fix_lower for indicator in complex_manual_indicators)
    
    if any(keyword in combined_text for keyword in truly_manual_keywords) or has_manual_check or has_complex_fix:
        # Mark as not scannable if it's truly GUI-only, subjective, requires manual review, or complex setup
        # Even if it has check commands, if the check requires manual review or complex setup, it's not scannable
        control.is_automatable = False
        control.category = "other"
        control.check_commands = control.candidate_check_blocks
        if control.candidate_shell_blocks or control.candidate_cli_blocks:
            control.manual_notes = (control.candidate_shell_blocks or control.candidate_cli_blocks)[:5]
        return control

    # Check for file permissions
    if any(keyword in combined_text for keyword in file_permission_keywords):
        # If it has check commands, it's scannable (even if commands aren't perfect)
        if has_check_commands or (has_extractable_commands and has_real_commands):
            control.is_automatable = True
            control.category = "file_permission"
            control.automatable_commands = control.candidate_shell_blocks or control.candidate_cli_blocks
            control.check_commands = control.candidate_check_blocks
            return control
        else:
            # Has keywords but no check commands - mark as not scannable
            control.is_automatable = False
            control.category = "other"
            control.check_commands = control.candidate_check_blocks
            if control.candidate_shell_blocks or control.candidate_cli_blocks:
                control.manual_notes = (control.candidate_shell_blocks or control.candidate_cli_blocks)[:5]
            return control

    # Check for services
    if any(keyword in combined_text for keyword in service_keywords):
        # If it has check commands, it's scannable
        if has_check_commands or (has_extractable_commands and has_real_commands):
            control.is_automatable = True
            control.category = "service"
            control.automatable_commands = control.candidate_shell_blocks or control.candidate_cli_blocks
            control.check_commands = control.candidate_check_blocks
            return control

    # Check for sysctl
    if any(keyword in combined_text for keyword in sysctl_keywords):
        # If it has check commands, it's scannable
        if has_check_commands or (has_extractable_commands and has_real_commands):
            control.is_automatable = True
            control.category = "sysctl"
            control.automatable_commands = control.candidate_shell_blocks or control.candidate_cli_blocks
            control.check_commands = control.candidate_check_blocks
            return control

    # Check for packages
    if any(keyword in combined_text for keyword in package_keywords):
        # If it has check commands, it's scannable
        if has_check_commands or (has_extractable_commands and has_real_commands):
            control.is_automatable = True
            control.category = "package"
            control.automatable_commands = control.candidate_shell_blocks or control.candidate_cli_blocks
            control.check_commands = control.candidate_check_blocks
            return control

    # Check for audit
    if any(keyword in combined_text for keyword in audit_keywords):
        # If it has check commands, it's scannable
        if has_check_commands or (has_extractable_commands and has_real_commands):
            control.is_automatable = True
            control.category = "audit"
            control.automatable_commands = control.candidate_shell_blocks or control.candidate_cli_blocks
            control.check_commands = control.candidate_check_blocks
            return control

    # Check for network device configuration (for network STIGs)
    if control.os_family == "network":
        # Network device checks that say "Review" or "Verify" are typically manual
        if any(keyword in check_lower for keyword in ["review the", "verify that", "verify the"]):
            control.is_automatable = False
            control.category = "other"
            control.check_commands = control.candidate_check_blocks
            return control
        # Network device fixes with clear IOS commands are automatable
        if has_cli_commands:
            control.is_automatable = True
            control.category = "config"
            control.automatable_commands = control.candidate_cli_blocks
            control.check_commands = control.candidate_check_blocks
            return control
        # Default network controls to manual (they require show commands for verification)
        control.is_automatable = False
        control.category = "other"
        control.check_commands = control.candidate_check_blocks
        return control

    # Check for config files
    if any(keyword in combined_text for keyword in config_keywords):
        # If it has check commands, it's scannable
        if has_check_commands or (has_extractable_commands and has_real_commands):
            control.is_automatable = True
            control.category = "config"
            control.automatable_commands = control.candidate_shell_blocks or control.candidate_cli_blocks
            control.check_commands = control.candidate_check_blocks
            return control

    # Default: Be more selective about what's scannable
    # Not everything with check commands is automatically scannable
    # Check commands must be executable and verifiable by Nessus
    
    # If we have check commands AND they're real commands (not just prose), mark as scannable
    if has_check_commands and has_real_commands:
        # But check if the check_text suggests manual review is needed
        if not has_manual_check:
            control.is_automatable = True
            control.category = "config"  # Default category for generic config checks
            control.check_commands = control.candidate_check_blocks
            control.automatable_commands = control.candidate_shell_blocks or control.candidate_cli_blocks
            return control
    
    # If we have extractable commands but they're not real commands, or if check requires manual review
    # Mark as not scannable
    control.is_automatable = False
    control.category = "other"
    control.check_commands = control.candidate_check_blocks
    # Store any extracted commands as manual_notes for CTP
    if control.candidate_shell_blocks or control.candidate_cli_blocks:
        control.manual_notes = (control.candidate_shell_blocks or control.candidate_cli_blocks)[:5]
    return control


def classify_controls(controls: list[StigControl]) -> list[StigControl]:
    """
    Classify a list of STIG controls.

    Args:
        controls: List of StigControl objects to classify

    Returns:
        List of classified StigControl objects (same objects, modified in place)
    """
    for control in controls:
        classify_control(control)
    return controls


