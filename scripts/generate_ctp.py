"""Generate CTP (Certification Test Procedure) CSV from StigControl JSON.

This script:
1. Reads StigControl objects from JSON
2. Generates CTP CSV with proper headers and format
3. Ensures 100% coverage of all STIG IDs

Usage:
    python scripts/generate_ctp.py --input data/rhel9_stig_controls.json --output stig_rhel9_ctp.csv
"""

import argparse
import csv
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
    split_command_and_prose,
)

logging.basicConfig(level=logging.INFO, format="%(levelname)s: %(message)s")
logger = logging.getLogger(__name__)


def load_controls_from_json(json_path: Path) -> list[dict]:
    """Load StigControl objects from JSON file."""
    with open(json_path, "r", encoding="utf-8") as f:
        controls = json.load(f)
    logger.info(f"Loaded {len(controls)} controls from {json_path}")
    return controls


def format_nist_control_id(nist_id: Optional[str]) -> str:
    """
    Format NIST control ID to AU.02, IA.5 format (not AU-2 or CCI-000048).
    
    Args:
        nist_id: NIST control ID in various formats
        
    Returns:
        Formatted NIST control ID or "N/A" if not available
    """
    if not nist_id:
        return "N/A"
    
    # Skip CCI IDs - they are not NIST control IDs
    if nist_id.startswith("CCI-"):
        return "N/A"
    
    # Skip OS-000023 format - not a NIST control ID
    if nist_id.startswith("OS-"):
        return "N/A"
    
    # Already in correct format (AU.02, AU.02.b, CM.06.1(iv))
    if re.match(r'^[A-Z]{2}\.\d{2}(?:\.[a-z]|\([^)]+\)|\.\d+)*$', nist_id):
        return nist_id
    
    # Convert AU-2 format to AU.02
    match = re.match(r'^([A-Z]{2})-(\d+)(.*)$', nist_id)
    if match:
        family = match.group(1)
        control_num = match.group(2).zfill(2)  # Ensure 2 digits
        suffix = match.group(3)  # Keep enhancements like (3)(a)
        return f"{family}.{control_num}{suffix}"
    
    # Return as-is if we can't parse it
    return nist_id


def _clean_command(cmd: str) -> str:
    """Clean command by removing prose, backticks, and normalizing."""
    cmd_part, _ = split_command_and_prose(cmd)
    if cmd_part:
        cleaned = normalize_command_line(cmd_part)
    else:
        cleaned = normalize_command_line(cmd)
    
    # Remove backticks
    cleaned = cleaned.replace('`', '')
    
    # Fix incomplete commands (e.g., "grep -" without pattern)
    if cleaned.strip().endswith('-') and len(cleaned.strip()) < 10:
        # Skip incomplete commands
        return None
    
    # Fix placeholder paths
    if '/path/to/file' in cleaned or '/path/to/' in cleaned:
        # Try to extract actual path from context or mark as manual
        return None
    
    return cleaned.strip()


def _extract_expected_result(check_text: str, command: str) -> str:
    """Extract expected result from check_text based on command context.
    
    Returns clean, auditor-friendly language without policy boilerplate.
    Aggressively extracts actual expected values from STIG check text.
    """
    # Handle None values
    if check_text is None:
        check_text = ""
    if command is None:
        command = ""
    
    # Clean up check_text - remove common prefixes
    text = check_text or ""
    
    # PRIORITY 1: Extract actual sysctl output values (e.g., "kernel.dmesg_restrict = 1")
    # Look for patterns like: "kernel.dmesg_restrict = 1" or "net.ipv4.tcp_syncookies = 1"
    sysctl_pattern = r'([a-z0-9_.]+)\s*=\s*([0-9]+)'
    sysctl_matches = re.findall(sysctl_pattern, text, re.IGNORECASE)
    for param, value in sysctl_matches:
        # Only use if it's a real sysctl parameter (contains dots or underscores)
        if '.' in param or '_' in param:
            # Check if this matches the command being run
            if command and param in command:
                return f"Output should show: {param} = {value}"
            # Or if it's mentioned near the command context
            if not command or param in text[:500]:  # Check first part of text
                return f"Output should show: {param} = {value}"
    
    # PRIORITY 2: Extract configuration file key=value pairs (e.g., "ProcessSizeMax=0", "Storage=none")
    # Look for patterns on their own line, not in command examples
    config_line_pattern = r'^([A-Za-z0-9_]+)\s*=\s*([^\s\n]{1,50})$'
    config_matches = re.findall(config_line_pattern, text, re.MULTILINE | re.IGNORECASE)
    for key, value in config_matches:
        # Skip if it's a placeholder or incomplete
        if value in ['{}', '$(stat', '$(firewall-cmd', '<accountname>', '<SAN>']:
            continue
        # Skip if it's part of a command example (has $ before it)
        key_pos = text.find(f"{key} = {value}")
        if key_pos > 0 and text[max(0, key_pos-20):key_pos].strip().endswith('$'):
            continue
        if len(key) > 2 and len(value) > 0 and len(value) < 50:
            # Check if this key is mentioned in the command
            if command and key.lower() in command.lower():
                return f"{key} should equal: {value}"
            # Or if it's a common config key
            if key in ['ProcessSizeMax', 'Storage', 'space_left_action', 'ExecStart', 'certificate_verification', 'matchrule']:
                return f"{key} should equal: {value}"
    
    # PRIORITY 3: Extract "If X is not set to Y" patterns
    not_set_pattern = r'["\']?([A-Za-z0-9_.]+)["\']?\s+is\s+not\s+set\s+to\s+["\']([^"\']{1,50})["\']'
    match = re.search(not_set_pattern, text, re.IGNORECASE)
    if match:
        key = match.group(1)
        expected_value = match.group(2)
        if expected_value not in ['{}', '$(stat', '$(firewall-cmd']:
            return f"{key} should equal: {expected_value}"
    
    # PRIORITY 4: Extract "If X does not have a value of Y" patterns
    value_pattern = r'["\']?([A-Za-z0-9_.]+)["\']?\s+does\s+not\s+have\s+a\s+value\s+of\s+["\']([^"\']{1,50})["\']'
    match = re.search(value_pattern, text, re.IGNORECASE)
    if match:
        key = match.group(1)
        expected_value = match.group(2)
        if expected_value not in ['{}', '$(stat', '$(firewall-cmd']:
            return f"{key} should equal: {expected_value}"
    
    # PRIORITY 5: Extract "If X is missing or commented out, or the value is anything other than Y"
    other_than_pattern = r'["\']?([A-Za-z0-9_.]+)["\']?.*?value\s+is\s+anything\s+other\s+than\s+["\']([^"\']{1,50})["\']'
    match = re.search(other_than_pattern, text, re.IGNORECASE)
    if match:
        key = match.group(1)
        expected_value = match.group(2)
        if expected_value not in ['{}', '$(stat', '$(firewall-cmd']:
            return f"{key} should equal: {expected_value}"
    
    # PRIORITY 6: Look for example outputs that show actual values (not commands)
    # Pattern: Look for lines that show parameter = value after a command example
    # Example: "$ sudo sysctl kernel.dmesg_restrict\n\nkernel.dmesg_restrict = 1"
    example_output_pattern = r'\$\s*(?:sudo\s+)?[^\n]+\n\n([a-z0-9_.]+)\s*=\s*([0-9]+)'
    match = re.search(example_output_pattern, text, re.IGNORECASE | re.MULTILINE)
    if match:
        param = match.group(1)
        value = match.group(2)
        if command and param in command:
            return f"Output should show: {param} = {value}"
    
    # PRIORITY 7: Look for configuration file examples (not commands)
    # Pattern: "ProcessSizeMax=0" on its own line (not in a command)
    config_example_pattern = r'\n([A-Za-z0-9_]+)\s*=\s*([^\s\n]{1,50})\n'
    matches = re.findall(config_example_pattern, text, re.MULTILINE)
    for key, value in matches:
        if value not in ['{}', '$(stat', '$(firewall-cmd', '<accountname>'] and len(value) < 50:
            if command and key.lower() in command.lower():
                return f"{key} should equal: {value}"
    
    # PRIORITY 8: Look for "The following condition must NOT be true" pattern
    not_true_pattern = r'the\s+following\s+condition\s+must\s+not\s+be\s+true:\s+([^\.]{10,120})'
    match = re.search(not_true_pattern, text, re.IGNORECASE)
    if match:
        condition = match.group(1).strip()
        if len(condition) > 5 and len(condition) < 150:
            return f"The following condition should NOT be true: {condition}."
    
    # PRIORITY 9: Look for "if" statements that describe what should NOT be true
    # Pattern: "if X, this is a finding" -> "X should NOT be true"
    if_pattern = r'if\s+([^,\.]{15,120})(?:,\s+this\s+is\s+a\s+finding|\.\s+If\s+it\s+is\s+true)'
    match = re.search(if_pattern, text, re.IGNORECASE)
    if match:
        condition = match.group(1).strip()
        # Clean up condition
        condition = re.sub(r'^the\s+', '', condition, flags=re.IGNORECASE)
        condition = re.sub(r'^that\s+', '', condition, flags=re.IGNORECASE)
        # Remove trailing "is not" or "does not" if present
        condition = re.sub(r'\s+(?:is|does)\s+not\s+.*$', '', condition, flags=re.IGNORECASE)
        if len(condition) > 10 and len(condition) < 150:
            return f"The following condition should NOT be true: {condition}."
    
    # PRIORITY 10: Look for "must" statements - extract the actual requirement
    # Pattern: "must be X" or "must display X" -> "Should be X" or "Should display X"
    must_patterns = [
        (r'must\s+be\s+["\']?([^"\'\n\.]{10,100})["\']?', 'be'),
        (r'must\s+display\s+["\']?([^"\'\n\.]{10,100})["\']?', 'display'),
        (r'must\s+show\s+["\']?([^"\'\n\.]{10,100})["\']?', 'show'),
        (r'must\s+indicate\s+["\']?([^"\'\n\.]{10,100})["\']?', 'indicate'),
        (r'must\s+have\s+["\']?([^"\'\n\.]{10,100})["\']?', 'have'),
        (r'must\s+equal\s+["\']?([^"\'\n\.]{10,100})["\']?', 'equal'),
        (r'must\s+contain\s+["\']?([^"\'\n\.]{10,100})["\']?', 'contain'),
        # Pattern: "must: X" (with colon)
        (r'must:\s+([^\.]{10,100})', 'be'),
        # Pattern: "must X" (direct, no verb)
        (r'must\s+([^\.]{10,100})(?:\.\s+If|\.\s*$)', 'be'),
    ]
    for pattern, verb in must_patterns:
        match = re.search(pattern, text, re.IGNORECASE)
        if match:
            value = match.group(1).strip()
            # Remove trailing "If it does not, this is a finding" if present
            value = re.sub(r'\s*\.\s*If\s+it\s+does\s+not.*$', '', value, flags=re.IGNORECASE)
            value = re.sub(r'\s*\.\s*If\s+it\s+is\s+not.*$', '', value, flags=re.IGNORECASE)
            # Remove trailing "If it is true" if present
            value = re.sub(r'\s*\.\s*If\s+it\s+is\s+true.*$', '', value, flags=re.IGNORECASE)
            if len(value) > 5 and len(value) < 120:
                if verb == 'be':
                    return f"Should be: {value}"
                else:
                    return f"Should {verb}: {value}"
    
    # 6. Look for file content requirements (e.g., banner text, specific strings)
    # Pattern: "file should contain X" or "output should include X"
    content_patterns = [
        r'file\s+should\s+contain\s+["\']([^"\']{10,150})["\']',
        r'output\s+should\s+include\s+["\']([^"\']{10,150})["\']',
        r'should\s+display\s+["\']([^"\']{10,150})["\']',
    ]
    for pattern in content_patterns:
        match = re.search(pattern, text, re.IGNORECASE)
        if match:
            content = match.group(1).strip()
            if len(content) > 10 and len(content) < 200:
                return f"Output should contain: {content[:100]}..." if len(content) > 100 else f"Output should contain: {content}"
    
    # 7. Look for "should" statements
    should_pattern = r'should\s+(?:be|display|show|indicate)\s+["\']?([^"\'\n\.]{10,100})["\']?'
    match = re.search(should_pattern, text, re.IGNORECASE)
    if match:
        value = match.group(1).strip()
        if len(value) > 5 and len(value) < 120:
            return f"Should be: {value}"
    
    # 8. Look for specific value requirements (e.g., "ENCRYPT_METHOD" does not equal SHA512)
    value_pattern = r'["\']?([A-Z_][A-Z0-9_]+)["\']?\s+(?:does\s+not\s+equal|must\s+equal|should\s+equal)\s+["\']?([^"\'\n\.]{5,50})["\']?'
    match = re.search(value_pattern, text, re.IGNORECASE)
    if match:
        key = match.group(1)
        expected = match.group(2)
        return f"{key} should equal {expected}"
    
    # 9. Look for file permission patterns
    perm_pattern = r'value\s+of\s+["\']?(\d{3,4})["\']?\s+or\s+less\s+permissive'
    match = re.search(perm_pattern, text, re.IGNORECASE)
    if match:
        mode = match.group(1)
        return f"File permissions should be {mode} or more restrictive"
    


def _extract_screen_output(check_text: str) -> str:
    """Extract expected screen output from check_text.
    
    Returns actual example output, not just pattern names.
    """
    # Look for example outputs with actual content
    output_patterns = [
        r'output\s+should\s+show[:\s]+([^\n]{20,150})',
        r'expected\s+output[:\s]+([^\n]{20,150})',
        r'you\s+should\s+see[:\s]+([^\n]{20,150})',
        r'example[:\s]+([^\n]{20,150})',
        r'configuration[:\s]+([^\n]{20,150})',
    ]
    
    for pattern in output_patterns:
        match = re.search(pattern, check_text, re.IGNORECASE)
        if match:
            output = match.group(1).strip()
            # Skip if it's just a pattern name like "-iH" or "-r"
            if not re.match(r'^[-][a-zA-Z]+$', output) and len(output) < 200:
                # Remove policy language
                output = re.sub(r'\.\s*If\s+it\s+does\s+not.*$', '', output, flags=re.IGNORECASE)
                return output
    
    # Look for actual configuration examples
    config_pattern = r'Configuration[:\s]+([^\n]{10,100})'
    match = re.search(config_pattern, check_text, re.IGNORECASE)
    if match:
        config = match.group(1).strip()
        if len(config) < 150:
            return config
    
    # Look for file location examples
    file_pattern = r'File\s+location[:\s]+([^\n]{10,100})'
    match = re.search(file_pattern, check_text, re.IGNORECASE)
    if match:
        file_path = match.group(1).strip()
        if len(file_path) < 150:
            return f"File location: {file_path}"
    
    # Default: generic description
    return "Review the command output and verify it matches the expected result."


def generate_ctp_rows_for_control(control: dict) -> list[list[str]]:
    """
    Generate CTP rows for a single control.
    
    Args:
        control: StigControl dict
        
    Returns:
        List of rows, where each row is a list of strings for CSV columns
    """
    rows = []
    
    sv_id = control.get("sv_id", "UNKNOWN")
    nist_id = format_nist_control_id(control.get("nist_id"))
    severity = control.get("severity", "medium").upper()
    check_text = control.get("check_text") or ""
    if check_text is None:
        check_text = ""
    # Use os_family if available, otherwise fall back to product
    os_family = control.get("os_family") or control.get("product", "rhel")
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
    
    # Extract check commands using existing extractor
    check_commands, _ = extract_check_commands_from_block(check_text, os_family)
    
    # Filter for real commands and clean them
    valid_commands = []
    for cmd in check_commands:
        if is_probable_cli_command(cmd):
            cmd_clean = _clean_command(cmd)
            if cmd_clean and len(cmd_clean) > 5:  # Skip very short/incomplete commands
                # Remove prompts (e.g., "Switch#", "SW1(config)#")
                cmd_clean = re.sub(r'^[A-Z0-9]+(?:\([^)]+\))?#\s*', '', cmd_clean, flags=re.IGNORECASE)
                cmd_clean = re.sub(r'^[A-Z0-9]+#\s*', '', cmd_clean, flags=re.IGNORECASE)
                # Ensure no backticks remain
                cmd_clean = cmd_clean.replace('`', '').strip()
                # For network devices, only show commands should be in CTP
                if os_family == "network" and not cmd_clean.lower().startswith('show '):
                    # Skip config commands for network CTP
                    continue
                if cmd_clean:
                    valid_commands.append(cmd_clean)
    
    # Generate 1-3 steps per control
    # Adjust language based on automation_level
    if valid_commands:
        for step_num, cmd in enumerate(valid_commands[:3], start=1):
            expected = _extract_expected_result(check_text, cmd)
            screen_output = _extract_screen_output(check_text)
            
            # Ensure expected is never None
            if expected is None or not isinstance(expected, str):
                expected = "Review the command output and verify it meets the STIG requirements."
            
            # Build notes based on automation level
            notes_parts = []
            if nist_id != "N/A":
                notes_parts.append(f"NIST: {nist_id}")
            if automation_level_normalized == "automated":
                if automation_source == "scap":
                    notes_parts.append("SCAP/OVAL automated check available - scanners should cover this")
                elif automation_source == "nessus":
                    notes_parts.append("Nessus automated check available - scanners should cover this")
                else:
                    notes_parts.append("Automated check available - scanners should cover this")
            elif automation_level_normalized == "manual_only":
                if automation_source in ["scap", "nessus"]:
                    notes_parts.append("Manual verification required - not covered by automated scanners")
                else:
                    notes_parts.append("Manual verification required")
            notes = "; ".join(notes_parts) if notes_parts else ""
            
            # Adjust action command based on automation level
            # For network devices, format as "Connect to the network device and run:"
            if os_family == "network":
                if automation_level_normalized == "automated":
                    if automation_source == "scap":
                        action = f"Connect to the network device and run: `{cmd}` (or use SCAP scan for automated validation)"
                    elif automation_source == "nessus":
                        action = f"Connect to the network device and run: `{cmd}` (or use Nessus scan for automated validation)"
                    else:
                        action = f"Connect to the network device and run: `{cmd}` (automated validation available)"
                else:
                    # Manual-only - primary verification step
                    action = f"Connect to the network device and run: `{cmd}`"
            else:
                if automation_level_normalized == "automated":
                    # Can reference automated scan
                    if automation_source == "scap":
                        action = f"Run: {cmd} (or use SCAP scan for automated validation)"
                    elif automation_source == "nessus":
                        action = f"Run: {cmd} (or use Nessus scan for automated validation)"
                    else:
                        action = f"Run: {cmd} (automated validation available)"
                else:
                    # Manual-only - primary verification step
                    action = f"Run: {cmd}"
            
            # Clean up expected result - remove any remaining policy language
            # Ensure expected is a string before regex operations
            if expected is None or not isinstance(expected, str):
                expected = "Review the command output and verify it meets the STIG requirements."
            
            # Remove "Must:" prefix
            expected = re.sub(r'^Must:\s*', '', expected, flags=re.IGNORECASE)
            # Remove trailing policy boilerplate
            expected = re.sub(r'\.\s*If\s+it\s+does\s+not.*$', '', expected, flags=re.IGNORECASE)
            expected = re.sub(r'\.\s*If\s+it\s+is\s+true.*$', '', expected, flags=re.IGNORECASE)
            expected = re.sub(r'\.\s*If\s+it\s+is\s+not.*$', '', expected, flags=re.IGNORECASE)
            expected = re.sub(r'\.\s*If\s+it\s+does\s+not,\s+this\s+is\s+a\s+finding.*$', '', expected, flags=re.IGNORECASE)
            expected = re.sub(r'\.\s*If\s+it\s+is\s+true,\s+this\s+is\s+a\s+finding.*$', '', expected, flags=re.IGNORECASE)
            expected = re.sub(r'\.\s*If\s+it\s+is\s+not,\s+this\s+is\s+a\s+finding.*$', '', expected, flags=re.IGNORECASE)
            # Remove quotes around single words/phrases that are just policy language
            expected = re.sub(r"^'([^']+)'\s+must\s+be\s+", r'\1 should be ', expected, flags=re.IGNORECASE)
            expected = expected.strip()
            
            rows.append([
                sv_id,
                nist_id,
                severity,
                str(step_num),
                action,  # Adjusted based on automation level
                expected,  # Clean expected result, no policy language
                screen_output,  # Actual example output
                notes,
                automation_level_normalized,  # Automation Level column
                automation_source,  # Automation Source column
                "[ ] Pass / [ ] Fail"
            ])
    else:
        # Manual verification step - but try to extract a command from check_text even if not perfect
        title = control.get("title", "")[:100]
        
        # Try to extract any command-like text from check_text for the action
        check_text_lower = check_text.lower()
        action_command = None
        
        # Look for common command patterns even if not perfect
        if "run" in check_text_lower or "execute" in check_text_lower:
            # Try multiple patterns to find the actual command
            # Pattern 1: "run the following command:" then $ sudo command on next line (multiline with dotall)
            # Look for newline, optional whitespace, optional $, optional sudo, then command
            cmd_match = re.search(r'run\s+the\s+following\s+command[:\s]*\n\s*\$?\s*sudo\s+([a-zA-Z][^\n|]{10,120})', check_text, re.IGNORECASE | re.MULTILINE | re.DOTALL)
            if not cmd_match:
                # Pattern 2: "run the following command:" then command on same or next line
                cmd_match = re.search(r'run\s+the\s+following\s+command[:\s]+(?:.*?\n\s*)?\$?\s*sudo\s+([a-zA-Z][^\n|]{10,120})', check_text, re.IGNORECASE | re.DOTALL)
            if not cmd_match:
                # Pattern 3: "run:" or "execute:" followed by $ sudo command
                cmd_match = re.search(r'(?:run|execute)[:\s]+\$?\s*sudo\s+([a-zA-Z][^\n|]{10,120})', check_text, re.IGNORECASE)
            if not cmd_match:
                # Pattern 4: Look for $ sudo command anywhere after "run" (within reasonable distance)
                cmd_match = re.search(r'run[^\n]{0,200}\$?\s*sudo\s+([a-zA-Z][^\n|]{5,100})', check_text, re.IGNORECASE | re.DOTALL)
            
            if cmd_match:
                potential_cmd = cmd_match.group(1).strip()
                # Clean it up - remove backticks, policy language, etc.
                potential_cmd = re.sub(r'\.\s*If.*$', '', potential_cmd)
                potential_cmd = re.sub(r'\s*\|.*$', '', potential_cmd)  # Remove pipe to grep if present
                potential_cmd = potential_cmd.replace('`', '').strip()
                # Normalize placeholder text
                potential_cmd = re.sub(r'<[^>]+>', '<account_name>', potential_cmd)
                # Remove quotes around command
                potential_cmd = re.sub(r'^["\']|["\']$', '', potential_cmd)
                if len(potential_cmd) > 5 and len(potential_cmd) < 150 and not potential_cmd.lower().startswith('the following'):
                    action_command = f"Run: {potential_cmd}"
        
        if not action_command:
            # Fallback to title-based action
            action_command = f"Verify: {title}"
        
        expected = _extract_expected_result(check_text or "", action_command if action_command else "")
        
        # Ensure expected is never None
        if expected is None:
            expected = "Review the command output and verify it meets the STIG requirements."
        
        if not expected or expected == "Command output should match the expected result described in the STIG." or "Review the command output" in expected:
            # Adjust expected result based on automation level
            if automation_level_normalized == "automated":
                if automation_source == "scap":
                    expected = "SCAP scan should pass for this control. Verify key outputs/logs match expected state."
                elif automation_source == "nessus":
                    expected = "Nessus scan should pass for this control. Verify key outputs/logs match expected state."
                else:
                    expected = "Automated scan should pass for this control. Verify key outputs/logs match expected state."
            else:
                # Manual-only - primary verification step
                expected = "All verification requirements must be met."
        else:
            # Clean up expected result - remove all policy language
            # Ensure expected is a string before regex operations
            if expected and isinstance(expected, str):
                expected = re.sub(r'^Must:\s*', '', expected, flags=re.IGNORECASE)
            expected = re.sub(r'\.\s*If\s+it\s+does\s+not.*$', '', expected, flags=re.IGNORECASE)
            expected = re.sub(r'\.\s*If\s+it\s+is\s+true.*$', '', expected, flags=re.IGNORECASE)
            expected = re.sub(r'\.\s*If\s+it\s+is\s+not.*$', '', expected, flags=re.IGNORECASE)
            expected = re.sub(r'\.\s*If\s+it\s+does\s+not,\s+this\s+is\s+a\s+finding.*$', '', expected, flags=re.IGNORECASE)
            expected = re.sub(r'\.\s*If\s+it\s+is\s+true,\s+this\s+is\s+a\s+finding.*$', '', expected, flags=re.IGNORECASE)
            expected = re.sub(r'\.\s*If\s+it\s+is\s+not,\s+this\s+is\s+a\s+finding.*$', '', expected, flags=re.IGNORECASE)
            # Remove quotes around single words/phrases
            expected = re.sub(r"^'([^']+)'\s+must\s+be\s+", r'\1 should be ', expected, flags=re.IGNORECASE)
            expected = expected.strip()
        
        # Clean action_command - remove backticks if present
        action_command = action_command.replace('`', '')
        
        screen_output = _extract_screen_output(check_text)
        
        # Build notes based on automation level
        notes_parts = []
        if nist_id != "N/A":
            notes_parts.append(f"NIST: {nist_id}")
        if automation_level_normalized == "automated":
            if automation_source == "scap":
                notes_parts.append("SCAP/OVAL automated check available - scanners should cover this")
            elif automation_source == "nessus":
                notes_parts.append("Nessus automated check available - scanners should cover this")
            else:
                notes_parts.append("Automated check available - scanners should cover this")
        elif automation_level_normalized == "manual_only":
            if automation_source in ["scap", "nessus"]:
                notes_parts.append("Manual verification required - not covered by automated scanners")
            else:
                notes_parts.append("Manual verification required")
        notes = "; ".join(notes_parts) if notes_parts else ""
        
        rows.append([
            sv_id,
            nist_id,
            severity,
            "1",
            action_command,  # Use extracted command or title-based action
            expected,  # Clean expected result
            screen_output,
            notes,
            automation_level_normalized,  # Automation Level column
            automation_source,  # Automation Source column
            "[ ] Pass / [ ] Fail"
        ])
    
    return rows


def generate_ctp_csv(controls: list[dict], output_path: Path, manual_only: bool = True) -> None:
    """
    Generate CTP CSV file from StigControl objects.
    
    CTP (Certification Test Procedure) can include all controls or only manual controls.
    When manual_only=True, only controls that are not automated by SCAP/Nessus are included.
    
    Args:
        controls: List of StigControl dicts
        output_path: Path where CSV should be written
        manual_only: If True, only include manual-only controls. If False, include all controls.
    """
    output_path.parent.mkdir(parents=True, exist_ok=True)
    
    # Filter controls if manual_only is requested
    if manual_only:
        filtered_controls = []
        for control in controls:
            automation_level = control.get("automation_level", "unknown")
            # Only include controls that are manual-only
            if automation_level in ["manual_only", "manual", "not_scannable_with_nessus"]:
                filtered_controls.append(control)
        
        logger.info(f"Filtering to {len(filtered_controls)} manual-only controls (out of {len(controls)} total)")
        logger.info(f"  - Automated controls (excluded from CTP): {len(controls) - len(filtered_controls)}")
        logger.info(f"  - Manual-only controls (included in CTP): {len(filtered_controls)}")
        controls_to_process = filtered_controls
    else:
        logger.info(f"Generating CTP for all {len(controls)} controls")
        controls_to_process = controls
    
    with open(output_path, "w", newline="", encoding="utf-8") as f:
        writer = csv.writer(f)
        
        # Write CSV header with automation columns
        writer.writerow([
            "STIG ID",
            "NIST 800-53 Control ID",
            "Severity",
            "Step Number",
            "Action/Command",
            "Expected Output/Result",
            "Expected Screen Output (what user sees)",
            "Notes",
            "Automation Level",
            "Automation Source",
            "Pass/Fail"
        ])
        
        # Write control rows
        total_rows = 0
        for control in controls_to_process:
            rows = generate_ctp_rows_for_control(control)
            for row in rows:
                writer.writerow(row)
                total_rows += 1
        
        logger.info(f"Generated {total_rows} CTP rows for {len(controls_to_process)} controls")


def verify_coverage(controls: list[dict], csv_path: Path, manual_only: bool = False) -> bool:
    """
    Verify that all STIG IDs appear in the CSV.
    
    If manual_only=True, only verifies manual-only controls.
    If manual_only=False, verifies all controls.
    
    Args:
        controls: List of StigControl dicts
        csv_path: Path to generated CSV
        manual_only: Whether CSV should only contain manual controls
        
    Returns:
        True if all relevant STIG IDs are covered, False otherwise
    """
    if manual_only:
        # Extract only MANUAL-ONLY STIG IDs from controls
        expected_control_ids = {
            control.get("sv_id") 
            for control in controls 
            if control.get("automation_level", "unknown") in ["manual_only", "manual", "not_scannable_with_nessus"]
        }
    else:
        # Extract ALL STIG IDs from controls
        expected_control_ids = {
            control.get("sv_id") 
            for control in controls 
            if control.get("sv_id")
        }
    
    # Read CSV and extract STIG IDs
    csv_ids = set()
    with open(csv_path, "r", encoding="utf-8") as f:
        reader = csv.DictReader(f)
        for row in reader:
            csv_ids.add(row.get("STIG ID", ""))
    
    # Check for missing IDs
    missing_ids = expected_control_ids - csv_ids
    
    if missing_ids:
        logger.error(f"Missing STIG IDs in CSV: {missing_ids}")
        return False
    
    logger.info(f"✓ Coverage verified: all {len(expected_control_ids)} expected STIG IDs present in CSV")
    return True


def main():
    """Main entry point for the CTP generator script."""
    parser = argparse.ArgumentParser(
        description="Generate CTP CSV from StigControl JSON"
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
        help="Path to output CSV file"
    )
    parser.add_argument(
        "--verify-coverage",
        action="store_true",
        help="Verify that all STIG IDs are covered in the CSV"
    )
    parser.add_argument(
        "--all",
        action="store_true",
        help="Generate CTP rows for all controls (default: manual-only controls only)"
    )
    
    args = parser.parse_args()
    
    try:
        # Load controls from JSON
        controls = load_controls_from_json(args.input)
        
        if not controls:
            logger.warning("No controls found in input file")
            return 1
        
        # Generate CTP CSV (default to manual-only, use --all to include all controls)
        generate_ctp_csv(controls, args.output, manual_only=not args.all)
        
        # Verify coverage if requested
        if args.verify_coverage:
            if not verify_coverage(controls, args.output, manual_only=not args.all):
                logger.error("Coverage verification failed")
                return 1
        
        logger.info("✓ CTP generation complete!")
        
    except FileNotFoundError as e:
        logger.error(f"File not found: {e}")
        return 1
    except Exception as e:
        logger.error(f"Error: {e}", exc_info=True)
        return 1
    
    return 0


if __name__ == "__main__":
    exit(main())


