"""Generate CTP (Certification Test Procedure) document from STIG controls."""

import csv
import re
from pathlib import Path

from ..model.controls import StigControl
from .utils import extract_cli_commands
from .extractors import (
    extract_shell_commands_from_block, split_command_and_prose, is_placeholder_command,
    is_probable_cli_command, looks_like_config_value, normalize_command_line
)


def _format_nist_control_id(nist_id: str | None) -> str | None:
    """
    Format NIST control ID to AU.02, IA.5 format (not AU-2 or CCI-000048).
    
    Args:
        nist_id: NIST control ID in various formats (AU-2, AU.02, CCI-000048, etc.)
    
    Returns:
        Formatted NIST control ID (AU.02, IA.5) or None if not a valid NIST control ID
    """
    if not nist_id:
        return None
    
    # Skip CCI IDs - they are not NIST control IDs
    if nist_id.startswith("CCI-"):
        return None
    
    # Skip OS-000023 format - not a NIST control ID
    if nist_id.startswith("OS-"):
        return None
    
    # Already in correct format (AU.02, AU.02.b)
    if re.match(r'^[A-Z]{2}\.\d{2}(?:\.[a-z]|\([^)]+\))*$', nist_id):
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


def generate_ctp_document(
    controls: list[StigControl], output_path: Path, stig_metadata: dict[str, str]
) -> None:
    """
    Generate a CTP document in CSV format for manual STIG controls.

    Args:
        controls: List of STIG controls
        output_path: Path where the CTP CSV file should be written
        stig_metadata: Dictionary with keys: stig_name, stig_release, source_file_name, generated_on
    """
    # Filter for manual controls
    manual_controls = [c for c in controls if not c.is_automatable]

    output_path.parent.mkdir(parents=True, exist_ok=True)

    with open(output_path, "w", newline="", encoding="utf-8") as f:
        writer = csv.writer(f)
        
        # Write CSV header
        writer.writerow([
            "STIG ID",
            "NIST 800-53 Control ID",
            "Severity",
            "Step Number",
            "Action/Command",
            "Expected Output/Result",
            "Expected Screen Output (what user sees)",
            "Notes",
            "Pass/Fail"
        ])

        # Write control rows
        for control in manual_controls:
            rows = _format_control_rows(control)
            for row in rows:
                writer.writerow(row)


def _format_control_rows(control: StigControl) -> list[list[str]]:
    """Format control rows for CSV CTP document."""
    rows = []

    # Format NIST control ID properly
    formatted_nist_id = _format_nist_control_id(control.nist_family_id) if control.nist_family_id else "N/A"
    
    # Use structured commands for manual steps
    # Prefer check_commands, fall back to candidate blocks, then extract from text
    # Filter out degenerate commands and prose using the same sanitization as hardening/checker
    check_commands = control.check_commands or control.candidate_check_blocks
    
    # If no structured commands, try extracting from check_text using the same extractor
    if not check_commands and control.check_text:
        extracted_cmds, _ = extract_shell_commands_from_block(
            control.check_text, 
            control.os_family or "rhel", 
            purpose="check"
        )
        check_commands = extracted_cmds
    
    # Filter commands to ensure they're real commands, not prose or placeholders
    # Separate commands from config values
    valid_commands = []
    config_values = []  # Config values that should go to Expected Output
    
    # Prose prefixes that should be rejected
    PROSE_PREFIXES = (
        "Configure ", "If ", "Document ", "To ", "NOTE:", "Must:", "The following condition",
        "All verification requirements", "Output must be:", "File location:",
        "Configuration: ", "Command output", "Review the command output",
    )
    
    for cmd in check_commands:
        if not cmd or len(cmd.strip()) < 3:
            continue
        
        # Normalize command
        normalized = normalize_command_line(cmd)
        
        # Skip prose prefixes
        if any(normalized.startswith(p) for p in PROSE_PREFIXES):
            continue
        
        # Check if it's a config value (not a command)
        if looks_like_config_value(cmd):
            config_values.append(cmd)
            continue
        
        # Only keep real CLI commands
        if is_probable_cli_command(cmd):
            valid_commands.append(cmd)
    
    if valid_commands:
        # Build steps from valid structured commands
        manual_steps = []
        for i, cmd in enumerate(valid_commands[:5], start=1):
            # Split command from prose to ensure clean action field
            cmd_part, prose_part = split_command_and_prose(cmd)
            if not cmd_part:
                continue
            
            # Final validation: ensure it's a real command
            if not is_probable_cli_command(cmd_part):
                continue
            
            # Use clean command part for action
            # Keep it short - truncate if too long
            action_cmd = cmd_part[:100] if len(cmd_part) > 100 else cmd_part
            
            # Build expected output - include config values if present
            expected = _extract_detailed_expected_result(control.check_text, cmd_part)
            if not expected:
                expected = _extract_stig_requirements(control.check_text)
            
            # Add config values to expected output
            if config_values:
                config_text = "The configuration includes:\n"
                for config_val in config_values[:3]:  # Limit to 3 config values
                    config_text += f"  {config_val}\n"
                if expected:
                    expected = f"{expected}\n\n{config_text.strip()}"
                else:
                    expected = config_text.strip()
            
            if not expected:
                expected = "Command output displayed. Verify output matches the expected result. If it does not, this is a finding."
            
            notes = _extract_autonomous_notes(control.check_text)
            # Add prose to notes if present
            if prose_part:
                if notes:
                    notes = f"{notes}; {prose_part}"
                else:
                    notes = prose_part
            
            expected_output = _extract_expected_screen_output(control.check_text)
            
            manual_steps.append({
                "action": f"Run `{action_cmd}`",
                "expected": expected,
                "expected_output": expected_output,
                "notes": notes or ""
            })
    else:
        # Extract manual CLI commands from check_text
        manual_steps = _extract_manual_ctp_steps(control)
    
    if not manual_steps:
        # If no valid commands can be extracted, create manual verification step
        # Use manual verification description instead of bogus commands
        stig_requirements = _extract_stig_requirements(control.check_text)
        verification_points = _extract_verification_points(control.check_text)
        expected_output = _extract_expected_screen_output(control.check_text)
        
        # Build manual verification action from manual_notes or check_text
        if control.manual_notes:
            # Use first manual note as short description
            short_desc = control.manual_notes[0]
            if len(short_desc) > 150:
                short_desc = short_desc[:147] + "..."
            action = f"Manual verification: {short_desc}"
        elif verification_points:
            # Use verification points
            action_parts = ["Manual verification:"]
            for point in verification_points[:2]:  # Limit to 2 points
                if len(point) > 100:
                    point = point[:97] + "..."
                action_parts.append(f"- {point}")
            action = "\n".join(action_parts)
        else:
            # Extract short description from check_text (first 1-2 sentences)
            check_sentences = control.check_text.split('.')[:2]
            short_desc = '. '.join(s.strip() for s in check_sentences if s.strip())
            if len(short_desc) > 150:
                short_desc = short_desc[:147] + "..."
            action = f"Manual verification: {short_desc}" if short_desc else "Manual verification: review STIG check text for detailed steps"
        
        # Build expected output - include config values if present
        expected = stig_requirements if stig_requirements else "All verification requirements must be met. If any requirement is not met, this is a finding."
        
        # Add config values to expected output if present
        if config_values:
            config_text = "The configuration should include:\n"
            for config_val in config_values[:3]:  # Limit to 3 config values
                config_text += f"  {config_val}\n"
            expected = f"{expected}\n\n{config_text.strip()}"
        
        notes = _extract_autonomous_notes(control.check_text)
        # Add manual_notes to Notes if available
        if control.manual_notes:
            manual_notes_text = "; ".join(control.manual_notes[:3])
            if notes:
                notes = f"{notes}; {manual_notes_text}"
            else:
                notes = manual_notes_text
        
        rows.append([
            control.id,  # STIG ID
            formatted_nist_id,  # NIST 800-53 Control ID
            control.severity.upper(),  # Severity
            "1",  # Step Number
            action,  # Action/Command (clean, no placeholders)
            expected,  # Expected Output/Result
            expected_output,  # Expected Screen Output
            notes,  # Notes
            "[ ] Pass / [ ] Fail"  # Pass/Fail
        ])
    else:
        # Use extracted manual commands
        for step_num, step in enumerate(manual_steps, start=1):
            expected_output = step.get("expected_output", _extract_expected_screen_output(control.check_text))
            rows.append([
                control.id,  # STIG ID
                formatted_nist_id,  # NIST 800-53 Control ID
                control.severity.upper(),  # Severity
                str(step_num),  # Step Number
                step["action"],  # Action/Command
                step["expected"],  # Expected Output/Result
                expected_output,  # Expected Screen Output
                step["notes"],  # Notes
                "[ ] Pass / [ ] Fail"  # Pass/Fail
            ])

    return rows


def _extract_manual_ctp_steps(control: StigControl) -> list[dict[str, str]]:
    """Extract manual CLI commands from check_text for CTP steps."""
    import re

    steps = []
    check_text = control.check_text
    
    # Windows-specific extraction
    if control.os_family == "windows":
        steps = _extract_windows_steps(control, check_text)
    elif control.os_family == "network":
        # Network device extraction
        steps = _extract_network_steps(control, check_text)
    else:
        # Linux/Unix extraction
        steps = _extract_linux_steps(control, check_text)
    
    return steps


def _extract_windows_steps(control: StigControl, check_text: str) -> list[dict[str, str]]:
    """Extract Windows-specific manual steps from check_text."""
    import re
    
    steps = []
    
    # 1. Extract PowerShell commands
    ps_patterns = [
        r'Get-ChildItem[^\n]+',
        r'Get-ItemProperty[^\n]+',
        r'Get-Service[^\n]+',
        r'Get-Process[^\n]+',
        r'Get-WmiObject[^\n]+',
        r'Get-CimInstance[^\n]+',
        r'Execute the following command:\s*\n\s*([^\n]+)',  # "Execute the following command:"
        r'Run ""PowerShell""[^\n]*\n[^\n]*Execute[^\n]*:\s*\n\s*([^\n]+)',  # PowerShell execute pattern
    ]
    
    found_commands = set()
    for pattern in ps_patterns:
        matches = re.findall(pattern, check_text, re.IGNORECASE | re.MULTILINE)
        for match in matches:
            if isinstance(match, tuple):
                cmd = match[0] if match[0] else match[1] if len(match) > 1 else ""
            else:
                cmd = match
            cmd = cmd.strip()
            if cmd and len(cmd) > 5 and cmd not in found_commands:
                found_commands.add(cmd)
                
                # Extract specific expected result from surrounding text
                expected = _extract_detailed_expected_result(check_text, cmd)
                
                # For certificate commands, extract specific certificate requirements
                if "Cert:" in cmd or "Certificate" in cmd or "Get-ChildItem.*Cert" in cmd:
                    cert_expected = _extract_certificate_requirements(check_text)
                    if cert_expected:
                        expected = cert_expected
                
                if not expected:
                    expected = _extract_stig_requirements(check_text)
                if not expected:
                    # Try to extract from "if" statements
                    if_pattern = r'if\s+([^,\.]{20,150}),\s+this\s+is\s+a\s+finding'
                    if_match = re.search(if_pattern, check_text, re.IGNORECASE)
                    if if_match:
                        condition = if_match.group(1).strip()
                        expected = f"The following condition must NOT be true: {condition}. If it is true, this is a finding."
                    else:
                        expected = "Command output must be reviewed. If output does not match the expected result, this is a finding."
                
                notes = _extract_autonomous_notes(check_text)
                if not notes:
                    # Extract registry path from command if present
                    if "Get-ItemProperty" in cmd:
                        path_match = re.search(r"-Path\s+['\"]([^'\"]+)['\"]", cmd)
                        if path_match:
                            notes = f"Registry path: {path_match.group(1)}"
                
                expected_output = _extract_expected_screen_output(check_text)
                steps.append({
                    "action": f"Open PowerShell as Administrator and run: `{cmd}`",
                    "expected": expected,
                    "expected_output": expected_output,
                    "notes": notes or ""
                })
    
    # 2. Extract GUI instructions and convert to commands
    # Handle both double quotes and single quotes, and variations
    gui_commands = [
        (r'Run\s+["\']System\s+Information["\']', 'msinfo32.exe', 'System Information'),
        (r'Run\s+["\']tpm\.msc["\']', 'tpm.msc', 'TPM Management'),
        (r'Run\s+["\']winver\.exe["\']', 'winver.exe', 'About Windows'),
        (r'Run\s+["\']Computer\s+Management["\']', 'compmgmt.msc', 'Computer Management'),
        (r'Run\s+["\']Local\s+Security\s+Policy["\']', 'secpol.msc', 'Local Security Policy'),
        (r'Run\s+["\']Group\s+Policy\s+Editor["\']', 'gpedit.msc', 'Group Policy Editor'),
        (r'Open\s+["\']Settings["\']', 'ms-settings:', 'Settings'),
        (r'Run\s+["\']gpedit\.msc["\']', 'gpedit.msc', 'Group Policy Editor'),
        (r'Run\s+["\']secpol\.msc["\']', 'secpol.msc', 'Local Security Policy'),
        # Also check for just the app name without quotes
        (r'Run\s+System\s+Information', 'msinfo32.exe', 'System Information'),
        (r'Run\s+tpm\.msc', 'tpm.msc', 'TPM Management'),
    ]
    
    for pattern, cmd, app_name in gui_commands:
        match = re.search(pattern, check_text, re.IGNORECASE)
        if match:
            # Extract what to check from the text
            expected = _extract_gui_expected_result(check_text, pattern)
            navigation_steps = _extract_navigation_steps(check_text, app_name)
            
            action_text = f"Run `{cmd}` from Run dialog (Win+R) or command prompt."
            if navigation_steps:
                action_text += f"\n\nNavigate to: {navigation_steps}"
            
            if not expected:
                expected = _extract_stig_requirements(check_text)
            if not expected:
                expected = f"{app_name} window opens. Verify the specified setting matches the expected value. If it does not, this is a finding."
            
            notes = _extract_autonomous_notes(check_text)
            if not notes and navigation_steps:
                notes = f"Navigate to the specified location and verify the setting value."
            
            expected_output = _extract_expected_screen_output(check_text)
            steps.append({
                "action": action_text,
                "expected": expected,
                "expected_output": expected_output,
                "notes": notes or ""
            })
            break  # Only add one GUI command per control
    
    # 3. Extract registry checks
    registry_pattern = re.compile(
        r'Registry Hive:\s*(HKEY_[A-Z_]+)\s*\n'
        r'Registry Path:\s*\\([^\n]+)\s*\n'
        r'Value Name:\s*([^\n]+)\s*\n'
        r'Type:\s*([^\n]+)\s*\n'
        r'Value:\s*([^\n]+)',
        re.IGNORECASE | re.MULTILINE
    )
    
    registry_matches = registry_pattern.findall(check_text)
    for hive, path, value_name, reg_type, expected_value in registry_matches:
        # Convert to PowerShell registry path
        ps_path = f"HKLM:\\{path.replace('/', '\\')}"
        ps_cmd = f"Get-ItemProperty -Path '{ps_path}' -Name '{value_name}' | Select-Object -ExpandProperty '{value_name}'"
        
        # Extract expected value description
        expected_desc = f"Registry value '{value_name}' should be set to {expected_value.strip()}"
        
        # Extract more specific expected result
        expected_full = _extract_detailed_expected_result(check_text, ps_cmd)
        if not expected_full:
            expected_full = f"{expected_desc}. If the displayed value does not match, this is a finding."
        
        expected_output = _extract_expected_screen_output(check_text)
        steps.append({
            "action": f"Open PowerShell as Administrator and run: `{ps_cmd}`",
            "expected": expected_full,
            "expected_output": expected_output or f"PowerShell should display the registry value: {expected_value.strip()}",
            "notes": f"Registry location: {hive}\\{path}\\{value_name} (Type: {reg_type})"
        })
    
    # 4. Extract executable commands in quotes (more comprehensive)
    exe_patterns = [
        r'Run\s+""([^""]+\.exe)""',
        r'Run\s+""([^""]+\.msc)""',
        r'execute:\s*([^\n]+\.exe)',
        r'command:\s*([^\n]+\.exe)',
    ]
    
    found_exes = set()
    for pattern in exe_patterns:
        exe_matches = re.findall(pattern, check_text, re.IGNORECASE)
        for exe in exe_matches:
            exe_clean = exe.strip()
            # Skip GUI apps already handled
            if exe_clean.lower() not in ['system information', 'computer management', 'tpm.msc'] and exe_clean not in found_exes:
                found_exes.add(exe_clean)
                expected = _extract_detailed_expected_result(check_text, exe_clean)
                if not expected:
                    expected = _extract_stig_requirements(check_text)
                if not expected:
                    expected = f"Application '{exe_clean}' opens. Verify the displayed information matches the expected result. If it does not, this is a finding."
                
                notes = _extract_autonomous_notes(check_text)
                
                expected_output = _extract_expected_screen_output(check_text)
                steps.append({
                    "action": f"Run `{exe_clean}` from Run dialog (Win+R) or command prompt.",
                    "expected": expected,
                    "expected_output": expected_output,
                    "notes": notes or ""
                })
    
    # 5. Extract reg query commands
    if "reg query" in check_text.lower():
        reg_query_match = re.search(r'reg\s+query\s+([^\n]+)', check_text, re.IGNORECASE)
        if reg_query_match:
            reg_path = reg_query_match.group(1).strip()
            expected = _extract_stig_requirements(check_text)
            if not expected:
                expected = "Registry values displayed. Verify the displayed values match the expected result. If they do not, this is a finding."
            
            notes = _extract_autonomous_notes(check_text)
            
            expected_output = _extract_expected_screen_output(check_text)
            steps.append({
                "action": f"Open Command Prompt as Administrator and run: `reg query {reg_path}`",
                "expected": expected,
                "expected_output": expected_output,
                "notes": notes or ""
            })
    
    # If no steps extracted, create a detailed manual verification step
    if not steps:
        # Try to extract key verification points from check_text
        verification_points = _extract_verification_points(check_text)
        # Extract actual STIG requirements for expected results
        stig_requirements = _extract_stig_requirements(check_text)
        
        if verification_points:
            action_parts = ["Manually verify the following:"]
            for point in verification_points[:3]:  # Limit to 3 points
                action_parts.append(f"- {point}")
            
            # If no specific requirements extracted, try to extract from verification points
            if not stig_requirements:
                # Look for key phrases that indicate requirements
                req_phrases = []
                if "must" in check_text.lower():
                    must_matches = re.findall(r'must\s+([^\.]{10,100})', check_text, re.IGNORECASE)
                    for match in must_matches[:2]:
                        req_phrases.append(f"Must: {match.strip()}")
                if "should" in check_text.lower():
                    should_matches = re.findall(r'should\s+([^\.]{10,100})', check_text, re.IGNORECASE)
                    for match in should_matches[:2]:
                        req_phrases.append(f"Should: {match.strip()}")
                if req_phrases:
                    stig_requirements = "; ".join(req_phrases[:2])
            
            expected_result = stig_requirements if stig_requirements else "All verification points must meet the specified requirements. If any point does not meet requirements, this is a finding."
            
            notes = _extract_autonomous_notes(check_text)
            
            expected_output = _extract_expected_screen_output(check_text)
            steps.append({
                "action": "\n".join(action_parts),
                "expected": expected_result,
                "expected_output": expected_output,
                "notes": notes or ""
            })
        else:
            # Last resort: extract requirements from check text
            expected_result = stig_requirements if stig_requirements else "All verification requirements must be met. If any requirement is not met, this is a finding."
            notes = _extract_autonomous_notes(check_text)
            
            expected_output = _extract_expected_screen_output(check_text)
            steps.append({
                "action": f"Manually verify compliance with control {_format_nist_control_id(control.nist_family_id) if control.nist_family_id else control.id}.",
                "expected": expected_result,
                "expected_output": expected_output,
                "notes": notes or ""
            })
    
    return steps[:5]  # Limit to 5 steps


def _extract_linux_steps(control: StigControl, check_text: str) -> list[dict[str, str]]:
    """Extract Linux/Unix-specific manual steps from check_text."""
    import re
    
    steps = []
    
    # Prose prefixes that should be rejected
    PROSE_PREFIXES = (
        "Configure ", "If ", "Document ", "To ", "NOTE:", "Must:", "The following condition",
        "All verification requirements", "Output must be:", "File location:",
        "Configuration: ", "Command output", "Review the command output",
    )
    
    # Use structured check commands from control
    extracted_commands = control.check_commands or control.candidate_check_blocks or []
    
    # Filter commands using robust detection
    valid_commands = []
    config_values = []
    
    for cmd in extracted_commands:
        normalized = normalize_command_line(cmd)
        
        # Skip prose prefixes
        if any(normalized.startswith(p) for p in PROSE_PREFIXES):
            continue
        
        # Check if it's a config value
        if looks_like_config_value(cmd):
            config_values.append(cmd)
            continue
        
        # Only keep real CLI commands
        if is_probable_cli_command(cmd):
            valid_commands.append(cmd)
    
    extracted_commands = valid_commands
    
    # If no structured commands, fall back to pattern extraction
    if not extracted_commands:
        # Extract commands in backticks, quotes, or explicit "run:" patterns
        command_patterns = [
            r'`([^`]+)`',  # Backtick commands
            r'run:\s*([^\n]+)',  # "run: command"
            r'execute:\s*([^\n]+)',  # "execute: command"
            r'command:\s*([^\n]+)',  # "command: command"
            r'Run\s+""([^""]+)""',  # Run "command"
        ]
        
        for pattern in command_patterns:
            matches = re.findall(pattern, check_text, re.IGNORECASE)
            for match in matches:
                cmd = match.strip() if isinstance(match, str) else match[0].strip()
                # Clean up command
                cmd = re.sub(r'^\$\s*sudo\s+', '', cmd)
                cmd = re.sub(r'^\$\s*', '', cmd)
                if cmd and len(cmd) > 3 and not cmd.endswith(('...', ':')) and len(cmd) < 300:
                    if any(cmd.startswith(prefix) for prefix in ['ls ', 'cat ', 'grep ', 'stat ', 'systemctl ', 'rpm ', 'find ', 'awk ', 'sed ', 'chmod ', 'chown ', '/', 'sudo ', 'grep']):
                        extracted_commands.append(cmd)
    
    # If no explicit commands, infer from text patterns
    if not extracted_commands:
        file_paths = re.findall(r'[/](?:etc|usr|var|opt|home|root)/[a-zA-Z0-9_/.-]+', check_text)
        
        if "ls -l" in check_text.lower() or "permission" in check_text.lower():
            if file_paths:
                extracted_commands.append(f"ls -l {file_paths[0]}")
        
        if "grep" in check_text.lower() and file_paths:
            grep_match = re.search(r'grep\s+["\']?([^"\'\s]+)["\']?\s+([/a-zA-Z0-9_/.-]+)', check_text, re.IGNORECASE)
            if grep_match:
                pattern = grep_match.group(1)
                file_path = grep_match.group(2) if len(grep_match.groups()) > 1 else file_paths[0]
                extracted_commands.append(f"grep '{pattern}' {file_path}")
            elif file_paths:
                extracted_commands.append(f"grep -E '.*' {file_paths[0]}")
        
        if ("cat" in check_text.lower() or "view" in check_text.lower()) and file_paths:
            extracted_commands.append(f"cat {file_paths[0]}")
        
        systemctl_match = re.search(r'systemctl\s+(status|is-enabled|is-active)\s+([a-zA-Z0-9-@.]+)', check_text, re.IGNORECASE)
        if systemctl_match:
            action = systemctl_match.group(1)
            service = systemctl_match.group(2)
            extracted_commands.append(f"systemctl {action} {service}")
    
    # Remove duplicates
    seen = set()
    unique_commands = []
    for cmd in extracted_commands:
        cmd_clean = cmd.strip()
        if cmd_clean and cmd_clean not in seen:
            seen.add(cmd_clean)
            unique_commands.append(cmd_clean)
    
    # Convert to steps
    for cmd in unique_commands[:5]:
        # Skip placeholder commands
        if is_placeholder_command(cmd):
            continue
        
        # Skip config values (they go to Expected Output)
        if looks_like_config_value(cmd):
            config_values.append(cmd)
            continue
        
        # Only keep real CLI commands
        if not is_probable_cli_command(cmd):
            continue
        
        # Split command from prose to ensure clean action
        cmd_part, prose_part = split_command_and_prose(cmd)
        if not cmd_part:
            continue
        
        # Final validation
        if not is_probable_cli_command(cmd_part):
            continue
        
        # Use clean command part
        clean_cmd = cmd_part[:100] if len(cmd_part) > 100 else cmd_part
        
        expected = _extract_detailed_expected_result(check_text, clean_cmd)
        if not expected:
            expected = _extract_stig_requirements(check_text)
        
        if clean_cmd.startswith("ls -l") or clean_cmd.startswith("stat"):
            if not expected:
                # Try to extract specific permission/ownership requirements
                perm_match = re.search(r'(\d{4})\s+or\s+less\s+permissive', check_text, re.IGNORECASE)
                owner_match = re.search(r'owned\s+by\s+([^\s,\.]+)', check_text, re.IGNORECASE)
                if perm_match:
                    expected = f"File permissions must be {perm_match.group(1)} or less permissive. If not, this is a finding."
                elif owner_match:
                    expected = f"File must be owned by {owner_match.group(1)}. If not, this is a finding."
                else:
                    expected = "File permissions and ownership displayed. Verify values match the expected result. If they do not, this is a finding."
        elif cmd.startswith("grep"):
            if not expected:
                # Try to determine if pattern should be present or absent
                if "does not exist" in check_text.lower() or "is not present" in check_text.lower():
                    expected = "No matching lines should be displayed. If matching lines are found, this is a finding."
                else:
                    expected = "Matching lines displayed. Verify the pattern matches the expected result. If it does not, this is a finding."
        elif cmd.startswith("cat") or cmd.startswith("less") or cmd.startswith("more"):
            if not expected:
                expected = "File contents displayed. Verify contents match the expected result. If they do not, this is a finding."
        elif cmd.startswith("systemctl"):
            if not expected:
                # Try to extract service state requirement
                state_match = re.search(r'(enabled|disabled|active|inactive)', check_text, re.IGNORECASE)
                if state_match:
                    state = state_match.group(1)
                    expected = f"Service must be {state}. If it is not, this is a finding."
                else:
                    expected = "Service status information displayed. Verify state matches the expected result. If it does not, this is a finding."
        else:
            if not expected:
                expected = "Command output displayed. Verify output matches the expected result. If it does not, this is a finding."
        
        # Add config values to expected output AFTER determining base expected
        if config_values:
            config_text = "The configuration should include:\n"
            for config_val in config_values[:3]:
                config_text += f"  {config_val}\n"
            if expected:
                expected = f"{expected}\n\n{config_text.strip()}"
            else:
                expected = config_text.strip()
        
        notes = _extract_autonomous_notes(check_text)
        # Add prose to notes if present
        if prose_part:
            if notes:
                notes = f"{notes}; {prose_part}"
            else:
                notes = prose_part
        
        expected_output = _extract_expected_screen_output(check_text)
        steps.append({
            "action": f"Run `{clean_cmd}` in a privileged terminal session.",
            "expected": expected,
            "expected_output": expected_output,
            "notes": notes or ""
        })
    
    if not steps:
        # Extract actual STIG requirements
        stig_requirements = _extract_stig_requirements(check_text)
        verification_points = _extract_verification_points(check_text)
        
        # Build manual verification action
        if control.manual_notes:
            short_desc = control.manual_notes[0]
            if len(short_desc) > 150:
                short_desc = short_desc[:147] + "..."
            action = f"Manual verification: {short_desc}"
        elif verification_points:
            action_parts = ["Manual verification:"]
            for point in verification_points[:2]:
                if len(point) > 100:
                    point = point[:97] + "..."
                action_parts.append(f"- {point}")
            action = "\n".join(action_parts)
        else:
            # Extract short description from check_text
            check_sentences = check_text.split('.')[:2]
            short_desc = '. '.join(s.strip() for s in check_sentences if s.strip())
            if len(short_desc) > 150:
                short_desc = short_desc[:147] + "..."
            action = f"Manual verification: {short_desc}" if short_desc else "Manual verification: review STIG check text for detailed steps"
        
        expected_result = stig_requirements if stig_requirements else "All verification requirements must be met. If any requirement is not met, this is a finding."
        
        # Add config values to expected output if present
        if config_values:
            config_text = "The configuration should include:\n"
            for config_val in config_values[:3]:
                config_text += f"  {config_val}\n"
            expected_result = f"{expected_result}\n\n{config_text.strip()}"
        
        notes = _extract_autonomous_notes(check_text)
        
        expected_output = _extract_expected_screen_output(check_text)
        steps.append({
            "action": action,
            "expected": expected_result,
            "expected_output": expected_output,
            "notes": notes or ""
        })
    
    return steps


def _extract_expected_result(check_text: str, command: str) -> str:
    """Extract expected result from check_text based on command context."""
    import re
    
    # Look for "if" or "verify" statements near the command
    lines = check_text.split('\n')
    cmd_lower = command.lower()
    
    for i, line in enumerate(lines):
        if any(word in line.lower() for word in cmd_lower.split()[:2]):  # Check if command words appear in line
            # Look at next few lines for expected results
            for j in range(i, min(i + 5, len(lines))):
                next_line = lines[j]
                if "display" in next_line.lower() or "show" in next_line.lower() or "indicate" in next_line.lower():
                    # Extract the expected value
                    if "does not display" in next_line.lower() or "does not show" in next_line.lower():
                        # Extract what it SHOULD display
                        match = re.search(r'should[^\n]*([^\n]+)', next_line, re.IGNORECASE)
                        if match:
                            return f"Output should display: {match.group(1).strip()}"
                    else:
                        # Extract what it displays
                        match = re.search(r'display[s]?\s+([^\n]+)', next_line, re.IGNORECASE)
                        if match:
                            return f"Output displays: {match.group(1).strip()}"
    
    return ""


def _extract_detailed_expected_result(check_text: str, command: str) -> str:
    """Extract detailed, specific expected result from check_text based on command context."""
    import re
    
    # First try to find specific "if" statements that describe what should be displayed
    # Pattern: "If X does not display Y, this is a finding"
    if_not_display_pattern = r'if\s+["\']?([^"\']+)["\']?\s+does\s+not\s+display\s+["\']?([^"\']+)["\']?[^\.]*this\s+is\s+a\s+finding'
    match = re.search(if_not_display_pattern, check_text, re.IGNORECASE)
    if match:
        field = match.group(1).strip()
        expected_value = match.group(2).strip()
        if len(expected_value) < 100:  # Avoid overly long values
            return f"'{field}' must display '{expected_value}'. If it does not, this is a finding."
    
    # Pattern: "If X is not Y, this is a finding"
    if_not_pattern = r'if\s+["\']?([^"\']+)["\']?\s+is\s+not\s+["\']?([^"\']+)["\']?[^\.]*this\s+is\s+a\s+finding'
    match = re.search(if_not_pattern, check_text, re.IGNORECASE)
    if match:
        field = match.group(1).strip()
        expected_value = match.group(2).strip()
        if len(expected_value) < 100:
            return f"'{field}' must be '{expected_value}'. If it is not, this is a finding."
    
    # Look for specific value requirements near the command
    lines = check_text.split('\n')
    cmd_lower = command.lower()
    
    for i, line in enumerate(lines):
        if any(word in line.lower() for word in cmd_lower.split()[:2]):
            # Look at surrounding lines for specific values
            for j in range(max(0, i-2), min(i + 10, len(lines))):
                check_line = lines[j]
                
                # Look for "must be" or "should be" with specific values
                must_be_pattern = r'must\s+be\s+["\']?([^"\'\n]{5,80})["\']?'
                match = re.search(must_be_pattern, check_line, re.IGNORECASE)
                if match:
                    value = match.group(1).strip()
                    if len(value) < 100:
                        return f"Output must be: {value}. If it is not, this is a finding."
                
                # Look for "should display" with specific values
                should_display_pattern = r'should\s+display\s+["\']?([^"\'\n]{5,80})["\']?'
                match = re.search(should_display_pattern, check_line, re.IGNORECASE)
                if match:
                    value = match.group(1).strip()
                    if len(value) < 100:
                        return f"Output should display: {value}. If it does not, this is a finding."
                
                # Look for "is a finding" statements that indicate what should NOT be
                finding_pattern = r'if\s+([^,\.]{10,80}),\s+this\s+is\s+a\s+finding'
                match = re.search(finding_pattern, check_line, re.IGNORECASE)
                if match:
                    condition = match.group(1).strip()
                    if len(condition) < 100:
                        return f"The following condition must NOT be true: {condition}. If it is true, this is a finding."
    
    return ""


def _extract_certificate_requirements(check_text: str) -> str:
    """Extract specific certificate requirements from check_text."""
    import re
    
    requirements = []
    
    # Extract from PowerShell command patterns (e.g., Where {$_.Issuer -Like "*DoD*"})
    issuer_like_pattern = r'Issuer\s+-Like\s+["\']([^"\']+)["\']'
    subject_like_pattern = r'Subject\s+-Like\s+["\']([^"\']+)["\']'
    
    issuer_matches = re.findall(issuer_like_pattern, check_text, re.IGNORECASE)
    subject_matches = re.findall(subject_like_pattern, check_text, re.IGNORECASE)
    
    if issuer_matches:
        for issuer in issuer_matches[:2]:
            issuer_clean = issuer.strip('*').strip()
            if len(issuer_clean) < 100:
                requirements.append(f"Certificate issuer must contain: {issuer_clean}")
    
    if subject_matches:
        for subject in subject_matches[:2]:
            subject_clean = subject.strip('*').strip()
            if len(subject_clean) < 100:
                requirements.append(f"Certificate subject must contain: {subject_clean}")
    
    # Look for certificate store location (disallowed, root, etc.)
    store_pattern = r'Cert:[^\\]+\\?([a-zA-Z]+)'
    store_match = re.search(store_pattern, check_text, re.IGNORECASE)
    if store_match:
        store_name = store_match.group(1)
        if store_name.lower() == "disallowed":
            requirements.append("Certificates must be present in the disallowed certificate store.")
        elif store_name.lower() == "root":
            requirements.append("Certificates must be present in the root certificate store.")
    
    # Look for certificate issuer/subject requirements in text
    issuer_pattern = r'Issuer.*?["\']([^"\']+)["\']'
    subject_pattern = r'Subject.*?["\']([^"\']+)["\']'
    
    issuers = re.findall(issuer_pattern, check_text, re.IGNORECASE)
    subjects = re.findall(subject_pattern, check_text, re.IGNORECASE)
    
    if issuers and not issuer_matches:  # Only if not already found in command
        for issuer in issuers[:2]:
            if len(issuer) < 100:
                requirements.append(f"Certificate issuer must contain: {issuer}")
    
    if subjects and not subject_matches:  # Only if not already found in command
        for subject in subjects[:2]:
            if len(subject) < 100:
                requirements.append(f"Certificate subject must contain: {subject}")
    
    # Look for "if" statements about certificates
    if_cert_pattern = r'if\s+([^,\.]{20,150})\s+does\s+not\s+exist[^\.]*this\s+is\s+a\s+finding'
    if_match = re.search(if_cert_pattern, check_text, re.IGNORECASE)
    if if_match:
        condition = if_match.group(1).strip()
        if len(condition) < 150:
            requirements.append(f"Certificates matching the following must exist: {condition}")
    
    # Look for "must be present" or "must exist"
    must_exist_pattern = r'certificates?\s+must\s+(?:be\s+)?(?:present|exist)[^\.]*\.'
    if re.search(must_exist_pattern, check_text, re.IGNORECASE):
        if not any("disallowed" in req.lower() for req in requirements):
            requirements.append("Certificates matching the specified criteria must be present in the disallowed store.")
    
    if requirements:
        return ". ".join(requirements) + ". If they are not, this is a finding."
    
    return ""


def _extract_autonomous_notes(check_text: str) -> str:
    """Extract notes from check_text that are autonomous (no external references)."""
    import re
    
    notes = []
    
    # Extract registry paths if present
    registry_pattern = r'Registry\s+(?:Hive|Path|Location):\s*([^\n]+)'
    registry_matches = re.findall(registry_pattern, check_text, re.IGNORECASE)
    if registry_matches:
        for match in registry_matches[:2]:  # Limit to 2
            reg_path = match.strip()
            if len(reg_path) < 150:
                notes.append(f"Registry location: {reg_path}")
    
    # Extract file paths if present
    file_path_pattern = r'([/\\][a-zA-Z0-9_/\\\\.-]+\.(?:conf|config|cfg|ini|xml|yml|yaml|json|log|txt))'
    file_matches = re.findall(file_path_pattern, check_text)
    if file_matches:
        for match in set(file_matches[:2]):  # Limit to 2 unique paths
            file_path = match.strip()
            if len(file_path) < 150:
                notes.append(f"File location: {file_path}")
    
    # Extract specific configuration values mentioned
    config_pattern = r'([A-Za-z0-9_]+)\s*=\s*([^\s,;]+)'
    config_matches = re.findall(config_pattern, check_text)
    if config_matches:
        for key, value in config_matches[:2]:  # Limit to 2
            if len(key) < 50 and len(value) < 50:
                notes.append(f"Configuration: {key} = {value}")
    
    # Combine notes
    if notes:
        return "; ".join(notes)
    
    return ""


def _extract_gui_expected_result(check_text: str, pattern: str) -> str:
    """Extract expected result for GUI-based checks."""
    import re
    
    # Look for "if" statements that describe what should be displayed
    if_pattern = r'if\s+["\']?([^"\']+)["\']?\s+does\s+not\s+display\s+["\']?([^"\']+)["\']?'
    match = re.search(if_pattern, check_text, re.IGNORECASE)
    if match:
        field = match.group(1)
        expected_value = match.group(2)
        return f"Verify that '{field}' displays '{expected_value}'. If it does not, this is a finding."
    
    # Look for "must indicate" or "must display"
    must_pattern = r'must\s+(?:indicate|display|show)\s+["\']?([^"\']+)["\']?'
    match = re.search(must_pattern, check_text, re.IGNORECASE)
    if match:
        return f"Verify the field displays: {match.group(1).strip()}"
    
    return ""


def _extract_navigation_steps(check_text: str, app_name: str) -> str:
    """Extract navigation steps from check_text for GUI applications."""
    import re
    
    # Look for navigation instructions like "Navigate to X >> Y"
    nav_pattern = r'Navigate\s+to\s+([^\n]+)'
    match = re.search(nav_pattern, check_text, re.IGNORECASE)
    if match:
        return match.group(1).strip()
    
    # Look for "Under" or "In" statements
    under_pattern = r'Under\s+""([^""]+)""'
    match = re.search(under_pattern, check_text, re.IGNORECASE)
    if match:
        return match.group(1).strip()
    
    # Look for "Select" statements
    select_pattern = r'Select\s+""([^""]+)""'
    match = re.search(select_pattern, check_text, re.IGNORECASE)
    if match:
        return match.group(1).strip()
    
    return ""


def _extract_stig_requirements(check_text: str) -> str:
    """Extract actual STIG requirements from check_text for expected results."""
    import re
    
    requirements = []
    
    # Extract "if" statements that describe what should be checked
    # Pattern: "if X does not display Y" or "if X is not Y"
    if_patterns = [
        (r'if\s+["\']([^"\']+)["\']\s+does\s+not\s+display\s+["\']([^"\']+)["\']', 'display'),
        (r'if\s+["\']([^"\']+)["\']\s+does\s+not\s+show\s+["\']([^"\']+)["\']', 'show'),
        (r'if\s+["\']([^"\']+)["\']\s+is\s+not\s+["\']([^"\']+)["\']', 'be'),
        (r'if\s+["\']([^"\']+)["\']\s+does\s+not\s+indicate\s+["\']([^"\']+)["\']', 'indicate'),
    ]
    
    for pattern, verb in if_patterns:
        matches = re.findall(pattern, check_text, re.IGNORECASE)
        for match in matches:
            field = match[0].strip()
            expected_value = match[1].strip()
            # Clean up expected_value - remove trailing ellipsis and incomplete text
            if expected_value.endswith('...'):
                expected_value = expected_value[:-3].strip()
            if len(expected_value) > 100:  # Too long, probably incomplete
                continue
            req = f"'{field}' must {verb} '{expected_value}'. If it does not, this is a finding."
            if req not in requirements and len(req) < 200:
                requirements.append(req)
    
    # Extract specific value requirements (e.g., "Value: 0x00000001 (1)")
    # Look for registry value requirements
    value_pattern = r'Value:\s*([^\n]+?)(?:\n|$)'
    matches = re.findall(value_pattern, check_text, re.IGNORECASE)
    for match in matches[:2]:  # Limit to 2
        value_str = match.strip()
        # Clean up - remove if too long or contains newlines
        if len(value_str) > 80 or '\n' in value_str:
            continue
        req = f"Value must be set to: {value_str}"
        if req not in requirements:
            requirements.append(req)
    
    # Extract "must" statements (but be careful not to duplicate)
    must_pattern = r'must\s+(?:display|show|indicate|be|have)\s+["\']?([^"\'\n]{5,80})["\']?'
    matches = re.findall(must_pattern, check_text, re.IGNORECASE)
    for match in matches[:2]:  # Limit to 2
        req = f"Must be: {match.strip()}"
        # Don't add if we already have a similar requirement
        if not any(match.strip() in r for r in requirements):
            if req not in requirements:
                requirements.append(req)
    
    # Extract "should" statements
    should_pattern = r'should\s+(?:be|display|show|indicate)\s+["\']?([^"\'\n]{5,80})["\']?'
    matches = re.findall(should_pattern, check_text, re.IGNORECASE)
    for match in matches[:2]:  # Limit to 2
        req = f"Should be: {match.strip()}"
        if req not in requirements:
            requirements.append(req)
    
    # Extract "verify" statements that contain requirements
    # Pattern: "Verify X. If it does not, this is a finding."
    verify_pattern = r'verify\s+([^\.]+?)(?:\.\s+If\s+it\s+does\s+not|\.\s+If\s+not|\.)'
    matches = re.findall(verify_pattern, check_text, re.IGNORECASE)
    for match in matches[:2]:  # Limit to 2
        req_text = match.strip()
        # Only use if it's a substantive requirement (not just "compliance")
        if len(req_text) > 15 and len(req_text) < 150 and 'compliance' not in req_text.lower():
            req = f"Must: {req_text}. If it does not, this is a finding."
            if req not in requirements:
                requirements.append(req)
    
    # Clean up requirements - remove duplicates and overly long ones
    cleaned_requirements = []
    seen = set()
    for req in requirements:
        # Normalize for comparison
        req_lower = req.lower()
        if req_lower not in seen and len(req) < 250:
            seen.add(req_lower)
            cleaned_requirements.append(req)
    
    # Combine requirements into a single string
    if cleaned_requirements:
        # Join with semicolons for clarity, limit to 2 most important
        return "; ".join(cleaned_requirements[:2])
    
    return ""


def _extract_verification_points(check_text: str) -> list[str]:
    """Extract key verification points from check_text."""
    import re
    
    points = []
    
    # Look for "if" statements that indicate what to check
    if_pattern = r'if\s+([^,]+?)(?:,|\.|this is a finding)'
    matches = re.findall(if_pattern, check_text, re.IGNORECASE)
    for match in matches[:3]:  # Limit to 3
        point = match.strip()
        if len(point) > 10 and len(point) < 150:
            points.append(point)
    
    # Look for "verify" statements
    verify_pattern = r'verify\s+([^\.]+?)(?:\.|$)'
    matches = re.findall(verify_pattern, check_text, re.IGNORECASE)
    for match in matches[:2]:  # Limit to 2
        point = match.strip()
        if len(point) > 10 and len(point) < 150:
            points.append(point)
    
    return points[:5]  # Total limit


def _extract_network_steps(control: StigControl, check_text: str) -> list[dict[str, str]]:
    """Extract network device-specific manual steps from check_text."""
    import re
    
    steps = []
    
    # Use structured check commands from control
    check_commands = control.check_commands or control.candidate_check_blocks
    
    # Filter for show commands (most common for network verification)
    show_commands = [cmd for cmd in check_commands if cmd.lower().startswith('show ')]
    
    # If no show commands, use any valid IOS commands
    if not show_commands:
        show_commands = check_commands[:5] if check_commands else []  # Limit to 5 commands
    
    found_commands = set()
    for cmd in show_commands:
        if cmd and len(cmd) > 5 and len(cmd) < 150 and cmd not in found_commands:
            found_commands.add(cmd)
            
            # Extract specific expected result
            expected = _extract_network_expected_result(check_text, cmd)
            if not expected:
                expected = _extract_stig_requirements(check_text)
            if not expected:
                # Look for "if" statements
                if_match = re.search(r'if\s+([^,\.]{20,100}),\s+this\s+is\s+a\s+finding', check_text, re.IGNORECASE)
                if if_match:
                    condition = if_match.group(1).strip()
                    expected = f"The following condition must NOT be true: {condition}. If it is true, this is a finding."
                else:
                    expected = "Command output displayed. Verify the output matches the expected configuration. If it does not, this is a finding."
            
            notes = _extract_autonomous_notes(check_text)
            
            expected_output = _extract_expected_screen_output(check_text)
            steps.append({
                "action": f"Connect to the network device and run: `{cmd}`",
                "expected": expected,
                "expected_output": expected_output,
                "notes": notes or ""
            })
    
    # Extract interface configuration examples from check_text
    interface_pattern = r'interface\s+([A-Za-z0-9/]+)'
    interface_matches = re.findall(interface_pattern, check_text, re.IGNORECASE)
    if interface_matches and not found_commands:
        # If we found interfaces but no show commands, create verification steps
        for iface in set(interface_matches[:2]):
            expected = _extract_stig_requirements(check_text)
            if not expected:
                expected = f"Interface {iface} must be configured as specified. If it is not, this is a finding."
            
            expected_output = _extract_expected_screen_output(check_text)
            steps.append({
                "action": f"Review the configuration of interface {iface} on the network device.",
                "expected": expected,
                "expected_output": expected_output,
                "notes": "Verify the interface configuration matches the STIG requirements."
            })
    
    # If no steps extracted, create manual verification step
    if not steps:
        verification_points = _extract_verification_points(check_text)
        stig_requirements = _extract_stig_requirements(check_text)
        
        if verification_points:
            action_parts = ["Manually verify the following on the network device:"]
            for point in verification_points[:3]:
                # Clean up verification points
                point_clean = point.strip()
                if len(point_clean) > 10 and len(point_clean) < 120:
                    action_parts.append(f"- {point_clean}")
            action = "\n".join(action_parts) if len(action_parts) > 1 else action_parts[0]
        else:
            control_id = _format_nist_control_id(control.nist_family_id) if control.nist_family_id else control.id
            action = f"Manually verify compliance with control {control_id} on the network device."
        
        expected_result = stig_requirements if stig_requirements else "All verification requirements must be met. If any requirement is not met, this is a finding."
        notes = _extract_autonomous_notes(check_text)
        
        expected_output = _extract_expected_screen_output(check_text)
        steps.append({
            "action": action,
            "expected": expected_result,
            "expected_output": expected_output,
            "notes": notes or ""
        })
    
    return steps[:5]  # Limit to 5 steps


def _extract_expected_screen_output(check_text: str) -> str:
    """Extract expected screen output that a user would see."""
    import re
    
    # Look for example outputs in the check text
    # Pattern: "Output should show:" or "Expected output:"
    output_patterns = [
        r'output\s+should\s+show[:\s]+([^\n]{20,200})',
        r'expected\s+output[:\s]+([^\n]{20,200})',
        r'you\s+should\s+see[:\s]+([^\n]{20,200})',
        r'display\s+should\s+show[:\s]+([^\n]{20,200})',
        r'verify\s+that\s+([^\n]{20,200})\s+is\s+displayed',
    ]
    
    for pattern in output_patterns:
        match = re.search(pattern, check_text, re.IGNORECASE)
        if match:
            output = match.group(1).strip()
            # Clean up
            output = re.sub(r'\s+', ' ', output)
            if len(output) < 250:
                return output
    
    # Look for specific value patterns
    value_patterns = [
        r'value\s+should\s+be\s+["\']?([^"\'\n]{5,100})["\']?',
        r'must\s+be\s+set\s+to\s+["\']?([^"\'\n]{5,100})["\']?',
        r'should\s+display\s+["\']?([^"\'\n]{5,100})["\']?',
    ]
    
    for pattern in value_patterns:
        match = re.search(pattern, check_text, re.IGNORECASE)
        if match:
            value = match.group(1).strip()
            if len(value) < 150:
                return f"Output should show: {value}"
    
    # Look for file content patterns
    if "grep" in check_text.lower() or "cat" in check_text.lower():
        # Try to extract what should be in the file
        grep_match = re.search(r'grep\s+["\']?([^"\'\s]+)["\']?', check_text, re.IGNORECASE)
        if grep_match:
            pattern = grep_match.group(1)
            return f"Command output should show lines matching pattern: {pattern}"
    
    # Default
    return "Review the command output and verify it matches the expected result described above."


def _extract_network_expected_result(check_text: str, command: str) -> str:
    """Extract specific expected result for network device commands."""
    import re
    
    # Look for configuration examples that should match
    # Pattern: "interface X\n switchport mode access\n authentication port-control auto"
    if "interface" in command.lower() or "show" in command.lower():
        # Look for "verify that" or "verify the" statements
        verify_pattern = r'verify\s+(?:that|the)\s+([^,\.]{20,150})'
        match = re.search(verify_pattern, check_text, re.IGNORECASE)
        if match:
            verify_text = match.group(1).strip()
            if len(verify_text) < 150:
                return f"Verify that {verify_text}. If it is not, this is a finding."
        
        # Look for "if" statements with specific conditions
        if_pattern = r'if\s+([^,\.]{20,120}),\s+this\s+is\s+a\s+finding'
        match = re.search(if_pattern, check_text, re.IGNORECASE)
        if match:
            condition = match.group(1).strip()
            if len(condition) < 120:
                return f"The following condition must NOT be true: {condition}. If it is true, this is a finding."
    
    # Look for specific configuration values that should be present
    config_patterns = [
        r'switchport\s+mode\s+access',
        r'spanning-tree\s+guard\s+root',
        r'spanning-tree\s+bpduguard\s+enable',
        r'mls\s+qos',
        r'vtp\s+password',
    ]
    
    for pattern in config_patterns:
        if re.search(pattern, check_text, re.IGNORECASE):
            config_name = pattern.replace('\\s+', ' ').replace('\\', '')
            return f"Configuration must include: {config_name}. If it does not, this is a finding."
    
    return ""

