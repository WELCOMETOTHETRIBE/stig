"""Robust command extraction helpers for STIG content."""

import re
from typing import List, Tuple, Optional


def split_command_and_prose(line: str) -> Tuple[Optional[str], Optional[str]]:
    """
    Split a raw line into command and prose portions.
    
    Given a raw line from fix_text or check_text, return:
      - command: the executable command portion, if any (None if no command found)
      - prose: any trailing narrative ("Verify that ...", etc.) (None if no prose found)
    
    Heuristics:
    - Treat the command as the part from the beginning up to prose markers
    - Prose markers include: " Verify that", " verify that", "NOTE:", " For example", etc.
    - If line starts with a shell-like token, treat that as a command candidate
    
    Args:
        line: Raw line from STIG text
        
    Returns:
        Tuple of (command, prose) where either or both may be None
    """
    if not line or not line.strip():
        return None, None
    
    line = line.strip()
    
    # Prose markers that indicate the start of narrative text
    prose_markers = [
        r'\s+Verify\s+that\s+',
        r'\s+verify\s+that\s+',
        r'\s+Verify\s+(?:that\s+)?(?:RHEL\s+\d+\s+)?',
        r'\s+verify\s+(?:that\s+)?(?:RHEL\s+\d+\s+)?',
        r'\s+NOTE\s*:',
        r'\s+Note\s*:',
        r'\s+note\s*:',
        r'\s+For\s+example',
        r'\s+for\s+example',
        r'\s+as\s+shown',
        r'\s+review\s+the\s+output',
        r'\s+Review\s+the\s+output',
        r'\s+Check\s+that\s+',
        r'\s+check\s+that\s+',
        r'\s+Ensure\s+that\s+',
        r'\s+ensure\s+that\s+',
        r'\s+Add\s+or\s+update',
        r'\s+add\s+or\s+update',
        r'\s+Configure\s+the\s+',
        r'\s+configure\s+the\s+',
    ]
    
    # Find the first prose marker
    prose_start = None
    prose_marker = None
    for marker in prose_markers:
        match = re.search(marker, line, re.IGNORECASE)
        if match:
            prose_start = match.start()
            prose_marker = marker
            break
    
    if prose_start is not None:
        # Split on the prose marker
        command_part = line[:prose_start].strip()
        prose_part = line[prose_start:].strip()
        
        # Only return command if it looks like a real command
        if command_part and len(command_part) > 2:
            # Check if command part looks like a command (starts with alphanumeric or common command chars)
            if re.match(r'^[a-zA-Z0-9_/.\-$]', command_part):
                return command_part, prose_part if prose_part else None
        
        # If command part doesn't look valid, treat whole line as prose
        return None, line
    
    # No prose marker found - check if entire line looks like prose
    prose_starters = [
        r'^Verify\s+that',
        r'^verify\s+that',
        r'^NOTE\s*:',
        r'^Note\s*:',
        r'^Add\s+or\s+update',
        r'^Configure\s+the',
        r'^Review\s+the',
        r'^Check\s+that',
    ]
    
    for starter in prose_starters:
        if re.match(starter, line, re.IGNORECASE):
            return None, line
    
    # No prose marker, treat as potential command
    if line and len(line) > 2:
        return line, None
    
    return None, None


def is_placeholder_command(line: str) -> bool:
    """
    Detect if a line contains placeholder tokens that make it non-automatable.
    
    Placeholders include:
    - <...> patterns like <unauthorized_user>, <file>, etc.
    - [...] patterns like [user], [Public Directory], [PART] (when clearly placeholders)
    
    Args:
        line: Command line to check
        
    Returns:
        True if line contains placeholders, False otherwise
    """
    if not line:
        return False
    
    # Pattern for <...> placeholders
    angle_bracket_pattern = r'<[^>]+>'
    if re.search(angle_bracket_pattern, line):
        return True
    
    # Pattern for [...] placeholders (but be careful - some are real flags like [-f])
    # Look for patterns like [user], [Public Directory], [PART] - typically capitalized or multi-word
    bracket_patterns = [
        r'\[[A-Z][a-zA-Z\s]+\]',  # [Public Directory], [PART], etc.
        r'\[user\]',  # Common placeholder
        r'\[file\]',  # Common placeholder
        r'\[directory\]',  # Common placeholder
        r'\[path\]',  # Common placeholder
    ]
    
    for pattern in bracket_patterns:
        if re.search(pattern, line, re.IGNORECASE):
            return True
    
    return False


def extract_cli_commands_from_block(text: str, purpose: str = "hardening") -> Tuple[List[str], List[str]]:
    """
    Extract CLI commands from a text block (Cisco IOS style).
    
    Given a raw text block from Fix Text or example sections,
    return (commands, notes).
    
    - commands: clean CLI commands (no prompts, no English sentences)
    - notes: remaining text (context, explanations) that is useful for CTP Notes
    
    Args:
        text: Raw text block containing potential CLI commands
        purpose: "hardening" (config commands) or "check" (show commands only)
        
    Returns:
        Tuple of (commands, notes) where:
        - commands: clean CLI commands ready for use
        - notes: contextual text for documentation
    """
    commands = []
    notes = []
    
    # Split into lines
    lines = [line.strip() for line in text.split('\n') if line.strip()]
    
    # Common IOS mode markers that should be filtered out
    mode_markers = {
        'config)', 'config-if)', 'config-ext-nacl)', 'config-cmap)', 'config-pmap)',
        'config-pmap-c)', 'config-pmap-c-police)', 'config-ipv6-acl)', 'config-std-nacl)',
        'config-line)', 'config-router)', 'config-vlan)', 'config-if-range)',
        'config-route-map)', 'config-router-ospf)', 'config-router-eigrp)', 'config-router-bgp)',
    }
    
    # Patterns that indicate prose/explanatory text (NOT commands)
    prose_patterns = [
        r'^[A-Z][^:]*:$',  # Lines ending with colon (often explanatory)
        r'as shown (below|above|in the example)',
        r'configure the (switch|device|router) to',
        r'disable all .* as shown',
        r'^example:',
        r'^alternate:',
        r'^note:',
        r'^step \d+',
        r'^the following',
        r'^verify that',
        r'^document all',
        r'^review the',
        r'^check the',
        r'^ensure that',
        r'^make sure',
        r'^see (the|below|above)',
        r'^ipv4 example:',
        r'^ipv6 example:',
    ]
    
    # Patterns that indicate real IOS commands
    ios_command_patterns = [
        r'^interface\s+[A-Za-z0-9/]+',
        r'^ip\s+',
        r'^no\s+',
        r'^switchport\s+',
        r'^spanning-tree\s+',
        r'^vlan\s+',
        r'^vtp\s+',
        r'^mls\s+',
        r'^dot1x\s+',
        r'^aaa\s+',
        r'^radius\s+',
        r'^tacacs\s+',
        r'^line\s+',
        r'^access-list\s+',
        r'^ip\s+access-list\s+',
        r'^route-map\s+',
        r'^router\s+',
        r'^hostname\s+',
        r'^banner\s+',
        r'^enable\s+secret',
        r'^username\s+',
        r'^service\s+',
        r'^logging\s+',
        r'^ntp\s+',
        r'^snmp-server\s+',
        r'^crypto\s+',
        r'^key\s+chain\s+',
        r'^key\s+\d+',
        r'^authentication\s+',
        r'^encryption\s+',
        r'^show\s+',
    ]
    
    seen_commands = set()
    
    for line in lines:
        if not line:
            continue
        
        # Skip XML/HTML tags
        if line.startswith('<') or line.startswith('&'):
            continue
        
        # Skip comments
        if line.startswith('!'):
            continue
        
        # Filter out mode markers (exact match, case-insensitive)
        if line.lower() in {m.lower() for m in mode_markers}:
            notes.append(f"Mode marker: {line}")
            continue
        
        # Filter out lines that are just mode markers (ending with ) and no spaces)
        if re.match(r'^config[^)]*\)$', line, re.IGNORECASE):
            notes.append(f"Mode marker pattern: {line}")
            continue
        
        # Filter out prose/explanatory text
        is_prose = False
        for pattern in prose_patterns:
            if re.search(pattern, line, re.IGNORECASE):
                is_prose = True
                notes.append(f"Prose text: {line}")
                break
        
        if is_prose:
            continue
        
        # Strip IOS prompts (e.g., SW1(config)# command or Switch# command)
        prompt_match = re.match(r'^[A-Z0-9]+(?:\([^)]+\))?#\s*(.+)', line)
        if prompt_match:
            line = prompt_match.group(1).strip()
            if not line:
                continue
        
        # For check purpose, only extract show commands
        if purpose == "check":
            # Only show commands are valid for checking
            if not line.lower().startswith('show '):
                # Not a show command, skip it
                if line and len(line) < 500:
                    notes.append(f"Non-show command (skipped for check): {line}")
                continue
        
        # Configuration commands that should NOT be used for checking
        config_only_commands = [
            r'^interface\s+',
            r'^hostname\s+',
            r'^no\s+',
            r'^switchport\s+',
            r'^spanning-tree\s+',
            r'^vlan\s+',
            r'^vtp\s+',
            r'^mls\s+',
            r'^dot1x\s+',
            r'^aaa\s+',
            r'^radius\s+',
            r'^tacacs\s+',
            r'^line\s+',
            r'^access-list\s+',
            r'^ip\s+access-list\s+',
            r'^route-map\s+',
            r'^router\s+',
            r'^banner\s+',
            r'^enable\s+secret',
            r'^username\s+',
            r'^service\s+',
            r'^logging\s+',
            r'^ntp\s+',
            r'^snmp-server\s+',
            r'^crypto\s+',
            r'^key\s+chain\s+',
            r'^key\s+\d+',
            r'^authentication\s+',
            r'^encryption\s+',
        ]
        
        # For check purpose, reject configuration commands
        if purpose == "check":
            is_config_command = False
            for pattern in config_only_commands:
                if re.match(pattern, line, re.IGNORECASE):
                    is_config_command = True
                    break
            if is_config_command:
                if line and len(line) < 500:
                    notes.append(f"Config command (skipped for check): {line}")
                continue
        
        # Check if line looks like a real IOS command
        is_command = False
        for pattern in ios_command_patterns:
            if re.match(pattern, line, re.IGNORECASE):
                is_command = True
                break
        
        # Additional heuristics for commands
        if not is_command:
            ios_keywords = [
                'interface', 'ip', 'switchport', 'vlan', 'spanning-tree',
                'vtp', 'mls', 'dot1x', 'aaa', 'radius', 'tacacs',
                'access-list', 'route-map', 'router', 'hostname',
                'banner', 'enable', 'username', 'service', 'logging',
                'ntp', 'snmp', 'crypto', 'key', 'authentication',
                'encryption', 'no ', 'shutdown', 'description', 'show'
            ]
            
            line_lower = line.lower()
            has_ios_keyword = any(keyword in line_lower for keyword in ios_keywords)
            
            if has_ios_keyword:
                if (len(line) < 200 and 
                    not line.endswith(('.', ':', ';')) and
                    not re.match(r'^[A-Z][a-z]+\s+[a-z]+', line)):
                    is_command = True
        
        if is_command:
            # Clean up the command
            cmd = line.strip()
            cmd = re.sub(r'[.,;:]$', '', cmd)
            
            if len(cmd) < 3:
                continue
            
            cmd_normalized = cmd.lower().strip()
            if cmd_normalized not in seen_commands:
                seen_commands.add(cmd_normalized)
                commands.append(cmd)
        else:
            # Not a command, add to notes
            if line and len(line) < 500:
                notes.append(line)
    
    return commands, notes


def extract_shell_commands_from_block(text: str, os_family: str = "rhel", purpose: str = "hardening") -> Tuple[List[str], List[str]]:
    """
    Extract shell commands from a text block (RHEL/Ubuntu/Windows CLI style).
    
    Enhanced filtering to only extract real commands, filtering out narrative/placeholder text.
    
    Args:
        text: Raw text block containing potential shell commands
        os_family: OS family (rhel, windows, ubuntu, etc.)
        purpose: "hardening" or "check" - affects extraction rules
        
    Returns:
        Tuple of (commands, notes) where:
        - commands: clean shell commands ready for use
        - notes: contextual text for documentation
    """
    commands = []
    notes = []
    
    # Split into lines
    lines = [line.strip() for line in text.split('\n') if line.strip()]
    
    # Expanded patterns that indicate prose/explanatory text (NOT commands)
    prose_patterns = [
        r'^[A-Z][^:]*:$',  # Lines ending with colon (often explanatory)
        r'as shown (below|above|in the example)',
        r'^example:',
        r'^alternate:',
        r'^note:',
        r'^step \d+',
        r'^the following',
        r'^verify that',
        r'^verify rhel',
        r'^verify the',
        r'^document all',
        r'^review the',
        r'^check the',
        r'^ensure that',
        r'^make sure',
        r'^see (the|below|above)',
        r'^run the following',
        r'^execute the following',
        r'^if this is not (documented|configured)',
        r'^if this is not (documented|configured)',
        r'^using interactive or recovery boot',
        r'^document the use',
        r'^the system is compliant if',
        r'^for example',
        r'^note\s*:',
        r'^<vulndiscussion>',
        r'^<fixtext>',
        r'^#\s*stig',
        r'^verify\s+that\s+rhel',
        r'^verify\s+rhel',
    ]
    
    # Patterns that indicate real shell commands
    shell_command_patterns = [
        r'^chmod\s+',
        r'^chown\s+',
        r'^systemctl\s+',
        r'^service\s+',
        r'^yum\s+',
        r'^dnf\s+',
        r'^rpm\s+',
        r'^apt\s+',
        r'^grep\s+',
        r'^sed\s+',
        r'^awk\s+',
        r'^cat\s+',
        r'^ls\s+',
        r'^find\s+',
        r'^stat\s+',
        r'^auditctl\s+',
        r'^sysctl\s+',
        r'^setenforce\s+',
        r'^getenforce\s+',
        r'^semanage\s+',
        r'^firewall-cmd\s+',
        r'^iptables\s+',
        r'^netstat\s+',
        r'^ss\s+',
        r'^ps\s+',
        r'^grubby\s+',
        r'^echo\s+',
        r'^modprobe\s+',
        r'^Get-ItemProperty',
        r'^Set-ItemProperty',
        r'^Get-ChildItem',
        r'^Get-Service',
        r'^Get-Process',
        r'^auditpol\s+',
        r'^netsh\s+',
        r'^reg\s+',
        r'^reg\.exe\s+',
        r'^sc\s+',
        r'^wmic\s+',
    ]
    
    seen_commands = set()
    
    for line in lines:
        if not line:
            continue
        
        # Skip XML/HTML tags
        if line.startswith('<') or line.startswith('&'):
            continue
        
        # Skip comments (but preserve them in notes if they're meaningful)
        if line.startswith('#'):
            # Skip pure comment lines, but allow commands that start with # (like # systemctl)
            if not any(pattern.match(line[1:].strip()) for pattern in [re.compile(p, re.IGNORECASE) for p in shell_command_patterns]):
                continue
        
        # Use split_command_and_prose to separate command from narrative
        command_part, prose_part = split_command_and_prose(line)
        
        # If no command part found, treat entire line as prose
        if not command_part:
            if prose_part:
                notes.append(prose_part)
            else:
                # Check if it's pure prose
                is_prose = False
                for pattern in prose_patterns:
                    if re.search(pattern, line, re.IGNORECASE):
                        is_prose = True
                        notes.append(line)
                        break
                if not is_prose:
                    # Might be a command that didn't match our patterns - check manually
                    if any(re.match(pattern, line, re.IGNORECASE) for pattern in shell_command_patterns):
                        command_part = line
            if not command_part:
                continue
        
        # Check for placeholder commands - these should not be automatable
        if is_placeholder_command(command_part):
            # Store as manual note, not as automatable command
            notes.append(f"Manual template command: {command_part}")
            if prose_part:
                notes.append(prose_part)
            continue
        
        # Use the clean command part
        cmd = command_part
        
        # Add prose to notes if present
        if prose_part:
            notes.append(prose_part)
        
        # Strip shell prompts (e.g., $ command or # command or $ sudo command)
        # Handle both $ and $ sudo patterns
        prompt_match = re.match(r'^[$#]\s*(.+)', cmd)
        if prompt_match:
            cmd = prompt_match.group(1).strip()
            if not cmd:
                continue
        
        # Strip $ prompt that might appear mid-line (e.g., "$ sudo command")
        cmd = re.sub(r'^\$\s*', '', cmd)
        
        # Strip sudo prefix
        cmd = re.sub(r'^sudo\s+', '', cmd, flags=re.IGNORECASE)
        
        # Final cleanup: remove trailing punctuation
        cmd = re.sub(r'[.,;:]$', '', cmd)
        
        if len(cmd) < 3:
            continue
        
        # Skip if it's just a flag or placeholder
        cmd_parts = cmd.split()
        if len(cmd_parts) == 1 and cmd_parts[0] in ['-r', '-i', '-n', '-E', '-A1', 'args', '--now', '--mask']:
            notes.append(f"Skipped flag-only command: {cmd}")
            continue
        
        # Handle risky commands conservatively
        # For reboot, we should mark as manual or skip from automated hardening
        risky_commands = ['reboot', 'shutdown', 'poweroff', 'halt']
        cmd_base = cmd_parts[0].lower() if cmd_parts else ""
        if cmd_base in risky_commands and purpose == "hardening":
            # Add to notes instead of commands for hardening
            notes.append(f"Risky command detected (requires manual review): {cmd}")
            continue
        
        # Check if it looks like a real shell command
        is_command = False
        for pattern in shell_command_patterns:
            if re.match(pattern, cmd, re.IGNORECASE):
                is_command = True
                break
        
        # Additional heuristics for commands
        if not is_command:
            shell_keywords = [
                'chmod', 'chown', 'systemctl', 'service', 'yum', 'dnf', 'rpm',
                'apt', 'grep', 'sed', 'awk', 'cat', 'ls', 'find', 'stat',
                'auditctl', 'sysctl', 'setenforce', 'getenforce', 'semanage',
                'firewall-cmd', 'iptables', 'netstat', 'ss', 'ps', 'grubby',
                'echo', 'modprobe', 'userdel', 'passwd', 'augenrules',
                'Get-ItemProperty', 'Set-ItemProperty', 'Get-ChildItem',
                'Get-Service', 'Get-Process', 'auditpol', 'netsh', 'reg',
                'sc', 'wmic'
            ]
            
            cmd_lower = cmd.lower()
            has_shell_keyword = any(keyword.lower() in cmd_lower for keyword in shell_keywords)
            
            if has_shell_keyword:
                # More strict: don't accept if it ends with colon or looks like prose
                if (len(cmd) < 300 and 
                    not cmd.endswith(('.', ':', ';')) and
                    not re.match(r'^[A-Z][a-z]+\s+[a-z]+', cmd) and
                    not re.search(r'verify\s+(that|rhel)', cmd_lower)):
                    is_command = True
        
        if is_command:
            cmd_normalized = cmd.lower().strip()
            if cmd_normalized not in seen_commands:
                seen_commands.add(cmd_normalized)
                commands.append(cmd)
        else:
            # Not a command, add to notes
            if cmd and len(cmd) < 500:
                notes.append(f"Potential command (not recognized): {cmd}")
    
    return commands, notes


def extract_check_commands_from_block(text: str, os_family: str) -> Tuple[List[str], List[str]]:
    """
    Extract check/validation commands from a text block.
    
    Enhanced filtering to avoid degenerate grep patterns and ensure meaningful commands.
    
    Args:
        text: Raw text block containing potential check commands
        os_family: OS family (rhel, windows, ubuntu, network, etc.)
        
    Returns:
        Tuple of (commands, notes) where:
        - commands: clean check commands ready for use
        - notes: contextual text for documentation
    """
    if os_family == "network":
        return extract_cli_commands_from_block(text, purpose="check")
    else:
        commands, notes = extract_shell_commands_from_block(text, os_family, purpose="check")
        
        # Additional filtering for check commands: ensure grep patterns are meaningful
        filtered_commands = []
        degenerate_flags = {'-r', '-i', '-n', '-E', '-A1', '-A', '-B', '-C', 'args'}
        
        for cmd in commands:
            # Check if it's a grep command
            if cmd.lower().startswith('grep'):
                # Extract the pattern part (after flags)
                # Patterns can be:
                # - grep -E 'PATTERN' file
                # - grep -E "PATTERN" file
                # - grep -E PATTERN file (unquoted)
                # - grep -rn PATTERN file
                
                # First, try to extract quoted patterns
                quoted_patterns = re.findall(r"['\"]([^'\"]+)['\"]", cmd)
                unquoted_parts = []
                
                # Split command and process parts
                parts = cmd.split()
                pattern_found = False
                pattern_value = None
                
                # Check quoted patterns first
                for pattern in quoted_patterns:
                    pattern_clean = pattern.strip()
                    # Skip if pattern is just a flag
                    if pattern_clean in degenerate_flags or pattern_clean.startswith('-') and len(pattern_clean) <= 3:
                        continue
                    # Pattern must have meaningful content (at least 3 alphanumeric chars)
                    if len(pattern_clean) >= 3 and re.search(r'[A-Za-z0-9_.=-]{3,}', pattern_clean):
                        pattern_found = True
                        pattern_value = pattern_clean
                        break
                
                # If no quoted pattern found, check unquoted parts
                if not pattern_found:
                    for part in parts:
                        # Skip flags
                        if part.startswith('-'):
                            continue
                        # Skip file paths (usually start with /)
                        if part.startswith('/'):
                            continue
                        # Found a potential pattern
                        part_clean = part.strip("'\"")
                        # Must not be a degenerate flag
                        if part_clean in degenerate_flags:
                            continue
                        # Must have meaningful content
                        if len(part_clean) >= 3 and re.search(r'[A-Za-z0-9_.=-]{3,}', part_clean):
                            pattern_found = True
                            pattern_value = part_clean
                            break
                
                if pattern_found and pattern_value:
                    filtered_commands.append(cmd)
                else:
                    notes.append(f"Skipped degenerate grep command: {cmd}")
            else:
                # Not a grep command, keep it
                filtered_commands.append(cmd)
        
        return filtered_commands, notes


def parse_systemctl_command(cmd: str) -> Optional[dict]:
    """
    Parse a systemctl command and extract:
    - action: "enable", "disable", "mask", "unmask", "start", "stop"
    - unit: the systemd unit name, normalized (ensure `.service` if appropriate)
    
    Examples:
    "systemctl enable --now rngd"           -> {"action": "enable_and_start", "unit": "rngd.service"}
    "systemctl disable debug-shell.service" -> {"action": "disable", "unit": "debug-shell.service"}
    "systemctl mask kdump"                  -> {"action": "mask", "unit": "kdump.service"}
    
    Returns:
        Dict with "action" and "unit" keys, or None if parsing fails
    """
    if not cmd:
        return None
    
    normalized = normalize_command_line(cmd)
    
    # Must contain systemctl
    if 'systemctl' not in normalized.lower():
        return None
    
    # Known flags that should never be treated as unit names
    invalid_flags = {'--now', '--mask', '--unmask', '--force', '--no-reload', '--no-block', '--status'}
    
    # Stopwords that should never be unit names
    stopwords = {'run', 'that', 'all', 'is', 'contents', 'red', 'the', 'a', 'an', 'and', 'or', 'with', 'on', 'following'}
    
    # Handle daemon-reload separately (not a service action)
    if re.search(r'systemctl\s+daemon-reload', normalized, re.IGNORECASE):
        return None
    
    # Try to match various systemctl patterns
    # Order matters: more specific patterns first
    # IMPORTANT: Patterns must not allow flags to be captured as unit names
    # Unit name pattern: alphanumeric, dots, @, and dashes (but not starting with dash)
    unit_pattern = r'[a-zA-Z0-9@.][a-zA-Z0-9@.-]*'
    patterns = [
        # With --now after unit: systemctl enable rngd --now
        rf'systemctl\s+(enable|disable|mask|unmask|stop|start|restart)\s+({unit_pattern})\s+--now',
        # With --now between action and unit: systemctl enable --now rngd (common format)
        rf'systemctl\s+(enable|disable|mask|unmask|stop|start|restart)\s+--now\s+({unit_pattern})',
        # With --now before action: systemctl --now enable rngd
        rf'systemctl\s+--now\s+(enable|disable|mask|unmask|stop|start|restart)\s+({unit_pattern})',
        # Standard: systemctl enable rngd (without --now flag, use negative lookahead)
        rf'systemctl\s+(enable|disable|mask|unmask|stop|start|restart)\s+({unit_pattern})(?!\s+--now)',
    ]
    
    for pattern in patterns:
        match = re.search(pattern, normalized, re.IGNORECASE)
        if match:
            action = match.group(1).lower()
            unit = match.group(2).strip()
            
            # Validate unit name - must not be a flag or stopword
            if not unit:
                continue
            if unit.startswith('-'):
                continue
            if unit.lower() in invalid_flags:
                continue
            if unit.lower() in stopwords:
                continue
            
            # Unit name must contain at least one alphanumeric character
            if not re.search(r'[a-zA-Z0-9]', unit):
                continue
            
            # Unit name should look like a service name (contains letters)
            if not re.search(r'[a-zA-Z]', unit):
                continue
            
            # Normalize unit name - ensure .service suffix if not present and no @ symbol
            if '@' not in unit and '.' not in unit:
                unit = f"{unit}.service"
            elif '@' in unit and not unit.endswith('.service'):
                # Template units like user@1000.service should keep their format
                pass
            
            # Determine structured action
            has_now = '--now' in normalized.lower()
            
            if action == 'enable' and has_now:
                structured_action = "enable_and_start"
            elif action == 'mask':
                structured_action = "mask"
            elif action == 'unmask':
                structured_action = "unmask"
            elif action == 'disable':
                structured_action = "disable"
            elif action == 'stop':
                structured_action = "stop"
            elif action == 'start':
                structured_action = "start"
            elif action == 'restart':
                structured_action = "restart"
            else:
                structured_action = "enable"
            
            return {
                "unit": unit,
                "action": structured_action
            }
    
    return None


def extract_systemd_actions(text: str) -> List[dict]:
    """
    Extract systemd service actions from text.
    
    Detects patterns like:
    - systemctl enable <unit> --now
    - systemctl --now enable <unit>
    - systemctl mask <unit>
    - systemctl disable <unit>
    - systemctl stop <unit>
    - systemctl restart <unit>
    - systemctl unmask <unit>
    
    Returns:
        List of dicts with keys: unit, action
        Actions: "enable_and_start", "mask", "unmask", "disable", "stop", "start", "restart", "enable"
    """
    actions = []
    lines = text.split('\n')
    
    for line in lines:
        parsed = parse_systemctl_command(line)
        if parsed:
            actions.append(parsed)
    
    return actions


def extract_sysctl_params(text: str) -> List[dict]:
    """
    Extract sysctl parameters and values from text.
    
    Detects both config-file and command-style forms:
    - kernel.randomize_va_space = 2
    - sysctl -w kernel.randomize_va_space=2
    
    Returns:
        List of dicts with keys: name, value
    """
    params = []
    
    # Pattern 1: Config file style: kernel.param = value
    pattern1 = r'([a-z0-9_.]+)\s*=\s*([0-9]+|[a-zA-Z0-9]+)'
    matches = re.findall(pattern1, text, re.IGNORECASE)
    for name, value in matches:
        # Filter out non-sysctl patterns
        if '.' in name and len(name.split('.')) >= 2:
            params.append({"name": name, "value": str(value)})
    
    # Pattern 2: Command style: sysctl -w kernel.param=value
    pattern2 = r'sysctl\s+(?:-w\s+)?([a-z0-9_.]+)\s*=\s*([0-9]+|[a-zA-Z0-9]+)'
    matches = re.findall(pattern2, text, re.IGNORECASE)
    for name, value in matches:
        if '.' in name:
            params.append({"name": name, "value": str(value)})
    
    # Pattern 3: /proc/sys/ path style
    pattern3 = r'/proc/sys/([a-z0-9_/.-]+)\s*=\s*([0-9]+|[a-zA-Z0-9]+)'
    matches = re.findall(pattern3, text, re.IGNORECASE)
    for path, value in matches:
        # Convert path to sysctl name
        name = path.replace('/', '.')
        params.append({"name": name, "value": str(value)})
    
    # Deduplicate by name
    seen = {}
    for param in params:
        name = param["name"]
        if name not in seen:
            seen[name] = param
    
    return list(seen.values())


def normalize_command_line(line: str) -> str:
    """
    Strip surrounding whitespace, leading shell prompts (`$`, `#`),
    and surrounding backticks. Collapse internal whitespace to single spaces.
    
    Args:
        line: Raw command line string
        
    Returns:
        Normalized command line
    """
    if not line:
        return ""
    
    # Strip surrounding whitespace
    line = line.strip()
    
    # Strip leading shell prompts
    line = re.sub(r'^[$#]\s*', '', line)
    
    # Strip surrounding backticks
    line = re.sub(r'^`+|`+$', '', line)
    
    # Strip sudo prefix
    line = re.sub(r'^sudo\s+', '', line, flags=re.IGNORECASE)
    
    # Collapse internal whitespace to single spaces
    line = re.sub(r'\s+', ' ', line)
    
    return line.strip()


def is_probable_cli_command(line: str) -> bool:
    """
    Return True if line looks like a real shell command the operator would type.
    
    Rules:
    - Work on the normalized line.
    - Reject empty lines.
    
    Reject if:
    - First token is purely numeric (e.g., "600", "640", "755").
    - First token is clearly a value or identifier, not a binary:
      - e.g., "root", "false", "'lock-screen'", "AutomaticLoginEnable=false"
    - The line looks like sample output:
      - starts with "/dev/" followed by "on ..."
      - starts with a bare path followed by "type vfat", "type xfs", etc.
      - starts with "LoadState=", "UnitFileState=", "services:", "protocols"
    - The line is obviously a config/value line rather than a command:
      - contains "=" but no known command at the beginning
      - starts with tokens like "GRUB2_PASSWORD=", "GRUB_CMDLINE_LINUX=", "MACs ", "PubkeyAuthentication ", "PermitEmptyPasswords ", "HostbasedAuthentication ", "GSSAPIAuthentication ", "KerberosAuthentication ".
    - Contains unresolved placeholders like "PART" where a filesystem path should be.
    
    Accept if:
    - First token is in a known allowlist of common CLI tools:
      {"cat","grep","egrep","fgrep","awk","sed","stat","find","mount","systemctl",
       "grubby","gsettings","dnf","yum","rpm","lsblk","cryptsetup","firewall-cmd",
       "ip","sshd","/usr/sbin/sshd","gpg","ls","df","chmod","chown","chgrp"} or
       starts with "/" and is clearly an executable path.
    - Or matches a pattern like:
      - starts with "sudo " followed by an allowed executable
    """
    normalized = normalize_command_line(line)
    
    if not normalized:
        return False
    
    # Reject empty lines
    if len(normalized) < 3:
        return False
    
    # Reject placeholder commands
    if is_placeholder_command(normalized):
        return False
    
    # Split into tokens
    tokens = normalized.split()
    if not tokens:
        return False
    
    first_token = tokens[0]
    first_token_lower = first_token.lower()
    
    # Reject if first token is purely numeric (mode numbers)
    if re.match(r'^[0-7]{3,4}$', first_token):
        return False
    
    # Reject if first token is a known value/identifier (not a command)
    value_identifiers = {
        "root", "bin", "daemon", "false", "true", "yes", "no",
        "'lock-screen'", "lock-screen", "AutomaticLoginEnable=false"
    }
    if first_token_lower in value_identifiers or first_token in value_identifiers:
        return False
    
    # Reject config/value lines (starts with config key patterns)
    config_key_patterns = [
        r'^GRUB2_PASSWORD=',
        r'^GRUB_CMDLINE_LINUX=',
        r'^MACs\s+',
        r'^PubkeyAuthentication\s+',
        r'^PermitEmptyPasswords\s+',
        r'^HostbasedAuthentication\s+',
        r'^GSSAPIAuthentication\s+',
        r'^KerberosAuthentication\s+',
    ]
    for pattern in config_key_patterns:
        if re.match(pattern, normalized, re.IGNORECASE):
            return False
    
    # Reject sample output patterns
    output_patterns = [
        r'^/dev/[^\s]+\s+on\s+',  # /dev/sda1 on /boot/efi type vfat
        r'^[^\s]+\s+type\s+(vfat|xfs|ext4)',  # path type vfat
        r'^LoadState=',
        r'^UnitFileState=',
        r'^services:',
        r'^protocols',
    ]
    for pattern in output_patterns:
        if re.match(pattern, normalized, re.IGNORECASE):
            return False
    
    # Reject lines with "=" but no command at beginning (config values)
    if '=' in normalized and not any(normalized.startswith(cmd) for cmd in [
        "grep", "awk", "sed", "export", "set", "unset"
    ]):
        # Check if it starts with a config key pattern
        if re.match(r'^[A-Z_][A-Z0-9_]*=', normalized):
            return False
    
    # Known CLI tools allowlist
    allowed_commands = {
        "cat", "grep", "egrep", "fgrep", "awk", "sed", "stat", "find",
        "mount", "systemctl", "grubby", "gsettings", "dnf", "yum", "rpm",
        "lsblk", "cryptsetup", "firewall-cmd", "ip", "sshd", "/usr/sbin/sshd",
        "gpg", "ls", "df", "chmod", "chown", "chgrp", "chattr", "lsattr",
        "getenforce", "setenforce", "semanage", "auditctl", "ausearch",
        "aureport", "sysctl", "modprobe", "rmmod", "insmod", "lsmod",
        "passwd", "useradd", "userdel", "groupadd", "groupdel", "usermod",
        "groupmod", "id", "whoami", "who", "w", "last", "lastlog",
        "crontab", "at", "atq", "atrm", "service", "chkconfig",
        "iptables", "ip6tables", "netstat", "ss", "ps", "top", "htop",
        "free", "vmstat", "iostat", "sar", "tcpdump", "wireshark",
        "traceroute", "ping", "nslookup", "dig", "host", "getent",
        "cut", "sort", "uniq", "wc", "head", "tail", "less", "more",
        "vi", "vim", "nano", "emacs", "touch", "mkdir", "rmdir", "rm",
        "cp", "mv", "ln", "tar", "gzip", "gunzip", "zip", "unzip",
        "rpm", "dpkg", "apt", "apt-get", "apt-cache", "snap",
        "journalctl", "dmesg", "lsblk", "blkid", "fdisk", "parted",
        "mkfs", "fsck", "mount", "umount", "df", "du", "ncdu",
        "rsync", "scp", "sftp", "ssh", "ssh-keygen", "ssh-add",
        "curl", "wget", "lynx", "links", "elinks", "nc", "telnet",
        "openssl", "gpg", "gpg2", "certutil", "keytool",
        "systemctl", "systemd-analyze", "systemd-cgls", "systemd-cgtop",
        "loginctl", "hostnamectl", "localectl", "timedatectl",
        "networkctl", "resolvectl", "busctl", "coredumpctl",
        "firewall-cmd", "firewall-offline-cmd", "iptables", "ip6tables",
        "nft", "nftables", "tc", "ip", "ss", "nmcli", "ifconfig",
        "route", "netstat", "arp", "ethtool", "mii-tool",
        "auditctl", "ausearch", "aureport", "autrace", "auditd",
        "semanage", "getsebool", "setsebool", "getenforce", "setenforce",
        "sestatus", "chcon", "restorecon", "fixfiles", "setfiles",
        "runcon", "newrole", "sandbox", "seunshare",
        "grubby", "grub2-mkconfig", "grub2-set-default", "grub2-setpassword",
        "update-grub", "grub-install", "grub-mkconfig",
        "cryptsetup", "luksFormat", "luksOpen", "luksClose", "luksAddKey",
        "luksRemoveKey", "luksChangeKey", "luksDump",
        "gsettings", "dconf", "dbus-send", "gconftool-2",
        "xrandr", "xset", "xsetroot", "xsetwacom",
        "chage", "passwd", "pwck", "grpck", "vigr", "vipw",
        "faillock", "pam_tally2", "pam_tally",
        "umask", "ulimit", "limits", "sysctl", "sysctl.conf",
        "modprobe", "rmmod", "insmod", "lsmod", "depmod", "modinfo",
        "dmesg", "journalctl", "rsyslog", "syslog-ng", "logrotate",
        "logwatch", "swatch", "multitail", "tail", "less", "more",
        "cat", "head", "tail", "grep", "egrep", "fgrep", "awk", "sed",
        "cut", "sort", "uniq", "wc", "tr", "tee", "xargs", "find",
        "locate", "updatedb", "which", "whereis", "type", "command",
        "hash", "alias", "unalias", "export", "set", "unset", "env",
        "printenv", "readonly", "declare", "typeset", "local",
        "sudo", "su", "runuser", "runuser", "newgrp", "sg",
        "chroot", "unshare", "nsenter", "ip netns", "mount --bind",
        "mount --move", "umount", "mountpoint", "findmnt",
        "lsblk", "blkid", "partprobe", "parted", "fdisk", "gdisk",
        "sgdisk", "cfdisk", "sfdisk", "gparted",
        "mkfs", "mke2fs", "mkfs.ext2", "mkfs.ext3", "mkfs.ext4",
        "mkfs.xfs", "mkfs.btrfs", "mkfs.vfat", "mkfs.ntfs",
        "fsck", "e2fsck", "xfs_repair", "btrfs", "btrfsck",
        "tune2fs", "dumpe2fs", "debugfs", "xfs_info", "xfs_admin",
        "resize2fs", "xfs_growfs", "btrfs", "btrfs filesystem",
        "df", "du", "ncdu", "baobab", "filelight", "kdirstat",
        "rsync", "scp", "sftp", "ssh", "ssh-keygen", "ssh-add",
        "ssh-agent", "ssh-copy-id", "ssh-keyscan", "ssh-keysign",
        "curl", "wget", "lynx", "links", "elinks", "nc", "telnet",
        "openssl", "gpg", "gpg2", "certutil", "keytool", "certtool",
        "update-ca-trust", "update-ca-certificates", "c_rehash",
        "systemctl", "systemd-analyze", "systemd-cgls", "systemd-cgtop",
        "loginctl", "hostnamectl", "localectl", "timedatectl",
        "networkctl", "resolvectl", "busctl", "coredumpctl",
        "firewall-cmd", "firewall-offline-cmd", "iptables", "ip6tables",
        "nft", "nftables", "tc", "ip", "ss", "nmcli", "ifconfig",
        "route", "netstat", "arp", "ethtool", "mii-tool",
        "auditctl", "ausearch", "aureport", "autrace", "auditd",
        "semanage", "getsebool", "setsebool", "getenforce", "setenforce",
        "sestatus", "chcon", "restorecon", "fixfiles", "setfiles",
        "runcon", "newrole", "sandbox", "seunshare",
        "grubby", "grub2-mkconfig", "grub2-set-default", "grub2-setpassword",
        "update-grub", "grub-install", "grub-mkconfig",
        "cryptsetup", "luksFormat", "luksOpen", "luksClose", "luksAddKey",
        "luksRemoveKey", "luksChangeKey", "luksDump",
        "gsettings", "dconf", "dbus-send", "gconftool-2",
        "xrandr", "xset", "xsetroot", "xsetwacom",
        "chage", "passwd", "pwck", "grpck", "vigr", "vipw",
        "faillock", "pam_tally2", "pam_tally",
        "umask", "ulimit", "limits", "sysctl", "sysctl.conf",
        "modprobe", "rmmod", "insmod", "lsmod", "depmod", "modinfo",
        "dmesg", "journalctl", "rsyslog", "syslog-ng", "logrotate",
        "logwatch", "swatch", "multitail", "tail", "less", "more",
    }
    
    # Check if first token is in allowlist
    if first_token_lower in allowed_commands:
        return True
    
    # Check if first token starts with "/" and looks like an executable path
    if first_token.startswith("/"):
        # Must contain at least one slash and look like a path
        if "/" in first_token and re.match(r'^/[a-zA-Z0-9_/.-]+$', first_token):
            return True
    
    # Check if starts with "sudo " followed by an allowed command
    if normalized.startswith("sudo "):
        sudo_tokens = normalized.split()
        if len(sudo_tokens) > 1:
            second_token = sudo_tokens[1].lower()
            if second_token in allowed_commands:
                return True
    
    # Reject everything else
    return False


def looks_like_config_value(line: str) -> bool:
    """
    True for lines that are clearly configuration lines or expected values,
    not commands, e.g.:
    - "GRUB2_PASSWORD=..."
    - "AutomaticLoginEnable=false"
    - "MACs hmac-sha2-256-..."
    - "600 /var/log/messages"
    - "root /etc/passwd"
    """
    normalized = normalize_command_line(line)
    
    if not normalized:
        return False
    
    # Numeric mode at start (^[0-7]{3,4}\s+/)
    if re.match(r'^[0-7]{3,4}\s+/', normalized):
        return True
    
    # First token in {"root","bin","daemon"} followed by a path
    tokens = normalized.split()
    if len(tokens) >= 2:
        first_token = tokens[0].lower()
        if first_token in {"root", "bin", "daemon"} and tokens[1].startswith("/"):
            return True
    
    # Presence of "=" but no allowed command token at beginning
    if '=' in normalized:
        # Check if it starts with a config key pattern (uppercase with underscores)
        if re.match(r'^[A-Z_][A-Z0-9_]*=', normalized):
            return True
        
        # Check if it's a config assignment without a command
        # e.g., "GRUB2_PASSWORD=...", "AutomaticLoginEnable=false"
        config_patterns = [
            r'^[A-Z_][A-Z0-9_]*=',
            r'^[a-z]+[A-Z][a-zA-Z]*=',
        ]
        for pattern in config_patterns:
            if re.match(pattern, normalized):
                # Make sure it's not a command like "export VAR=value"
                if not normalized.startswith(("export ", "set ", "unset ")):
                    return True
    
    # Config key patterns without "="
    config_key_patterns = [
        r'^MACs\s+',
        r'^PubkeyAuthentication\s+',
        r'^PermitEmptyPasswords\s+',
        r'^HostbasedAuthentication\s+',
        r'^GSSAPIAuthentication\s+',
        r'^KerberosAuthentication\s+',
    ]
    for pattern in config_key_patterns:
        if re.match(pattern, normalized, re.IGNORECASE):
            return True
    
    return False


def extract_package_names_from_commands(text: str) -> List[str]:
    """
    Extract package names from command-style lines only.
    
    Only extracts from actual package management commands like:
    - dnf install subscription-manager
    - sudo dnf remove sendmail
    - yum remove vsftpd
    - rpm -q audit
    
    Rejects stopwords and prose-only mentions.
    
    Args:
        text: Text block containing potential package commands
        
    Returns:
        List of valid package names extracted from commands
    """
    package_names = []
    
    # Stopwords that should NEVER be treated as package names
    stopwords = {
        "that", "all", "is", "contents", "red", "run", "--now", "--mask",
        "the", "a", "an", "and", "or", "but", "in", "on", "at", "to", "for",
        "of", "with", "by", "from", "as", "if", "when", "where", "which",
        "this", "these", "those", "what", "who", "how", "why", "can", "will",
        "should", "must", "may", "might", "could", "would", "have", "has",
        "had", "do", "does", "did", "get", "got", "set", "use", "used",
        "install", "remove", "uninstall", "package", "packages", "software"
    }
    
    # Split into lines
    lines = text.split('\n')
    
    # Patterns for package management commands
    package_command_patterns = [
        # dnf/yum install <package>
        r'(?:dnf|yum|apt-get|apt)\s+(?:install|remove|erase|uninstall)\s+([a-zA-Z0-9_.-]+)',
        # rpm -q <package> or rpm -qa | grep <package>
        r'rpm\s+(?:-q|-qa)\s+([a-zA-Z0-9_.-]+)',
        # rpm -e <package> (erase)
        r'rpm\s+-e\s+([a-zA-Z0-9_.-]+)',
        # dnf/yum install -y <package>
        r'(?:dnf|yum)\s+install\s+(?:-y\s+)?([a-zA-Z0-9_.-]+)',
        # sudo dnf install <package>
        r'sudo\s+(?:dnf|yum|apt-get|apt)\s+install\s+([a-zA-Z0-9_.-]+)',
    ]
    
    seen = set()
    for line in lines:
        line = line.strip()
        if not line:
            continue
        
        # Strip $ prompt if present
        line = re.sub(r'^\$\s*', '', line)
        # Strip sudo prefix
        line = re.sub(r'^sudo\s+', '', line, flags=re.IGNORECASE)
        
        # Try each pattern
        for pattern in package_command_patterns:
            match = re.search(pattern, line, re.IGNORECASE)
            if match:
                pkg_name = match.group(1).strip()
                
                # Validate package name
                if not pkg_name:
                    continue
                
                # Reject stopwords
                if pkg_name.lower() in stopwords:
                    continue
                
                # Reject if it starts with a dash (flag)
                if pkg_name.startswith('-'):
                    continue
                
                # Reject if it's too short (likely not a package name)
                if len(pkg_name) < 2:
                    continue
                
                # Reject if it contains only uppercase letters (likely prose)
                if pkg_name.isupper() and len(pkg_name) < 5:
                    continue
                
                # Reject common English words that might be extracted
                if pkg_name.lower() in ['install', 'remove', 'update', 'upgrade', 'list', 'search']:
                    continue
                
                # Package names typically contain lowercase letters, numbers, dashes, underscores
                # Reject if it doesn't match this pattern
                if not re.match(r'^[a-z0-9][a-z0-9_.-]*$', pkg_name, re.IGNORECASE):
                    continue
                
                # Add to list if not seen
                pkg_lower = pkg_name.lower()
                if pkg_lower not in seen:
                    seen.add(pkg_lower)
                    package_names.append(pkg_name)
                break  # Only extract one package per line
    
    return package_names

