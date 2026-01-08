"""Utility functions for command extraction and filtering."""

import re
from typing import List, Tuple


def extract_cli_commands(raw_lines: List[str]) -> Tuple[List[str], List[str]]:
    """
    Extract real CLI commands from raw text/lines, filtering out placeholders and prose.
    
    Given raw text/lines parsed from Fix Text / VulnDiscussion, split them into:
    - cli_commands: lines that look like real IOS CLI commands
    - notes: everything else (English text, labels, prompts, placeholders)
    
    Args:
        raw_lines: List of raw text lines to process
        
    Returns:
        Tuple of (cli_commands, notes) where:
        - cli_commands: cleaned, deduplicated list of real CLI commands
        - notes: list of non-command text (for documentation/debugging)
    """
    cli_commands = []
    notes = []
    
    # Common IOS mode markers that should be filtered out
    mode_markers = {
        'config)',
        'config-if)',
        'config-ext-nacl)',
        'config-cmap)',
        'config-pmap)',
        'config-pmap-c)',
        'config-pmap-c-police)',
        'config-ipv6-acl)',
        'config-std-nacl)',
        'config-line)',
        'config-router)',
        'config-vlan)',
        'config-if-range)',
        'config-route-map)',
        'config-route-map-route-map)',
        'config-router-ospf)',
        'config-router-eigrp)',
        'config-router-bgp)',
    }
    
    # Patterns that indicate prose/explanatory text (NOT commands)
    prose_indicators = [
        r'^[A-Z][^:]*:$',  # Lines ending with colon (often explanatory)
        r'as shown (below|above|in the example)',
        r'configure the (switch|device|router) to',
        r'disable all .* as shown',
        r'example:',
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
    ]
    
    # Patterns that indicate real IOS commands
    ios_command_patterns = [
        r'^interface\s+[A-Za-z0-9/]+',  # interface GigabitEthernet0/1
        r'^ip\s+',  # ip address, ip ospf, etc.
        r'^no\s+',  # no cdp run, no lldp transmit
        r'^switchport\s+',  # switchport mode access
        r'^spanning-tree\s+',  # spanning-tree guard root
        r'^vlan\s+',  # vlan 10
        r'^vtp\s+',  # vtp mode transparent
        r'^mls\s+',  # mls qos
        r'^dot1x\s+',  # dot1x pae authenticator
        r'^aaa\s+',  # aaa new-model
        r'^radius\s+',  # radius-server host
        r'^tacacs\s+',  # tacacs-server host
        r'^line\s+',  # line vty 0 4
        r'^access-list\s+',  # access-list 100 permit
        r'^ip\s+access-list\s+',  # ip access-list extended
        r'^route-map\s+',  # route-map MAP1 permit 10
        r'^router\s+',  # router ospf 1
        r'^hostname\s+',  # hostname SW1
        r'^banner\s+',  # banner motd
        r'^enable\s+secret',  # enable secret
        r'^username\s+',  # username admin
        r'^service\s+',  # service password-encryption
        r'^logging\s+',  # logging host
        r'^ntp\s+',  # ntp server
        r'^snmp-server\s+',  # snmp-server community
        r'^crypto\s+',  # crypto key generate
        r'^key\s+chain\s+',  # key chain OSPF_KEY_CHAIN
        r'^key\s+\d+',  # key 1
        r'^authentication\s+',  # authentication mode
        r'^encryption\s+',  # encryption aes-256-cbc
    ]
    
    seen_commands = set()
    
    for line in raw_lines:
        if not line:
            continue
            
        line = line.strip()
        
        # Skip empty lines
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
        for pattern in prose_indicators:
            if re.search(pattern, line, re.IGNORECASE):
                is_prose = True
                notes.append(f"Prose text: {line}")
                break
        
        if is_prose:
            continue
        
        # Strip IOS prompts (e.g., SW1(config)# command)
        # Pattern: SW1(config)# command or R1(config-if)# command
        prompt_match = re.match(r'^[A-Z0-9]+\([^)]+\)#\s*(.+)', line)
        if prompt_match:
            line = prompt_match.group(1).strip()
            if not line:
                continue
        
        # Check if line looks like a real IOS command
        is_command = False
        for pattern in ios_command_patterns:
            if re.match(pattern, line, re.IGNORECASE):
                is_command = True
                break
        
        # Additional heuristics for commands:
        # - Lines that start with lowercase and contain common IOS keywords
        # - Lines that don't end with punctuation (except for some commands)
        # - Lines that are reasonably short (most commands are < 200 chars)
        if not is_command:
            # Check for common IOS keywords anywhere in the line
            ios_keywords = [
                'interface', 'ip', 'switchport', 'vlan', 'spanning-tree',
                'vtp', 'mls', 'dot1x', 'aaa', 'radius', 'tacacs',
                'access-list', 'route-map', 'router', 'hostname',
                'banner', 'enable', 'username', 'service', 'logging',
                'ntp', 'snmp', 'crypto', 'key', 'authentication',
                'encryption', 'no ', 'shutdown', 'description'
            ]
            
            line_lower = line.lower()
            has_ios_keyword = any(keyword in line_lower for keyword in ios_keywords)
            
            # If it has an IOS keyword and doesn't look like prose
            if has_ios_keyword:
                # Additional checks: not a sentence, not too long, doesn't start with capital letter (unless it's a command)
                if (len(line) < 200 and 
                    not line.endswith(('.', ':', ';')) and
                    not re.match(r'^[A-Z][a-z]+\s+[a-z]+', line)):  # Not "The switch" or "Configure the"
                    is_command = True
        
        if is_command:
            # Clean up the command
            cmd = line.strip()
            
            # Remove trailing punctuation that might have been added
            cmd = re.sub(r'[.,;:]$', '', cmd)
            
            # Skip if it's too short or looks like a placeholder
            if len(cmd) < 3:
                continue
            
            # Skip if it's a duplicate
            cmd_normalized = cmd.lower().strip()
            if cmd_normalized in seen_commands:
                continue
            
            seen_commands.add(cmd_normalized)
            cli_commands.append(cmd)
        else:
            # Not a command, add to notes
            if line and len(line) < 500:  # Don't add extremely long text
                notes.append(line)
    
    return cli_commands, notes







