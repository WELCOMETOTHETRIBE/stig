"""XCCDF XML parser for DISA STIG files."""

import csv
import re
from pathlib import Path
from typing import Literal
from xml.etree import ElementTree

from ..model.controls import StigControl, normalize_severity
from ..generators.extractors import (
    extract_cli_commands_from_block,
    extract_shell_commands_from_block,
    extract_check_commands_from_block,
    extract_systemd_actions,
    extract_sysctl_params,
)

# Global cache for CCI-to-NIST mapping
_CCI_TO_NIST_MAP: dict[str, str] | None = None


def _load_cci_to_nist_mapping() -> dict[str, str]:
    """
    Load CCI-to-NIST mapping from CSV file.
    
    Returns:
        Dictionary mapping CCI identifiers (e.g., "CCI-001545") to NIST control IDs (e.g., "AC.01.a")
    """
    global _CCI_TO_NIST_MAP
    
    if _CCI_TO_NIST_MAP is not None:
        return _CCI_TO_NIST_MAP
    
    _CCI_TO_NIST_MAP = {}
    mapping_file = Path(__file__).parent / "stig-mapping-to-nist-800-53.csv"
    
    if not mapping_file.exists():
        return _CCI_TO_NIST_MAP
    
    try:
        with open(mapping_file, 'r', encoding='utf-8') as f:
            reader = csv.reader(f)
            # Skip first empty row
            next(reader, None)
            # Skip header row
            headers = next(reader, None)
            if not headers:
                return _CCI_TO_NIST_MAP
            
            # Find column indices
            cci_col = headers.index('CCI') if 'CCI' in headers else 1
            nist_col = headers.index('index') if 'index' in headers else 8
            
            for row in reader:
                if len(row) <= max(cci_col, nist_col):
                    continue
                
                cci = row[cci_col].strip() if row[cci_col] else ""
                nist_raw = row[nist_col].strip() if len(row) > nist_col and row[nist_col] else ""
                
                if cci and cci.startswith("CCI-") and nist_raw:
                    # Convert NIST ID from CSV format to desired format
                    nist_formatted = _convert_nist_id_from_csv(nist_raw)
                    if nist_formatted:
                        # Store the most specific mapping (prefer longer/more specific IDs)
                        if cci not in _CCI_TO_NIST_MAP or len(nist_formatted) > len(_CCI_TO_NIST_MAP[cci]):
                            _CCI_TO_NIST_MAP[cci] = nist_formatted
    except Exception as e:
        print(f"Warning: Failed to load CCI-to-NIST mapping: {e}")
    
    return _CCI_TO_NIST_MAP


def _convert_nist_id_from_csv(nist_id: str) -> str | None:
    """
    Convert NIST control ID from CSV format to desired format.
    
    Converts formats like:
    - "AC-1 a" -> "AC.01.a"
    - "AC-1.1 (i)" -> "AC.01.1(i)"
    - "AC-10" -> "AC.10"
    - "AC-11 (1)" -> "AC.11(1)"
    
    Args:
        nist_id: NIST ID in CSV format (e.g., "AC-1 a")
    
    Returns:
        Formatted NIST ID (e.g., "AC.01.a") or None if invalid
    """
    if not nist_id:
        return None
    
    nist_id = nist_id.strip()
    
    # Skip non-NIST identifiers
    if not re.match(r'^[A-Z]{2}-', nist_id):
        return None
    
    # Extract base: AC-1, AC-10, etc.
    base_match = re.match(r'^([A-Z]{2})-(\d+)', nist_id)
    if not base_match:
        return None
    
    family = base_match.group(1)
    control_num = base_match.group(2).zfill(2)  # Ensure 2 digits
    result = f"{family}.{control_num}"
    
    # Extract sub-control number (e.g., AC-1.1 -> .1)
    sub_match = re.search(r'\.(\d+)', nist_id)
    if sub_match:
        result += f".{sub_match.group(1)}"
    
    # Extract enhancements in parentheses (e.g., (1), (i), (i and ii))
    enhancements = re.findall(r'\(([^)]+)\)', nist_id)
    for enh in enhancements:
        result += f"({enh})"
    
    # Extract letter suffix (e.g., " a", " b") - must be after base and before parentheses
    # Look for space followed by single lowercase letter
    letter_match = re.search(r'\s+([a-z])(?:\s|$|\(|\.)', nist_id)
    if letter_match:
        # Only add if it's not part of an enhancement
        letter_pos = letter_match.start()
        paren_pos = nist_id.find('(')
        if paren_pos == -1 or letter_pos < paren_pos:
            result += f".{letter_match.group(1)}"
    
    return result


def parse_xccdf(file_path: Path, os_family: str | None = None) -> list[StigControl]:
    """
    Parse an XCCDF XML file and extract STIG controls.

    Args:
        file_path: Path to the XCCDF XML file
        os_family: Optional OS family identifier (e.g., "rhel"). If not provided, will be extracted from STIG.

    Returns:
        List of StigControl objects

    Raises:
        FileNotFoundError: If the file doesn't exist
        ValueError: If the XML is malformed or invalid
    """
    if not file_path.exists():
        raise FileNotFoundError(f"STIG file not found: {file_path}")

    try:
        tree = ElementTree.parse(file_path)
        root = tree.getroot()
    except ElementTree.ParseError as e:
        raise ValueError(f"Failed to parse XML file: {e}") from e

    # XCCDF namespace handling
    namespaces = {
        "xccdf": "http://checklists.nist.gov/xccdf/1.2",
        "dc": "http://purl.org/dc/elements/1.1/",
        "cpe": "http://cpe.mitre.org/language/2.0",
    }

    # Try to detect namespaces from root if not present
    if root.tag.startswith("{"):
        default_ns = root.tag.split("}")[0].strip("{")
        if "xccdf" not in namespaces.values():
            namespaces["xccdf"] = default_ns

    # Extract OS family from Benchmark if not provided
    if os_family is None:
        os_family = _extract_os_family_from_benchmark(root, namespaces)
    
    if not os_family:
        os_family = "rhel"  # Default fallback

    controls = []

    # Build a map of Group IDs to their titles (for SRG-OS extraction)
    group_map = {}
    groups = root.findall(".//xccdf:Group", namespaces)
    if not groups:
        groups = root.findall(".//Group")
    
    for group in groups:
        group_id = group.get("id", "")
        group_title_elem = group.find("xccdf:title", namespaces)
        if group_title_elem is None:
            group_title_elem = group.find("title")
        if group_title_elem is not None and group_title_elem.text:
            group_map[group_id] = group_title_elem.text
            # Also process rules within this group
            group_rules = group.findall("xccdf:Rule", namespaces)
            if not group_rules:
                group_rules = group.findall("Rule")
            
            for rule in group_rules:
                try:
                    control = _parse_rule(rule, os_family, namespaces, group_map, group_id)
                    if control:
                        controls.append(control)
                except Exception as e:
                    rule_id = rule.get("id", "unknown")
                    print(f"Warning: Failed to parse rule {rule_id}: {e}")
                    continue

    # Also find any rules not in groups (shouldn't happen in STIGs, but be safe)
    all_rules = root.findall(".//xccdf:Rule", namespaces)
    if not all_rules:
        all_rules = root.findall(".//Rule")
    
    processed_rule_ids = {c.id for c in controls}
    for rule in all_rules:
        rule_id = rule.get("id", "")
        if rule_id and rule_id not in processed_rule_ids:
            try:
                control = _parse_rule(rule, os_family, namespaces, group_map, None)
                if control:
                    controls.append(control)
            except Exception as e:
                print(f"Warning: Failed to parse rule {rule_id}: {e}")
                continue

    return controls


def _parse_rule(
    rule: ElementTree.Element, os_family: str, namespaces: dict[str, str], 
    group_map: dict[str, str] | None = None, parent_group_id: str | None = None
) -> StigControl | None:
    """Parse a single Rule element into a StigControl."""
    rule_id = rule.get("id", "")
    if not rule_id:
        return None

    # Extract title
    title_elem = rule.find("xccdf:title", namespaces)
    if title_elem is None:
        title_elem = rule.find("title")
    title = title_elem.text if title_elem is not None and title_elem.text else ""

    # Extract severity
    severity_attr = rule.get("severity", "medium")
    severity = normalize_severity(severity_attr)

    # Extract description
    desc_elem = rule.find("xccdf:description", namespaces)
    if desc_elem is None:
        desc_elem = rule.find("description")
    description = _extract_text(desc_elem) if desc_elem is not None else ""

    # Extract rationale
    rationale_elem = rule.find("xccdf:rationale", namespaces)
    if rationale_elem is None:
        rationale_elem = rule.find("rationale")
    rationale = _extract_text(rationale_elem) if rationale_elem is not None else None

    # Extract check text
    check_elem = rule.find("xccdf:check/xccdf:check-content", namespaces)
    if check_elem is None:
        check_elem = rule.find(".//check-content")
    check_text = _extract_text(check_elem) if check_elem is not None else ""

    # Extract fix text
    fix_elem = rule.find("xccdf:fixtext", namespaces)
    if fix_elem is None:
        fix_elem = rule.find("fixtext")
    fix_text = _extract_text(fix_elem) if fix_elem is not None else ""

    # Extract references
    references = []
    nist_family_id = None

    ref_elems = rule.findall("xccdf:reference", namespaces)
    if not ref_elems:
        ref_elems = rule.findall("reference")

    for ref_elem in ref_elems:
        ref_href = ref_elem.get("href", "")
        ref_text = ref_elem.text if ref_elem.text else ""
        if ref_href:
            references.append(f"{ref_href}:{ref_text}")
        elif ref_text:
            references.append(ref_text)

        # Try to extract NIST family ID from references
        if not nist_family_id:
            nist_id = _extract_nist_id(ref_href, ref_text)
            if nist_id:
                nist_family_id = nist_id

    # Extract CCI identifiers (Control Correlation Identifiers)
    # Use CCI-to-NIST mapping as fallback if regex extraction fails
    ident_elems = rule.findall("xccdf:ident", namespaces)
    if not ident_elems:
        ident_elems = rule.findall("ident")
    
    cci_identifiers = []
    for ident_elem in ident_elems:
        ident_system = ident_elem.get("system", "")
        ident_text = ident_elem.text if ident_elem.text else ""
        if "cci" in ident_system.lower() and ident_text:
            cci_identifiers.append(ident_text.strip())
    
    # Try CCI-to-NIST mapping as fallback if no NIST ID found yet
    if not nist_family_id and cci_identifiers:
        cci_map = _load_cci_to_nist_mapping()
        for cci in cci_identifiers:
            if cci in cci_map:
                nist_family_id = cci_map[cci]
                break

    # Extract SRG-OS identifiers from Group title (parent element)
    if not nist_family_id and group_map and parent_group_id:
        group_title = group_map.get(parent_group_id, "")
        if group_title:
            # Extract SRG-OS identifier (e.g., "SRG-OS-000023-GPOS-00006")
            srg_match = re.search(r'SRG-OS-(\d{6})', group_title)
            if srg_match:
                srg_num = srg_match.group(1)
                # Format as OS-000023 (DISA control format)
                nist_family_id = f"OS-{srg_num}"
    
    # Also try to find Group by checking if rule is in any group's children
    if not nist_family_id and group_map:
        # Find the group that contains this rule
        for group_id, group_title in group_map.items():
            # Check if this rule's ID pattern matches (heuristic)
            # In practice, we'd need to traverse the tree, but this is a workaround
            srg_match = re.search(r'SRG-OS-(\d{6})', group_title)
            if srg_match:
                srg_num = srg_match.group(1)
                nist_family_id = f"OS-{srg_num}"
                break

    # Also check description and other fields for NIST identifiers
    if not nist_family_id:
        nist_id = _extract_nist_id(description, check_text, fix_text)
        if nist_id:
            nist_family_id = nist_id

    # Extract raw metadata
    raw_metadata = {
        "rule_id": rule_id,
        "weight": rule.get("weight", ""),
    }

    # Extract candidate command blocks from fix_text and check_text
    candidate_cli_blocks = []
    candidate_check_blocks = []
    candidate_shell_blocks = []
    automatable_commands = []
    check_commands = []
    manual_notes = []
    service_actions = []
    sysctl_params = []
    
    # Extract CLI blocks from fix_text (for network devices)
    if os_family == "network":
        cli_commands, cli_notes = extract_cli_commands_from_block(fix_text)
        candidate_cli_blocks = cli_commands
        automatable_commands = cli_commands
        manual_notes = cli_notes
    else:
        # Extract shell commands from fix_text (for OSes)
        shell_commands, shell_notes = extract_shell_commands_from_block(fix_text, os_family, purpose="hardening")
        candidate_shell_blocks = shell_commands
        automatable_commands = shell_commands
        manual_notes = shell_notes
        
        # Extract structured systemd actions
        service_actions = extract_systemd_actions(fix_text)
        
        # Extract structured sysctl parameters
        sysctl_params = extract_sysctl_params(fix_text)
    
    # Extract check commands from check_text
    check_cmds, check_notes = extract_check_commands_from_block(check_text, os_family)
    candidate_check_blocks = check_cmds
    check_commands = check_cmds
    if check_notes:
        manual_notes.extend(check_notes)

    return StigControl(
        id=rule_id,
        title=title,
        severity=severity,
        description=description,
        rationale=rationale,
        check_text=check_text,
        fix_text=fix_text,
        references=references,
        os_family=os_family,
        nist_family_id=nist_family_id,
        raw_metadata=raw_metadata,
        candidate_cli_blocks=candidate_cli_blocks,
        candidate_check_blocks=candidate_check_blocks,
        candidate_shell_blocks=candidate_shell_blocks,
        automatable_commands=automatable_commands,
        check_commands=check_commands,
        manual_notes=manual_notes,
        service_actions=service_actions,
        sysctl_params=sysctl_params,
    )


def _extract_text(elem: ElementTree.Element | None) -> str:
    """Extract text content from an XML element, handling nested tags."""
    if elem is None:
        return ""
    if elem.text:
        text = elem.text
    else:
        text = ""
    # Also get tail text from nested elements
    for child in elem:
        if child.text:
            text += " " + child.text
        if child.tail:
            text += " " + child.tail
    return text.strip()


def _extract_nist_id(*texts: str) -> str | None:
    """
    Extract NIST control family ID from text.
    
    Only extracts actual NIST 800-53 control IDs, NOT CCI IDs.
    Converts formats like "AU-2" to "AU.02" as requested.

    Looks for patterns like:
    - AU-2 -> converts to AU.02
    - AU.02.b (keeps as is)
    - AC-3(3) -> converts to AC.03(3)
    - SI-2(1)(a) -> converts to SI.02(1)(a)

    Returns the most specific match found in "AU.02" format, or None.
    """
    nist_patterns = [
        # Most specific: AU.02.b format (already in desired format)
        r"\b([A-Z]{2})\.(\d{2})\.([a-z])\b",
        # Standard: AU-2(3)(a) format - convert to AU.02(3)(a)
        r"\b([A-Z]{2})-(\d+)(?:\((\d+)\))?(?:\(([a-z])\))?\b",
        # Simple: AU-2 format - convert to AU.02
        r"\b([A-Z]{2})-(\d+)\b",
    ]

    best_match = None
    best_specificity = 0

    for text in texts:
        if not text:
            continue

        for pattern in nist_patterns:
            matches = re.finditer(pattern, text, re.IGNORECASE)
            for match in matches:
                # Calculate specificity (more parts = more specific)
                specificity = len([g for g in match.groups() if g])
                if specificity > best_specificity:
                    best_specificity = specificity
                    # Reconstruct the ID in AU.02 format
                    family = match.group(1).upper()
                    control_num = match.group(2).zfill(2)  # Ensure 2 digits (e.g., "2" -> "02")
                    
                    if "." in pattern and len(match.groups()) >= 3:
                        # AU.02.b format - already correct
                        subpart = match.group(3)
                        best_match = f"{family}.{control_num}.{subpart}"
                    elif len(match.groups()) >= 3 and match.group(3):
                        # AU-2(3)(a) format - convert to AU.02(3)(a)
                        enhancement = match.group(3)
                        subpart = f"({match.group(4)})" if len(match.groups()) >= 4 and match.group(4) else ""
                        best_match = f"{family}.{control_num}({enhancement}){subpart}"
                    else:
                        # AU-2 format - convert to AU.02
                        best_match = f"{family}.{control_num}"

    return best_match


def _extract_os_family_from_benchmark(root: ElementTree.Element, namespaces: dict[str, str]) -> str:
    """
    Extract OS family from Benchmark element (title or id attribute).
    
    Returns:
        OS family identifier (e.g., "rhel", "windows", "ubuntu")
    """
    # Get Benchmark title
    title_elem = root.find("xccdf:title", namespaces)
    if title_elem is None:
        title_elem = root.find("title")
    title = (title_elem.text if title_elem is not None and title_elem.text else "").lower()
    
    # Get Benchmark id
    benchmark_id = root.get("id", "").lower()
    
    # Check title and id for OS family indicators
    text_to_check = f"{title} {benchmark_id}"
    
    # Windows indicators
    if any(indicator in text_to_check for indicator in ["windows", "microsoft", "ms_"]):
        return "windows"
    
    # RHEL indicators
    if any(indicator in text_to_check for indicator in ["rhel", "red hat", "red_hat"]):
        return "rhel"
    
    # Ubuntu indicators
    if "ubuntu" in text_to_check:
        return "ubuntu"
    
    # Network indicators
    if "network" in text_to_check or "cisco" in text_to_check:
        return "network"
    
    # Database indicators
    if any(indicator in text_to_check for indicator in ["database", "db", "oracle", "sql server"]):
        return "db"
    
    # Default to rhel if unclear
    return "rhel"


