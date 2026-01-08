"""Parse SCAP benchmark files to determine automation levels for STIG controls."""

import logging
import re
from pathlib import Path
from typing import Optional
from xml.etree import ElementTree

logger = logging.getLogger(__name__)


def parse_scap_benchmark(benchmark_path: Path) -> dict[str, dict]:
    """
    Parse a SCAP benchmark XML file and extract automation level information.
    
    Args:
        benchmark_path: Path to SCAP benchmark XML file
        
    Returns:
        Dictionary mapping STIG ID (e.g., "SV-230221r1017040_rule") to automation info:
        {
            "SV-230221r1017040_rule": {
                "has_oval": True,
                "has_ocil": False,
                "check_systems": ["oval"],
                "automation_level": "automated"
            }
        }
    """
    if not benchmark_path.exists():
        logger.warning(f"SCAP benchmark file not found: {benchmark_path}")
        return {}
    
    try:
        tree = ElementTree.parse(benchmark_path)
        root = tree.getroot()
    except Exception as e:
        logger.error(f"Failed to parse SCAP benchmark {benchmark_path}: {e}")
        return {}
    
    # XCCDF and SCAP namespaces
    namespaces = {
        "xccdf": "http://checklists.nist.gov/xccdf/1.2",
        "ds": "http://scap.nist.gov/schema/scap/source/1.2",
    }
    
    # Try to detect namespaces from root
    if root.tag.startswith("{"):
        default_ns = root.tag.split("}")[0].strip("{")
        if "ds" in default_ns:
            namespaces["ds"] = default_ns
    
    mapping = {}
    
    # Find XCCDF component (could be in data-stream or directly in file)
    xccdf_component = None
    
    # Try to find component with XCCDF
    components = root.findall(".//ds:component", namespaces)
    if not components:
        components = root.findall(".//component")
    
    for comp in components:
        comp_id = comp.get("id", "")
        if "xccdf" in comp_id.lower():
            xccdf_component = comp
            break
    
    # If no component found, try root directly
    if xccdf_component is None:
        benchmark = root.find(".//xccdf:Benchmark", namespaces)
        if benchmark is None:
            benchmark = root.find(".//Benchmark")
        if benchmark is not None:
            xccdf_component = benchmark
    
    if xccdf_component is None:
        # Try finding rules directly
        rules = root.findall(".//xccdf:Rule", namespaces)
        if not rules:
            rules = root.findall(".//Rule")
    else:
        # Find rules in component
        rules = xccdf_component.findall(".//xccdf:Rule", namespaces)
        if not rules:
            rules = xccdf_component.findall(".//Rule")
    
    logger.info(f"Found {len(rules)} rules in SCAP benchmark")
    
    for rule in rules:
        rule_id = rule.get("id", "")
        if not rule_id:
            continue
        
        # Extract STIG ID from rule ID
        # Format: xccdf_mil.disa.stig_rule_SV-230221r1017040_rule
        # Or: SV-230221r1017040_rule
        stig_id = _extract_stig_id_from_rule_id(rule_id)
        if not stig_id:
            continue
        
        # Find check elements
        checks = rule.findall("xccdf:check", namespaces)
        if not checks:
            checks = rule.findall("check")
        
        has_oval = False
        has_ocil = False
        check_systems = []
        
        for check in checks:
            system = check.get("system", "")
            if not system:
                continue
            
            check_systems.append(system)
            
            # OVAL check system
            if "oval" in system.lower() or "oval.mitre.org" in system:
                has_oval = True
            
            # OCIL check system
            if "ocil" in system.lower() or "ocil.mitre.org" in system:
                has_ocil = True
        
        # Determine automation level
        if has_oval:
            automation_level = "automated"
        elif has_ocil:
            automation_level = "semi_automated"
        else:
            automation_level = "manual"
        
        mapping[stig_id] = {
            "has_oval": has_oval,
            "has_ocil": has_ocil,
            "check_systems": check_systems,
            "automation_level": automation_level,
            "rule_id": rule_id,
        }
    
    logger.info(f"Extracted automation levels for {len(mapping)} STIG controls")
    return mapping


def _extract_stig_id_from_rule_id(rule_id: str) -> Optional[str]:
    """
    Extract STIG ID from SCAP rule ID.
    
    Examples:
        "xccdf_mil.disa.stig_rule_SV-230221r1017040_rule" -> "SV-230221r1017040_rule"
        "SV-230221r1017040_rule" -> "SV-230221r1017040_rule"
    """
    # Pattern: SV- followed by digits, optional 'r' and digits, optional '_rule'
    match = re.search(r'(SV-\d+r?\d*_?rule)', rule_id, re.IGNORECASE)
    if match:
        return match.group(1)
    
    # If rule_id already looks like a STIG ID, return it
    if rule_id.startswith("SV-"):
        return rule_id
    
    return None


def find_scap_benchmark_for_stig(stig_path: Path, benchmark_dir: Path) -> Optional[Path]:
    """
    Find the corresponding SCAP benchmark file for a given STIG file.
    
    Args:
        stig_path: Path to STIG XCCDF file
        benchmark_dir: Directory containing SCAP benchmark files
        
    Returns:
        Path to SCAP benchmark file, or None if not found
    """
    if not benchmark_dir.exists():
        return None
    
    stig_name = stig_path.stem.lower()
    
    # Try to match STIG name to benchmark name
    # Examples:
    #   U_RHEL_8_STIG_V2R5_Manual-xccdf.xml -> U_RHEL_8_V2R5_STIG_SCAP_1-3_Benchmark.xml
    #   U_RHEL_9_STIG_V2R6_Manual-xccdf.xml -> U_RHEL_9_V2R6_STIG_SCAP_1-3_Benchmark.xml
    
    # Extract product and version from STIG name
    # Pattern: U_<PRODUCT>_STIG_V<VER>_Manual-xccdf.xml
    match = re.search(r'u_([a-z0-9_-]+)_stig_v([0-9r]+)', stig_name, re.IGNORECASE)
    if match:
        product = match.group(1)
        version = match.group(2)
        
        # Try to find matching benchmark
        # Pattern: U_<PRODUCT>_V<VER>_STIG_SCAP_1-3_Benchmark.xml
        pattern = f"*{product}*v{version}*scap*benchmark*.xml"
        matches = list(benchmark_dir.glob(pattern))
        if matches:
            return matches[0]
        
        # Try alternative pattern
        pattern = f"*{product}*{version}*scap*.xml"
        matches = list(benchmark_dir.glob(pattern))
        if matches:
            return matches[0]
    
    # Fallback: try to find any benchmark that might match
    # Look for common patterns
    if "rhel" in stig_name:
        if "8" in stig_name or "rhel8" in stig_name:
            pattern = "*RHEL_8*SCAP*Benchmark*.xml"
        elif "9" in stig_name or "rhel9" in stig_name:
            pattern = "*RHEL_9*SCAP*Benchmark*.xml"
        else:
            pattern = "*RHEL*SCAP*Benchmark*.xml"
    elif "windows" in stig_name:
        if "11" in stig_name:
            pattern = "*Windows_11*SCAP*Benchmark*.xml"
        elif "2022" in stig_name:
            pattern = "*Windows_Server_2022*SCAP*Benchmark*.xml"
        else:
            pattern = "*Windows*SCAP*Benchmark*.xml"
    elif "cisco" in stig_name or "ios" in stig_name:
        pattern = "*Cisco*SCAP*Benchmark*.xml"
    else:
        return None
    
    matches = list(benchmark_dir.glob(pattern))
    if matches:
        return matches[0]
    
    return None


def load_scap_mapping_for_stig(stig_path: Path, benchmark_dir: Optional[Path] = None) -> dict[str, dict]:
    """
    Load SCAP automation level mapping for a given STIG file.
    
    Args:
        stig_path: Path to STIG XCCDF file
        benchmark_dir: Optional directory containing SCAP benchmark files.
                      If None, uses stigs/benchmark/ relative to project root.
        
    Returns:
        Dictionary mapping STIG ID to automation info
    """
    if benchmark_dir is None:
        # Default to stigs/benchmark/ relative to this file
        project_root = Path(__file__).parent.parent.parent
        benchmark_dir = project_root / "stigs" / "benchmark"
    
    benchmark_path = find_scap_benchmark_for_stig(stig_path, benchmark_dir)
    
    if benchmark_path is None:
        logger.warning(f"No SCAP benchmark found for {stig_path}")
        return {}
    
    logger.info(f"Loading SCAP benchmark: {benchmark_path}")
    return parse_scap_benchmark(benchmark_path)




