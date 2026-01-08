"""Parse SCAP benchmark files to determine which STIG controls are automated.

This script parses SCAP benchmark files (datastream or XCCDF) and extracts
information about which STIG rule IDs are covered by automated checks (OVAL).

Usage:
    python scripts/parse_scap_benchmark.py --scap stigs/benchmark/U_RHEL_9_V2R6_STIG_SCAP_1-3_Benchmark.xml
"""

import argparse
import logging
import re
import sys
from pathlib import Path
from typing import Any, Optional
from xml.etree import ElementTree

# Add parent directory to path to import app modules
sys.path.insert(0, str(Path(__file__).parent.parent))

logging.basicConfig(level=logging.INFO, format="%(levelname)s: %(message)s")
logger = logging.getLogger(__name__)


def load_scap_automation_map(scap_path: str) -> dict[str, dict[str, Any]]:
    """
    Parse a SCAP benchmark (datastream/XCCDF) and return a mapping:
    
    {
        "SV-..._rule": {
            "has_oval": bool,
            "has_ocil": bool,
            "rule_id": "...",
            "title": "...",
            # any other useful metadata
        },
        ...
    }
    
    Only include rule IDs that correspond to STIG IDs (e.g., SV- or V-).
    
    Args:
        scap_path: Path to SCAP benchmark XML file
        
    Returns:
        Dictionary mapping STIG ID to automation metadata
    """
    scap_path_obj = Path(scap_path)
    if not scap_path_obj.exists():
        logger.warning(f"SCAP benchmark file not found: {scap_path}")
        return {}
    
    try:
        tree = ElementTree.parse(scap_path_obj)
        root = tree.getroot()
    except Exception as e:
        logger.error(f"Failed to parse SCAP benchmark {scap_path}: {e}")
        return {}
    
    # XCCDF and SCAP namespaces
    namespaces = {
        "xccdf": "http://checklists.nist.gov/xccdf/1.2",
        "ds": "http://scap.nist.gov/schema/scap/source/1.2",
    }
    
    # Try to detect namespaces from root
    if root.tag.startswith("{"):
        default_ns = root.tag.split("}")[0].strip("{")
        if "ds" in default_ns or "scap" in default_ns:
            namespaces["ds"] = default_ns
        if "xccdf" in default_ns:
            namespaces["xccdf"] = default_ns
    
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
        stig_id = _extract_stig_id_from_rule_id(rule_id)
        if not stig_id:
            continue
        
        # Get title
        title_elem = rule.find("xccdf:title", namespaces)
        if title_elem is None:
            title_elem = rule.find("title")
        title = title_elem.text if title_elem is not None and title_elem.text else ""
        
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
            
            # OVAL check system - this indicates automation
            if "oval" in system.lower() or "oval.mitre.org" in system:
                has_oval = True
            
            # OCIL check system - partial automation
            if "ocil" in system.lower() or "ocil.mitre.org" in system:
                has_ocil = True
        
        mapping[stig_id] = {
            "has_oval": has_oval,
            "has_ocil": has_ocil,
            "rule_id": rule_id,
            "title": title,
            "check_systems": check_systems,
        }
    
    logger.info(f"Extracted automation metadata for {len(mapping)} STIG controls")
    return mapping


def _extract_stig_id_from_rule_id(rule_id: str) -> Optional[str]:
    """
    Extract STIG ID from SCAP rule ID.
    
    Examples:
        "xccdf_mil.disa.stig_rule_SV-230221r1017040_rule" -> "SV-230221r1017040_rule"
        "SV-230221r1017040_rule" -> "SV-230221r1017040_rule"
        "V-230221" -> "V-230221"
    """
    # Pattern: SV- followed by digits, optional 'r' and digits, optional '_rule'
    match = re.search(r'(SV-\d+r?\d*_?rule)', rule_id, re.IGNORECASE)
    if match:
        return match.group(1)
    
    # Pattern: V- followed by digits
    match = re.search(r'(V-\d+)', rule_id, re.IGNORECASE)
    if match:
        return match.group(1)
    
    # If rule_id already looks like a STIG ID, return it
    if rule_id.startswith("SV-") or rule_id.startswith("V-"):
        return rule_id
    
    return None


def main():
    """Main entry point for the SCAP parser script."""
    parser = argparse.ArgumentParser(
        description="Parse SCAP benchmark to extract automation metadata"
    )
    parser.add_argument(
        "--scap", "-s",
        type=Path,
        required=True,
        help="Path to SCAP benchmark XML file"
    )
    parser.add_argument(
        "--output", "-o",
        type=Path,
        help="Optional: Path to output JSON file (for debugging)"
    )
    
    args = parser.parse_args()
    
    try:
        automation_map = load_scap_automation_map(str(args.scap))
        
        if args.output:
            import json
            args.output.parent.mkdir(parents=True, exist_ok=True)
            with open(args.output, "w", encoding="utf-8") as f:
                json.dump(automation_map, f, indent=2, ensure_ascii=False)
            logger.info(f"Saved automation map to {args.output}")
        
        # Print summary
        automated = sum(1 for v in automation_map.values() if v.get("has_oval"))
        semi_automated = sum(1 for v in automation_map.values() if v.get("has_ocil") and not v.get("has_oval"))
        manual = len(automation_map) - automated - semi_automated
        
        logger.info(f"Summary:")
        logger.info(f"  - Automated (OVAL): {automated}")
        logger.info(f"  - Semi-automated (OCIL only): {semi_automated}")
        logger.info(f"  - Manual (no checks): {manual}")
        
        return 0
        
    except FileNotFoundError as e:
        logger.error(f"File not found: {e}")
        return 1
    except Exception as e:
        logger.error(f"Error: {e}", exc_info=True)
        return 1


if __name__ == "__main__":
    exit(main())




