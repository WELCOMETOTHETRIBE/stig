"""Parse Nessus XML scan files to determine which STIG controls are automated.

This script parses Nessus XML scan files and extracts information about which
STIG rule IDs are covered by automated checks.

Usage:
    python scripts/parse_nessus_scan.py --nessus scan_results.xml
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


def load_nessus_automation_map(nessus_path: str) -> dict[str, dict[str, Any]]:
    """
    Parse a Nessus XML file and return a mapping:
    
    {
        "SV-..._rule": {
            "plugin_ids": [ ... ],
            "hosts": [ ... ],
            # any other metadata you find useful
        },
        ...
    }
    
    Args:
        nessus_path: Path to Nessus XML file
        
    Returns:
        Dictionary mapping STIG ID to automation metadata
    """
    nessus_path_obj = Path(nessus_path)
    if not nessus_path_obj.exists():
        logger.warning(f"Nessus scan file not found: {nessus_path}")
        return {}
    
    try:
        tree = ElementTree.parse(nessus_path_obj)
        root = tree.getroot()
    except Exception as e:
        logger.error(f"Failed to parse Nessus XML {nessus_path}: {e}")
        return {}
    
    mapping = {}
    
    # Nessus XML structure:
    # <NessusClientData_v2>
    #   <Report>
    #     <ReportHost>
    #       <ReportItem>
    #         <plugin_output>...</plugin_output>
    #         <description>...</description>
    #         <see_also>...</see_also>
    #       </ReportItem>
    #     </ReportHost>
    #   </Report>
    # </NessusClientData_v2>
    
    # Find all ReportItem elements
    report_items = root.findall(".//ReportItem")
    if not report_items:
        # Try alternative structure
        report_items = root.findall(".//report_item")
    
    logger.info(f"Found {len(report_items)} report items in Nessus scan")
    
    for item in report_items:
        plugin_id = item.get("pluginID", "")
        if not plugin_id:
            continue
        
        # Extract text from various fields that might contain STIG IDs
        plugin_output = ""
        description = ""
        see_also = ""
        
        plugin_output_elem = item.find("plugin_output")
        if plugin_output_elem is not None and plugin_output_elem.text:
            plugin_output = plugin_output_elem.text
        
        description_elem = item.find("description")
        if description_elem is not None and description_elem.text:
            description = description_elem.text
        
        see_also_elem = item.find("see_also")
        if see_also_elem is not None and see_also_elem.text:
            see_also = see_also_elem.text
        
        # Combine all text fields
        combined_text = f"{plugin_output} {description} {see_also}"
        
        # Extract STIG IDs from text
        stig_ids = _extract_stig_ids_from_text(combined_text)
        
        # Get host information
        host_elem = item.getparent()
        host_name = ""
        if host_elem is not None:
            host_name_attr = host_elem.get("name", "")
            if host_name_attr:
                host_name = host_name_attr
        
        # Map each STIG ID found
        for stig_id in stig_ids:
            if stig_id not in mapping:
                mapping[stig_id] = {
                    "plugin_ids": [],
                    "hosts": [],
                }
            
            if plugin_id not in mapping[stig_id]["plugin_ids"]:
                mapping[stig_id]["plugin_ids"].append(plugin_id)
            
            if host_name and host_name not in mapping[stig_id]["hosts"]:
                mapping[stig_id]["hosts"].append(host_name)
    
    logger.info(f"Extracted automation metadata for {len(mapping)} STIG controls")
    return mapping


def _extract_stig_ids_from_text(text: str) -> list[str]:
    """
    Extract STIG IDs from text.
    
    Looks for patterns like:
    - SV-257879r1045454_rule
    - V-257879
    - STIG ID: SV-257879r1045454_rule
    - Rule ID: V-257879
    
    Args:
        text: Text to search
        
    Returns:
        List of STIG IDs found
    """
    stig_ids = set()
    
    # Pattern 1: SV- followed by digits, optional 'r' and digits, optional '_rule'
    pattern1 = r'SV-\d+r?\d*_?rule'
    matches = re.findall(pattern1, text, re.IGNORECASE)
    stig_ids.update(matches)
    
    # Pattern 2: V- followed by digits
    pattern2 = r'V-\d+'
    matches = re.findall(pattern2, text, re.IGNORECASE)
    stig_ids.update(matches)
    
    # Pattern 3: "STIG ID: SV-..." or "Rule ID: V-..."
    pattern3 = r'(?:STIG\s+ID|Rule\s+ID)[:\s]+(SV-\d+r?\d*_?rule|V-\d+)'
    matches = re.findall(pattern3, text, re.IGNORECASE)
    stig_ids.update(matches)
    
    # Normalize to include _rule suffix for SV- IDs if not present
    normalized_ids = []
    for stig_id in stig_ids:
        if stig_id.startswith("SV-") and not stig_id.endswith("_rule"):
            # Check if it should have _rule suffix
            # If it matches the pattern with digits after 'r', add _rule
            if re.match(r'SV-\d+r\d+', stig_id, re.IGNORECASE):
                normalized_ids.append(f"{stig_id}_rule")
            else:
                normalized_ids.append(stig_id)
        else:
            normalized_ids.append(stig_id)
    
    return normalized_ids


def main():
    """Main entry point for the Nessus parser script."""
    parser = argparse.ArgumentParser(
        description="Parse Nessus XML scan to extract automation metadata"
    )
    parser.add_argument(
        "--nessus", "-n",
        type=Path,
        required=True,
        help="Path to Nessus XML scan file"
    )
    parser.add_argument(
        "--output", "-o",
        type=Path,
        help="Optional: Path to output JSON file (for debugging)"
    )
    
    args = parser.parse_args()
    
    try:
        automation_map = load_nessus_automation_map(str(args.nessus))
        
        if args.output:
            import json
            args.output.parent.mkdir(parents=True, exist_ok=True)
            with open(args.output, "w", encoding="utf-8") as f:
                json.dump(automation_map, f, indent=2, ensure_ascii=False)
            logger.info(f"Saved automation map to {args.output}")
        
        # Print summary
        total_plugins = sum(len(v.get("plugin_ids", [])) for v in automation_map.values())
        total_hosts = len(set(host for v in automation_map.values() for host in v.get("hosts", [])))
        
        logger.info(f"Summary:")
        logger.info(f"  - STIG controls found: {len(automation_map)}")
        logger.info(f"  - Total plugins: {total_plugins}")
        logger.info(f"  - Total hosts: {total_hosts}")
        
        return 0
        
    except FileNotFoundError as e:
        logger.error(f"File not found: {e}")
        return 1
    except Exception as e:
        logger.error(f"Error: {e}", exc_info=True)
        return 1


if __name__ == "__main__":
    exit(main())




