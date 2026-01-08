"""Parse XCCDF XML STIG files into structured JSON.

This script serves as the central parser that:
1. Reads XCCDF/XML STIG files
2. Extracts each Rule into a StigControl dataclass
3. Saves the controls as JSON for downstream generators

Usage:
    python scripts/parse_stig.py --xccdf data/stigs/rhel9/2024_Q4/U_RHEL_9_STIG_V1R5_20241212.xml --output data/json/rhel9_2024_Q4_controls.json
"""

import argparse
import json
import logging
import re
import sys
from dataclasses import asdict, dataclass
from pathlib import Path
from typing import Literal, Optional

# Add parent directory to path to import app modules
sys.path.insert(0, str(Path(__file__).parent.parent))

from app.parsers.scap_benchmark import load_scap_mapping_for_stig
from app.parsers.xccdf_parser import parse_xccdf as parse_xccdf_legacy

logging.basicConfig(level=logging.INFO, format="%(levelname)s: %(message)s")
logger = logging.getLogger(__name__)


@dataclass
class StigControl:
    """Represents a single STIG control/rule.
    
    This is the central data model that all generators consume.
    """
    sv_id: str  # STIG ID (e.g., "RHEL-09-010010")
    nist_id: Optional[str] = None  # NIST 800-53 Control ID (e.g., "AC.02.b")
    severity: str = "medium"  # "low", "medium", "high", "critical"
    title: str = ""
    description: str = ""
    check_text: str = ""  # The "Check" section from the STIG
    fix_text: str = ""  # The "Fix" section from the STIG
    product: str = "rhel9"  # e.g. "rhel9", "rhel8", "windows11"
    category: str = "other"  # e.g. "file_permissions", "package_present", "service_enabled", etc.
    automation_level: Literal["automated", "manual_only", "unknown"] = "unknown"  # Automation classification
    automation_source: Literal["none", "scap", "nessus"] = "none"  # Source of automation metadata
    
    def to_dict(self) -> dict:
        """Convert to dictionary for JSON serialization."""
        return asdict(self)


def _extract_product_from_path(file_path: Path) -> str:
    """
    Extract product identifier from STIG file path.
    
    Examples:
        U_RHEL_9_V2R6_STIG/... → rhel9
        U_MS_Windows_11_V2R5_STIG/... → windows11
        U_Cisco_IOS_Switch_NDM_STIG/... → cisco_ios_switch_ndm
    """
    path_str = str(file_path)
    
    # RHEL patterns
    if "RHEL_9" in path_str or "rhel_9" in path_str or "rhel9" in path_str.lower():
        return "rhel9"
    elif "RHEL_8" in path_str or "rhel_8" in path_str or "rhel8" in path_str.lower():
        return "rhel8"
    elif "RHEL_7" in path_str or "rhel_7" in path_str or "rhel7" in path_str.lower():
        return "rhel7"
    
    # Windows patterns
    elif "Windows_11" in path_str or "windows_11" in path_str or "windows11" in path_str.lower():
        return "windows11"
    elif "Windows_Server_2022" in path_str or "windows_server_2022" in path_str:
        return "windows2022"
    elif "Windows_Server_2019" in path_str or "windows_server_2019" in path_str:
        return "windows2019"
    elif "Windows_10" in path_str or "windows_10" in path_str:
        return "windows10"
    
    # Cisco patterns
    elif "Cisco_IOS_Switch" in path_str:
        if "NDM" in path_str:
            return "cisco_ios_switch_ndm"
        elif "L2S" in path_str:
            return "cisco_ios_switch_l2s"
        elif "RTR" in path_str:
            return "cisco_ios_switch_rtr"
        else:
            return "cisco_ios_switch"
    elif "Cisco_IOS_Router" in path_str:
        if "NDM" in path_str:
            return "cisco_ios_router_ndm"
        elif "RTR" in path_str:
            return "cisco_ios_router_rtr"
        else:
            return "cisco_ios_router"
    elif "Cisco_NX-OS_Switch" in path_str or "Cisco_NX_OS_Switch" in path_str:
        return "cisco_nxos_switch"
    elif "Cisco_ISE" in path_str:
        return "cisco_ise"
    
    # Default: try to extract from filename
    filename = file_path.name
    if "rhel" in filename.lower():
        match = re.search(r'rhel[_-]?(\d+)', filename, re.IGNORECASE)
        if match:
            return f"rhel{match.group(1)}"
    elif "windows" in filename.lower():
        match = re.search(r'windows[_-]?(\d+)', filename, re.IGNORECASE)
        if match:
            return f"windows{match.group(1)}"
    
    # Fallback
    return "unknown"


def parse_xccdf_file(
    file_path: Path,
    secondary_artifact: Optional[Path] = None,
    secondary_type: Optional[str] = None,
    original_filename: Optional[str] = None
) -> list[StigControl]:
    """
    Parse an XCCDF XML file and extract STIG controls.
    
    Uses the existing app.parsers.xccdf_parser and maps to simplified StigControl.
    
    Args:
        file_path: Path to the XCCDF XML file
        secondary_artifact: Optional path to SCAP benchmark or Nessus scan
        secondary_type: Optional type of secondary artifact ("scap" or "nessus")
        
    Returns:
        List of StigControl objects
        
    Raises:
        FileNotFoundError: If the file doesn't exist
        ValueError: If the XML is malformed
    """
    if not file_path.exists():
        raise FileNotFoundError(f"STIG file not found: {file_path}")
    
    logger.info(f"Parsing XCCDF file: {file_path}")
    
    # Load automation mapping from secondary artifact if provided
    automation_map = {}
    automation_source = "none"
    
    if secondary_artifact and secondary_artifact.exists():
        # Auto-detect type if not provided
        if not secondary_type:
            if secondary_artifact.suffix.lower() == ".xml":
                # Try to detect by content
                try:
                    with open(secondary_artifact, "rb") as f:
                        content = f.read(1024).decode("utf-8", errors="ignore")
                        if "nessus" in content.lower() or "NessusClientData" in content:
                            secondary_type = "nessus"
                        elif "scap" in content.lower() or "xccdf" in content.lower() or "Benchmark" in content:
                            secondary_type = "scap"
                        else:
                            # Default to SCAP for XML files
                            secondary_type = "scap"
                except Exception:
                    secondary_type = "scap"  # Default
        
        if secondary_type == "scap":
            from scripts.parse_scap_benchmark import load_scap_automation_map
            automation_map = load_scap_automation_map(str(secondary_artifact))
            automation_source = "scap"
            logger.info(f"Loaded SCAP automation map from {secondary_artifact}: {len(automation_map)} controls")
        elif secondary_type == "nessus":
            from scripts.parse_nessus_scan import load_nessus_automation_map
            automation_map = load_nessus_automation_map(str(secondary_artifact))
            automation_source = "nessus"
            logger.info(f"Loaded Nessus automation map from {secondary_artifact}: {len(automation_map)} controls")
    else:
        # Try to find SCAP benchmark automatically (backward compatibility)
        scap_mapping = load_scap_mapping_for_stig(file_path)
        if scap_mapping:
            automation_map = scap_mapping
            automation_source = "scap"
            logger.info(f"Auto-loaded SCAP automation levels for {len(automation_map)} controls")
        else:
            logger.warning("No secondary artifact provided and no SCAP benchmark found - will use fallback classification")
    
    # Use existing parser
    legacy_controls = parse_xccdf_legacy(file_path, os_family=None)
    
    # Extract product from path or original filename
    if original_filename:
        # Try original filename first (for uploaded files with temp paths)
        product = _extract_product_from_path(Path(original_filename))
        if product == "unknown":
            # Fall back to file path
            product = _extract_product_from_path(file_path)
    else:
        product = _extract_product_from_path(file_path)
    logger.info(f"Detected product: {product}")
    
    # Map legacy StigControl to simplified version
    controls = []
    for legacy in legacy_controls:
        # Determine automation level from secondary artifact
        stig_id = legacy.id  # e.g., "SV-230221r1017040_rule"
        automation_level = "unknown"  # Default
        control_automation_source = "none"
        
        # Normalize STIG ID for lookup (try multiple formats)
        stig_id_variants = [stig_id]
        # Try without _rule suffix
        if stig_id.endswith("_rule"):
            stig_id_variants.append(stig_id[:-5])
        # Try with _rule suffix
        if not stig_id.endswith("_rule") and re.match(r'SV-\d+r\d+', stig_id):
            stig_id_variants.append(f"{stig_id}_rule")
        
        # Check automation map
        found_in_map = False
        for variant in stig_id_variants:
            if variant in automation_map:
                found_in_map = True
                control_automation_source = automation_source
                
                if automation_source == "scap":
                    # SCAP provides has_oval and has_ocil
                    scap_info = automation_map[variant]
                    if scap_info.get("has_oval"):
                        automation_level = "automated"
                    elif scap_info.get("has_ocil"):
                        automation_level = "manual_only"  # OCIL is not fully automated
                    else:
                        automation_level = "manual_only"
                elif automation_source == "nessus":
                    # Nessus indicates automation capability
                    automation_level = "automated"
                
                logger.debug(f"{stig_id}: Found in {automation_source} map -> {automation_level}")
                break
        
        if not found_in_map:
            # Not found in automation map
            if automation_source != "none":
                # We checked but didn't find it - it's manual-only
                control_automation_source = automation_source
                automation_level = "manual_only"
                logger.debug(f"{stig_id}: Not found in {automation_source} map -> manual_only")
            else:
                # No secondary artifact provided - use unknown
                automation_level = "unknown"
                logger.debug(f"{stig_id}: No secondary artifact -> unknown")
        
        # Categorize control using the same logic as generate_hardening.py
        # Import here to avoid circular dependency
        from scripts.generate_hardening import categorize_control
        
        # Build a dict for categorization
        control_dict = {
            "sv_id": legacy.id,
            "fix_text": legacy.fix_text or "",
            "check_text": legacy.check_text or "",
            "title": legacy.title or "",
            "product": product,
            "category": getattr(legacy, 'category', None) if hasattr(legacy, 'category') else None,
        }
        category = categorize_control(control_dict)
        
        control = StigControl(
            sv_id=legacy.id,  # e.g., "SV-257777r991589_rule"
            nist_id=legacy.nist_family_id,  # e.g., "CM.06.1(iv)" or None
            severity=legacy.severity,  # Already normalized: "high", "medium", "low", "critical"
            title=legacy.title or "",
            description=legacy.description or "",
            check_text=legacy.check_text or "",
            fix_text=legacy.fix_text or "",
            product=product,  # e.g., "rhel9", "windows11", "cisco_ios_switch_ndm"
            category=category,  # e.g., "file_permission", "service", "package", etc.
            automation_level=automation_level,  # "automated", "manual_only", "unknown"
            automation_source=control_automation_source  # "none", "scap", "nessus"
        )
        controls.append(control)
    
    logger.info(f"Parsed {len(controls)} controls from {file_path}")
    
    # Count by automation level
    automated = sum(1 for c in controls if c.automation_level == 'automated')
    manual_only = sum(1 for c in controls if c.automation_level == 'manual_only')
    unknown = sum(1 for c in controls if c.automation_level == 'unknown')
    
    # Log automation classification
    if automation_source != "none":
        logger.info(f"Automation classification (source: {automation_source}):")
        logger.info(f"  - Automated: {automated} ({automated*100//len(controls) if controls else 0}%)")
        logger.info(f"  - Manual-only: {manual_only} ({manual_only*100//len(controls) if controls else 0}%)")
        if unknown > 0:
            logger.info(f"  - Unknown: {unknown} ({unknown*100//len(controls) if controls else 0}%)")
    else:
        logger.info(f"Automation classification (no secondary artifact):")
        logger.info(f"  - Unknown: {unknown} ({unknown*100//len(controls) if controls else 0}%)")
    
    return controls


def save_controls_to_json(controls: list[StigControl], output_path: Path) -> None:
    """
    Save StigControl objects to JSON file.
    
    Args:
        controls: List of StigControl objects
        output_path: Path where JSON should be written
    """
    output_path.parent.mkdir(parents=True, exist_ok=True)
    
    # Convert to list of dicts
    controls_dict = [control.to_dict() for control in controls]
    
    with open(output_path, "w", encoding="utf-8") as f:
        json.dump(controls_dict, f, indent=2, ensure_ascii=False)
    
    logger.info(f"Saved {len(controls)} controls to {output_path}")


def load_controls_from_json(json_path: Path) -> list[StigControl]:
    """
    Load StigControl objects from JSON file.
    
    Args:
        json_path: Path to JSON file
        
    Returns:
        List of StigControl objects
    """
    with open(json_path, "r", encoding="utf-8") as f:
        controls_dict = json.load(f)
    
    controls = [StigControl(**control_dict) for control_dict in controls_dict]
    logger.info(f"Loaded {len(controls)} controls from {json_path}")
    return controls


def main():
    """Main entry point for the parser script."""
    parser = argparse.ArgumentParser(
        description="Parse XCCDF XML STIG files into structured JSON"
    )
    parser.add_argument(
        "--xccdf", "-x",
        type=Path,
        required=True,
        help="Path to input XCCDF XML file (e.g., data/stigs/rhel9/2024_Q4/U_RHEL_9_STIG_V1R5_20241212.xml)"
    )
    parser.add_argument(
        "--output", "-o",
        type=Path,
        required=True,
        help="Path to output JSON file (e.g., data/json/rhel9_2024_Q4_controls.json)"
    )
    parser.add_argument(
        "--secondary-artifact",
        type=Path,
        help="Optional: Path to SCAP benchmark or Nessus scan XML file"
    )
    parser.add_argument(
        "--secondary-type",
        choices=["scap", "nessus"],
        help="Optional: Type of secondary artifact (scap or nessus). Auto-detected if not provided."
    )
    
    args = parser.parse_args()
    
    try:
        # Parse XCCDF file with optional secondary artifact
        controls = parse_xccdf_file(
            args.xccdf,
            secondary_artifact=args.secondary_artifact,
            secondary_type=args.secondary_type
        )
        
        # Save to JSON
        save_controls_to_json(controls, args.output)
        
        logger.info("✓ Parsing complete!")
        
    except FileNotFoundError as e:
        logger.error(f"File not found: {e}")
        return 1
    except ValueError as e:
        logger.error(f"Invalid input: {e}")
        return 1
    except Exception as e:
        logger.error(f"Error: {e}", exc_info=True)
        return 1
    
    return 0


if __name__ == "__main__":
    exit(main())


