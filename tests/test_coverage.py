"""Test coverage verification for STIG generators.

This test ensures that:
1. Every STIG ID in the source JSON appears in the hardening playbook
2. Every STIG ID in the source JSON appears in the checker playbook
3. Every STIG ID in the source JSON appears in the CTP CSV

Usage:
    pytest tests/test_coverage.py --json-path data/rhel9_stig_controls.json --hardening-path output/ansible/stig_rhel9_hardening.yml --checker-path output/ansible/stig_rhel9_checker.yml --ctp-path output/ctp/stig_rhel9_ctp.csv
"""

import csv
import json
import re
from pathlib import Path
from typing import Set


def load_stig_ids_from_json(json_path: Path) -> Set[str]:
    """Load all STIG IDs from JSON file."""
    with open(json_path, "r", encoding="utf-8") as f:
        controls = json.load(f)
    
    stig_ids = {control.get("sv_id") for control in controls if control.get("sv_id")}
    return stig_ids


def load_controls_from_json(json_path: Path) -> list[dict]:
    """Load all controls from JSON file."""
    with open(json_path, "r", encoding="utf-8") as f:
        controls = json.load(f)
    return controls


def extract_stig_ids_from_playbook(playbook_path: Path) -> Set[str]:
    """Extract STIG IDs from Ansible playbook tags."""
    with open(playbook_path, "r") as f:
        content = f.read()
    
    stig_ids = set()
    
    # Pattern 1: SV- format (e.g., SV-257777r991589_rule)
    sv_pattern = r'(SV-\d+r\d+_rule)'
    sv_matches = re.findall(sv_pattern, content)
    stig_ids.update(sv_matches)
    
    # Pattern 2: V- format (e.g., V-257777)
    v_pattern = r'(V-\d+)'
    v_matches = re.findall(v_pattern, content)
    stig_ids.update(v_matches)
    
    # Pattern 3: Legacy RHEL- format (e.g., RHEL-09-010010)
    legacy_pattern = r'-\s+([A-Z]+-\d+-\d+)'
    legacy_matches = re.findall(legacy_pattern, content)
    stig_ids.update(legacy_matches)
    
    return stig_ids


def extract_stig_ids_from_csv(csv_path: Path) -> Set[str]:
    """Extract STIG IDs from CTP CSV file."""
    stig_ids = set()
    
    with open(csv_path, "r", encoding="utf-8") as f:
        reader = csv.DictReader(f)
        for row in reader:
            stig_id = row.get("STIG ID", "").strip()
            if stig_id:
                stig_ids.add(stig_id)
    
    return stig_ids


def verify_hardening_coverage(json_path: Path, playbook_path: Path) -> tuple[bool, Set[str]]:
    """
    Verify that all STIG IDs from JSON appear in hardening playbook.
    
    Returns:
        (is_covered, missing_ids)
    """
    json_ids = load_stig_ids_from_json(json_path)
    playbook_ids = extract_stig_ids_from_playbook(playbook_path)
    
    missing_ids = json_ids - playbook_ids
    return len(missing_ids) == 0, missing_ids


def verify_checker_coverage(json_path: Path, playbook_path: Path) -> tuple[bool, Set[str]]:
    """
    Verify that all STIG IDs from JSON appear in checker playbook.
    
    Returns:
        (is_covered, missing_ids)
    """
    json_ids = load_stig_ids_from_json(json_path)
    playbook_ids = extract_stig_ids_from_playbook(playbook_path)
    
    missing_ids = json_ids - playbook_ids
    return len(missing_ids) == 0, missing_ids


def verify_ctp_coverage(json_path: Path, csv_path: Path, manual_only: bool = False) -> tuple[bool, Set[str]]:
    """
    Verify that all STIG IDs from JSON appear in CTP CSV.
    
    If manual_only=True, only verifies manual-only controls.
    If manual_only=False, verifies all controls.
    
    Returns:
        (is_covered, missing_ids)
    """
    controls = load_controls_from_json(json_path)
    
    if manual_only:
        # Only verify manual-only controls
        expected_ids = {
            control.get("sv_id")
            for control in controls
            if control.get("sv_id")
            and control.get("automation_level", "unknown") in ["manual_only", "manual", "not_scannable_with_nessus"]
        }
    else:
        # Verify all controls
        expected_ids = {control.get("sv_id") for control in controls if control.get("sv_id")}
    
    csv_ids = extract_stig_ids_from_csv(csv_path)
    
    missing_ids = expected_ids - csv_ids
    return len(missing_ids) == 0, missing_ids


def test_hardening_coverage(json_path: Path, hardening_path: Path):
    """Test that all STIG IDs are covered in hardening playbook."""
    is_covered, missing_ids = verify_hardening_coverage(json_path, hardening_path)
    
    assert is_covered, f"Missing STIG IDs in hardening playbook: {missing_ids}"


def test_checker_coverage(json_path: Path, checker_path: Path):
    """Test that all STIG IDs are covered in checker playbook."""
    is_covered, missing_ids = verify_checker_coverage(json_path, checker_path)
    
    assert is_covered, f"Missing STIG IDs in checker playbook: {missing_ids}"


def test_ctp_coverage(json_path: Path, ctp_path: Path):
    """Test that all STIG IDs are covered in CTP CSV."""
    is_covered, missing_ids = verify_ctp_coverage(json_path, ctp_path, manual_only=False)
    
    assert is_covered, f"Missing STIG IDs in CTP CSV: {missing_ids}"


def test_automation_metadata_present(json_path: Path):
    """Test that all controls have automation_level and automation_source fields."""
    controls = load_controls_from_json(json_path)
    
    for control in controls:
        automation_level = control.get("automation_level")
        automation_source = control.get("automation_source")
        
        assert automation_level is not None, f"Control {control.get('sv_id')} missing automation_level"
        assert automation_level in ["automated", "manual_only", "unknown"], \
            f"Control {control.get('sv_id')} has invalid automation_level: {automation_level}"
        
        assert automation_source is not None, f"Control {control.get('sv_id')} missing automation_source"
        assert automation_source in ["none", "scap", "nessus"], \
            f"Control {control.get('sv_id')} has invalid automation_source: {automation_source}"


def test_ctp_manual_only_filtering(json_path: Path, ctp_path: Path):
    """Test that CTP with --manual-only only includes manual-only controls."""
    controls = load_controls_from_json(json_path)
    
    # Get all automated controls
    automated_ids = {
        control.get("sv_id")
        for control in controls
        if control.get("automation_level", "unknown") == "automated"
    }
    
    # Read CTP CSV
    csv_ids = extract_stig_ids_from_csv(ctp_path)
    
    # If CTP was generated with --manual-only, it should not contain automated controls
    # (This is a best-effort check - we can't know for sure if --manual-only was used)
    # But we can verify that if automated controls are missing, manual-only controls are present
    if automated_ids and not automated_ids.intersection(csv_ids):
        # CTP doesn't contain automated controls - verify it contains manual-only
        manual_only_ids = {
            control.get("sv_id")
            for control in controls
            if control.get("automation_level", "unknown") in ["manual_only", "manual", "not_scannable_with_nessus"]
        }
        assert manual_only_ids.intersection(csv_ids), \
            "CTP appears to be filtered but doesn't contain manual-only controls"


def test_full_coverage(json_path: Path, hardening_path: Path, checker_path: Path, ctp_path: Path, manual_only: bool = False):
    """
    Test that all STIG IDs are covered in all artifacts.
    
    Args:
        json_path: Path to JSON file
        hardening_path: Path to hardening playbook
        checker_path: Path to checker playbook
        ctp_path: Path to CTP CSV
        manual_only: Whether CTP should only contain manual controls
    """
    hardening_covered, hardening_missing = verify_hardening_coverage(json_path, hardening_path)
    checker_covered, checker_missing = verify_checker_coverage(json_path, checker_path)
    ctp_covered, ctp_missing = verify_ctp_coverage(json_path, ctp_path, manual_only=manual_only)
    
    all_covered = hardening_covered and checker_covered and ctp_covered
    
    error_msg = []
    if not hardening_covered:
        error_msg.append(f"Hardening: {hardening_missing}")
    if not checker_covered:
        error_msg.append(f"Checker: {checker_missing}")
    if not ctp_covered:
        error_msg.append(f"CTP: {ctp_missing}")
    
    assert all_covered, f"Coverage failures:\n" + "\n".join(error_msg)


if __name__ == "__main__":
    # Example usage as a script
    import argparse
    
    parser = argparse.ArgumentParser(description="Test coverage of STIG generators")
    parser.add_argument("--json-path", type=Path, required=True, help="Path to StigControl JSON")
    parser.add_argument("--hardening-path", type=Path, help="Path to hardening playbook")
    parser.add_argument("--checker-path", type=Path, help="Path to checker playbook")
    parser.add_argument("--ctp-path", type=Path, help="Path to CTP CSV")
    
    args = parser.parse_args()
    
    if args.hardening_path:
        is_covered, missing = verify_hardening_coverage(args.json_path, args.hardening_path)
        if is_covered:
            print("✓ Hardening playbook: All STIG IDs covered")
        else:
            print(f"✗ Hardening playbook: Missing {len(missing)} STIG IDs: {missing}")
    
    if args.checker_path:
        is_covered, missing = verify_checker_coverage(args.json_path, args.checker_path)
        if is_covered:
            print("✓ Checker playbook: All STIG IDs covered")
        else:
            print(f"✗ Checker playbook: Missing {len(missing)} STIG IDs: {missing}")
    
    if args.ctp_path:
        is_covered, missing = verify_ctp_coverage(args.json_path, args.ctp_path)
        if is_covered:
            print("✓ CTP CSV: All STIG IDs covered")
        else:
            print(f"✗ CTP CSV: Missing {len(missing)} STIG IDs: {missing}")


