#!/usr/bin/env python3
"""Sanity check test - verify core functionality without dependencies."""

import sys
from pathlib import Path

# Add current directory to path
sys.path.insert(0, str(Path(__file__).parent))

from app.model.controls import StigControl, normalize_severity
from app.classifiers.automatable import classify_control
from app.generators.ansible_hardening import generate_hardening_playbook
from app.generators.ansible_checker import generate_checker_playbook
from app.generators.ctp_doc import generate_ctp_document


def test_model():
    """Test the data model."""
    print("Testing data model...")
    control = StigControl(
        id="RHEL-08-010010",
        title="Test Control",
        severity="high",
        description="Test description",
        rationale="Test rationale",
        check_text="Check /etc/passwd permissions",
        fix_text="chmod 644 /etc/passwd",
        os_family="rhel",
    )
    assert control.id == "RHEL-08-010010"
    assert control.severity == "high"
    print("  ✓ Data model works")


def test_severity_normalization():
    """Test severity normalization."""
    print("Testing severity normalization...")
    assert normalize_severity("high") == "high"
    assert normalize_severity("HIGH") == "high"
    assert normalize_severity("cat ii") == "high"
    assert normalize_severity("cat i") == "critical"
    assert normalize_severity("cat iii") == "medium"
    print("  ✓ Severity normalization works")


def test_classification():
    """Test control classification."""
    print("Testing classification...")
    # File permission control
    control = StigControl(
        id="RHEL-08-010010",
        title="File Permission Control",
        severity="high",
        description="Test",
        rationale=None,
        check_text="Check /etc/passwd permissions using chmod",
        fix_text="chmod 644 /etc/passwd",
        os_family="rhel",
    )
    control = classify_control(control)
    assert control.is_automatable == True
    assert control.category == "file_permission"
    
    # Manual control
    control2 = StigControl(
        id="RHEL-08-999999",
        title="Manual Review",
        severity="medium",
        description="Test",
        rationale=None,
        check_text="Review screenshot of GUI settings",
        fix_text="Manually configure in GUI",
        os_family="rhel",
    )
    control2 = classify_control(control2)
    assert control2.is_automatable == False
    print("  ✓ Classification works")


def test_generators():
    """Test generators with mock data."""
    print("Testing generators...")
    
    # Create test controls
    automatable = StigControl(
        id="RHEL-08-010010",
        title="File Permission Control",
        severity="high",
        description="Set /etc/passwd permissions",
        rationale=None,
        check_text="Check /etc/passwd permissions",
        fix_text="chmod 644 /etc/passwd",
        os_family="rhel",
        category="file_permission",
        is_automatable=True,
    )
    
    manual = StigControl(
        id="RHEL-08-999999",
        title="Manual Review Control",
        severity="medium",
        description="Manual review required",
        rationale=None,
        check_text="Review documentation",
        fix_text="Manual process",
        os_family="rhel",
        category="other",
        is_automatable=False,
    )
    
    controls = [automatable, manual]
    metadata = {
        "stig_name": "Test STIG",
        "stig_release": "v1.0",
        "source_file_name": "test.xml",
        "generated_on": "2024-01-01T00:00:00",
    }
    
    # Test hardening generator
    hardening_path = Path("output/test_hardening.yml")
    generate_hardening_playbook(controls, hardening_path, metadata)
    assert hardening_path.exists()
    content = hardening_path.read_text()
    assert "RHEL-08-010010" in content
    assert "file_permission" in content
    print("  ✓ Hardening generator works")
    
    # Test checker generator
    checker_path = Path("output/test_checker.yml")
    generate_checker_playbook(controls, checker_path, metadata)
    assert checker_path.exists()
    content = checker_path.read_text()
    assert "RHEL-08-999999" in content
    print("  ✓ Checker generator works")
    
    # Test CTP generator
    ctp_path = Path("output/test_ctp.md")
    generate_ctp_document(controls, ctp_path, metadata)
    assert ctp_path.exists()
    content = ctp_path.read_text()
    assert "RHEL-08-999999" in content
    assert "Pass/Fail" in content
    print("  ✓ CTP generator works")
    
    # Cleanup
    hardening_path.unlink()
    checker_path.unlink()
    ctp_path.unlink()


def main():
    """Run all sanity checks."""
    print("=" * 60)
    print("STIG Generator Sanity Check")
    print("=" * 60)
    print()
    
    try:
        test_model()
        test_severity_normalization()
        test_classification()
        test_generators()
        
        print()
        print("=" * 60)
        print("✓ ALL SANITY CHECKS PASSED")
        print("=" * 60)
        print()
        print("The application is ready to use!")
        print("Install dependencies with: pip install -r requirements.txt")
        print("Then run: python -m app.main --stig-file <path> --product rhel8")
        return 0
    except Exception as e:
        print()
        print("=" * 60)
        print("✗ SANITY CHECK FAILED")
        print("=" * 60)
        print(f"Error: {e}")
        import traceback
        traceback.print_exc()
        return 1


if __name__ == "__main__":
    sys.exit(main())

