"""Tests for data model."""

import pytest

from app.model.controls import StigControl, normalize_severity


def test_stig_control_creation():
    """Test creating a StigControl object."""
    control = StigControl(
        id="TEST-00-000001",
        title="Test Control",
        severity="high",
        description="Test description",
        rationale="Test rationale",
        check_text="Check something",
        fix_text="Fix something",
        os_family="rhel",
    )
    
    assert control.id == "TEST-00-000001"
    assert control.severity == "high"
    assert control.is_automatable == False
    assert control.category == "other"


def test_normalize_severity():
    """Test severity normalization."""
    assert normalize_severity("high") == "high"
    assert normalize_severity("HIGH") == "high"
    assert normalize_severity("cat ii") == "high"
    assert normalize_severity("cat i") == "critical"
    assert normalize_severity("cat iii") == "medium"
    assert normalize_severity("medium") == "medium"
    assert normalize_severity("low") == "low"
    assert normalize_severity("unknown") == "medium"  # Default


def test_normalize_severity_edge_cases():
    """Test severity normalization edge cases."""
    # Test that "cat ii" is checked before "cat i"
    assert normalize_severity("cat ii") == "high"
    assert normalize_severity("cat i") == "critical"
    
    # Test whitespace handling
    assert normalize_severity("  high  ") == "high"
    assert normalize_severity("\thigh\n") == "high"
    
    # Test case insensitivity
    assert normalize_severity("CRITICAL") == "critical"
    assert normalize_severity("Critical") == "critical"







