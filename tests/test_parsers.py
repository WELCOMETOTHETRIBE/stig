"""Tests for XCCDF parser."""

import tempfile
import xml.etree.ElementTree as ET
from pathlib import Path
import pytest

from app.parsers.xccdf_parser import parse_xccdf, _extract_os_family_from_benchmark
from app.model.controls import StigControl


def test_parse_xccdf_file_not_found():
    """Test that FileNotFoundError is raised for non-existent files."""
    with pytest.raises(FileNotFoundError):
        parse_xccdf(Path("/nonexistent/file.xml"))


def test_parse_xccdf_invalid_xml():
    """Test that ValueError is raised for invalid XML."""
    with tempfile.NamedTemporaryFile(mode='w', suffix='.xml', delete=False) as f:
        f.write("<?xml version='1.0'?><invalid><unclosed>")
        temp_path = Path(f.name)
    
    try:
        with pytest.raises(ValueError, match="Failed to parse XML"):
            parse_xccdf(temp_path)
    finally:
        temp_path.unlink()


def test_parse_xccdf_empty_file():
    """Test parsing empty XML file."""
    with tempfile.NamedTemporaryFile(mode='w', suffix='.xml', delete=False) as f:
        f.write("<?xml version='1.0'?><Benchmark></Benchmark>")
        temp_path = Path(f.name)
    
    try:
        controls = parse_xccdf(temp_path)
        assert controls == []
    finally:
        temp_path.unlink()


def test_parse_xccdf_minimal_valid():
    """Test parsing minimal valid XCCDF file."""
    xml_content = """<?xml version='1.0'?>
<Benchmark xmlns="http://checklists.nist.gov/xccdf/1.2" id="test-benchmark">
    <title>Test STIG</title>
    <Group id="test-group">
        <title>Test Group</title>
        <Rule id="TEST-00-000001" severity="high">
            <title>Test Rule</title>
            <description>Test description</description>
            <check>
                <check-content>Check something</check-content>
            </check>
            <fixtext>Fix something</fixtext>
        </Rule>
    </Group>
</Benchmark>"""
    
    with tempfile.NamedTemporaryFile(mode='w', suffix='.xml', delete=False) as f:
        f.write(xml_content)
        temp_path = Path(f.name)
    
    try:
        controls = parse_xccdf(temp_path)
        assert len(controls) == 1
        assert controls[0].id == "TEST-00-000001"
        assert controls[0].severity == "high"
        assert controls[0].title == "Test Rule"
    finally:
        temp_path.unlink()


def test_extract_os_family_windows():
    """Test OS family extraction for Windows."""
    root = ET.Element("Benchmark")
    root.set("id", "windows-benchmark")
    title = ET.SubElement(root, "title")
    title.text = "Windows 11 STIG"
    
    namespaces = {"xccdf": "http://checklists.nist.gov/xccdf/1.2"}
    os_family = _extract_os_family_from_benchmark(root, namespaces)
    assert os_family == "windows"


def test_extract_os_family_rhel():
    """Test OS family extraction for RHEL."""
    root = ET.Element("Benchmark")
    root.set("id", "rhel-benchmark")
    title = ET.SubElement(root, "title")
    title.text = "RHEL 8 STIG"
    
    namespaces = {"xccdf": "http://checklists.nist.gov/xccdf/1.2"}
    os_family = _extract_os_family_from_benchmark(root, namespaces)
    assert os_family == "rhel"


def test_extract_os_family_network():
    """Test OS family extraction for network devices."""
    root = ET.Element("Benchmark")
    root.set("id", "cisco-benchmark")
    title = ET.SubElement(root, "title")
    title.text = "Cisco IOS Switch STIG"
    
    namespaces = {"xccdf": "http://checklists.nist.gov/xccdf/1.2"}
    os_family = _extract_os_family_from_benchmark(root, namespaces)
    assert os_family == "network"


def test_parse_xccdf_missing_required_fields():
    """Test parsing with missing required fields (should handle gracefully)."""
    xml_content = """<?xml version='1.0'?>
<Benchmark xmlns="http://checklists.nist.gov/xccdf/1.2" id="test-benchmark">
    <title>Test STIG</title>
    <Group id="test-group">
        <title>Test Group</title>
        <Rule id="TEST-00-000001" severity="high">
            <title>Test Rule</title>
        </Rule>
    </Group>
</Benchmark>"""
    
    with tempfile.NamedTemporaryFile(mode='w', suffix='.xml', delete=False) as f:
        f.write(xml_content)
        temp_path = Path(f.name)
    
    try:
        controls = parse_xccdf(temp_path)
        assert len(controls) == 1
        assert controls[0].description == ""
        assert controls[0].check_text == ""
        assert controls[0].fix_text == ""
    finally:
        temp_path.unlink()


def test_parse_xccdf_multiple_rules():
    """Test parsing multiple rules."""
    xml_content = """<?xml version='1.0'?>
<Benchmark xmlns="http://checklists.nist.gov/xccdf/1.2" id="test-benchmark">
    <title>Test STIG</title>
    <Group id="test-group">
        <title>Test Group</title>
        <Rule id="TEST-00-000001" severity="high">
            <title>Rule 1</title>
            <check><check-content>Check 1</check-content></check>
            <fixtext>Fix 1</fixtext>
        </Rule>
        <Rule id="TEST-00-000002" severity="medium">
            <title>Rule 2</title>
            <check><check-content>Check 2</check-content></check>
            <fixtext>Fix 2</fixtext>
        </Rule>
    </Group>
</Benchmark>"""
    
    with tempfile.NamedTemporaryFile(mode='w', suffix='.xml', delete=False) as f:
        f.write(xml_content)
        temp_path = Path(f.name)
    
    try:
        controls = parse_xccdf(temp_path)
        assert len(controls) == 2
        assert controls[0].id == "TEST-00-000001"
        assert controls[1].id == "TEST-00-000002"
    finally:
        temp_path.unlink()







