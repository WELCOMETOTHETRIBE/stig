"""Tests for control classification."""

from app.classifiers.automatable import classify_control
from app.model.controls import StigControl


def test_classify_file_permission():
    """Test classification of file permission controls."""
    control = StigControl(
        id="TEST-00-000001",
        title="File Permission Control",
        severity="high",
        description="Test",
        rationale=None,
        check_text="Check /etc/passwd permissions using chmod",
        fix_text="chmod 644 /etc/passwd",
        os_family="rhel",
    )
    
    classified = classify_control(control)
    assert classified.is_automatable == True
    assert classified.category == "file_permission"


def test_classify_service():
    """Test classification of service controls."""
    control = StigControl(
        id="TEST-00-000002",
        title="Service Control",
        severity="medium",
        description="Test",
        rationale=None,
        check_text="Check if service is enabled",
        fix_text="systemctl enable service-name",
        os_family="rhel",
    )
    
    classified = classify_control(control)
    assert classified.is_automatable == True
    assert classified.category == "service"


def test_classify_manual():
    """Test classification of manual controls."""
    control = StigControl(
        id="TEST-00-000003",
        title="Manual Review",
        severity="medium",
        description="Test",
        rationale=None,
        check_text="Review screenshot of GUI settings",
        fix_text="Manually configure in GUI",
        os_family="rhel",
    )
    
    classified = classify_control(control)
    assert classified.is_automatable == False
    assert classified.category == "other"


def test_classify_sysctl():
    """Test classification of sysctl controls."""
    control = StigControl(
        id="TEST-00-000004",
        title="Sysctl Control",
        severity="high",
        description="Test",
        rationale=None,
        check_text="Check kernel parameter",
        fix_text="sysctl -w net.ipv4.ip_forward=0",
        os_family="rhel",
    )
    
    classified = classify_control(control)
    assert classified.is_automatable == True
    assert classified.category == "sysctl"


def test_classify_package():
    """Test classification of package controls."""
    control = StigControl(
        id="TEST-00-000005",
        title="Package Control",
        severity="medium",
        description="Test",
        rationale=None,
        check_text="Check if package is installed",
        fix_text="yum install package-name",
        os_family="rhel",
    )
    
    classified = classify_control(control)
    assert classified.is_automatable == True
    assert classified.category == "package"


def test_classify_network_device():
    """Test classification of network device controls."""
    control = StigControl(
        id="TEST-00-000006",
        title="Network Device Control",
        severity="high",
        description="Test",
        rationale=None,
        check_text="Review the configuration",
        fix_text="configure terminal\ninterface gig0/1\nswitchport mode access",
        os_family="network",
    )
    
    classified = classify_control(control)
    # Network controls with "Review" should be manual
    assert classified.is_automatable == False
    assert classified.category == "other"


def test_classify_network_device_automatable():
    """Test classification of automatable network device controls."""
    control = StigControl(
        id="TEST-00-000007",
        title="Network Device Control",
        severity="high",
        description="Test",
        rationale=None,
        check_text="Check interface configuration",
        fix_text="configure terminal\ninterface gig0/1\nswitchport mode access\nmls qos",
        os_family="network",
    )
    
    classified = classify_control(control)
    assert classified.is_automatable == True
    assert classified.category == "config"







