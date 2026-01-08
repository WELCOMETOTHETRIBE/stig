"""Tests for generators."""

import tempfile
from pathlib import Path

from app.generators.ansible_hardening import generate_hardening_playbook
from app.generators.ansible_checker import generate_checker_playbook
from app.generators.ctp_doc import generate_ctp_document
from app.model.controls import StigControl


def test_generate_hardening_playbook_empty_controls():
    """Test generating hardening playbook with empty controls list."""
    with tempfile.TemporaryDirectory() as tmpdir:
        output_path = Path(tmpdir) / "test_hardening.yml"
        metadata = {
            "stig_name": "Test STIG",
            "stig_release": "v1.0",
            "source_file_name": "test.xml",
            "generated_on": "2024-01-01T00:00:00",
        }
        
        # Should handle empty list gracefully
        generate_hardening_playbook([], output_path, metadata)
        assert output_path.exists()
        
        content = output_path.read_text()
        assert "Total Controls: 0" in content


def test_generate_checker_playbook_empty_controls():
    """Test generating checker playbook with empty controls list."""
    with tempfile.TemporaryDirectory() as tmpdir:
        output_path = Path(tmpdir) / "test_checker.yml"
        metadata = {
            "stig_name": "Test STIG",
            "stig_release": "v1.0",
            "source_file_name": "test.xml",
            "generated_on": "2024-01-01T00:00:00",
        }
        
        generate_checker_playbook([], output_path, metadata)
        assert output_path.exists()
        
        content = output_path.read_text()
        assert "Total Controls: 0" in content


def test_generate_ctp_document_empty_controls():
    """Test generating CTP document with empty controls list."""
    with tempfile.TemporaryDirectory() as tmpdir:
        output_path = Path(tmpdir) / "test_ctp.csv"
        metadata = {
            "stig_name": "Test STIG",
            "stig_release": "v1.0",
            "source_file_name": "test.xml",
            "generated_on": "2024-01-01T00:00:00",
        }
        
        generate_ctp_document([], output_path, metadata)
        assert output_path.exists()
        
        content = output_path.read_text()
        assert "STIG ID" in content  # Header should be present


def test_generate_hardening_playbook_special_characters():
    """Test generating playbook with special characters in control text."""
    control = StigControl(
        id="TEST-00-000001",
        title="Control with: colons and 'quotes'",
        severity="high",
        description="Description with: colons",
        rationale=None,
        check_text="Check text with: colons",
        fix_text="Fix text with: colons and 'quotes'",
        os_family="rhel",
        category="file_permission",
        is_automatable=True,
    )
    
    with tempfile.TemporaryDirectory() as tmpdir:
        output_path = Path(tmpdir) / "test_hardening.yml"
        metadata = {
            "stig_name": "Test STIG",
            "stig_release": "v1.0",
            "source_file_name": "test.xml",
            "generated_on": "2024-01-01T00:00:00",
        }
        
        generate_hardening_playbook([control], output_path, metadata)
        assert output_path.exists()
        
        content = output_path.read_text()
        # Should handle special characters without breaking YAML
        assert "TEST-00-000001" in content


def test_hardening_playbook_includes_all_controls():
    """Test that hardening playbook includes ALL controls, even manual ones."""
    automatable_with_commands = StigControl(
        id="TEST-00-000001",
        title="Automatable Control with Commands",
        severity="high",
        description="Test",
        rationale=None,
        check_text="Check something",
        fix_text="Fix something",
        os_family="rhel",
        category="file_permission",
        is_automatable=True,
        automatable_commands=["chmod 644 /etc/test.conf"],
    )
    
    manual_without_commands = StigControl(
        id="TEST-00-000002",
        title="Manual Control without Commands",
        severity="medium",
        description="Test manual",
        rationale=None,
        check_text="Review something",
        fix_text="Manual process - no commands",
        os_family="rhel",
        category="other",
        is_automatable=False,
        automatable_commands=[],  # No commands
    )
    
    manual_with_commands = StigControl(
        id="TEST-00-000003",
        title="Manual Control with Commands",
        severity="low",
        description="Test",
        rationale=None,
        check_text="Check something",
        fix_text="Fix something",
        os_family="rhel",
        category="config",
        is_automatable=False,  # Marked as manual but has commands
        automatable_commands=["echo 'test'"],
    )
    
    controls = [automatable_with_commands, manual_without_commands, manual_with_commands]
    
    with tempfile.TemporaryDirectory() as tmpdir:
        output_path = Path(tmpdir) / "test_hardening.yml"
        metadata = {
            "stig_name": "Test STIG",
            "stig_release": "v1.0",
            "source_file_name": "test.xml",
            "generated_on": "2024-01-01T00:00:00",
        }
        
        generate_hardening_playbook(controls, output_path, metadata)
        content = output_path.read_text()
        
        # All controls should be included
        assert "TEST-00-000001" in content
        assert "TEST-00-000002" in content
        assert "TEST-00-000003" in content
        
        # Control with commands should have real task (not just debug)
        assert "chmod 644" in content or "file:" in content or "shell:" in content
        
        # Control without commands should have debug task
        assert "Manual hardening required" in content or "debug:" in content
        
        # Control marked manual but with commands should still have real task
        assert "echo 'test'" in content or "shell:" in content


def test_generate_checker_playbook_includes_all_controls():
    """Test that checker playbook includes ALL controls regardless of is_automatable."""
    automatable = StigControl(
        id="TEST-00-000001",
        title="Automatable Control",
        severity="high",
        description="Test",
        rationale=None,
        check_text="Check something",
        fix_text="Fix something",
        os_family="rhel",
        category="file_permission",
        is_automatable=True,
    )
    
    manual = StigControl(
        id="TEST-00-000002",
        title="Manual Control",
        severity="medium",
        description="Test",
        rationale=None,
        check_text="Review something",
        fix_text="Manual process",
        os_family="rhel",
        category="other",
        is_automatable=False,
    )
    
    controls = [automatable, manual]
    
    with tempfile.TemporaryDirectory() as tmpdir:
        output_path = Path(tmpdir) / "test_checker.yml"
        metadata = {
            "stig_name": "Test STIG",
            "stig_release": "v1.0",
            "source_file_name": "test.xml",
            "generated_on": "2024-01-01T00:00:00",
        }
        
        # All controls should be included
        generate_checker_playbook(controls, output_path, metadata)
        content = output_path.read_text()
        assert "TEST-00-000001" in content
        assert "TEST-00-000002" in content
        
        # Check that tags are correct
        assert "validate_automatable" in content
        assert "validate_manual" in content
        
        # Check that automatable control has validate_automatable tag
        assert "validate_automatable" in content[content.find("TEST-00-000001"):content.find("TEST-00-000001")+500]
        
        # Check that manual control has validate_manual tag
        assert "validate_manual" in content[content.find("TEST-00-000002"):content.find("TEST-00-000002")+500]
        
        # Check usage documentation is present
        assert "ansible-playbook checker.yml --tags validate_automatable" in content
        assert "ansible-playbook checker.yml --tags validate_manual" in content


def test_network_hardening_no_placeholders():
    """Test that network hardening playbook doesn't contain placeholder tokens."""
    control = StigControl(
        id="SV-220424r1117237_rule",
        title="Test Network Control",
        severity="low",
        description="Test",
        rationale=None,
        check_text="Check something",
        fix_text="""Disable all inactive interfaces as shown below:
SW1(config)#interface GigabitEthernet0/1
SW1(config-if)#shutdown
SW1(config-if)#exit
config)
config-if)
config-ext-nacl)""",
        os_family="network",
        category="other",
        is_automatable=False,
    )
    
    with tempfile.TemporaryDirectory() as tmpdir:
        output_path = Path(tmpdir) / "test_network_hardening.yml"
        metadata = {
            "stig_name": "Test Network STIG",
            "stig_release": "v1.0",
            "source_file_name": "test.xml",
            "generated_on": "2024-01-01T00:00:00",
        }
        
        generate_hardening_playbook([control], output_path, metadata)
        assert output_path.exists()
        
        content = output_path.read_text()
        
        # Should NOT contain placeholder tokens
        assert "config)" not in content
        assert "config-if)" not in content
        assert "config-ext-nacl)" not in content
        assert "Disable all inactive interfaces as shown below:" not in content
        
        # Should contain real commands if any were extracted
        # If no real commands, should have debug message instead
        assert ("interface GigabitEthernet0/1" in content or 
                "Manual configuration required" in content or
                "debug:" in content)


def test_extract_cli_commands_filters_placeholders():
    """Test that extract_cli_commands filters out placeholders correctly."""
    from app.generators.utils import extract_cli_commands
    
    raw_lines = [
        "config)",
        "config-if)",
        "config-ext-nacl)",
        "Disable all inactive interfaces as shown below:",
        "interface GigabitEthernet0/1",
        "ip address 192.168.1.1 255.255.255.0",
        "no cdp run",
        "SW1(config)#interface GigabitEthernet0/2",
        "SW1(config-if)#shutdown",
    ]
    
    cli_commands, notes = extract_cli_commands(raw_lines)
    
    # Should filter out placeholders
    assert "config)" not in cli_commands
    assert "config-if)" not in cli_commands
    assert "config-ext-nacl)" not in cli_commands
    assert "Disable all inactive interfaces as shown below:" not in cli_commands
    
    # Should extract real commands
    assert "interface GigabitEthernet0/1" in cli_commands
    assert "ip address 192.168.1.1 255.255.255.0" in cli_commands
    assert "no cdp run" in cli_commands
    assert "interface GigabitEthernet0/2" in cli_commands
    assert "shutdown" in cli_commands
    
    # Should strip prompts
    assert "SW1(config)#" not in " ".join(cli_commands)
    assert "SW1(config-if)#" not in " ".join(cli_commands)


def test_hardening_playbook_no_placeholder_junk():
    """Test that hardening playbook doesn't contain placeholder junk."""
    import re
    
    control = StigControl(
        id="SV-TEST-001",
        title="Test Control",
        severity="high",
        description="Test description",
        rationale=None,
        check_text="Check text",
        fix_text="""Configure the switch to enable password encryption:
config)
service password-encryption
config-if)
no cdp run
as shown in the example""",
        os_family="network",
        category="config",
        is_automatable=True,
        automatable_commands=["service password-encryption", "no cdp run"],
    )
    
    with tempfile.TemporaryDirectory() as tmpdir:
        output_path = Path(tmpdir) / "test_hardening.yml"
        metadata = {
            "stig_name": "Test STIG",
            "stig_release": "v1.0",
            "source_file_name": "test.xml",
            "generated_on": "2024-01-01T00:00:00",
        }
        
        generate_hardening_playbook([control], output_path, metadata)
        content = output_path.read_text()
        
        # Blacklist patterns that should NOT appear in command fields
        blacklist_patterns = [
            r'config\)\s*$',  # Lines ending with config)
            r'config-if\)\s*$',
            r'config-ext-nacl\)\s*$',
            r'as shown (below|above|in the example)',
            r'^Step \d+',
            r'Configure the (switch|device|router) to',
        ]
        
        # Check lines: or cmd: fields
        lines_pattern = r'lines:\s*\n((?:\s+-\s+[^\n]+\n?)+)'
        cmd_pattern = r'cmd:\s*([^\n]+)'
        
        for pattern in blacklist_patterns:
            # Check in lines: blocks
            matches = re.findall(lines_pattern, content, re.MULTILINE)
            for match in matches:
                assert not re.search(pattern, match, re.IGNORECASE), \
                    f"Found blacklisted pattern '{pattern}' in lines block"
            
            # Check in cmd: fields
            matches = re.findall(cmd_pattern, content)
            for match in matches:
                assert not re.search(pattern, match, re.IGNORECASE), \
                    f"Found blacklisted pattern '{pattern}' in cmd field"


def test_checker_playbook_no_placeholder_junk():
    """Test that checker playbook doesn't contain placeholder junk."""
    import re
    
    control = StigControl(
        id="SV-TEST-001",
        title="Test Control",
        severity="high",
        description="Test description",
        rationale=None,
        check_text="""Review the configuration:
config)
show running-config
as shown in the example""",
        fix_text="Fix text",
        os_family="network",
        category="other",
        is_automatable=False,
        check_commands=["show running-config"],
    )
    
    with tempfile.TemporaryDirectory() as tmpdir:
        output_path = Path(tmpdir) / "test_checker.yml"
        metadata = {
            "stig_name": "Test STIG",
            "stig_release": "v1.0",
            "source_file_name": "test.xml",
            "generated_on": "2024-01-01T00:00:00",
        }
        
        generate_checker_playbook([control], output_path, metadata)
        content = output_path.read_text()
        
        # Blacklist patterns
        blacklist_patterns = [
            r'config\)\s*$',
            r'as shown (below|above|in the example)',
            r'^Step \d+',
        ]
        
        # Check commands: fields
        cmd_pattern = r'commands:\s*\n((?:\s+-\s+[^\n]+\n?)+)'
        matches = re.findall(cmd_pattern, content, re.MULTILINE)
        for match in matches:
            for pattern in blacklist_patterns:
                assert not re.search(pattern, match, re.IGNORECASE), \
                    f"Found blacklisted pattern '{pattern}' in commands block"


def test_ctp_csv_no_placeholder_junk():
    """Test that CTP CSV doesn't contain placeholder junk."""
    import csv
    import io
    
    control = StigControl(
        id="SV-TEST-001",
        title="Test Control",
        severity="high",
        description="Test description",
        rationale=None,
        check_text="""Review the configuration:
config)
show running-config
as shown in the example""",
        fix_text="Fix text",
        os_family="network",
        category="other",
        is_automatable=False,
        check_commands=["show running-config"],
    )
    
    with tempfile.TemporaryDirectory() as tmpdir:
        output_path = Path(tmpdir) / "test_ctp.csv"
        metadata = {
            "stig_name": "Test STIG",
            "stig_release": "v1.0",
            "source_file_name": "test.xml",
            "generated_on": "2024-01-01T00:00:00",
        }
        
        generate_ctp_document([control], output_path, metadata)
        content = output_path.read_text()
        
        # Parse CSV
        reader = csv.DictReader(io.StringIO(content))
        for row in reader:
            command_field = row.get("Command_or_Process", "")
            
            # Should NOT contain placeholder tokens
            assert "config)" not in command_field
            assert "config-if)" not in command_field
            assert "as shown in the example" not in command_field.lower()
            
            # Should contain real commands or be empty/clear manual instruction
            if command_field:
                assert len(command_field.strip()) > 0
                # Should not be just prose
                assert not command_field.strip().endswith(":")


def test_hardening_no_systemd_flag_as_name():
    """Test that hardening playbook doesn't have systemd tasks with flags as unit names."""
    control = StigControl(
        id="RHEL-09-000001",
        title="Test Service Control",
        severity="high",
        description="Test",
        rationale=None,
        check_text="Check service",
        fix_text="systemctl enable rngd --now",
        os_family="rhel",
        category="service",
        is_automatable=True,
        automatable_commands=["systemctl enable rngd --now"],
        service_actions=[{"unit": "rngd", "action": "enable_and_start"}],
    )
    
    with tempfile.TemporaryDirectory() as tmpdir:
        output_path = Path(tmpdir) / "test_hardening.yml"
        metadata = {
            "stig_name": "RHEL 9 STIG",
            "stig_release": "v2.6",
            "source_file_name": "test.xml",
            "generated_on": "2024-01-01T00:00:00",
        }
        
        generate_hardening_playbook([control], output_path, metadata)
        content = output_path.read_text()
        
        # Should NOT have systemd tasks with flags as unit names
        assert 'name: --now' not in content
        assert 'name: --mask' not in content
        assert 'name: --status' not in content
        
        # Should have proper unit name
        assert 'name: rngd' in content or 'name: "rngd"' in content


def test_hardening_sysctl_has_value():
    """Test that all sysctl tasks include a value field."""
    control = StigControl(
        id="RHEL-09-000002",
        title="Test Sysctl Control",
        severity="high",
        description="Test",
        rationale=None,
        check_text="Check sysctl",
        fix_text="kernel.randomize_va_space = 2",
        os_family="rhel",
        category="sysctl",
        is_automatable=True,
        automatable_commands=["sysctl -w kernel.randomize_va_space=2"],
        sysctl_params=[{"name": "kernel.randomize_va_space", "value": "2"}],
    )
    
    with tempfile.TemporaryDirectory() as tmpdir:
        output_path = Path(tmpdir) / "test_hardening.yml"
        metadata = {
            "stig_name": "RHEL 9 STIG",
            "stig_release": "v2.6",
            "source_file_name": "test.xml",
            "generated_on": "2024-01-01T00:00:00",
        }
        
        generate_hardening_playbook([control], output_path, metadata)
        content = output_path.read_text()
        
        # Should have sysctl task with value
        assert "sysctl:" in content
        assert "name: kernel.randomize_va_space" in content
        assert "value:" in content
        assert "'2'" in content or '"2"' in content


def test_checker_no_degenerate_grep():
    """Test that checker playbook doesn't use degenerate grep patterns."""
    control = StigControl(
        id="RHEL-09-000003",
        title="Test Check Control",
        severity="high",
        description="Test",
        rationale=None,
        check_text="grep -rn kernel.dmesg_restrict /etc/sysctl.conf",
        fix_text="Fix text",
        os_family="rhel",
        category="sysctl",
        is_automatable=True,
        check_commands=["grep -rn kernel.dmesg_restrict /etc/sysctl.conf"],
    )
    
    with tempfile.TemporaryDirectory() as tmpdir:
        output_path = Path(tmpdir) / "test_checker.yml"
        metadata = {
            "stig_name": "RHEL 9 STIG",
            "stig_release": "v2.6",
            "source_file_name": "test.xml",
            "generated_on": "2024-01-01T00:00:00",
        }
        
        generate_checker_playbook([control], output_path, metadata)
        content = output_path.read_text()
        
        # Should have meaningful grep pattern
        assert "kernel.dmesg_restrict" in content
        
        # Should NOT have degenerate patterns
        assert "grep -E '-r'" not in content
        assert "grep -E '-i'" not in content
        assert "grep -E 'args'" not in content


def test_control_has_real_commands():
    """Test that has_real_commands() correctly identifies real commands."""
    # Control with real commands
    control_with_commands = StigControl(
        id="TEST-001",
        title="Test",
        severity="high",
        description="Test",
        rationale=None,
        check_text="Check",
        fix_text="Fix",
        os_family="rhel",
        automatable_commands=["systemctl enable rngd"],
    )
    assert control_with_commands.has_real_commands() == True
    
    # Control with only prose
    control_with_prose = StigControl(
        id="TEST-002",
        title="Test",
        severity="high",
        description="Test",
        rationale=None,
        check_text="Check",
        fix_text="Fix",
        os_family="rhel",
        automatable_commands=["Verify that RHEL 9 is configured"],
    )
    assert control_with_prose.has_real_commands() == False
    
    # Control with only flags
    control_with_flags = StigControl(
        id="TEST-003",
        title="Test",
        severity="high",
        description="Test",
        rationale=None,
        check_text="Check",
        fix_text="Fix",
        os_family="rhel",
        automatable_commands=["-r", "-i"],
    )
    assert control_with_flags.has_real_commands() == False
    
    # Control with no commands
    control_no_commands = StigControl(
        id="TEST-004",
        title="Test",
        severity="high",
        description="Test",
        rationale=None,
        check_text="Check",
        fix_text="Fix",
        os_family="rhel",
    )
    assert control_no_commands.has_real_commands() == False


def test_hardening_no_prose_in_shell():
    """Test that hardening playbook doesn't contain prose in shell commands."""
    control = StigControl(
        id="RHEL-09-000004",
        title="Test Control",
        severity="high",
        description="Test",
        rationale=None,
        check_text="Check",
        fix_text="systemctl daemon-reload Verify RHEL 9 is configured to boot to the command line",
        os_family="rhel",
        category="service",
        is_automatable=True,
        automatable_commands=["systemctl daemon-reload"],
    )
    
    with tempfile.TemporaryDirectory() as tmpdir:
        output_path = Path(tmpdir) / "test_hardening.yml"
        metadata = {
            "stig_name": "RHEL 9 STIG",
            "stig_release": "v2.6",
            "source_file_name": "test.xml",
            "generated_on": "2024-01-01T00:00:00",
        }
        
        generate_hardening_playbook([control], output_path, metadata)
        content = output_path.read_text()
        
        # Should NOT contain prose in commands
        assert "Verify RHEL" not in content
        assert "Verify that RHEL 9" not in content
        assert "as shown in the example" not in content.lower()
        assert "this is a finding" not in content.lower()
        
        # Should contain clean command
        if "systemctl daemon-reload" in content:
            # Ensure it's not followed by prose
            cmd_pos = content.find("systemctl daemon-reload")
            after_cmd = content[cmd_pos:cmd_pos+100]
            assert "Verify" not in after_cmd or "Verify" not in after_cmd.split("\n")[0]


def test_systemd_extraction_various_patterns():
    """Test systemd extraction handles various command patterns correctly."""
    from app.generators.extractors import extract_systemd_actions
    
    # Test case 1: systemctl enable rngd --now
    actions = extract_systemd_actions("systemctl enable rngd --now")
    assert len(actions) == 1
    assert actions[0]["unit"] == "rngd"
    assert actions[0]["action"] == "enable_and_start"
    
    # Test case 2: systemctl --now enable rngd
    actions = extract_systemd_actions("systemctl --now enable rngd")
    assert len(actions) == 1
    assert actions[0]["unit"] == "rngd"
    assert actions[0]["action"] == "enable_and_start"
    
    # Test case 3: systemctl mask ctrl-alt-del.target
    actions = extract_systemd_actions("systemctl mask ctrl-alt-del.target")
    assert len(actions) == 1
    assert actions[0]["unit"] == "ctrl-alt-del.target"
    assert actions[0]["action"] == "mask"
    
    # Test case 4: systemctl disable service-name
    actions = extract_systemd_actions("systemctl disable service-name")
    assert len(actions) == 1
    assert actions[0]["unit"] == "service-name"
    assert actions[0]["action"] == "disable"
    
    # Test case 5: Should NOT extract --now as unit
    actions = extract_systemd_actions("systemctl enable --now")
    assert len(actions) == 0  # Should be empty - no valid unit
    
    # Test case 6: systemctl restart systemd-journald
    actions = extract_systemd_actions("systemctl restart systemd-journald")
    assert len(actions) == 1
    assert actions[0]["unit"] == "systemd-journald"
    assert actions[0]["action"] == "restart"


def test_grep_pattern_validation():
    """Test that degenerate grep patterns are filtered out."""
    from app.generators.extractors import extract_check_commands_from_block
    
    # Test case 1: Degenerate pattern - grep -E '-r'
    check_text = "grep -E '-r' /etc/sysctl.conf"
    commands, notes = extract_check_commands_from_block(check_text, "rhel")
    assert len(commands) == 0  # Should be filtered out
    assert any("degenerate" in note.lower() for note in notes)
    
    # Test case 2: Degenerate pattern - grep -E '-A1'
    check_text = "grep -E '-A1' /etc/grub2.cfg"
    commands, notes = extract_check_commands_from_block(check_text, "rhel")
    assert len(commands) == 0  # Should be filtered out
    
    # Test case 3: Valid pattern - grep with meaningful pattern
    check_text = "grep 'systemd.confirm_spawn' /etc/default/grub"
    commands, notes = extract_check_commands_from_block(check_text, "rhel")
    assert len(commands) > 0
    assert any("systemd.confirm_spawn" in cmd for cmd in commands)
    
    # Test case 4: Valid pattern - grep vsyscall
    check_text = "grep vsyscall /etc/default/grub"
    commands, notes = extract_check_commands_from_block(check_text, "rhel")
    assert len(commands) > 0
    assert any("vsyscall" in cmd for cmd in commands)
    
    # Test case 5: Valid pattern with flags - grep -rn kernel.dmesg_restrict
    check_text = "grep -rn kernel.dmesg_restrict /etc/sysctl.conf"
    commands, notes = extract_check_commands_from_block(check_text, "rhel")
    assert len(commands) > 0
    assert any("kernel.dmesg_restrict" in cmd for cmd in commands)


def test_checker_no_degenerate_grep_in_output():
    """Test that checker playbook doesn't contain degenerate grep patterns."""
    control = StigControl(
        id="RHEL-09-000005",
        title="Test Check Control",
        severity="high",
        description="Test",
        rationale=None,
        check_text="grep -E '-r' /etc/sysctl.conf",
        fix_text="Fix text",
        os_family="rhel",
        category="sysctl",
        is_automatable=True,
        check_commands=[],  # Empty - should trigger fallback
    )
    
    with tempfile.TemporaryDirectory() as tmpdir:
        output_path = Path(tmpdir) / "test_checker.yml"
        metadata = {
            "stig_name": "RHEL 9 STIG",
            "stig_release": "v2.6",
            "source_file_name": "test.xml",
            "generated_on": "2024-01-01T00:00:00",
        }
        
        generate_checker_playbook([control], output_path, metadata)
        content = output_path.read_text()
        
        # Should NOT have degenerate grep patterns
        assert "grep -E '-r'" not in content
        assert "grep -E '-i'" not in content
        assert "grep -E '-A1'" not in content
        
        # Should have a debug task for manual validation
        assert "debug:" in content or "Manual validation" in content


def test_ctp_no_prose_in_commands():
    """Test that CTP Action/Command fields don't contain prose."""
    import csv
    import io
    
    control = StigControl(
        id="RHEL-09-000006",
        title="Test Control",
        severity="high",
        description="Test",
        rationale=None,
        check_text="grep 'kernel.dmesg_restrict' /etc/sysctl.conf",
        fix_text="Fix text",
        os_family="rhel",
        category="sysctl",
        is_automatable=False,
        check_commands=["grep 'kernel.dmesg_restrict' /etc/sysctl.conf"],
    )
    
    with tempfile.TemporaryDirectory() as tmpdir:
        output_path = Path(tmpdir) / "test_ctp.csv"
        metadata = {
            "stig_name": "RHEL 9 STIG",
            "stig_release": "v2.6",
            "source_file_name": "test.xml",
            "generated_on": "2024-01-01T00:00:00",
        }
        
        generate_ctp_document([control], output_path, metadata)
        content = output_path.read_text()
        
        # Parse CSV
        reader = csv.DictReader(io.StringIO(content))
        for row in reader:
            command_field = row.get("Action/Command", "")
            
            # Should NOT contain prose markers
            assert "Verify RHEL 9" not in command_field
            assert "as shown in the example" not in command_field.lower()
            assert "this is a finding" not in command_field.lower()
            assert "with the following command" not in command_field.lower()
            
            # Should contain real command or clear manual instruction
            if command_field:
                assert len(command_field.strip()) > 0


def test_rhel9_no_bogus_package_names():
    """Test that RHEL 9 hardening playbook never generates bogus package names."""
    # Test cases that previously generated bad package names
    test_cases = [
        {
            "id": "SV-257823r1051231_rule",
            "fix_text": "RHEL 9 must be configured so that the cryptographic hashes of system files match vendor values.",
            "expected_bad": ["that"]
        },
        {
            "id": "SV-257824r1044886_rule",
            "fix_text": "RHEL 9 must remove all software components after updated versions have been installed.",
            "expected_bad": ["all"]
        },
        {
            "id": "SV-258234r1051250_rule",
            "fix_text": "RHEL 9 must have the crypto-policies package installed.",
            "expected_bad": ["is"]
        },
        {
            "id": "SV-257819r1015075_rule",
            "fix_text": "RHEL 9 must ensure cryptographic verification of vendor software packages.",
            "expected_bad": ["red"]
        },
    ]
    
    blacklist = {"that", "all", "is", "contents", "red", "run", "--now", "--mask"}
    
    for test_case in test_cases:
        control = StigControl(
            id=test_case["id"],
            title="Test Package Control",
            severity="high",
            description="Test",
            rationale=None,
            check_text="Check text",
            fix_text=test_case["fix_text"],
            os_family="rhel",
            category="package",
            is_automatable=True,
        )
        
        with tempfile.TemporaryDirectory() as tmpdir:
            output_path = Path(tmpdir) / "test_hardening.yml"
            metadata = {
                "stig_name": "RHEL 9 STIG",
                "stig_release": "v2.6",
                "source_file_name": "test.xml",
                "generated_on": "2024-01-01T00:00:00",
            }
            
            generate_hardening_playbook([control], output_path, metadata)
            content = output_path.read_text()
            
            # Should NOT contain any blacklisted package names
            for bad_name in blacklist:
                assert f'name: {bad_name}' not in content
                assert f'name: "{bad_name}"' not in content
                assert f"name: '{bad_name}'" not in content


def test_rhel9_no_bogus_systemd_names():
    """Test that RHEL 9 hardening playbook never generates bogus systemd unit names."""
    test_cases = [
        {
            "id": "SV-257782r991589_rule",
            "fix_text": "systemctl enable --now run",
            "expected_bad": ["run", "--now"]
        },
        {
            "id": "SV-257818r1044876_rule",
            "fix_text": "systemctl disable --now kdump",
            "expected_bad": ["--now"]
        },
    ]
    
    blacklist = {"run", "--now", "that", "all", "is", "contents", "red"}
    
    for test_case in test_cases:
        control = StigControl(
            id=test_case["id"],
            title="Test Service Control",
            severity="high",
            description="Test",
            rationale=None,
            check_text="Check service",
            fix_text=test_case["fix_text"],
            os_family="rhel",
            category="service",
            is_automatable=True,
        )
        
        with tempfile.TemporaryDirectory() as tmpdir:
            output_path = Path(tmpdir) / "test_hardening.yml"
            metadata = {
                "stig_name": "RHEL 9 STIG",
                "stig_release": "v2.6",
                "source_file_name": "test.xml",
                "generated_on": "2024-01-01T00:00:00",
            }
            
            generate_hardening_playbook([control], output_path, metadata)
            content = output_path.read_text()
            
            # Should NOT contain any blacklisted systemd names
            for bad_name in blacklist:
                # Check systemd name field
                if 'systemd:' in content:
                    assert f'name: {bad_name}' not in content
                    assert f'name: "{bad_name}"' not in content
                    assert f"name: '{bad_name}'" not in content


def test_rhel9_no_shell_prompts():
    """Test that RHEL 9 hardening playbook doesn't contain shell prompts."""
    control = StigControl(
        id="SV-258241r1106302_rule",
        title="Test Control",
        severity="high",
        description="Test",
        rationale=None,
        check_text="Check text",
        fix_text="$ sudo sed -i 's/gpgcheck\\s*=.*/gpgcheck=1/g' /etc/yum.repos.d/*",
        os_family="rhel",
        category="config",
        is_automatable=True,
    )
    
    with tempfile.TemporaryDirectory() as tmpdir:
        output_path = Path(tmpdir) / "test_hardening.yml"
        metadata = {
            "stig_name": "RHEL 9 STIG",
            "stig_release": "v2.6",
            "source_file_name": "test.xml",
            "generated_on": "2024-01-01T00:00:00",
        }
        
        generate_hardening_playbook([control], output_path, metadata)
        content = output_path.read_text()
        
        # Should NOT contain $ prompts in shell commands
        # Check shell: blocks
        if 'shell:' in content or 'shell: |' in content:
            # Find shell blocks
            import re
            shell_blocks = re.findall(r'shell:\s*\|\s*\n((?:\s+[^\n]+\n?)+)', content, re.MULTILINE)
            for block in shell_blocks:
                # No line should start with $
                lines = block.split('\n')
                for line in lines:
                    stripped = line.strip()
                    if stripped and not stripped.startswith('#'):
                        assert not stripped.startswith('$'), f"Found $ prompt in shell command: {line}"


def test_rhel9_no_mixed_command_prose():
    """Test that RHEL 9 hardening playbook doesn't mix commands with prose."""
    control = StigControl(
        id="SV-258241r1106302_rule",
        title="Test Control",
        severity="high",
        description="Test",
        rationale=None,
        check_text="Check text",
        fix_text="update-crypto-policies --set FIPS:STIG\nreboot Verify RHEL 9 is set to use a FIPS 140-3-compliant systemwide cryptographic policy",
        os_family="rhel",
        category="config",
        is_automatable=True,
    )
    
    with tempfile.TemporaryDirectory() as tmpdir:
        output_path = Path(tmpdir) / "test_hardening.yml"
        metadata = {
            "stig_name": "RHEL 9 STIG",
            "stig_release": "v2.6",
            "source_file_name": "test.xml",
            "generated_on": "2024-01-01T00:00:00",
        }
        
        generate_hardening_playbook([control], output_path, metadata)
        content = output_path.read_text()
        
        # Should NOT contain mixed command+prose patterns
        assert "reboot Verify" not in content
        assert "reboot Verify RHEL" not in content
        assert "reboot Verify that RHEL" not in content
        
        # If reboot is present, it should be isolated or in manual notes
        if "reboot" in content.lower():
            # Should be either in a comment or isolated
            import re
            # Check that reboot is not followed immediately by "Verify"
            reboot_pattern = r'reboot\s+Verify'
            assert not re.search(reboot_pattern, content, re.IGNORECASE)


def test_rhel9_ctp_no_bogus_tokens():
    """Test that RHEL 9 CTP CSV doesn't contain bogus tokens in Command_or_Process."""
    import csv
    import io
    
    control = StigControl(
        id="SV-TEST-001",
        title="Test Control",
        severity="high",
        description="Test",
        rationale=None,
        check_text="Check text",
        fix_text="Install the crypto-policies package that is required for RHEL 9.",
        os_family="rhel",
        category="package",
        is_automatable=False,
    )
    
    with tempfile.TemporaryDirectory() as tmpdir:
        output_path = Path(tmpdir) / "test_ctp.csv"
        metadata = {
            "stig_name": "RHEL 9 STIG",
            "stig_release": "v2.6",
            "source_file_name": "test.xml",
            "generated_on": "2024-01-01T00:00:00",
        }
        
        generate_ctp_document([control], output_path, metadata)
        content = output_path.read_text()
        
        # Parse CSV
        reader = csv.DictReader(io.StringIO(content))
        for row in reader:
            command_field = row.get("Action/Command", "")
            
            # Should NOT contain bogus tokens
            blacklist = {"that", "all", "is", "contents", "red", "run", "--now"}
            for token in blacklist:
                # Check if token appears as standalone command
                if command_field.strip().lower() == token:
                    assert False, f"Found bogus token '{token}' as standalone command"
            
            # Should NOT start with $
            assert not command_field.strip().startswith('$')


def test_package_extractor_rejects_stopwords():
    """Test that package name extractor rejects stopwords."""
    from app.generators.extractors import extract_package_names_from_commands
    
    # Test cases that should NOT extract stopwords
    test_cases = [
        ("Install the crypto-policies package that is required", []),
        ("RHEL 9 must remove all software components", []),
        ("dnf install subscription-manager", ["subscription-manager"]),
        ("yum remove vsftpd", ["vsftpd"]),
        ("rpm -q audit", ["audit"]),
    ]
    
    for text, expected_packages in test_cases:
        packages = extract_package_names_from_commands(text)
        # Should not contain stopwords
        stopwords = {"that", "all", "is", "contents", "red", "run"}
        for pkg in packages:
            assert pkg.lower() not in stopwords, f"Extracted stopword '{pkg}' from '{text}'"
        
        # Should extract expected packages
        if expected_packages:
            for expected in expected_packages:
                assert expected in packages or any(expected.lower() == p.lower() for p in packages), \
                    f"Expected '{expected}' not found in extracted packages from '{text}'"


def test_systemd_extractor_rejects_flags():
    """Test that systemd extractor rejects flags as unit names."""
    from app.generators.extractors import extract_systemd_actions
    
    # Test cases
    test_cases = [
        ("systemctl enable --now", []),  # No unit, should be empty
        ("systemctl enable rngd --now", [{"unit": "rngd", "action": "enable_and_start"}]),
        ("systemctl disable --now kdump", [{"unit": "kdump", "action": "disable"}]),
        ("systemctl mask kdump", [{"unit": "kdump", "action": "mask"}]),
    ]
    
    for text, expected_actions in test_cases:
        actions = extract_systemd_actions(text)
        
        # Should never have --now or other flags as unit names
        for action in actions:
            assert action["unit"] != "--now"
            assert action["unit"] != "--mask"
            assert not action["unit"].startswith('-')
        
        # Should match expected actions
        if expected_actions:
            assert len(actions) == len(expected_actions)
            for expected in expected_actions:
                found = any(
                    a["unit"] == expected["unit"] and a["action"] == expected["action"]
                    for a in actions
                )
                assert found, f"Expected action {expected} not found in {actions}"


def test_yaml_validity_hardening():
    """Test that generated hardening playbook is valid YAML."""
    import yaml
    
    control = StigControl(
        id="SV-TEST-001",
        title="Test Control",
        severity="high",
        description="Test description",
        rationale=None,
        check_text="Check text",
        fix_text="""Configure dnf to always check the GPG signature.
Add or update the following line in the [main] section of the /etc/dnf/dnf.conf file:
gpgcheck=1""",
        os_family="rhel",
        category="config",
        is_automatable=True,
    )
    
    with tempfile.TemporaryDirectory() as tmpdir:
        output_path = Path(tmpdir) / "test_hardening.yml"
        metadata = {
            "stig_name": "RHEL 9 STIG",
            "stig_release": "v2.6",
            "source_file_name": "test.xml",
            "generated_on": "2024-01-01T00:00:00",
        }
        
        generate_hardening_playbook([control], output_path, metadata)
        content = output_path.read_text()
        
        # Should parse as valid YAML
        try:
            yaml.safe_load(content)
        except yaml.YAMLError as e:
            assert False, f"Generated YAML is invalid: {e}"


def test_yaml_validity_checker():
    """Test that generated checker playbook is valid YAML."""
    import yaml
    
    control = StigControl(
        id="SV-TEST-002",
        title="Test Control",
        severity="high",
        description="Test description",
        rationale=None,
        check_text="Check text",
        fix_text="Fix text",
        os_family="rhel",
        category="config",
        is_automatable=True,
    )
    
    with tempfile.TemporaryDirectory() as tmpdir:
        output_path = Path(tmpdir) / "test_checker.yml"
        metadata = {
            "stig_name": "RHEL 9 STIG",
            "stig_release": "v2.6",
            "source_file_name": "test.xml",
            "generated_on": "2024-01-01T00:00:00",
        }
        
        generate_checker_playbook([control], output_path, metadata)
        content = output_path.read_text()
        
        # Should parse as valid YAML
        try:
            yaml.safe_load(content)
        except yaml.YAMLError as e:
            assert False, f"Generated YAML is invalid: {e}"


def test_no_prose_in_commands():
    """Test that commands in hardening/checker playbooks don't contain prose."""
    prose_markers = [
        "Verify that",
        "verify that",
        "as shown in the example",
        "Add or update",
        "NOTE:",
        "Note:",
        "For example",
        "review the output",
    ]
    
    control = StigControl(
        id="SV-TEST-003",
        title="Test Control",
        severity="high",
        description="Test",
        rationale=None,
        check_text="Check text",
        fix_text="grubby --update-kernel=ALL --remove-args='systemd...' Verify that GRUB 2 is configured",
        os_family="rhel",
        category="config",
        is_automatable=True,
    )
    
    with tempfile.TemporaryDirectory() as tmpdir:
        output_path = Path(tmpdir) / "test_hardening.yml"
        metadata = {
            "stig_name": "RHEL 9 STIG",
            "stig_release": "v2.6",
            "source_file_name": "test.xml",
            "generated_on": "2024-01-01T00:00:00",
        }
        
        generate_hardening_playbook([control], output_path, metadata)
        content = output_path.read_text()
        
        # Check shell blocks for prose
        import re
        shell_blocks = re.findall(r'shell:\s*\|\s*\n((?:\s+[^\n]+\n?)+)', content, re.MULTILINE)
        for block in shell_blocks:
            for line in block.split('\n'):
                line_clean = line.strip()
                if line_clean and not line_clean.startswith('#'):
                    for marker in prose_markers:
                        assert marker not in line_clean, f"Found prose marker '{marker}' in command: {line_clean}"


def test_placeholder_commands_not_automatable():
    """Test that placeholder commands are not treated as automatable."""
    from app.generators.extractors import is_placeholder_command
    
    placeholder_commands = [
        "userdel <unauthorized_user>",
        "chown root [Public Directory]",
        "passwd -n 1 [user]",
        "grubby --update-kernel=ALL --remove-args=<PART>",
    ]
    
    for cmd in placeholder_commands:
        assert is_placeholder_command(cmd), f"Should detect placeholder in: {cmd}"
    
    # Test that controls with placeholder commands are not automatable
    control = StigControl(
        id="SV-TEST-004",
        title="Test Control",
        severity="high",
        description="Test",
        rationale=None,
        check_text="Check text",
        fix_text="userdel <unauthorized_user> Verify that there are no unauthorized accounts",
        os_family="rhel",
        category="other",
        is_automatable=False,  # Should be False
        automatable_commands=["userdel <unauthorized_user>"],
    )
    
    # Should not have real commands (because of placeholder)
    assert not control.has_real_commands()


def test_split_command_and_prose():
    """Test the split_command_and_prose helper function."""
    from app.generators.extractors import split_command_and_prose
    
    test_cases = [
        ("grubby --update-kernel=ALL Verify that GRUB 2 is configured", 
         "grubby --update-kernel=ALL", 
         "Verify that GRUB 2 is configured"),
        ("reboot Verify that GRUB2 is configured", 
         "reboot", 
         "Verify that GRUB2 is configured"),
        ("chown root [Public Directory] Verify that world writable", 
         "chown root [Public Directory]", 
         "Verify that world writable"),
        ("systemctl daemon-reload", 
         "systemctl daemon-reload", 
         None),
        ("Verify that RHEL 9 is configured", 
         None, 
         "Verify that RHEL 9 is configured"),
    ]
    
    for line, expected_cmd, expected_prose in test_cases:
        cmd_part, prose_part = split_command_and_prose(line)
        if expected_cmd:
            assert cmd_part == expected_cmd, f"Expected command '{expected_cmd}', got '{cmd_part}'"
        else:
            assert cmd_part is None, f"Expected no command, got '{cmd_part}'"
        
        if expected_prose:
            assert prose_part is not None, f"Expected prose '{expected_prose}', got None"
            assert expected_prose in prose_part, f"Expected prose to contain '{expected_prose}', got '{prose_part}'"
        else:
            assert prose_part is None or len(prose_part) == 0, f"Expected no prose, got '{prose_part}'"


def test_is_probable_cli_command():
    """Test is_probable_cli_command function."""
    from app.generators.extractors import is_probable_cli_command
    
    # Real commands should return True
    assert is_probable_cli_command("grep -i pattern /etc/file")
    assert is_probable_cli_command("systemctl enable rngd")
    assert is_probable_cli_command("cat /etc/passwd")
    assert is_probable_cli_command("ls -l /var/log")
    assert is_probable_cli_command("sudo dnf install package")
    
    # Config values should return False
    assert not is_probable_cli_command("GRUB2_PASSWORD=password")
    assert not is_probable_cli_command("600 /var/log/messages")
    assert not is_probable_cli_command("root /etc/passwd")
    assert not is_probable_cli_command("AutomaticLoginEnable=false")
    assert not is_probable_cli_command("MACs hmac-sha2-256-etm@openssh.com")
    
    # Sample output should return False
    assert not is_probable_cli_command("/dev/sda1 on /boot/efi type vfat")
    assert not is_probable_cli_command("LoadState=loaded")
    assert not is_probable_cli_command("services: ssh")
    
    # Prose should return False
    assert not is_probable_cli_command("Configure the system to...")
    assert not is_probable_cli_command("If this is not configured")
    assert not is_probable_cli_command("Document the use of...")
    
    # Placeholders should return False
    assert not is_probable_cli_command("find PART -xdev")
    assert not is_probable_cli_command("chmod <mode> <file>")


def test_looks_like_config_value():
    """Test looks_like_config_value function."""
    from app.generators.extractors import looks_like_config_value
    
    # Config values should return True
    assert looks_like_config_value("GRUB2_PASSWORD=password")
    assert looks_like_config_value("600 /var/log/messages")
    assert looks_like_config_value("root /etc/passwd")
    assert looks_like_config_value("AutomaticLoginEnable=false")
    assert looks_like_config_value("MACs hmac-sha2-256-etm@openssh.com")
    
    # Commands should return False
    assert not looks_like_config_value("grep -i pattern /etc/file")
    assert not looks_like_config_value("systemctl enable rngd")
    assert not looks_like_config_value("cat /etc/passwd")


def test_parse_systemctl_command():
    """Test parse_systemctl_command function."""
    from app.generators.extractors import parse_systemctl_command
    
    # Test various systemctl command patterns
    result = parse_systemctl_command("systemctl enable --now rngd")
    assert result is not None
    assert result["action"] == "enable_and_start"
    assert result["unit"] == "rngd.service"
    
    result = parse_systemctl_command("systemctl disable debug-shell.service")
    assert result is not None
    assert result["action"] == "disable"
    assert result["unit"] == "debug-shell.service"
    
    result = parse_systemctl_command("systemctl mask kdump")
    assert result is not None
    assert result["action"] == "mask"
    assert result["unit"] == "kdump.service"
    
    result = parse_systemctl_command("systemctl --now enable rngd")
    assert result is not None
    assert result["action"] == "enable_and_start"
    assert result["unit"] == "rngd.service"
    
    # Invalid commands should return None
    assert parse_systemctl_command("systemctl enable --now") is None
    assert parse_systemctl_command("systemctl enable run") is None  # "run" is a stopword
    assert parse_systemctl_command("systemctl enable with") is None  # "with" is a stopword
    assert parse_systemctl_command("systemctl enable on") is None  # "on" is a stopword


def test_hardening_playbook_no_prose_in_shell():
    """Test that hardening playbook doesn't contain prose in shell tasks."""
    from app.model.controls import StigControl
    
    control = StigControl(
        id="TEST-01-000001",
        title="Test Control",
        severity="medium",
        description="Test description",
        check_text="Check text",
        fix_text="Configure the system. Run grep -i pattern /etc/file Verify that output shows pattern",
        is_automatable=True,
        category="config",
        automatable_commands=["grep -i pattern /etc/file Verify that output shows pattern"]
    )
    
    with tempfile.TemporaryDirectory() as tmpdir:
        output_path = Path(tmpdir) / "test_hardening.yml"
        metadata = {
            "stig_name": "Test STIG",
            "stig_release": "v1.0",
            "source_file_name": "test.xml",
            "generated_on": "2024-01-01T00:00:00",
        }
        
        generate_hardening_playbook([control], output_path, metadata)
        content = output_path.read_text()
        
        # Should not contain prose prefixes in shell tasks
        PROSE_PREFIXES = [
            "Configure ", "If ", "Document ", "To ", "NOTE:", "Must:",
            "The following condition", "All verification requirements",
            "Output must be:", "File location:", "Configuration: ",
            "Command output", "Review the command output"
        ]
        
        # Check that shell tasks don't start with prose
        lines = content.split('\n')
        in_shell_task = False
        for line in lines:
            if 'shell: |' in line:
                in_shell_task = True
                continue
            if in_shell_task:
                if line.strip().startswith('-') or line.strip().startswith('#'):
                    in_shell_task = False
                    continue
                if line.strip() and not line.strip().startswith(' '):
                    in_shell_task = False
                    continue
                # Check that shell command lines don't start with prose
                stripped = line.strip()
                if stripped:
                    for prefix in PROSE_PREFIXES:
                        assert not stripped.startswith(prefix), f"Found prose prefix '{prefix}' in shell task: {line}"


def test_checker_playbook_no_prose_in_commands():
    """Test that checker playbook doesn't contain prose in commands."""
    from app.model.controls import StigControl
    
    control = StigControl(
        id="TEST-01-000001",
        title="Test Control",
        severity="medium",
        description="Test description",
        check_text="Configure the system. Run grep -i pattern /etc/file Verify that output shows pattern",
        fix_text="Fix text",
        is_automatable=False,
        category="config",
        check_commands=["grep -i pattern /etc/file Verify that output shows pattern"]
    )
    
    with tempfile.TemporaryDirectory() as tmpdir:
        output_path = Path(tmpdir) / "test_checker.yml"
        metadata = {
            "stig_name": "Test STIG",
            "stig_release": "v1.0",
            "source_file_name": "test.xml",
            "generated_on": "2024-01-01T00:00:00",
        }
        
        generate_checker_playbook([control], output_path, metadata)
        content = output_path.read_text()
        
        # Should not contain prose prefixes in commands
        PROSE_PREFIXES = [
            "Configure ", "If ", "Document ", "To ", "NOTE:", "Must:",
            "The following condition", "All verification requirements",
            "Output must be:", "File location:", "Configuration: ",
            "Command output", "Review the command output"
        ]
        
        # Check that commands don't start with prose
        lines = content.split('\n')
        for line in lines:
            if 'cmd:' in line.lower():
                stripped = line.strip()
                for prefix in PROSE_PREFIXES:
                    assert not stripped.startswith(prefix), f"Found prose prefix '{prefix}' in command: {line}"


def test_ctp_no_config_values_in_action():
    """Test that CTP Action/Command doesn't contain config values."""
    from app.model.controls import StigControl
    
    control = StigControl(
        id="TEST-01-000001",
        title="Test Control",
        severity="medium",
        description="Test description",
        check_text="Run grep -i automaticlogin /etc/gdm/custom.conf\nAutomaticLoginEnable=false",
        fix_text="Fix text",
        is_automatable=False,
        category="config",
        check_commands=["grep -i automaticlogin /etc/gdm/custom.conf", "AutomaticLoginEnable=false"]
    )
    
    with tempfile.TemporaryDirectory() as tmpdir:
        output_path = Path(tmpdir) / "test_ctp.csv"
        metadata = {
            "stig_name": "Test STIG",
            "stig_release": "v1.0",
            "source_file_name": "test.xml",
            "generated_on": "2024-01-01T00:00:00",
        }
        
        generate_ctp_document([control], output_path, metadata)
        content = output_path.read_text()
        
        # Parse CSV
        import csv
        from io import StringIO
        reader = csv.DictReader(StringIO(content))
        rows = list(reader)
        
        # Check that Action/Command doesn't contain config values
        config_value_patterns = [
            "GRUB2_PASSWORD=",
            "AutomaticLoginEnable=",
            "600 /var/log",
            "root /etc",
            "MACs ",
        ]
        
        for row in rows:
            action = row.get("Action/Command", "")
            for pattern in config_value_patterns:
                assert pattern not in action, f"Found config value pattern '{pattern}' in Action/Command: {action}"


def test_systemd_task_no_invalid_names():
    """Test that systemd tasks don't have invalid unit names."""
    from app.model.controls import StigControl
    
    control = StigControl(
        id="TEST-01-000001",
        title="Test Control",
        severity="medium",
        description="Test description",
        check_text="Check text",
        fix_text="systemctl enable --now rngd",
        is_automatable=True,
        category="service",
        service_actions=[{"unit": "rngd", "action": "enable_and_start"}]
    )
    
    with tempfile.TemporaryDirectory() as tmpdir:
        output_path = Path(tmpdir) / "test_hardening.yml"
        metadata = {
            "stig_name": "Test STIG",
            "stig_release": "v1.0",
            "source_file_name": "test.xml",
            "generated_on": "2024-01-01T00:00:00",
        }
        
        generate_hardening_playbook([control], output_path, metadata)
        content = output_path.read_text()
        
        # Check that systemd tasks don't have invalid names
        invalid_names = {"run", "with", "on", "following"}
        lines = content.split('\n')
        in_systemd_task = False
        for i, line in enumerate(lines):
            if 'systemd:' in line:
                in_systemd_task = True
                continue
            if in_systemd_task:
                if 'name:' in line:
                    unit_name = line.split('name:')[1].strip()
                    # Extract just the unit name (remove quotes if present)
                    unit_name = unit_name.strip("'\"")
                    assert unit_name.lower() not in invalid_names, f"Found invalid systemd unit name '{unit_name}'"
                    in_systemd_task = False

