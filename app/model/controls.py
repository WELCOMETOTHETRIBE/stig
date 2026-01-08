"""STIG Control data model definitions."""

from dataclasses import dataclass, field
from typing import Literal, Optional


@dataclass
class StigControl:
    """Represents a single STIG control/rule."""

    id: str  # e.g. "RHEL-08-010010"
    title: str
    severity: Literal["low", "medium", "high", "critical"]
    description: str
    rationale: Optional[str]
    check_text: str  # The "Check" section from the STIG
    fix_text: str  # The "Fix" section from the STIG
    references: list[str] = field(default_factory=list)
    os_family: Literal["rhel", "windows", "ubuntu", "network", "db", "other"] = "rhel"
    category: Literal[
        "config",
        "file_permission",
        "service",
        "package",
        "sysctl",
        "audit",
        "registry",
        "gpo",
        "other",
    ] = "other"
    is_automatable: bool = False
    nist_family_id: Optional[str] = None  # e.g. "AU.02.b" if available
    raw_metadata: dict[str, str] = field(default_factory=dict)
    # Structured command/check blocks extracted from XCCDF content
    candidate_cli_blocks: list[str] = field(default_factory=list)  # CLI configuration examples
    candidate_check_blocks: list[str] = field(default_factory=list)  # Validation/check procedures
    candidate_shell_blocks: list[str] = field(default_factory=list)  # Shell commands (RHEL/Ubuntu/Windows)
    # Extracted commands (populated after extraction)
    automatable_commands: list[str] = field(default_factory=list)  # Concrete config commands for hardening
    check_commands: list[str] = field(default_factory=list)  # Non-destructive commands to verify state
    manual_notes: list[str] = field(default_factory=list)  # Residual instructions for CTP Notes
    # Structured data for specific control types
    service_actions: list[dict] = field(default_factory=list)  # Systemd service actions: [{"unit": "rngd", "action": "enable_and_start"}]
    sysctl_params: list[dict] = field(default_factory=list)  # Sysctl parameters: [{"name": "kernel.randomize_va_space", "value": "2"}]
    
    def has_real_commands(self) -> bool:
        """
        Check if this control has real, executable commands (not just prose/narrative or placeholders).
        
        Returns:
            True if at least one real command exists in automatable_commands or check_commands
        """
        from ..generators.extractors import is_probable_cli_command
        
        all_commands = self.automatable_commands + self.check_commands + self.candidate_shell_blocks + self.candidate_cli_blocks
        
        if not all_commands:
            return False
        
        # Check if any command passes robust validation
        for cmd in all_commands:
            if is_probable_cli_command(cmd):
                return True
        
        return False


def normalize_severity(severity_str: str) -> Literal["low", "medium", "high", "critical"]:
    """
    Convert STIG severity string to normalized enum value.

    Args:
        severity_str: Raw severity string from XML (e.g., "high", "HIGH", "CAT I", etc.)

    Returns:
        Normalized severity value
    """
    severity_lower = severity_str.lower().strip()

    # Handle common STIG severity formats
    # Check longer patterns first to avoid false matches (e.g., "cat ii" contains "cat i")
    if "critical" in severity_lower or severity_lower == "i":
        return "critical"
    elif "cat iii" in severity_lower or severity_lower == "iii":
        return "medium"
    elif "cat ii" in severity_lower or severity_lower == "ii" or "high" in severity_lower:
        return "high"
    elif "cat i" in severity_lower:
        return "critical"
    elif "medium" in severity_lower:
        return "medium"
    elif "low" in severity_lower:
        return "low"
    else:
        # Default to medium if unclear
        return "medium"

