# STIG Generator

A Python CLI application that generates Ansible hardening playbooks, checker playbooks, and Certification Test Procedure (CTP) documents from DISA STIG XCCDF XML files.

## Overview

This tool automates the process of converting DISA STIG (Security Technical Implementation Guide) files into actionable automation artifacts for DoD environments:

1. **Ansible Hardening Playbook** - Automates the application of STIG controls that can be programmatically enforced
2. **Ansible Checker Playbook** - Validates STIG compliance for manual and semi-manual controls
3. **CTP Document** - Provides structured test procedures for manual controls in table format

## Features

- Parses XCCDF XML STIG files exported from public.cyber.mil
- Classifies controls as automatable vs manual using heuristic analysis
- Generates idempotent Ansible playbooks with proper tagging
- Creates CTP documents with standardized table format for manual controls
- Extracts NIST control family IDs when available in STIG metadata
- Designed for extensibility to support additional OS families and formats

## Changelog

### v0.9.1 - STIG Generator Improvements

**Production-Ready Artifact Generation**

This release significantly improves the quality of generated artifacts, especially for RHEL 9 STIG and other OS families:

#### Command Extraction Improvements
- **Enhanced filtering**: Only extracts real, executable commands; filters out narrative/placeholder text
- **Prose detection**: Discards lines containing phrases like "Verify that", "as shown in the example", "NOTE:", etc.
- **Mixed-line splitting**: Splits lines containing commands followed by narrative, keeping only the command portion
- **Systemd extraction**: Detects structured systemd actions (`enable_and_start`, `mask`, `disable`) with proper unit names
- **Sysctl extraction**: Extracts both config-file and command-style sysctl parameters with values
- **Grep pattern validation**: Ensures grep commands contain meaningful patterns, not just flags like `-r`, `-i`, or `args`

#### Hardening Playbook Improvements
- **Systemd tasks**: Properly extracts unit names, avoiding flags like `--now` or `--mask` being treated as unit names
- **Sysctl tasks**: All sysctl tasks now include required `value` field; controls without values generate manual debug tasks instead
- **Manual-only controls**: Generate clean debug tasks with concise messages referencing STIG FixText
- **Command validation**: Only generates shell tasks from commands that pass `has_real_commands()` filtering

#### Checker Playbook Improvements
- **Meaningful checks**: Uses structured `check_commands` with validation to avoid degenerate grep patterns
- **Pattern validation**: Filters out grep commands that only contain flags without real patterns
- **Fallback handling**: For controls without valid check commands, generates appropriate debug tasks with manual guidance

#### CTP Document Improvements
- **Clean Command_or_Process**: Field contains only real commands or clear manual instructions; no placeholders or prose
- **Command sanitization**: Applies same filtering rules as checker to ensure production-ready commands
- **Notes enhancement**: Includes manual guidance from `manual_notes` when commands are not sufficient

#### Classification Improvements
- **Real command validation**: Controls are only marked automatable if `has_real_commands()` returns True
- **Manual fallback**: Controls with only narrative instructions are correctly classified as manual

#### Systemd Extraction Fixes
- **Robust unit name extraction**: Handles various command patterns:
  - `systemctl enable rngd --now`
  - `systemctl --now enable rngd`
  - `systemctl mask ctrl-alt-del.target`
  - `systemctl restart systemd-journald`
- **Flag validation**: Explicitly guards against treating flags (`--now`, `--mask`, etc.) as unit names
- **Action mapping**: Properly maps to Ansible systemd module parameters (enabled, masked, state)

#### Prose Stripping
- **Command sanitization**: Removes narrative text from shell commands
- **Pattern detection**: Splits on common prose introducers ("Verify RHEL 9", "as shown in the example", etc.)
- **Clean output**: Hardening playbooks contain only pure commands, no trailing prose

#### Degenerate Pattern Filtering
- **Grep validation**: Filters out patterns that are just flags (`-r`, `-i`, `-A1`) without meaningful content
- **Quoted pattern handling**: Properly validates both quoted and unquoted grep patterns
- **Meaningful checks**: Only generates checker tasks with valid, executable commands

#### Regression Testing
- Added comprehensive tests to lock in behavior:
  - No systemd tasks with flags as unit names (`name: --now`)
  - All sysctl tasks include values
  - No degenerate grep patterns in checker (`grep -E '-r'`)
  - No prose in shell commands ("Verify RHEL 9", "as shown in the example")
  - Clean CTP Action/Command fields
  - Proper `has_real_commands()` validation

**Backward Compatibility**: All improvements maintain backward compatibility with RHEL 8 and Cisco NDM STIGs.

## Requirements

- Python 3.11 or higher
- XCCDF XML STIG files from DISA (public.cyber.mil)

## Installation

### From Source

```bash
cd stig_generator
pip install -e .
```

### Dependencies

The project uses:
- `typer` for CLI interface
- `pyyaml` for YAML generation
- Standard library `xml.etree.ElementTree` for XML parsing

## Usage

### Basic Usage

```bash
python -m app.main \
  --stig-file stigs/input/RHEL_8_STIG.xml \
  --product rhel8
```

### Options

- `--stig-file`, `-f`: Path to the XCCDF XML STIG file (required)
- `--product`, `-p`: Product identifier (default: `rhel8`)
- `--output-dir`, `-o`: Output directory for generated artifacts (default: `output`)

### Example

```bash
python -m app.main \
  --stig-file stigs/input/U_RHEL_8_V3R1_STIG_Manual-xccdf.xml \
  --product rhel8 \
  --output-dir output
```

This will generate:
- `output/ansible/stig_rhel8_hardening.yml`
- `output/ansible/stig_rhel8_checker.yml`
- `output/ctp/stig_rhel8_ctp.md`

## Project Structure

```
stig_generator/
├── app/
│   ├── __init__.py
│   ├── main.py              # CLI entry point
│   ├── parsers/
│   │   ├── __init__.py
│   │   └── xccdf_parser.py  # XCCDF XML parser
│   ├── model/
│   │   ├── __init__.py
│   │   └── controls.py      # StigControl dataclass
│   ├── classifiers/
│   │   ├── __init__.py
│   │   └── automatable.py   # Control classification logic
│   └── generators/
│       ├── __init__.py
│       ├── ansible_hardening.py
│       ├── ansible_checker.py
│       └── ctp_doc.py
├── stigs/
│   └── input/               # Place XCCDF XML files here
├── output/                  # Generated artifacts
│   ├── ansible/
│   └── ctp/
├── pyproject.toml
└── README.md
```

## How It Works

### 1. Parsing

The XCCDF parser extracts:
- Control ID (e.g., `RHEL-08-010010`)
- Title, description, rationale
- Check text and fix text
- Severity level
- References (SRG, CCI, NIST mappings)
- NIST control family IDs when available

### 2. Classification

Controls are classified as automatable or manual based on:
- **Automatable**: File permissions, services, sysctl, packages, audit rules, config files
- **Manual**: GUI-only configs, policy reviews, subjective analysis, interviews

When in doubt, controls default to manual to ensure safety.

### 3. Generation

- **Hardening Playbook**: Contains tasks for all controls:
  - Automatable controls: Real Ansible module tasks (systemd, sysctl, file, package, etc.)
  - Manual controls: Clean debug tasks with STIG references
  - One task per STIG control
  - Proper tagging for selective execution
- **Checker Playbook**: Contains validation tasks for all controls:
  - Meaningful check commands (grep, stat, systemctl status, etc.)
  - Degenerate patterns filtered out
  - Manual validation tasks where automation isn't possible
  - Tagged with `validate_automatable` or `validate_manual`
- **CTP Document**: Provides step-by-step test procedures in CSV format:
  - Clean Action/Command fields (no prose or placeholders)
  - Real commands or clear manual instructions
  - Expected results and notes

## Output Format

### Ansible Playbooks

Both playbooks follow standard Ansible structure:
- Proper tagging (`stig`, control ID, category, severity, automatable/manual)
- Idempotent tasks using native Ansible modules where possible
- Comments with metadata (severity, NIST ID, description)
- **Production-ready**: No placeholder commands, no prose mixed with commands, no degenerate patterns

### CTP Document

The CTP document uses a standardized CSV format with columns:
- STIG ID
- NIST 800-53 Control ID
- Severity
- Step Number
- Action/Command (clean commands or manual instructions)
- Expected Output/Result
- Expected Screen Output
- Notes
- Pass/Fail

**Production-ready**: Action/Command fields contain only real commands or clear manual instructions; no narrative glue or placeholders.

## Production Readiness

The generator produces production-ready artifacts:

- **One task per STIG control**: Every control has a corresponding task in hardening and checker playbooks
- **Structured output**: CTP documents use standardized CSV format for easy import into test management systems
- **Idempotent modules**: Uses native Ansible modules (systemd, sysctl, file, package) where possible
- **Clear manual tasks**: Controls that cannot be automated generate clean debug tasks with STIG references
- **Meaningful validation**: Checker playbooks contain only valid, executable check commands
- **No placeholders**: All generated commands are real, executable commands or clear manual instructions

## Supported STIGs

The generator currently supports:

- **RHEL 8 STIG** - Full support for hardening, checker, and CTP generation
- **RHEL 9 STIG** - Full support with production-ready artifacts
- **Cisco IOS Switch STIGs** (NDM, L2S, RTR) - Network device configuration
- **Windows 11 STIG** - Basic support (extensible)

Additional OS families can be added by extending the extractors and generators.

## Current Limitations

- XCCDF XML format only (other STIG formats not yet supported)
- Some complex controls may require manual review of generated tasks
- Classification heuristics may need refinement for edge cases

## Future Enhancements

- Support for additional OS families (Windows, Ubuntu, etc.)
- Support for other STIG formats
- Enhanced task implementation with actual Ansible module logic
- Improved classification accuracy
- Integration with STIG validation tools

## Contributing

This is a v1 implementation focused on structure and extensibility. Contributions welcome for:
- Task implementation details
- Classification improvements
- Additional OS support
- Format support

## License

MIT License

## Disclaimer

This tool is provided as-is for automation assistance. Always validate generated playbooks and procedures against official STIG documentation and your organization's security policies before use in production environments.


