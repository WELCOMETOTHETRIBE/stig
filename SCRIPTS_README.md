# Scripts Directory - Quick Start Guide

This directory contains skeleton scripts for the refactored STIG generator workflow. These are **starting points** that you can refine with Cursor's help.

## Workflow Overview

The new workflow follows a clean pipeline:

```
XCCDF XML (+ optional SCAP/Nessus) → parse_stig.py → JSON → [generate_hardening.py, generate_checker.py, generate_ctp.py] → Artifacts
```

### Complete Example with Secondary Artifact

```bash
# 1) Parse STIG + SCAP benchmark
python scripts/parse_stig.py \
    --xccdf stigs/input/U_RHEL_9_STIG_V2R6_Manual-xccdf.xml \
    --output data/json/rhel9.json \
    --secondary-artifact stigs/benchmark/U_RHEL_9_V2R6_STIG_SCAP_1-3_Benchmark.xml \
    --secondary-type scap

# 2) Generate hardening / checker / CTP
python scripts/generate_hardening.py \
    --input data/json/rhel9.json \
    --output output/ansible/stig_rhel9_hardening.yml

python scripts/generate_checker.py \
    --input data/json/rhel9.json \
    --output output/ansible/stig_rhel9_checker.yml

python scripts/generate_ctp.py \
    --input data/json/rhel9.json \
    --output output/ctp/stig_rhel9_ctp.csv \
    --manual-only
```

**Guarantee**: "SCAP/Nessus tells us what is automated; any STIG controls not covered are treated as manual-only and preserved in the CTP."

## Step-by-Step Usage

### 1. Parse STIG XML to JSON

**Basic usage (without secondary artifact):**

```bash
python scripts/parse_stig.py \
  --xccdf stigs/input/U_RHEL_9_STIG_V2R6_Manual-xccdf.xml \
  --output data/rhel9_stig_controls.json
```

**With SCAP benchmark (recommended):**

```bash
python scripts/parse_stig.py \
  --xccdf stigs/input/U_RHEL_9_STIG_V2R6_Manual-xccdf.xml \
  --output data/rhel9_stig_controls.json \
  --secondary-artifact stigs/benchmark/U_RHEL_9_V2R6_STIG_SCAP_1-3_Benchmark.xml \
  --secondary-type scap
```

**With Nessus scan:**

```bash
python scripts/parse_stig.py \
  --xccdf stigs/input/U_RHEL_9_STIG_V2R6_Manual-xccdf.xml \
  --output data/rhel9_stig_controls.json \
  --secondary-artifact scan_results.xml \
  --secondary-type nessus
```

**Auto-detect secondary artifact type:**

```bash
python scripts/parse_stig.py \
  --xccdf stigs/input/U_RHEL_9_STIG_V2R6_Manual-xccdf.xml \
  --output data/rhel9_stig_controls.json \
  --secondary-artifact stigs/benchmark/U_RHEL_9_V2R6_STIG_SCAP_1-3_Benchmark.xml
  # Type will be auto-detected from file content
```

**What is a secondary artifact?**

A secondary artifact (SCAP benchmark or Nessus scan) helps distinguish between:
- **Automated controls**: Covered by SCAP/Nessus (scanner can test them)
- **Manual-only controls**: Present in the STIG but not covered by SCAP/Nessus

**Key rule**: "The benchmark is the automated scans; the items left in the STIG that aren't covered in the benchmark are manual and need to be kept in the CTP."

When a secondary artifact is provided:
- Controls found in the SCAP/Nessus map are marked as `automation_level: "automated"` and `automation_source: "scap"` or `"nessus"`
- Controls NOT found in the map are marked as `automation_level: "manual_only"` and `automation_source: "scap"` or `"nessus"` (indicating we checked)

When no secondary artifact is provided:
- All controls are marked as `automation_level: "unknown"` and `automation_source: "none"`

### 2. Generate Hardening Playbook

```bash
python scripts/generate_hardening.py \
  --input data/rhel9_stig_controls.json \
  --output ansible/stig_rhel9_hardening.yml \
  --product rhel9 \
  --verify-coverage
```

**Current Status**: Skeleton with category detection and placeholder tasks. You'll need to:
- Implement category-specific task generators (e.g., `generate_file_permission_tasks`)
- Extract actual values from `fix_text` (file paths, modes, package names, etc.)
- Use proper Ansible modules (`file`, `package`, `systemd`, `sysctl`, etc.)

### 3. Generate Checker Playbook

```bash
python scripts/generate_checker.py \
  --input data/rhel9_stig_controls.json \
  --output ansible/stig_rhel9_checker.yml \
  --product rhel9 \
  --verify-coverage
```

**Current Status**: Skeleton with placeholder check tasks. You'll need to:
- Extract check commands from `check_text`
- Prefer Ansible modules (`stat`, `package_facts`, `systemd`) over shell
- Generate proper assertions with clear pass/fail messages

### 4. Generate CTP CSV

**Generate CTP for all controls:**

```bash
python scripts/generate_ctp.py \
  --input data/rhel9_stig_controls.json \
  --output ctp/stig_rhel9_ctp.csv \
  --verify-coverage
```

**Generate CTP for manual-only controls only:**

```bash
python scripts/generate_ctp.py \
  --input data/rhel9_stig_controls.json \
  --output ctp/stig_rhel9_ctp_manual_only.csv \
  --manual-only \
  --verify-coverage
```

**CTP CSV columns:**

The generated CTP CSV includes the following columns:
- STIG ID
- NIST 800-53 Control ID
- Severity
- Step Number
- Action/Command
- Expected Output/Result
- Expected Screen Output (what user sees)
- Notes
- **Automation Level** (new): `automated`, `manual_only`, or `unknown`
- **Automation Source** (new): `none`, `scap`, or `nessus`
- Pass/Fail

**When to use `--manual-only`:**

Use `--manual-only` when you want to generate a CTP that only includes controls that require manual verification. Automated controls are tested via SCAP/Nessus scans and don't need manual CTP steps.

### 5. Verify Coverage

```bash
python tests/test_coverage.py \
  --json-path data/rhel9_stig_controls.json \
  --hardening-path ansible/stig_rhel9_hardening.yml \
  --checker-path ansible/stig_rhel9_checker.yml \
  --ctp-path ctp/stig_rhel9_ctp.csv
```

**Current Status**: Fully functional! This test ensures 100% coverage of all STIG IDs.

## Using Cursor to Refine

### For `parse_stig.py`:

Ask Cursor:
> "Refine `scripts/parse_stig.py` to:
> - Import the actual XCCDF parser from `app.parsers.xccdf_parser`
> - Map parsed `StigControl` objects to the simplified dataclass in this file
> - Ensure all required fields (sv_id, nist_id, severity, title, description, check_text, fix_text, product, category, automation_level) are populated
> - Handle errors gracefully with logging"

### For `generate_hardening.py`:

Ask Cursor:
> "Refine `scripts/generate_hardening.py` to:
> - Implement `generate_file_permission_tasks()` to extract file path and mode from `fix_text` and generate proper `file:` tasks
> - Implement `generate_package_present_tasks()` and `generate_package_absent_tasks()` to extract package names and generate `package:` tasks
> - Implement `generate_service_enabled_tasks()` to extract service names and generate `systemd:` tasks
> - Implement `generate_sysctl_tasks()` to extract sysctl parameters and values and generate `sysctl:` tasks
> - Use the existing extractors from `app.generators.extractors` where possible"

### For `generate_checker.py`:

Ask Cursor:
> "Refine `scripts/generate_checker.py` to:
> - Extract actual check commands from `check_text` using the same extractors as the hardening generator
> - Prefer Ansible modules (`stat`, `package_facts`, `systemd`) over shell commands
> - Generate proper assertions with clear pass/fail messages
> - Handle edge cases where no valid check command can be extracted"

### For `generate_ctp.py`:

Ask Cursor:
> "Refine `scripts/generate_ctp.py` to:
> - Extract actual commands from `check_text` (same as checker generator)
> - Generate 1-3 CTP steps per control with proper formatting
> - Include clear expected outputs extracted from `check_text`
> - Format NIST IDs properly (AU.02 format, not AU-2)
> - Ensure every STIG ID has at least one row"

## Directory Structure

```
stig_generator/
├── scripts/
│   ├── parse_stig.py          # Parse XCCDF → JSON
│   ├── generate_hardening.py  # JSON → hardening playbook
│   ├── generate_checker.py   # JSON → checker playbook
│   └── generate_ctp.py        # JSON → CTP CSV
├── data/
│   └── stigs/
│       └── RHEL9/              # Place quarterly STIGs here
│           └── rhel9_stig_quarterly_2025Q1.xml
├── ansible/                    # Generated playbooks
│   ├── stig_rhel9_hardening.yml
│   └── stig_rhel9_checker.yml
├── ctp/                        # Generated CTP CSVs
│   └── stig_rhel9_ctp.csv
└── tests/
    └── test_coverage.py        # Coverage verification
```

## Next Steps

1. **Start with `parse_stig.py`**: Get the parser working first, as all other scripts depend on it
2. **Test with one STIG**: Use RHEL 9 STIG as your test case
3. **Iterate with Cursor**: Use the prompts above to refine each script incrementally
4. **Run coverage tests**: After each refinement, run `test_coverage.py` to ensure nothing broke
5. **Expand to other STIGs**: Once RHEL 9 works, test with RHEL 8, Windows, etc.

## Secondary Artifact Parsers

Two new parsers are available for processing secondary artifacts:

### `scripts/parse_scap_benchmark.py`

Parses SCAP benchmark files (datastream or XCCDF) to determine which STIG rule IDs are covered by automated checks (OVAL).

```bash
python scripts/parse_scap_benchmark.py \
    --scap stigs/benchmark/U_RHEL_9_V2R6_STIG_SCAP_1-3_Benchmark.xml \
    --output automation_map.json  # Optional: save for debugging
```

### `scripts/parse_nessus_scan.py`

Parses Nessus XML scan files to infer which STIG IDs are covered by automated checks.

```bash
python scripts/parse_nessus_scan.py \
    --nessus scan_results.xml \
    --output automation_map.json  # Optional: save for debugging
```

## Integration with Existing Code

The existing code in `app/` can be reused:
- `app.parsers.xccdf_parser.parse_xccdf()` - Use this in `parse_stig.py`
- `app.generators.extractors.*` - Use these in all generators
- `app.model.controls.StigControl` - You can either use this directly or map to the simplified version in `parse_stig.py`
- `app.parsers.scap_benchmark.*` - Existing SCAP parsing utilities (still used for auto-detection)

The goal is to create a clean, maintainable pipeline while leveraging the existing parsing and extraction logic.


